// Server.cs — warm-core epoll API worker. 1:1 with the validated engine's server
// loop (net.c primitives + the Zig api.zig worker). Single-threaded, pinned to a
// core; receives client fds from the LB over an AF_UNIX/SEQPACKET control socket
// (SCM_RIGHTS fd passing), runs the IVF fraud search, and writes precomputed
// HTTP/1.1 responses. All raw syscalls go through Syscalls (net.c port).
//
// Warm-core wait strategy (mirrors api.zig epollWaitUs + the spin loop):
//   1. EpollWaitUs(timeout=0)  -> non-blocking poll for ready events.
//   2. if none, busy-spin with X86Base.Pause for up to spinUs (NowNs-gated).
//   3. if still none, EpollWaitUs(timeout=idleUs) to sleep briefly.
//
// Connection lifecycle exactly mirrors net.c / the C server loop:
//   listen fd -> accept4 loop (the single LB control connection) -> ctrl
//   ctrl fd   -> RecvFd loop (SCM_RIGHTS), each yields a client fd
//   client fd -> set TCP_QUICKACK + SO_BUSY_POLL, epoll-add IN|RDHUP, then on
//                read: parse complete requests, respond, compact, keep-alive.

using System;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;
using System.Text;
using static Rinha.Syscalls;

namespace Rinha;

internal static unsafe class Server
{
    // EPIOCSPARAMS ioctl request + params struct (8 bytes), best-effort tuning.
    private const ulong EPIOCSPARAMS = 0x40086502;

    [StructLayout(LayoutKind.Sequential)]
    private struct EpollParams
    {
        public uint BusyPollUsecs;
        public ushort BusyPollBudget;
        public byte PreferBusyPoll;
        public byte Pad;
    }

    // token sentinels for the epoll Data field
    private const ulong TOKEN_LISTEN = ulong.MaxValue;
    private const ulong TOKEN_CTRL = ulong.MaxValue - 1;

    private const int MAX_EVENTS = 256;

    // ---- connection table (slab), fd-indexed --------------------------------
    private static readonly byte[][] ConnBuf = new byte[Const.MAX_FDS][];
    private static readonly int[] ConnUsed = new int[Const.MAX_FDS];

    // scratch for IvfIndex.Search (>= n_clusters ulong). Allocated after load.
    private static ulong[] _searchKeys = Array.Empty<ulong>();

    // ---- entry point --------------------------------------------------------
    // spinUs: busy-spin window before sleeping; idleUs: idle epoll sleep timeout.
    public static void RunServer(string ctrlPath, string indexPath, int spinUs, int idleUs)
    {
        // Load the IVF index (anonymous resident RAM; pointers into a pinned buffer).
        var index = IvfIndex.Load(indexPath, pin: true);
        _searchKeys = new ulong[(int)index.NClusters];

        int listenFd = UdsListener(ctrlPath, backlog: 16);
        if (listenFd < 0)
            throw new Exception($"uds_listener({ctrlPath}) failed: {Marshal.GetLastPInvokeError()}");

        int epfd = epoll_create1(EPOLL_CLOEXEC);
        if (epfd < 0)
            throw new Exception($"epoll_create1 failed: {Marshal.GetLastPInvokeError()}");

        ConfigureEpollBusyPoll(epfd);

        EpollAdd(epfd, listenFd, TOKEN_LISTEN, EPOLLIN);

        int ctrlFd = -1;
        var events = stackalloc EpollEvent[MAX_EVENTS];
        long spinNs = (long)spinUs * 1000L;
        // idleUs <= 0 means "block" in EpollWaitUs (timeout < 0). The C worker uses a
        // small positive idle timeout; passing -1 blocks until an event arrives.
        long idleTimeout = idleUs;

        while (true)
        {
            // ---- warm-core wait: poll -> spin -> idle sleep ----------------
            int ready = EpollWaitUs(epfd, events, MAX_EVENTS, 0);
            if (ready == 0 && spinNs > 0)
            {
                long start = NowNs();
                while (NowNs() - start < spinNs)
                {
                    X86Base.Pause();
                    ready = EpollWaitUs(epfd, events, MAX_EVENTS, 0);
                    if (ready != 0)
                        break;
                }
            }
            if (ready == 0)
                ready = EpollWaitUs(epfd, events, MAX_EVENTS, idleTimeout);

            if (ready < 0)
            {
                if (Marshal.GetLastPInvokeError() == EINTR)
                    continue;
                break;
            }

            for (int i = 0; i < ready; i++)
            {
                ulong token = events[i].Data;
                uint rev = events[i].Events;

                if (token == TOKEN_LISTEN)
                {
                    AcceptCtrl(epfd, listenFd, ref ctrlFd);
                    continue;
                }

                if (token == TOKEN_CTRL)
                {
                    if ((rev & (EPOLLERR | EPOLLHUP)) != 0)
                    {
                        epoll_ctl(epfd, EPOLL_CTL_DEL, ctrlFd, null);
                        close(ctrlFd);
                        ctrlFd = -1;
                        continue;
                    }
                    if ((rev & EPOLLIN) != 0)
                        DrainFds(epfd, ctrlFd, ref ctrlFd);
                    continue;
                }

                // client fd
                int fd = (int)token;
                if ((rev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0)
                {
                    CloseClient(epfd, fd);
                    continue;
                }
                if ((rev & EPOLLIN) != 0)
                    OnClientReadable(epfd, fd, index);
            }
        }
    }

    // ---- listener (mirrors net.c uds_listener) ------------------------------
    private static int UdsListener(string path, int backlog)
    {
        int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0)
            return -1;

        var bytes = Encoding.UTF8.GetBytes(path);
        if (bytes.Length >= 108)
        {
            close(fd);
            return -1;
        }

        var un = new SockAddrUn { SunFamily = AF_UNIX };
        SockAddrUn* pun = &un;
        byte* sp = pun->SunPath;
        for (int i = 0; i < bytes.Length; i++)
            sp[i] = bytes[i];
        sp[bytes.Length] = 0;

        // un_len = offsetof(sun_path) + plen + 1 (include trailing NUL), matching net.c.
        uint unLen = (uint)(2 + bytes.Length + 1);

        // unlink the stale path first (best-effort).
        unlink(path);

        if (bind(fd, pun, unLen) != 0)
        {
            close(fd);
            return -1;
        }
        if (listen(fd, backlog) != 0)
        {
            close(fd);
            return -1;
        }
        return fd;
    }

    // ---- accept the single LB control connection ----------------------------
    private static void AcceptCtrl(int epfd, int listenFd, ref int ctrlFd)
    {
        while (true)
        {
            int fd = accept4(listenFd, null, null, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (fd < 0)
            {
                int err = Marshal.GetLastPInvokeError();
                if (err == EAGAIN || err == EWOULDBLOCK)
                    return;
                return;
            }
            if (ctrlFd == -1)
            {
                ctrlFd = fd;
                EpollAdd(epfd, ctrlFd, TOKEN_CTRL, EPOLLIN);
            }
            else
            {
                // only one control connection expected; reject extras
                close(fd);
            }
        }
    }

    // ---- drain client fds from the control socket (SCM_RIGHTS) --------------
    private static void DrainFds(int epfd, int ctrlFd, ref int ctrlFdRef)
    {
        while (true)
        {
            int fd = RecvFd(ctrlFd);
            if (fd == RECVFD_AGAIN)
                return;
            if (fd == RECVFD_CLOSED)
            {
                epoll_ctl(epfd, EPOLL_CTL_DEL, ctrlFd, null);
                close(ctrlFd);
                ctrlFdRef = -1;
                return;
            }
            OnNewClient(epfd, fd);
        }
    }

    private static void OnNewClient(int epfd, int fd)
    {
        if (fd < 0 || fd >= Const.MAX_FDS)
        {
            if (fd >= 0)
                close(fd);
            return;
        }

        SetQuickAck(fd);
        SetBusyPoll(fd, 50);

        ConnBuf[fd] ??= new byte[Const.CONN_BUF];
        ConnUsed[fd] = 0;

        EpollAdd(epfd, fd, (ulong)fd, EPOLLIN | EPOLLRDHUP);
    }

    // ---- client readable: parse complete requests, respond ------------------
    private static void OnClientReadable(int epfd, int fd, IvfIndex index)
    {
        byte[] buf = ConnBuf[fd];
        if (buf == null)
        {
            CloseClient(epfd, fd);
            return;
        }

        int used = ConnUsed[fd];

        // greedy read up to CONN_BUF
        while (used < Const.CONN_BUF)
        {
            nint n;
            fixed (byte* p = buf)
                n = recv(fd, p + used, (nuint)(Const.CONN_BUF - used), MSG_DONTWAIT);

            if (n > 0)
            {
                used += (int)n;
                continue;
            }
            if (n == 0)
            {
                // peer closed
                CloseClient(epfd, fd);
                return;
            }
            int err = Marshal.GetLastPInvokeError();
            if (err == EAGAIN || err == EWOULDBLOCK)
                break;
            if (err == EINTR)
                continue;
            CloseClient(epfd, fd);
            return;
        }

        // process complete requests from buf[0..used). Every precomputed response
        // carries Connection: keep-alive, so the connection is never closed here on
        // success (mirrors the C server's keep-alive loop).
        int processed = 0;
        while (processed < used)
        {
            ReadOnlySpan<byte> slice = buf.AsSpan(processed, used - processed);
            int headerEnd = Http.HeaderEnd(slice);
            if (headerEnd < 0)
                break; // need more header bytes

            byte first = slice[0];
            byte[] resp;
            int consumed;

            if (first == (byte)'P')
            {
                // POST: needs Content-Length + a full body before we vectorize/search.
                ReadOnlySpan<byte> headers = slice.Slice(0, headerEnd);
                long cl = Http.ContentLength(headers);
                if (cl < 0)
                {
                    // No Content-Length on a POST: treat as a body-less request -> Ready.
                    resp = Http.Ready;
                    consumed = headerEnd;
                }
                else
                {
                    long bodyEnd = headerEnd + cl;
                    if (bodyEnd > slice.Length)
                        break; // body not fully arrived yet

                    ReadOnlySpan<byte> body = slice.Slice(headerEnd, (int)cl);
                    Span<short> q = stackalloc short[Const.VPAD];
                    int fraud;
                    if (Vectorize.DoVectorize(body, q))
                    {
                        var r = index.Search(q, Const.INIT_PROBE, Const.MAX_PROBE, _searchKeys);
                        fraud = r.FraudCount;
                    }
                    else
                    {
                        fraud = 0; // unparseable payload -> safe 200 (approved, score 0)
                    }
                    resp = Http.Resp[fraud];
                    consumed = (int)bodyEnd;
                }
            }
            else
            {
                // non-POST (e.g. GET health) -> Ready (200, empty body).
                resp = Http.Ready;
                consumed = headerEnd;
            }

            if (!SendAll(fd, resp))
            {
                CloseClient(epfd, fd);
                return;
            }
            processed += consumed;
        }

        // compact any leftover partial request to the front of the buffer
        int remaining = used - processed;
        if (remaining > 0 && processed > 0)
            Buffer.BlockCopy(buf, processed, buf, 0, remaining);
        ConnUsed[fd] = remaining;
    }

    // ---- blocking write-all (spin on EAGAIN) --------------------------------
    private static bool SendAll(int fd, byte[] payload)
    {
        int off = 0;
        int len = payload.Length;
        fixed (byte* p = payload)
        {
            while (off < len)
            {
                nint n = send(fd, p + off, (nuint)(len - off), MSG_NOSIGNAL | MSG_DONTWAIT);
                if (n > 0)
                {
                    off += (int)n;
                    continue;
                }
                int err = Marshal.GetLastPInvokeError();
                if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR)
                    continue;
                return false;
            }
        }
        return true;
    }

    private static void CloseClient(int epfd, int fd)
    {
        if (fd >= 0 && fd < Const.MAX_FDS)
            ConnUsed[fd] = 0;
        epoll_ctl(epfd, EPOLL_CTL_DEL, fd, null);
        close(fd);
    }

    // ---- helpers ------------------------------------------------------------
    private static void EpollAdd(int epfd, int fd, ulong token, int eventMask)
    {
        var ev = new EpollEvent { Events = (uint)eventMask, Data = token };
        epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    }

    private static void ConfigureEpollBusyPoll(int epfd)
    {
        var ep = new EpollParams
        {
            BusyPollUsecs = 64,
            BusyPollBudget = 8,
            PreferBusyPoll = 1,
            Pad = 0,
        };
        // best-effort: ignore failure (kernel may not support EPIOCSPARAMS)
        ioctl(epfd, EPIOCSPARAMS, &ep);
    }
}
