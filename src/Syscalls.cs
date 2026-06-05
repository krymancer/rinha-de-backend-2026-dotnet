// Syscalls.cs — raw Linux syscall surface for the Rinha 2026 API/LB.
// 1:1 with net.c of the validated C engine: epoll, accept4, SCM_RIGHTS fd-passing
// over AF_UNIX SOCK_SEQPACKET, socket tuning, mlockall, microsecond epoll waits
// (epoll_pwait2 syscall 441 with epoll_wait(ms) fallback on ENOSYS).
//
// All P/Invokes are [DllImport("libc", SetLastError=true)] so callers can read the
// errno via Marshal.GetLastPInvokeError(). Everything is unsafe / pointer-based to
// keep the wire layout (msghdr, cmsghdr, iovec, sockaddr_un) byte-exact.
using System.Runtime.InteropServices;

namespace Rinha;

internal static unsafe class Syscalls
{
    // ====================================================================
    //  Constants (from net.c / rinha.h / <sys/*.h>)
    // ====================================================================

    // ---- epoll events ----
    public const int EPOLLIN = 0x001;
    public const int EPOLLOUT = 0x004;
    public const int EPOLLERR = 0x008;
    public const int EPOLLHUP = 0x010;
    public const int EPOLLRDHUP = 0x2000;
    public const uint EPOLLET = 0x80000000u;

    // ---- epoll_ctl ops ----
    public const int EPOLL_CTL_ADD = 1;
    public const int EPOLL_CTL_DEL = 2;
    public const int EPOLL_CTL_MOD = 3;

    // ---- epoll_create1 / accept4 / socket flags ----
    public const int EPOLL_CLOEXEC = 0x80000;

    // ---- address families ----
    public const int AF_INET = 2;
    public const int AF_UNIX = 1;

    // ---- socket types ----
    public const int SOCK_STREAM = 1;
    public const int SOCK_SEQPACKET = 5;
    public const int SOCK_NONBLOCK = 0x800;
    public const int SOCK_CLOEXEC = 0x80000;

    // ---- protocols ----
    public const int IPPROTO_TCP = 6;

    // ---- socket option levels ----
    public const int SOL_SOCKET = 1;

    // ---- SCM control ----
    public const int SCM_RIGHTS = 1;

    // ---- TCP / SO options ----
    public const int TCP_NODELAY = 1;
    public const int TCP_QUICKACK = 12;   // matches net.c (#define TCP_QUICKACK 12)
    public const int SO_REUSEADDR = 2;
    public const int SO_BUSY_POLL = 46;

    // ---- send/recv flags ----
    public const int MSG_NOSIGNAL = 0x4000;
    public const int MSG_DONTWAIT = 0x40;

    // ---- mlockall flags ----
    public const int MCL_CURRENT = 1;
    public const int MCL_FUTURE = 2;

    // ---- fcntl cmds / flags ----
    public const int F_GETFL = 3;
    public const int F_SETFL = 4;
    public const int O_NONBLOCK = 0x800;

    // ---- open flags ----
    public const int O_RDONLY = 0;

    // ---- clock ids ----
    public const int CLOCK_MONOTONIC = 1;

    // ---- errno ----
    public const int EAGAIN = 11;
    public const int EWOULDBLOCK = 11;
    public const int EINTR = 4;
    public const int ENOSYS = 38;

    // ---- recv_fd return codes (mirror recvOneFd's union(again/closed/fd)) ----
    public const int RECVFD_AGAIN = -1;   // EAGAIN / non-SCM_RIGHTS message
    public const int RECVFD_CLOSED = -2;  // peer closed / error

    // epoll_pwait2 syscall number (x86-64).
    private const long SYS_epoll_pwait2 = 441;

    // ====================================================================
    //  Structs (wire-layout-exact)
    // ====================================================================

    // struct epoll_event is __attribute__((packed)) on x86-64: u32 events then
    // u64 data with NO padding (Pack=1). Mismatch here corrupts epoll_ctl.
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct EpollEvent
    {
        public uint Events;
        public ulong Data;
    }

    // struct iovec { void *iov_base; size_t iov_len; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct IOVec
    {
        public void* Base;
        public nuint Length;
    }

    // struct msghdr (Linux): name/namelen, iov/iovlen, control/controllen, flags.
    // namelen is socklen_t (u32) followed by 4 bytes of implicit padding on LP64
    // before the 8-byte iov pointer; LayoutKind.Sequential with default packing
    // reproduces that padding exactly.
    [StructLayout(LayoutKind.Sequential)]
    internal struct MsgHdr
    {
        public void* Name;
        public uint NameLen;
        public IOVec* Iov;
        public nuint IovLen;
        public void* Control;
        public nuint ControlLen;
        public int Flags;
    }

    // struct sockaddr_un { sa_family_t sun_family; char sun_path[108]; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct SockAddrUn
    {
        public ushort SunFamily;
        public fixed byte SunPath[108];
    }

    // struct sockaddr_in { u16 family; u16 port(be); u32 addr; u8 zero[8]; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct SockAddrIn
    {
        public ushort SinFamily;
        public ushort SinPort;     // network byte order
        public uint SinAddr;       // network byte order (INADDR_ANY = 0)
        public ulong SinZero;      // 8 bytes padding
    }

    // struct timespec { time_t tv_sec; long tv_nsec; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct Timespec
    {
        public long Sec;
        public long Nsec;
    }

    // cmsghdr ABI offsets on LP64: cmsg_len (size_t, 8 bytes) at 0,
    // cmsg_level (int) at 8, cmsg_type (int) at 12, data at 16 (CMSG_DATA after
    // the 16-byte aligned header). CMSG_LEN(sizeof(int)) = 16 + 4 = 20.
    public const int CMSG_LEN_FD = 20;          // CMSG_LEN(sizeof(int))
    public const int CMSG_SPACE_FD = 24;        // CMSG_SPACE(sizeof(int))
    public const int CMSG_DATA_OFFSET = 16;     // offset of fd within the cmsg buffer
    public const int CMSG_LEVEL_OFFSET = 8;     // offsetof(cmsghdr, cmsg_level) on LP64
    public const int CMSG_TYPE_OFFSET = 12;     // offsetof(cmsghdr, cmsg_type) on LP64

    // ====================================================================
    //  P/Invoke declarations
    // ====================================================================

    [DllImport("libc", SetLastError = true)]
    public static extern int epoll_create1(int flags);

    [DllImport("libc", SetLastError = true)]
    public static extern int epoll_ctl(int epfd, int op, int fd, EpollEvent* ev);

    [DllImport("libc", SetLastError = true)]
    public static extern int epoll_wait(int epfd, EpollEvent* events, int maxevents, int timeout);

    [DllImport("libc", SetLastError = true)]
    public static extern int accept4(int sockfd, void* addr, void* addrlen, int flags);

    [DllImport("libc", SetLastError = true)]
    public static extern nint read(int fd, void* buf, nuint count);

    [DllImport("libc", SetLastError = true)]
    public static extern nint write(int fd, void* buf, nuint count);

    [DllImport("libc", SetLastError = true)]
    public static extern int close(int fd);

    [DllImport("libc", SetLastError = true)]
    public static extern int socket(int domain, int type, int protocol);

    [DllImport("libc", SetLastError = true)]
    public static extern int bind(int sockfd, void* addr, uint addrlen);

    [DllImport("libc", SetLastError = true)]
    public static extern int listen(int sockfd, int backlog);

    [DllImport("libc", SetLastError = true)]
    public static extern int connect(int sockfd, void* addr, uint addrlen);

    [DllImport("libc", SetLastError = true)]
    public static extern int setsockopt(int sockfd, int level, int optname, void* optval, uint optlen);

    [DllImport("libc", SetLastError = true)]
    public static extern nint recvmsg(int sockfd, MsgHdr* msg, int flags);

    [DllImport("libc", SetLastError = true)]
    public static extern nint sendmsg(int sockfd, MsgHdr* msg, int flags);

    [DllImport("libc", SetLastError = true)]
    public static extern int mlockall(int flags);

    [DllImport("libc", SetLastError = true)]
    public static extern int ioctl(int fd, ulong request, void* arg);

    [DllImport("libc", SetLastError = true)]
    public static extern int clock_gettime(int clkId, Timespec* tp);

    [DllImport("libc", SetLastError = true)]
    public static extern int fcntl(int fd, int cmd, int arg);

    [DllImport("libc", SetLastError = true)]
    public static extern int unlink([MarshalAs(UnmanagedType.LPStr)] string pathname);

    [DllImport("libc", SetLastError = true)]
    public static extern int open([MarshalAs(UnmanagedType.LPStr)] string pathname, int flags);

    [DllImport("libc", SetLastError = true)]
    public static extern long lseek(int fd, long offset, int whence);

    [DllImport("libc", SetLastError = true)]
    public static extern nint recv(int sockfd, byte* buf, nuint len, int flags);

    [DllImport("libc", SetLastError = true)]
    public static extern nint send(int sockfd, byte* buf, nuint len, int flags);

    // Generic 6-arg syscall, used for epoll_pwait2 (441).
    [DllImport("libc", SetLastError = true, EntryPoint = "syscall")]
    public static extern long syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6);

    // htons for the TCP listener port.
    [DllImport("libc")]
    public static extern ushort htons(ushort hostshort);

    // ====================================================================
    //  Helpers (mirror net.c functions)
    // ====================================================================

    // epoll_wait_us: microsecond-precision timeout. <0 blocks; 0 returns
    // immediately; otherwise epoll_pwait2 (kernel >= 5.11) falling back to
    // millisecond epoll_wait (ceil) on ENOSYS. Returns event count, or -1.
    public static int EpollWaitUs(int epfd, EpollEvent* events, int maxevents, long timeoutUs)
    {
        if (timeoutUs < 0) return epoll_wait(epfd, events, maxevents, -1);
        if (timeoutUs == 0) return epoll_wait(epfd, events, maxevents, 0);

        Timespec ts;
        ts.Sec = timeoutUs / 1_000_000L;
        ts.Nsec = (timeoutUs % 1_000_000L) * 1000L;

        // epoll_pwait2(epfd, events, maxevents, &ts, sigmask=NULL, sigsetsize=8)
        long rc = syscall(SYS_epoll_pwait2, epfd, (long)events, maxevents,
                          (long)(&ts), 0, 8);
        if (rc < 0 && Marshal.GetLastPInvokeError() == ENOSYS)
        {
            int ms = (int)((timeoutUs + 999) / 1000);
            return epoll_wait(epfd, events, maxevents, ms);
        }
        return (int)rc;
    }

    public static void SetNonBlocking(int fd)
    {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) flags = 0;
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    public static void SetNoDelay(int fd)
    {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(int));
    }

    public static void SetQuickAck(int fd)
    {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(int));
    }

    public static void SetBusyPoll(int fd, int usecs)
    {
        setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &usecs, sizeof(int));
    }

    // now_ns: CLOCK_MONOTONIC nanoseconds (os.c now_ns).
    public static long NowNs()
    {
        Timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ts.Sec * 1_000_000_000L + ts.Nsec;
    }

    // ---- SCM_RIGHTS fd passing (net.c send_fd / recv_fd) -------------------

    // Send one fd over a SEQPACKET socket via SCM_RIGHTS. 1-byte iov payload
    // (0x46), MSG_NOSIGNAL. Spin on EAGAIN/EINTR (cap 1,000,000). controllen is
    // set to CMSG_LEN (== net.c). Returns true on success.
    public static bool SendFd(int sock, int fd)
    {
        byte payload = 0x46;
        byte* control = stackalloc byte[CMSG_SPACE_FD];
        for (int i = 0; i < CMSG_SPACE_FD; i++) control[i] = 0;

        // cmsg_len (size_t) = CMSG_LEN(4) = 20
        *(nuint*)(control + 0) = CMSG_LEN_FD;
        // cmsg_level = SOL_SOCKET
        *(int*)(control + CMSG_LEVEL_OFFSET) = SOL_SOCKET;
        // cmsg_type = SCM_RIGHTS
        *(int*)(control + CMSG_TYPE_OFFSET) = SCM_RIGHTS;
        // CMSG_DATA = fd
        *(int*)(control + CMSG_DATA_OFFSET) = fd;

        IOVec iov = new() { Base = &payload, Length = 1 };
        MsgHdr msg = new()
        {
            Iov = &iov,
            IovLen = 1,
            Control = control,
            ControlLen = CMSG_LEN_FD,   // match Zig/C: controllen = CMSG_LEN
        };

        uint spins = 0;
        for (; ; )
        {
            nint rc = sendmsg(sock, &msg, MSG_NOSIGNAL);
            if (rc >= 0) return true;
            int err = Marshal.GetLastPInvokeError();
            if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR)
            {
                if (++spins > 1_000_000u) return false;
                continue;
            }
            return false;
        }
    }

    // Receive one fd over SCM_RIGHTS. 1-byte iov. Returns fd>=0,
    // RECVFD_AGAIN(-1) (EAGAIN / non-SCM message), or RECVFD_CLOSED(-2).
    public static int RecvFd(int ctrlSock)
    {
        byte data = 0;
        byte* control = stackalloc byte[CMSG_SPACE_FD];

        IOVec iov = new() { Base = &data, Length = 1 };
        MsgHdr msg = new()
        {
            Iov = &iov,
            IovLen = 1,
            Control = control,
            ControlLen = CMSG_SPACE_FD,
        };

        nint rc = recvmsg(ctrlSock, &msg, 0);
        if (rc < 0)
        {
            int err = Marshal.GetLastPInvokeError();
            if (err == EAGAIN || err == EWOULDBLOCK) return RECVFD_AGAIN;
            return RECVFD_CLOSED;
        }
        if (rc == 0) return RECVFD_CLOSED; // peer closed

        // Need at least a full cmsghdr (16 bytes) worth of control data.
        if (msg.ControlLen < (nuint)CMSG_DATA_OFFSET) return RECVFD_AGAIN;

        int level = *(int*)(control + CMSG_LEVEL_OFFSET);
        int type = *(int*)(control + CMSG_TYPE_OFFSET);
        if (level != SOL_SOCKET || type != SCM_RIGHTS) return RECVFD_AGAIN;

        return *(int*)(control + CMSG_DATA_OFFSET);
    }
}
