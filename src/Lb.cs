// Lb.cs — SCM_RIGHTS fd-passing load balancer.
// 1:1 port of engine/net.c (tcp_listener, uds_connect, send_fd) plus the LB
// round-robin accept loop. A blocking TCP listener accepts connections and hands
// each accepted socket fd to one of the API workers over an AF_UNIX SEQPACKET
// control socket via sendmsg/SCM_RIGHTS, round-robining across the workers.
//
// All libc bindings, the SCM_RIGHTS cmsg layout (Syscalls.SendFd) and socket
// tuning live in the shared Syscalls class so there is a single source of truth.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Rinha
{
    internal static unsafe class Lb
    {
        // ---- tcp_listener (net.c) ---------------------------------------------
        // AF_INET SOCK_STREAM, SO_REUSEADDR, bind INADDR_ANY:port, listen 1024.
        // Blocking. Returns fd, or -1 on error.
        private static int TcpListener(ushort port)
        {
            int fd = Syscalls.socket(Syscalls.AF_INET,
                                     Syscalls.SOCK_STREAM | Syscalls.SOCK_CLOEXEC,
                                     Syscalls.IPPROTO_TCP);
            if (fd < 0) return -1;

            int one = 1;
            Syscalls.setsockopt(fd, Syscalls.SOL_SOCKET, Syscalls.SO_REUSEADDR,
                                &one, sizeof(int));

            Syscalls.SockAddrIn addr = default;
            addr.SinFamily = Syscalls.AF_INET;
            addr.SinPort = Syscalls.htons(port);
            addr.SinAddr = 0; // INADDR_ANY
            if (Syscalls.bind(fd, &addr, (uint)sizeof(Syscalls.SockAddrIn)) != 0)
            {
                Syscalls.close(fd);
                return -1;
            }
            if (Syscalls.listen(fd, 1024) != 0)
            {
                Syscalls.close(fd);
                return -1;
            }
            return fd;
        }

        // ---- uds_connect (net.c) ----------------------------------------------
        // AF_UNIX SOCK_SEQPACKET connect, ~600 attempts x 100ms retries.
        // un_len = offsetof(sun_path) + plen + 1 (include trailing NUL).
        // Returns fd, or -1 if all attempts fail.
        private static int UdsConnect(string path)
        {
            byte[] pathBytes = Encoding.UTF8.GetBytes(path);
            int plen = pathBytes.Length;
            if (plen >= 108) return -1;

            for (int attempt = 0; attempt < 600; attempt++)
            {
                int fd = Syscalls.socket(Syscalls.AF_UNIX,
                                         Syscalls.SOCK_SEQPACKET | Syscalls.SOCK_CLOEXEC, 0);
                if (fd < 0)
                {
                    SleepMs(100);
                    continue;
                }

                Syscalls.SockAddrUn un = default;
                un.SunFamily = Syscalls.AF_UNIX;
                for (int i = 0; i < plen; i++) un.SunPath[i] = pathBytes[i];
                // offsetof(sockaddr_un, sun_path) == 2 (the ushort family field).
                uint unLen = (uint)(2 + plen + 1);

                if (Syscalls.connect(fd, &un, unLen) == 0) return fd;
                Syscalls.close(fd);
                SleepMs(100);
            }
            return -1;
        }

        [DllImport("libc", SetLastError = true)]
        private static extern int nanosleep(TimeSpec* req, TimeSpec* rem);

        [StructLayout(LayoutKind.Sequential)]
        private struct TimeSpec
        {
            public long tv_sec;
            public long tv_nsec;
        }

        private static void SleepMs(long ms)
        {
            TimeSpec ts;
            ts.tv_sec = ms / 1000;
            ts.tv_nsec = (ms % 1000) * 1_000_000L;
            nanosleep(&ts, &ts);
        }

        // ---- RunLb -------------------------------------------------------------
        // Connect each api control socket (SEQPACKET, with retries); open the TCP
        // listener; round-robin: accept4(NONBLOCK|CLOEXEC), set TCP_NODELAY,
        // send_fd to apiFds[rr], close our copy, rr = (rr+1) % n.
        public static int RunLb(int port, string[] apiSocks)
        {
            int n = apiSocks.Length;
            if (n == 0)
            {
                Console.Error.WriteLine("lb: no api sockets specified");
                return 1;
            }

            int[] apiFds = new int[n];
            for (int i = 0; i < n; i++)
            {
                int fd = UdsConnect(apiSocks[i]);
                if (fd < 0)
                {
                    Console.Error.WriteLine($"lb: failed to connect api socket '{apiSocks[i]}'");
                    return 1;
                }
                apiFds[i] = fd;
            }

            int listener = TcpListener((ushort)port);
            if (listener < 0)
            {
                Console.Error.WriteLine($"lb: failed to listen on port {port}");
                return 1;
            }

            int rr = 0;
            for (;;)
            {
                int conn = Syscalls.accept4(listener, null, null,
                                            Syscalls.SOCK_NONBLOCK | Syscalls.SOCK_CLOEXEC);
                if (conn < 0)
                {
                    // EINTR / EAGAIN / transient (ECONNABORTED...): keep going.
                    continue;
                }

                Syscalls.SetNoDelay(conn);
                Syscalls.SendFd(apiFds[rr], conn);
                Syscalls.close(conn);

                rr = rr + 1;
                if (rr == n) rr = 0;
            }
        }
    }
}
