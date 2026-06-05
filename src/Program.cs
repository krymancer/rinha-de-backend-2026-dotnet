// Program.cs — entry point. Dispatches to the API server or the fd-passing LB.
//   rinha server <sock> <index> [busyPollUs=0] [cpu=-1]
//   rinha lb <port> <api-sock> [<api-sock> ...]
// SIGPIPE is ignored process-wide (matching the C engine, which uses MSG_NOSIGNAL
// on sends but also wants writes on dead peers to fail with EPIPE rather than die).

using System;
using System.Runtime.InteropServices;

namespace Rinha
{
    internal static class Program
    {
        private const int SIGPIPE = 13;
        private static readonly nint SIG_IGN = (nint)1;

        [DllImport("libc", SetLastError = true)]
        private static extern nint signal(int signum, nint handler);

        private static int Main(string[] args)
        {
            // Ignore SIGPIPE so writes to closed peers return EPIPE instead of
            // terminating the process.
            signal(SIGPIPE, SIG_IGN);

            if (args.Length < 1)
            {
                Console.Error.WriteLine("usage: rinha (server <sock> <index> [busyPollUs] [cpu]) | (lb <port> <api-sock>...)");
                return 1;
            }

            switch (args[0])
            {
                case "server":
                    if (args.Length < 3)
                    {
                        Console.Error.WriteLine("usage: rinha server <sock> <index> [busyPollUs] [cpu]");
                        return 1;
                    }
                    // Called as a statement so this compiles whether Server.RunServer
                    // returns void or int (the integrator owns the Server module).
                    Server.RunServer(
                        args[1],
                        args[2],
                        args.Length > 3 ? int.Parse(args[3]) : 0,
                        args.Length > 4 ? int.Parse(args[4]) : -1);
                    return 0;

                case "lb":
                    if (args.Length < 3)
                    {
                        Console.Error.WriteLine("usage: rinha lb <port> <api-sock>...");
                        return 1;
                    }
                    return Lb.RunLb(int.Parse(args[1]), args[2..]);

                default:
                    Console.Error.WriteLine($"unknown command '{args[0]}'");
                    return 1;
            }
        }
    }
}
