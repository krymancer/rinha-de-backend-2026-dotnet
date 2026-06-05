// Const.cs — shared compile-time constants for the Rinha 2026 fraud-detection API.
// 1:1 with the validated C engine (rinha.h). Every value here is E-critical: the
// index format, the dist8/clusterLB kernels, and the probe budget all depend on
// these being byte/bit-exact with the Zig submission and its C port.
using System;

namespace Rinha;

internal static class Const
{
    // ---- dimensions / layout (rinha.h) --------------------------------------
    public const int DIMS = 14;          // VDIM: real dimensions
    public const int VDIM = 14;          // alias used by the search module
    public const string IVF_MAGIC = "RNHZIVF2"; // alias used by the search module
    public const int VPAD = 16;          // padded to 16 (two trailing zero dims; AVX2)
    public const int K = 5;              // nearest neighbours
    public const int LANES = 8;          // vectors per SoA block
    public const int PAIRS = 7;          // VDIM/2 dim-pairs for the vpmaddwd kernel
    public const int PBLOCK = 112;       // PAIRS*16 = 112 int16 per block (8 vectors x 14 dims)

    // packed key = (dist<<23)|(orig_idx<<1)|label  ;  cluster key = (lb<<13)|cluster_id
    public const int DIST_SHIFT = 23;
    public const int CL_BITS = 13;       // n_clusters <= 8192

    // ---- search probe budget (matches the Zig submission exactly) -----------
    public const int INIT_PROBE = 24;
    public const int MAX_PROBE = 96;
    public const int MAX_CLUSTERS = 8192;

    // ---- server limits ------------------------------------------------------
    public const int MAX_FDS = 8192;
    public const int CONN_BUF = 4096;

    // ---- on-disk index magic ("RNHZIVF2", pair-SoA block format) ------------
    public const string MAGIC = "RNHZIVF2";

    // Magic as raw bytes, for byte-comparison against the file header.
    public static ReadOnlySpan<byte> MagicBytes =>
        new byte[] { (byte)'R', (byte)'N', (byte)'H', (byte)'Z',
                     (byte)'I', (byte)'V', (byte)'F', (byte)'2' };
}
