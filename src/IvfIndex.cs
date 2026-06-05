// IvfIndex.cs — RNHZIVF2 IVF (inverted-file) k-NN index: load + exact search.
// 1:1 port of engine/ivf.c (which is itself a 1:1 port of the validated Zig
// submission). Correctness is paramount: identical int16 vectors, identical
// distances, identical fraud decisions. Detection error E must stay 0.
//
// The runtime path here mirrors ivf.c exactly:
//   * cluster_lb   : branchless 16-wide box lower bound (vpmaddwd e^2, i64 sum)
//   * key          : (lb << CL_BITS) | cluster_id, min-heap (heapify + sift-down)
//   * dist8        : pair-SoA vpmaddwd kernel over 7 dim-pairs -> 8 lane dists
//   * Top5         : 5 packed (dist<<DIST_SHIFT)|meta keys, worst recompute
//   * probe loop   : exact-prune (lb >= worstDist) + confident-stop (0 or K frauds)
//
// CRITICAL fidelity points carried over from the C engine:
//   * pack_q masks each dim to ushort BEFORE the <<16, so the -10000 sentinel's
//     sign bit is not propagated (left-shift of a negative miscompiles at -O3 in C
//     and would be a different bit pattern here). We replicate the exact masking.
//   * blocks load is an aligned 256-bit load in C (_mm256_load_si256). The backing
//     buffer is allocated 64-byte aligned and section offsets are 64-byte aligned,
//     so block pointers are 32-byte aligned; we use an aligned-equivalent load.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Rinha;

/// <summary>
/// Result of a search: fraud_count (0..5) and the approval decision (fraud &lt; 3).
/// </summary>
public readonly struct SearchResult
{
    public readonly int FraudCount;
    public readonly bool Approved;

    public SearchResult(int fraudCount, bool approved)
    {
        FraudCount = fraudCount;
        Approved = approved;
    }
}

/// <summary>
/// On-disk RNHZIVF2 index loaded into a single native buffer. Spans/pointers
/// reference offsets inside that buffer (no copies). Disposable: frees the buffer.
/// </summary>
public sealed unsafe class IvfIndex : IDisposable
{
    // ---- header field layout (88 bytes: 8-byte magic + 10 little-endian u64) ----
    // struct ivf_header_t {
    //   char magic[8]; u64 n, n_clusters, n_blocks, cl_blk_off, cl_cnt_off,
    //   bbox_min_off, bbox_max_off, blocks_off, meta_off, total; }
    private const int HeaderSize = 88;

    private byte* _buf;          // 64-byte-aligned native backing buffer (whole file)
    private nuint _bufLen;

    private ulong _n;
    private ulong _nClusters;
    private ulong _nBlocks;

    private short* _blocks;      // n_blocks * PBLOCK, pair-SoA, 32-byte aligned
    private uint* _meta;         // n_blocks * LANES : (orig_idx<<1)|label
    private uint* _clBlk;        // n_clusters : first block index of each cluster
    private uint* _clCnt;        // n_clusters : real vector count of each cluster
    private short* _bboxMin;     // n_clusters * VPAD
    private short* _bboxMax;     // n_clusters * VPAD

    public ulong N => _n;
    public ulong NClusters => _nClusters;
    public ulong NBlocks => _nBlocks;

    private IvfIndex() { }

    // ---- libc P/Invoke for an aligned native allocation + optional mlock --------
    [DllImport("libc", SetLastError = true)]
    private static extern int posix_memalign(out IntPtr memptr, nuint alignment, nuint size);

    [DllImport("libc")]
    private static extern void free(IntPtr ptr);

    [DllImport("libc", SetLastError = true)]
    private static extern int mlockall(int flags);

    private const int MCL_CURRENT = 1;
    private const int MCL_FUTURE = 2;

    /// <summary>
    /// Load index.bin into a 64-byte-aligned native buffer (read, not file-mmap),
    /// validate the RNHZIVF2 magic, and point the section pointers at the offsets.
    /// pin=true -> mlockall(MCL_CURRENT|MCL_FUTURE), matching ivf_map().
    /// </summary>
    public static IvfIndex Load(string path, bool pin = false)
    {
        var idx = new IvfIndex();
        try
        {
            idx.LoadInternal(path, pin);
            return idx;
        }
        catch
        {
            idx.Dispose();
            throw;
        }
    }

    private void LoadInternal(string path, bool pin)
    {
        // Read the whole file into a 64-byte-aligned native buffer. The 64-byte
        // alignment of the buffer base plus the 64-byte-aligned section offsets
        // guarantees `blocks` is 32-byte aligned (matches read_file_alloc + layout).
        // Stream the file directly into the native aligned buffer in 1 MiB chunks.
        // (Do NOT File.ReadAllBytes: a 96 MB managed copy + the native copy peaks
        //  at ~192 MB and OOMs under the 160 MB container limit.)
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read);
        long fsize = fs.Length;
        if (fsize < HeaderSize)
            throw new InvalidDataException($"index too small: {fsize} < {HeaderSize}");

        nuint len = (nuint)fsize;
        if (posix_memalign(out IntPtr mem, 64, len == 0 ? 1 : len) != 0 || mem == IntPtr.Zero)
            throw new OutOfMemoryException("posix_memalign failed for index buffer");

        _buf = (byte*)mem;
        _bufLen = len;
        long roff = 0;
        while (roff < fsize)
        {
            int want = (int)Math.Min(1 << 20, fsize - roff);
            int got = fs.Read(new Span<byte>(_buf + roff, want));
            if (got <= 0) throw new InvalidDataException("short read on index");
            roff += got;
        }

        // magic check
        for (int i = 0; i < 8; i++)
        {
            if (_buf[i] != (byte)Const.IVF_MAGIC[i])
                throw new InvalidDataException("bad magic (expected RNHZIVF2)");
        }

        if (pin)
            mlockall(MCL_CURRENT | MCL_FUTURE); // best-effort, ignore failure (matches C)

        // header fields (little-endian u64s at fixed offsets)
        _n = ReadU64(8);
        _nClusters = ReadU64(16);
        _nBlocks = ReadU64(24);
        ulong clBlkOff = ReadU64(32);
        ulong clCntOff = ReadU64(40);
        ulong bboxMinOff = ReadU64(48);
        ulong bboxMaxOff = ReadU64(56);
        ulong blocksOff = ReadU64(64);
        ulong metaOff = ReadU64(72);
        // total is ReadU64(80); not needed at runtime.

        _clBlk = (uint*)(_buf + clBlkOff);
        _clCnt = (uint*)(_buf + clCntOff);
        _bboxMin = (short*)(_buf + bboxMinOff);
        _bboxMax = (short*)(_buf + bboxMaxOff);
        _blocks = (short*)(_buf + blocksOff);
        _meta = (uint*)(_buf + metaOff);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private ulong ReadU64(int offset)
    {
        // little-endian; on x64 this is a direct load.
        return Unsafe.ReadUnaligned<ulong>(_buf + offset);
    }

    // ============================================================================
    //  clusterLB  (port of ivf.c cluster_lb)
    // ============================================================================
    // Branchless 16-wide box lower bound: e = max(mn-q,0)+max(q-mx,0) per dim,
    // sum e^2 as i64. VPAD==16 fits one 256-bit i16 register exactly; pad dims
    // contribute 0. The horizontal sum stores the 8 i32 lanes and sums in lane
    // order (0..7) as i64 — byte-identical to the C scalar tmp[8] loop.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static long ClusterLb(short* q, short* mn, short* mx)
    {
        Vector256<short> qv = Avx.LoadVector256(q);
        Vector256<short> mnv = Avx.LoadVector256(mn);
        Vector256<short> mxv = Avx.LoadVector256(mx);
        Vector256<short> zero = Vector256<short>.Zero;

        // max(mn-q,0) + max(q-mx,0)  (i16 lanes; mn<=mx so at most one term positive)
        Vector256<short> below = Avx2.Max(Avx2.Subtract(mnv, qv), zero);
        Vector256<short> above = Avx2.Max(Avx2.Subtract(qv, mxv), zero);
        Vector256<short> e = Avx2.Add(below, above);

        // vpmaddwd(e,e) -> 8 i32 lanes, each = e_2k^2 + e_(2k+1)^2.
        Vector256<int> sq = Avx2.MultiplyAddAdjacent(e, e);

        // horizontal sum of the 8 i32 into i64 (match C: scalar lane-order sum).
        int* tmp = stackalloc int[8];
        Avx.Store((short*)tmp, sq.AsInt16());
        long s = 0;
        for (int i = 0; i < 8; i++) s += (long)tmp[i];
        return s;
    }

    // ============================================================================
    //  packQ + dist8  (port of ivf.c pack_q / dist8)
    // ============================================================================
    // qp[p] = set1_epi32( (ushort)q[2p] | ((uint)(ushort)q[2p+1] << 16) ): the
    // (a,b) dim-pair splatted across all 8 lanes (16 i16). Mask to ushort BEFORE
    // the shift — the -10000 sentinel must not sign-extend (the C UB bug).
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void PackQ(short* q, Vector256<int>* qp)
    {
        for (int p = 0; p < Const.PAIRS; p++)
        {
            uint lo = (ushort)q[2 * p];
            uint hi = (ushort)q[2 * p + 1];
            qp[p] = Vector256.Create(unchecked((int)(lo | (hi << 16))));
        }
    }

    // Squared distance of 8 vectors (one block) to the query; lane j = vector j.
    // acc += vpmaddwd(block_p - qp_p, ...) over the 7 pairs. Distances fit i32.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<int> Dist8(short* block, Vector256<int>* qp)
    {
        Vector256<int> acc = Vector256<int>.Zero;
        for (int p = 0; p < Const.PAIRS; p++)
        {
            // aligned 256-bit load: block is 32-byte aligned by layout.
            Vector256<short> bp = Avx.LoadVector256(block + p * 16);
            Vector256<short> diff = Avx2.Subtract(bp, qp[p].AsInt16());
            acc = Avx2.Add(acc, Avx2.MultiplyAddAdjacent(diff, diff));
        }
        return acc;
    }

    // Horizontal min of 8 i32 lanes (scalar, matches @reduce(.Min) / C hmin8).
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int HMin8(Vector256<int> v, int* scratch)
    {
        Avx.Store(scratch, v);
        int m = scratch[0];
        for (int i = 1; i < 8; i++) if (scratch[i] < m) m = scratch[i];
        return m;
    }

    // ============================================================================
    //  Top5  (port of index.zig Top5 via ivf.c top5_*)
    // ============================================================================
    // 5 packed keys (dist<<DIST_SHIFT)|meta, init ulong.MaxValue; offer replaces
    // the current worst slot then recomputes the worst over all K slots.
    private struct Top5
    {
        public ulong K0, K1, K2, K3, K4; // keys[0..4]
        public int WorstI;
        public ulong Worst;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Init()
        {
            K0 = K1 = K2 = K3 = K4 = ulong.MaxValue;
            WorstI = 0;
            Worst = ulong.MaxValue;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ulong Get(int j) => j switch
        {
            0 => K0,
            1 => K1,
            2 => K2,
            3 => K3,
            _ => K4,
        };

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Set(int j, ulong v)
        {
            switch (j)
            {
                case 0: K0 = v; break;
                case 1: K1 = v; break;
                case 2: K2 = v; break;
                case 3: K3 = v; break;
                default: K4 = v; break;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Offer(ulong key)
        {
            if (key < Worst)
            {
                Set(WorstI, key);
                // worst recompute: start from keys[0], scan j=1..K-1 (matches C).
                Worst = K0;
                WorstI = 0;
                if (K1 > Worst) { Worst = K1; WorstI = 1; }
                if (K2 > Worst) { Worst = K2; WorstI = 2; }
                if (K3 > Worst) { Worst = K3; WorstI = 3; }
                if (K4 > Worst) { Worst = K4; WorstI = 4; }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public long WorstDist() => (long)(Worst >> Const.DIST_SHIFT);
    }

    // ============================================================================
    //  scanCluster  (port of ivf.c scan_cluster)
    // ============================================================================
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void ScanCluster(uint c, Vector256<int>* qp, ref Top5 top, int* distScratch)
    {
        uint cnt = _clCnt[c];
        uint blk0 = _clBlk[c];
        uint nfull = cnt / Const.LANES;
        uint rem = cnt % Const.LANES;

        for (uint b = 0; b < nfull; b++)
        {
            Vector256<int> dv = Dist8(_blocks + (nuint)(blk0 + b) * Const.PBLOCK, qp);
            if ((long)HMin8(dv, distScratch) >= top.WorstDist())
                continue;
            // distScratch now holds the 8 lane dists (HMin8 stored them).
            nuint mbase = (nuint)(blk0 + b) * Const.LANES;
            for (int lane = 0; lane < Const.LANES; lane++)
            {
                ulong key = ((ulong)(uint)distScratch[lane] << Const.DIST_SHIFT)
                            | _meta[mbase + (uint)lane];
                top.Offer(key);
            }
        }

        if (rem != 0)
        {
            Vector256<int> dv = Dist8(_blocks + (nuint)(blk0 + nfull) * Const.PBLOCK, qp);
            Avx.Store(distScratch, dv);
            nuint mbase = (nuint)(blk0 + nfull) * Const.LANES;
            for (uint lane = 0; lane < rem; lane++)
            {
                ulong key = ((ulong)(uint)distScratch[lane] << Const.DIST_SHIFT)
                            | _meta[mbase + lane];
                top.Offer(key);
            }
        }
    }

    // ============================================================================
    //  min-heap over cluster keys  (port of ivf.c sift_down)
    // ============================================================================
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void SiftDown(ulong* h, nuint n, nuint start)
    {
        nuint i = start;
        for (; ; )
        {
            nuint l = 2 * i + 1;
            nuint r = 2 * i + 2;
            nuint m = i;
            if (l < n && h[l] < h[m]) m = l;
            if (r < n && h[r] < h[m]) m = r;
            if (m == i) break;
            ulong t = h[i];
            h[i] = h[m];
            h[m] = t;
            i = m;
        }
    }

    // ============================================================================
    //  search  (port of ivf.c ivf_search)
    // ============================================================================
    /// <summary>
    /// Adaptive IVF search. q16 is the 16-wide int16 query (dims 14,15 = 0).
    /// keysScratch is caller scratch of >= n_clusters ulong. Returns fraud count
    /// (sum of K labels) and approval (fraud &lt; 3). Bit-exact with ivf_search().
    /// </summary>
    public SearchResult Search(ReadOnlySpan<short> q16, int initProbe, int maxProbe, Span<ulong> keysScratch)
    {
        nuint nc = (nuint)_nClusters;
        if (keysScratch.Length < (int)nc)
            throw new ArgumentException($"keysScratch too small: need {nc}", nameof(keysScratch));
        if (q16.Length < Const.VPAD)
            throw new ArgumentException($"query must have >= {Const.VPAD} dims", nameof(q16));

        fixed (short* q = q16)
        fixed (ulong* keys = keysScratch)
        {
            // per-cluster lower-bound keys: (lb << CL_BITS) | cluster_id
            for (nuint cc = 0; cc < nc; cc++)
            {
                long lb = ClusterLb(q, _bboxMin + cc * Const.VPAD, _bboxMax + cc * Const.VPAD);
                keys[cc] = ((ulong)lb << Const.CL_BITS) | (ulong)cc;
            }

            // heapify keys[0..nc] (sift-down from nc/2 - 1 down to 0)
            nuint hn = nc;
            {
                nuint i = nc / 2;
                while (i > 0)
                {
                    i -= 1;
                    SiftDown(keys, hn, i);
                }
            }

            // pack query into the 7 pair-splats.
            Vector256<int>* qp = stackalloc Vector256<int>[Const.PAIRS];
            PackQ(q, qp);

            Top5 top = default;
            top.Init();

            int* distScratch = stackalloc int[Const.LANES];

            nuint probed = 0;
            const ulong mask = ((ulong)1 << Const.CL_BITS) - 1;
            while (probed < (nuint)maxProbe && hn > 0)
            {
                ulong kmin = keys[0];
                long lb = (long)(kmin >> Const.CL_BITS);
                if (lb >= top.WorstDist())
                    break; // exact prune
                hn -= 1;   // pop min
                keys[0] = keys[hn];
                SiftDown(keys, hn, 0);
                ScanCluster((uint)(kmin & mask), qp, ref top, distScratch);
                probed += 1;
                if (probed >= (nuint)initProbe)
                {
                    int fr = (int)(top.K0 & 1) + (int)(top.K1 & 1) + (int)(top.K2 & 1)
                             + (int)(top.K3 & 1) + (int)(top.K4 & 1);
                    if (fr == 0 || fr == Const.K)
                        break; // confident
                }
            }

            int fraud = (int)(top.K0 & 1) + (int)(top.K1 & 1) + (int)(top.K2 & 1)
                        + (int)(top.K3 & 1) + (int)(top.K4 & 1);
            return new SearchResult(fraud, fraud < 3);
        }
    }

    public void Dispose()
    {
        if (_buf != null)
        {
            free((IntPtr)_buf);
            _buf = null;
            _bufLen = 0;
        }
        GC.SuppressFinalize(this);
    }

    ~IvfIndex()
    {
        if (_buf != null)
        {
            free((IntPtr)_buf);
            _buf = null;
        }
    }
}
