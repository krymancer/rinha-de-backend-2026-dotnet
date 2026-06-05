// Payload (JSON) -> 14-dimension int16 query vector.
// 1:1 port of vec.c (itself a 1:1 port of vectorize.zig, validated, E=0). Every
// coordinate the data-generator emits is round4'd, so multiplying by 10000 and
// rounding yields an EXACT int16 in [-10000, 10000]. Dims 14,15 are always 0.
//
// All floating-point math uses `double` to match the C `double`/Zig f64 path
// bit-for-bit. round() is ties-away-from-zero (Math.Round MidpointRounding.
// AwayFromZero == C round() == Zig @round). Integer date math uses long with
// floored div/mod (matching Zig @divFloor/@mod). Returns false on any parse
// failure (caller emits a safe 200).

using System;
using System.Globalization;
using System.Runtime.CompilerServices;

namespace Rinha;

public static class Vectorize
{
    // ---- dimensions (must match rinha.h) -------------------------------------
    private const int VPAD = 16; // padded query width (dims 14,15 always 0)

    // ---- normalization.json constants (fixed for the edition) ----------------
    private const double MAX_AMOUNT = 10000.0;
    private const double MAX_INSTALLMENTS = 12.0;
    private const double AMOUNT_VS_AVG_RATIO = 10.0;
    private const double MAX_MINUTES = 1440.0;
    private const double MAX_KM = 1000.0;
    private const double MAX_TX_24H = 20.0;
    private const double MAX_MERCH_AVG = 10000.0;

    // A non-owning text slice over the request body (mirrors C slice_t / Zig []const u8).
    // Spans can't live in a struct field if we want to store nullable "missing", so we
    // model a slice as (start, len) offsets into the single backing body span and pass
    // the body span explicitly to the few helpers that need it.
    private readonly struct Slice
    {
        public readonly int Start;
        public readonly int Len;
        public Slice(int start, int len) { Start = start; Len = len; }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static double Clamp01(double v)
    {
        if (v < 0.0) return 0.0;
        if (v > 1.0) return 1.0;
        return v;
    }

    // round(v*10000) clamped to int16 sentinel range. C round() = ties away from
    // zero (Math.Round AwayFromZero matches). Clamp before cast.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static short Q(double v)
    {
        double r = Math.Round(v * 10000.0, MidpointRounding.AwayFromZero);
        if (r < -10000.0) r = -10000.0;
        if (r > 10000.0) r = 10000.0;
        return (short)r;
    }

    // mcc_risk.json lookup; default 0.5 for unknown MCCs. `mcc` is the inner string.
    private static double MccRisk(ReadOnlySpan<byte> mcc)
    {
        // (code, risk) table, identical ordering/values to vec.c.
        if (Eq(mcc, "5411")) return 0.15;
        if (Eq(mcc, "5812")) return 0.30;
        if (Eq(mcc, "5912")) return 0.20;
        if (Eq(mcc, "5944")) return 0.45;
        if (Eq(mcc, "7801")) return 0.80;
        if (Eq(mcc, "7802")) return 0.75;
        if (Eq(mcc, "7995")) return 0.85;
        if (Eq(mcc, "4511")) return 0.35;
        if (Eq(mcc, "5311")) return 0.25;
        if (Eq(mcc, "5999")) return 0.50;
        return 0.5;
    }

    // Compare a byte slice against an ASCII literal (exact length + bytes).
    private static bool Eq(ReadOnlySpan<byte> s, string lit)
    {
        if (s.Length != lit.Length) return false;
        for (int i = 0; i < lit.Length; i++)
            if (s[i] != (byte)lit[i]) return false;
        return true;
    }

    // ----- timestamp helpers (UTC) -------------------------------------------

    private struct Ts { public long Y, Mo, D, H, Mi, S; }

    // Strict base-10 integer parse over exactly [start, start+n) of body, matching
    // Zig parseInt: optional single leading '+'/'-', then digits only; any other
    // char -> error. Returns true on success.
    private static bool ParseIntFixed(ReadOnlySpan<byte> body, int start, int n, out long outv)
    {
        outv = 0;
        if (n == 0) return false;
        int i = 0;
        bool neg = false;
        byte c0 = body[start];
        if (c0 == (byte)'+' || c0 == (byte)'-')
        {
            neg = (c0 == (byte)'-');
            i = 1;
            if (i >= n) return false; // sign with no digits
        }
        long acc = 0;
        for (; i < n; i++)
        {
            byte c = body[start + i];
            if (c < (byte)'0' || c > (byte)'9') return false;
            acc = acc * 10 + (long)(c - (byte)'0');
        }
        outv = neg ? -acc : acc;
        return true;
    }

    // Parse "YYYY-MM-DDThh:mm:ssZ" by fixed offsets. Returns false on failure.
    private static bool ParseTs(ReadOnlySpan<byte> body, Slice s, out Ts outv)
    {
        outv = default;
        if (s.Len < 19) return false;
        int b = s.Start;
        return ParseIntFixed(body, b + 0, 4, out outv.Y) &&
               ParseIntFixed(body, b + 5, 2, out outv.Mo) &&
               ParseIntFixed(body, b + 8, 2, out outv.D) &&
               ParseIntFixed(body, b + 11, 2, out outv.H) &&
               ParseIntFixed(body, b + 14, 2, out outv.Mi) &&
               ParseIntFixed(body, b + 17, 2, out outv.S);
    }

    // Floored division/modulo, matching Zig @divFloor / @mod for i64.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static long DivFloor(long a, long b)
    {
        long qd = a / b, r = a % b;
        if (r != 0 && ((r < 0) != (b < 0))) qd--;
        return qd;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static long ModFloor(long a, long b)
    {
        long r = a % b;
        if (r != 0 && ((r < 0) != (b < 0))) r += b;
        return r;
    }

    // days since 1970-01-01 (Howard Hinnant). The era uses @divFloor, the rest
    // @divTrunc (plain C / for the involved nonneg operands).
    private static long DaysFromCivil(long yIn, long m, long d)
    {
        long y = yIn - (m <= 2 ? 1 : 0);
        long era = DivFloor((y >= 0 ? y : y - 399), 400);
        long yoe = y - era * 400;                 // [0, 399]
        long mp = ModFloor(m + 9, 12);            // [0,11] with Mar=0
        long doy = (153 * mp + 2) / 5 + d - 1;    // [0,365]
        long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0,146096]
        return era * 146097 + doe - 719468;
    }

    private static long EpochSecs(Ts t)
    {
        return DaysFromCivil(t.Y, t.Mo, t.D) * 86400 + t.H * 3600 + t.Mi * 60 + t.S;
    }

    // day_of_week, Monday=0..Sunday=6 (Sakamoto). Replicates the generator exactly.
    private static readonly long[] DowTbl = { 0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4 };

    private static long DayOfWeek(long yIn, long m, long d)
    {
        long y = yIn - (m < 3 ? 1 : 0);
        long dow = ModFloor(y + y / 4 - y / 100 + y / 400 + DowTbl[m - 1] + d, 7); // 0=Sun
        return ModFloor(dow + 6, 7); // 0=Mon
    }

    // ----- minimal JSON field extraction -------------------------------------
    // Extract the value text for "key": within buf (first occurrence). For
    // objects/arrays/strings the returned slice includes the delimiters; for bare
    // values it excludes the trailing ',' '}' ']'. Returns false if not found.
    //
    // `searchBase` is the absolute offset/len within `body` we are scanning inside
    // (i.e. a previously extracted sub-object slice). The returned Slice is in
    // absolute body coordinates.
    private static bool Field(ReadOnlySpan<byte> body, Slice buf, string key, out Slice outv)
    {
        outv = default;

        // needle = "\"" ++ key ++ "\":"  (klen+3 must fit the C 64-byte buffer)
        int klen = key.Length;
        if (klen + 3 >= 64) return false;
        int nlen = klen + 3;

        if (buf.Len < nlen) return false;

        // first occurrence of needle in buf (memcmp scan over the slice)
        int hit = -1;
        int bufStart = buf.Start;
        int bufEnd = buf.Start + buf.Len;
        for (int off = bufStart; off + nlen <= bufEnd; off++)
        {
            if (body[off] != (byte)'"') continue;
            bool match = true;
            for (int k = 0; k < klen; k++)
            {
                if (body[off + 1 + k] != (byte)key[k]) { match = false; break; }
            }
            if (!match) continue;
            if (body[off + 1 + klen] != (byte)'"') continue;
            if (body[off + 2 + klen] != (byte)':') continue;
            hit = off;
            break;
        }
        if (hit < 0) return false;

        int i = hit + nlen;
        // skip optional whitespace
        while (i < bufEnd)
        {
            byte w = body[i];
            if (w == (byte)' ' || w == (byte)'\t' || w == (byte)'\n' || w == (byte)'\r') i++;
            else break;
        }
        if (i >= bufEnd) return false;
        int start = i;
        byte c = body[i];
        if (c == (byte)'{' || c == (byte)'[')
        {
            byte open = c;
            byte close = (c == (byte)'{') ? (byte)'}' : (byte)']';
            int depth = 0;
            bool inStr = false;
            for (; i < bufEnd; i++)
            {
                byte ch = body[i];
                if (inStr)
                {
                    if (ch == (byte)'\\') i++;
                    else if (ch == (byte)'"') inStr = false;
                }
                else if (ch == (byte)'"')
                {
                    inStr = true;
                }
                else if (ch == open)
                {
                    depth++;
                }
                else if (ch == close)
                {
                    depth--;
                    if (depth == 0) { outv = new Slice(start, (i + 1) - start); return true; }
                }
            }
            return false;
        }
        else if (c == (byte)'"')
        {
            i++;
            for (; i < bufEnd; i++)
            {
                if (body[i] == (byte)'\\') i++;
                else if (body[i] == (byte)'"') { outv = new Slice(start, (i + 1) - start); return true; }
            }
            return false;
        }
        else
        {
            while (i < bufEnd && body[i] != (byte)',' && body[i] != (byte)'}' && body[i] != (byte)']') i++;
            outv = new Slice(start, i - start);
            return true;
        }
    }

    // Parse the field's value as f64 (Zig parseFloat). Returns false if missing or
    // the value text isn't a valid float over its FULL extent (parseFloat / strtod
    // is strict: must consume the whole slice).
    private static bool NumField(ReadOnlySpan<byte> body, Slice buf, string key, out double outv)
    {
        outv = 0.0;
        if (!Field(body, buf, key, out Slice v)) return false;
        if (v.Len == 0) return false;
        if (v.Len >= 64) return false; // matches C tmp[64] guard
        return ParseFloatExact(body.Slice(v.Start, v.Len), out outv);
    }

    // Strict float parse over the whole byte slice, matching strtod()+full-consume
    // and Zig std.fmt.parseFloat. Accepts decimal/scientific notation. Uses the
    // invariant culture and rejects any trailing/leading garbage or whitespace.
    private static bool ParseFloatExact(ReadOnlySpan<byte> s, out double outv)
    {
        outv = 0.0;
        if (s.Length == 0) return false;
        // strtod skips leading whitespace; parseFloat does not, but the generator
        // never emits whitespace inside a numeric value and the C path requires the
        // parsed length to equal the slice length, so a leading space would fail
        // anyway. We forbid leading/trailing whitespace explicitly for safety.
        Span<char> chars = s.Length <= 64 ? stackalloc char[64] : new char[s.Length];
        for (int i = 0; i < s.Length; i++) chars[i] = (char)s[i];
        ReadOnlySpan<char> cs = chars.Slice(0, s.Length);

        // double.TryParse with the chosen styles; AllowLeadingSign covers '+'/'-'.
        // No AllowLeadingWhite / AllowTrailingWhite so the entire slice must be the
        // number (mirrors strtod end==slice-end). InvariantCulture -> '.' decimal.
        const NumberStyles styles = NumberStyles.AllowLeadingSign |
                                    NumberStyles.AllowDecimalPoint |
                                    NumberStyles.AllowExponent;
        return double.TryParse(cs, styles, CultureInfo.InvariantCulture, out outv);
    }

    // Strip surrounding quotes if present (Zig strInner).
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Slice StrInner(ReadOnlySpan<byte> body, Slice v)
    {
        if (v.Len >= 2 && body[v.Start] == (byte)'"' && body[v.Start + v.Len - 1] == (byte)'"')
            return new Slice(v.Start + 1, v.Len - 2);
        return v;
    }

    // Search for `needle` bytes within a slice of body (Zig indexOf != null).
    private static bool SliceContains(ReadOnlySpan<byte> body, Slice hay, ReadOnlySpan<byte> needle)
    {
        int nlen = needle.Length;
        if (hay.Len < nlen) return false;
        int hayEnd = hay.Start + hay.Len;
        for (int off = hay.Start; off + nlen <= hayEnd; off++)
        {
            bool match = true;
            for (int k = 0; k < nlen; k++)
            {
                if (body[off + k] != needle[k]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }

    // Vectorize a raw POST body into a 16-wide int16 vector (dims 14,15 = 0).
    // Returns false only if the payload is unparseable.
    public static bool DoVectorize(ReadOnlySpan<byte> body, Span<short> outv16)
    {
        // zero the full padded vector up front
        for (int i = 0; i < VPAD; i++) outv16[i] = 0;

        Slice full = new Slice(0, body.Length);

        if (!Field(body, full, "transaction", out Slice tx)) return false;
        if (!Field(body, full, "customer", out Slice cust)) return false;
        if (!Field(body, full, "merchant", out Slice merch)) return false;
        if (!Field(body, full, "terminal", out Slice term)) return false;

        if (!NumField(body, tx, "amount", out double amount)) return false;
        if (!NumField(body, tx, "installments", out double installments)) return false;
        if (!Field(body, tx, "requested_at", out Slice reqAtV)) return false;
        Slice reqAt = StrInner(body, reqAtV);
        if (!ParseTs(body, reqAt, out Ts ts)) return false;

        if (!NumField(body, cust, "avg_amount", out double avgAmount)) return false;
        if (!NumField(body, cust, "tx_count_24h", out double tx24)) return false;

        // known_merchants: default to a literal "[]" when missing. We keep the
        // sliceContains semantics by tracking a separate "empty" flag instead of a
        // synthetic body slice; an empty/"[]" haystack can never contain a quoted id.
        bool hasKnown = Field(body, cust, "known_merchants", out Slice known);

        if (!Field(body, merch, "id", out Slice merchIdV)) return false;
        Slice merchId = StrInner(body, merchIdV);
        if (!Field(body, merch, "mcc", out Slice mccV)) return false;
        Slice mcc = StrInner(body, mccV);
        if (!NumField(body, merch, "avg_amount", out double merchAvg)) return false;

        if (!Field(body, term, "is_online", out Slice vOnline)) return false;
        bool isOnline = (vOnline.Len > 0 && body[vOnline.Start] == (byte)'t');
        if (!Field(body, term, "card_present", out Slice vPresent)) return false;
        bool cardPresent = (vPresent.Len > 0 && body[vPresent.Start] == (byte)'t');
        if (!NumField(body, term, "km_from_home", out double kmHome)) return false;

        // last_transaction: null or {timestamp, km_from_current}
        bool hasLast = false;
        double minutes = -1.0, lastKm = -1.0;
        if (Field(body, full, "last_transaction", out Slice lt))
        {
            if (lt.Len > 0 && body[lt.Start] == (byte)'{')
            {
                if (!Field(body, lt, "timestamp", out Slice ltTsV)) return false;
                Slice ltTs = StrInner(body, ltTsV);
                if (!NumField(body, lt, "km_from_current", out double lk)) return false;
                if (!ParseTs(body, ltTs, out Ts tprev)) return false;
                hasLast = true;
                minutes = (double)(EpochSecs(ts) - EpochSecs(tprev)) / 60.0;
                lastKm = lk;
            }
        }

        // unknown_merchant: merchant.id NOT present (quoted) in known_merchants.
        // Zig builds "\"{id}\"" into a 40-byte buffer; id longer than 38 -> null.
        int qlen = merchId.Len + 2;
        if (qlen > 40) return false;
        Span<byte> idbuf = stackalloc byte[40];
        idbuf[0] = (byte)'"';
        for (int k = 0; k < merchId.Len; k++) idbuf[1 + k] = body[merchId.Start + k];
        idbuf[1 + merchId.Len] = (byte)'"';
        ReadOnlySpan<byte> idquoted = idbuf.Slice(0, qlen);

        // When known_merchants is absent the C code uses "[]" which never contains
        // the quoted id, so known_flag is 0 -> unknown_merchant = 1.
        bool foundKnown = hasKnown && SliceContains(body, known, idquoted);
        double knownFlag = foundKnown ? 1.0 : 0.0;
        double unknownMerchant = 1.0 - knownFlag;

        double hour = (double)ts.H;
        double dow = (double)DayOfWeek(ts.Y, ts.Mo, ts.D);

        outv16[0] = Q(Clamp01(amount / MAX_AMOUNT));
        outv16[1] = Q(Clamp01(installments / MAX_INSTALLMENTS));
        outv16[2] = Q(Clamp01((amount / avgAmount) / AMOUNT_VS_AVG_RATIO));
        outv16[3] = Q(hour / 23.0);
        outv16[4] = Q(dow / 6.0);
        if (hasLast)
        {
            outv16[5] = Q(Clamp01(minutes / MAX_MINUTES));
            outv16[6] = Q(Clamp01(lastKm / MAX_KM));
        }
        else
        {
            outv16[5] = -10000;
            outv16[6] = -10000;
        }
        outv16[7] = Q(Clamp01(kmHome / MAX_KM));
        outv16[8] = Q(Clamp01(tx24 / MAX_TX_24H));
        outv16[9] = isOnline ? (short)10000 : (short)0;
        outv16[10] = cardPresent ? (short)10000 : (short)0;
        outv16[11] = Q(unknownMerchant);
        outv16[12] = Q(MccRisk(body.Slice(mcc.Start, mcc.Len)));
        outv16[13] = Q(Clamp01(merchAvg / MAX_MERCH_AVG));
        // dims 14,15 already 0
        return true;
    }

#if VEC_TEST
    // Self-test mirroring vec.c's VEC_TEST: the two DETECTION_RULES example vectors
    // (legit, fraud) plus the smoke case with a non-null last_transaction.
    public static int Main()
    {
        Check("legit",
            "{\"id\":\"tx-1329056812\",\"transaction\":{\"amount\":41.12,\"installments\":2," +
            "\"requested_at\":\"2026-03-11T18:45:53Z\"},\"customer\":{\"avg_amount\":82.24," +
            "\"tx_count_24h\":3,\"known_merchants\":[\"MERC-003\",\"MERC-016\"]}," +
            "\"merchant\":{\"id\":\"MERC-016\",\"mcc\":\"5411\",\"avg_amount\":60.25}," +
            "\"terminal\":{\"is_online\":false,\"card_present\":true,\"km_from_home\":29.23}," +
            "\"last_transaction\":null}",
            new short[] { 41, 1667, 500, 7826, 3333, -10000, -10000, 292, 1500, 0, 10000, 0, 1500, 60, 0, 0 });

        Check("fraud",
            "{\"id\":\"tx-3330991687\",\"transaction\":{\"amount\":9505.97,\"installments\":10," +
            "\"requested_at\":\"2026-03-14T05:15:12Z\"},\"customer\":{\"avg_amount\":81.28," +
            "\"tx_count_24h\":20,\"known_merchants\":[\"MERC-008\",\"MERC-007\",\"MERC-005\"]}," +
            "\"merchant\":{\"id\":\"MERC-068\",\"mcc\":\"7802\",\"avg_amount\":54.86}," +
            "\"terminal\":{\"is_online\":false,\"card_present\":true,\"km_from_home\":952.27}," +
            "\"last_transaction\":null}",
            new short[] { 9506, 8333, 10000, 2174, 8333, -10000, -10000, 9523, 10000, 0, 10000, 10000, 7500, 55, 0, 0 });

        Check("smoke",
            "{\"id\":\"tx-smoke-001\",\"transaction\":{\"amount\":384.88,\"installments\":3," +
            "\"requested_at\":\"2026-03-11T20:23:35Z\"},\"customer\":{\"avg_amount\":769.76," +
            "\"tx_count_24h\":3,\"known_merchants\":[\"MERC-009\",\"MERC-001\",\"MERC-001\"]}," +
            "\"merchant\":{\"id\":\"MERC-001\",\"mcc\":\"5912\",\"avg_amount\":298.95}," +
            "\"terminal\":{\"is_online\":false,\"card_present\":true,\"km_from_home\":13.7090520965}," +
            "\"last_transaction\":{\"timestamp\":\"2026-03-11T14:58:35Z\"," +
            "\"km_from_current\":18.8626479774}}",
            new short[] { 385, 2500, 500, 8696, 3333, 2257, 189, 137, 1500, 0, 10000, 0, 2000, 299, 0, 0 });

        // day_of_week spot checks (2026-03-11 Wed->2, 2026-03-14 Sat->5)
        if (DayOfWeek(2026, 3, 11) != 2) { Console.Error.WriteLine("FAIL day_of_week 2026-03-11"); Environment.Exit(1); }
        if (DayOfWeek(2026, 3, 14) != 5) { Console.Error.WriteLine("FAIL day_of_week 2026-03-14"); Environment.Exit(1); }
        Console.WriteLine("ok day_of_week");
        Console.WriteLine("all vec tests passed");
        return 0;
    }

    private static void Check(string name, string payload, short[] want)
    {
        byte[] bytes = System.Text.Encoding.ASCII.GetBytes(payload);
        Span<short> got = stackalloc short[VPAD];
        if (!DoVectorize(bytes, got))
        {
            Console.Error.WriteLine($"FAIL {name}: vectorize returned false");
            Environment.Exit(1);
        }
        for (int i = 0; i < VPAD; i++)
        {
            if (got[i] != want[i])
            {
                Console.Error.WriteLine($"FAIL {name}: out[{i}]={got[i]} want {want[i]}");
                Environment.Exit(1);
            }
        }
        Console.WriteLine($"ok {name}");
    }
#endif
}
