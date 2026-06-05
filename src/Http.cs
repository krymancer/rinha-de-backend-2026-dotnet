// Http.cs — precomputed full HTTP/1.1 responses + header parsing.
// 1:1 with the validated engine's http.c contract (rinha.h: http_resp / http_ready
// / http_header_end / http_content_length). The six fraud responses are fully
// precomputed (headers + body) so the hot path is a single byte[] write.
//
// Fraud decision mirrors ivf_search: approved = (fraud_count < 3). The fraud_score
// is fraud_count/5.0 (0.0, 0.2, 0.4, 0.6, 0.8, 1.0). Bodies match the reference
// {"approved":<bool>,"fraud_score":<f>} format exactly.
using System;
using System.Text;

namespace Rinha;

internal static class Http
{
    // ---- precomputed bodies (fraud_count 0..5) ------------------------------
    // approved true for 0..2 (fraud < 3), false for 3..5; score = count/5.0.
    private static readonly string[] Bodies =
    {
        "{\"approved\":true,\"fraud_score\":0.0}",
        "{\"approved\":true,\"fraud_score\":0.2}",
        "{\"approved\":true,\"fraud_score\":0.4}",
        "{\"approved\":false,\"fraud_score\":0.6}",
        "{\"approved\":false,\"fraud_score\":0.8}",
        "{\"approved\":false,\"fraud_score\":1.0}",
    };

    // Indexed by fraud_count 0..5: full HTTP/1.1 response (status + headers + body).
    public static readonly byte[][] Resp = BuildResponses();

    // 200 OK with empty body — the "not-a-POST" / health reply (Ready in the spec).
    public static readonly byte[] Ready =
        Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: application/json\r\n" +
            "Content-Length: 0\r\n" +
            "Connection: keep-alive\r\n" +
            "\r\n");

    private static byte[][] BuildResponses()
    {
        var resp = new byte[6][];
        for (int i = 0; i < 6; i++)
        {
            string body = Bodies[i];
            int len = Encoding.ASCII.GetByteCount(body);
            string head =
                "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/json\r\n" +
                "Content-Length: " + len.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\r\n" +
                "Connection: keep-alive\r\n" +
                "\r\n";
            resp[i] = Encoding.ASCII.GetBytes(head + body);
        }
        return resp;
    }

    // ---- header parsing (mirrors http_header_end / http_content_length) ------

    // Index just past "\r\n\r\n" within buf[0..len), or -1 if not found yet.
    // Matches http_header_end's return of (offset + 4).
    public static int HeaderEnd(ReadOnlySpan<byte> buf)
    {
        int idx = buf.IndexOf(CrlfCrlf);
        return idx >= 0 ? idx + 4 : -1;
    }

    private static ReadOnlySpan<byte> CrlfCrlf => "\r\n\r\n"u8;
    private static ReadOnlySpan<byte> ContentLengthNeedle => "content-length:"u8;

    // Parse the Content-Length value from a header region (case-insensitive header
    // name match), or -1 if absent / malformed. `headers` should be the bytes up to
    // and including the header terminator; the value is read up to CR/space/tab.
    public static long ContentLength(ReadOnlySpan<byte> headers)
    {
        int n = ContentLengthNeedle.Length;
        for (int i = 0; i + n <= headers.Length; i++)
        {
            if (!EqualsAsciiIgnoreCase(headers.Slice(i, n), ContentLengthNeedle))
                continue;

            ReadOnlySpan<byte> rest = headers.Slice(i + n);
            int j = 0;
            while (j < rest.Length && (rest[j] == (byte)' ' || rest[j] == (byte)'\t'))
                j++;

            long value = 0;
            bool any = false;
            for (; j < rest.Length; j++)
            {
                byte b = rest[j];
                if (b == (byte)'\r' || b == (byte)'\n' || b == (byte)' ' || b == (byte)'\t')
                    break;
                if (b < (byte)'0' || b > (byte)'9')
                    return -1;
                value = value * 10 + (b - (byte)'0');
                any = true;
            }
            return any ? value : -1;
        }
        return -1;
    }

    private static bool EqualsAsciiIgnoreCase(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length)
            return false;
        for (int i = 0; i < a.Length; i++)
        {
            byte x = a[i];
            byte y = b[i];
            if (x >= (byte)'A' && x <= (byte)'Z') x = (byte)(x | 0x20);
            if (y >= (byte)'A' && y <= (byte)'Z') y = (byte)(y | 0x20);
            if (x != y)
                return false;
        }
        return true;
    }
}
