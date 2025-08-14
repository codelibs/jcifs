/* encdec - encode and decode integers, times, and
 * internationalized strings to and from popular binary formats
 * http://www.ioplex.com/~miallen/encdec/
 * Copyright (c) 2003 Michael B. Allen <mballen@erols.com>
 *
 * The GNU Library General Public License
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA
 */

package jcifs.util;

import java.io.IOException;
import java.util.Date;

import jcifs.SmbConstants;

/**
 * Encoding and decoding utility class for SMB protocol.
 * Provides methods for encoding/decoding various data types in different byte orders.
 */
public final class Encdec {

    private static final long SEC_BETWEEEN_1904_AND_1970 = 2082844800L;
    private static final int TIME_1970_SEC_32BE = 1;
    private static final int TIME_1970_SEC_32LE = 2;
    private static final int TIME_1904_SEC_32BE = 3;
    private static final int TIME_1904_SEC_32LE = 4;
    private static final int TIME_1601_NANOS_64LE = 5;
    private static final int TIME_1601_NANOS_64BE = 6;
    private static final int TIME_1970_MILLIS_64BE = 7;
    private static final int TIME_1970_MILLIS_64LE = 8;

    /**
     *
     */
    private Encdec() {
    }

    /*
     * Encode integers
     */

    /**
     * Encodes a 16-bit unsigned integer in big-endian byte order.
     *
     * @param s the short value to encode
     * @param dst the destination byte array
     * @param di the starting index in the destination array
     * @return the number of bytes written (2)
     */
    public static int enc_uint16be(final short s, final byte[] dst, int di) {
        dst[di] = (byte) (s >> 8 & 0xFF);
        di++;
        dst[di] = (byte) (s & 0xFF);
        return 2;
    }

    /**
     * Encodes a 32-bit unsigned integer in big-endian byte order.
     *
     * @param i the integer value to encode
     * @param dst the destination byte array
     * @param di the starting index in the destination array
     * @return the number of bytes written (4)
     */
    public static int enc_uint32be(final int i, final byte[] dst, int di) {
        dst[di] = (byte) (i >> 24 & 0xFF);
        di++;
        dst[di++] = (byte) (i >> 16 & 0xFF);
        dst[di++] = (byte) (i >> 8 & 0xFF);
        dst[di] = (byte) (i & 0xFF);
        return 4;
    }

    /**
     * Encodes a 16-bit unsigned integer in little-endian byte order.
     *
     * @param s the short value to encode
     * @param dst the destination byte array
     * @param di the starting index in the destination array
     * @return the number of bytes written (2)
     */
    public static int enc_uint16le(final short s, final byte[] dst, int di) {
        dst[di] = (byte) (s & 0xFF);
        di++;
        dst[di] = (byte) (s >> 8 & 0xFF);
        return 2;
    }

    /**
     * Encodes a 32-bit unsigned integer in little-endian byte order.
     *
     * @param i the integer value to encode
     * @param dst the destination byte array
     * @param di the starting index in the destination array
     * @return the number of bytes written (4)
     */
    public static int enc_uint32le(final int i, final byte[] dst, int di) {
        dst[di] = (byte) (i & 0xFF);
        di++;
        dst[di++] = (byte) (i >> 8 & 0xFF);
        dst[di++] = (byte) (i >> 16 & 0xFF);
        dst[di] = (byte) (i >> 24 & 0xFF);
        return 4;
    }

    /*
     * Decode integers
     */

    /**
     * Decodes a 16-bit unsigned integer from big-endian byte order.
     *
     * @param src the source byte array
     * @param si the starting index in the source array
     * @return the decoded short value
     */
    public static short dec_uint16be(final byte[] src, final int si) {
        return (short) ((src[si] & 0xFF) << 8 | src[si + 1] & 0xFF);
    }

    /**
     * Decodes a 32-bit unsigned integer from big-endian byte order.
     *
     * @param src the source byte array
     * @param si the starting index in the source array
     * @return the decoded integer value
     */
    public static int dec_uint32be(final byte[] src, final int si) {
        return (src[si] & 0xFF) << 24 | (src[si + 1] & 0xFF) << 16 | (src[si + 2] & 0xFF) << 8 | src[si + 3] & 0xFF;
    }

    /**
     * Decodes a 16-bit unsigned integer from little-endian byte order.
     *
     * @param src the source byte array
     * @param si the starting index in the source array
     * @return the decoded short value
     */
    public static short dec_uint16le(final byte[] src, final int si) {
        return (short) (src[si] & 0xFF | (src[si + 1] & 0xFF) << 8);
    }

    /**
     * Decodes a 32-bit unsigned integer from little-endian byte order.
     *
     * @param src the source byte array
     * @param si the starting index in the source array
     * @return the decoded integer value
     */
    public static int dec_uint32le(final byte[] src, final int si) {
        return src[si] & 0xFF | (src[si + 1] & 0xFF) << 8 | (src[si + 2] & 0xFF) << 16 | (src[si + 3] & 0xFF) << 24;
    }

    /*
     * Encode and decode 64 bit integers
     */

    /**
     * Encodes a 64-bit unsigned integer in big-endian byte order.
     *
     * @param l the long value to encode
     * @param dst the destination byte array
     * @param di the starting index in the destination array
     * @return the number of bytes written (8)
     */
    public static int enc_uint64be(final long l, final byte[] dst, final int di) {
        enc_uint32be((int) (l & 0xFFFFFFFFL), dst, di + 4);
        enc_uint32be((int) (l >> 32L & 0xFFFFFFFFL), dst, di);
        return 8;
    }

    /**
     * Encodes a 64-bit unsigned integer in little-endian byte order.
     *
     * @param l the long value to encode
     * @param dst the destination byte array
     * @param di the starting index in the destination array
     * @return the number of bytes written (8)
     */
    public static int enc_uint64le(final long l, final byte[] dst, final int di) {
        enc_uint32le((int) (l & 0xFFFFFFFFL), dst, di);
        enc_uint32le((int) (l >> 32L & 0xFFFFFFFFL), dst, di + 4);
        return 8;
    }

    /**
     * Decodes a 64-bit unsigned integer from big-endian byte order.
     *
     * @param src the source byte array
     * @param si the starting index in the source array
     * @return the decoded long value
     */
    public static long dec_uint64be(final byte[] src, final int si) {
        long l = dec_uint32be(src, si) & 0xFFFFFFFFL;
        l <<= 32L;
        l |= dec_uint32be(src, si + 4) & 0xFFFFFFFFL;
        return l;
    }

    /**
     * Decodes a 64-bit unsigned integer from little-endian byte order.
     *
     * @param src the source byte array
     * @param si the starting index in the source array
     * @return the decoded long value
     */
    public static long dec_uint64le(final byte[] src, final int si) {
        long l = dec_uint32le(src, si + 4) & 0xFFFFFFFFL;
        l <<= 32L;
        l |= dec_uint32le(src, si) & 0xFFFFFFFFL;
        return l;
    }

    /*
     * Encode floats
     */

    /**
     * Encodes a float value in little-endian byte order.
     *
     * @param f the float value to encode
     * @param dst the destination byte array
     * @param di the starting index in the destination array
     * @return the number of bytes written (4)
     */
    public static int enc_floatle(final float f, final byte[] dst, final int di) {
        return enc_uint32le(Float.floatToIntBits(f), dst, di);
    }

    /**
     * Encodes a float value in big-endian byte order.
     *
     * @param f the float value to encode
     * @param dst the destination byte array
     * @param di the starting index in the destination array
     * @return the number of bytes written (4)
     */
    public static int enc_floatbe(final float f, final byte[] dst, final int di) {
        return enc_uint32be(Float.floatToIntBits(f), dst, di);
    }

    /*
     * Decode floating point numbers
     */

    /**
     * Decodes a float value from little-endian byte order.
     *
     * @param src the source byte array
     * @param si the starting index in the source array
     * @return the decoded float value
     */
    public static float dec_floatle(final byte[] src, final int si) {
        return Float.intBitsToFloat(dec_uint32le(src, si));
    }

    /**
     * Decodes a float value from big-endian byte order.
     *
     * @param src the source byte array
     * @param si the starting index in the source array
     * @return the decoded float value
     */
    public static float dec_floatbe(final byte[] src, final int si) {
        return Float.intBitsToFloat(dec_uint32be(src, si));
    }

    /*
     * Encode and decode doubles
     */

    /**
     * Encodes a double value in little-endian byte order.
     *
     * @param d the double value to encode
     * @param dst the destination byte array
     * @param di the starting index in the destination array
     * @return the number of bytes written (8)
     */
    public static int enc_doublele(final double d, final byte[] dst, final int di) {
        return enc_uint64le(Double.doubleToLongBits(d), dst, di);
    }

    /**
     * Encodes a double value in big-endian byte order.
     *
     * @param d the double value to encode
     * @param dst the destination byte array
     * @param di the starting index in the destination array
     * @return the number of bytes written (8)
     */
    public static int enc_doublebe(final double d, final byte[] dst, final int di) {
        return enc_uint64be(Double.doubleToLongBits(d), dst, di);
    }

    /**
     * Decodes a double value from little-endian byte order.
     *
     * @param src the source byte array
     * @param si the starting index in the source array
     * @return the decoded double value
     */
    public static double dec_doublele(final byte[] src, final int si) {
        return Double.longBitsToDouble(dec_uint64le(src, si));
    }

    /**
     * Decodes a double value from big-endian byte order.
     *
     * @param src the source byte array
     * @param si the starting index in the source array
     * @return the decoded double value
     */
    public static double dec_doublebe(final byte[] src, final int si) {
        return Double.longBitsToDouble(dec_uint64be(src, si));
    }

    /*
     * Encode times
     */

    /**
     * Encodes a Date value according to the specified time encoding type.
     *
     * @param date the Date to encode
     * @param dst the destination byte array
     * @param di the starting index in the destination array
     * @param enc the time encoding type (e.g., TIME_1970_SEC_32BE)
     * @return the number of bytes written
     */
    public static int enc_time(final Date date, final byte[] dst, final int di, final int enc) {
        long t;

        return switch (enc) {
        case TIME_1970_SEC_32BE -> enc_uint32be((int) (date.getTime() / 1000L), dst, di);
        case TIME_1970_SEC_32LE -> enc_uint32le((int) (date.getTime() / 1000L), dst, di);
        case TIME_1904_SEC_32BE -> enc_uint32be((int) (date.getTime() / 1000L + SEC_BETWEEEN_1904_AND_1970 & 0xFFFFFFFF), dst, di);
        case TIME_1904_SEC_32LE -> enc_uint32le((int) (date.getTime() / 1000L + SEC_BETWEEEN_1904_AND_1970 & 0xFFFFFFFF), dst, di);
        case TIME_1601_NANOS_64BE -> {
            t = (date.getTime() + SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601) * 10000L;
            yield enc_uint64be(t, dst, di);
        }
        case TIME_1601_NANOS_64LE -> {
            t = (date.getTime() + SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601) * 10000L;
            yield enc_uint64le(t, dst, di);
        }
        case TIME_1970_MILLIS_64BE -> enc_uint64be(date.getTime(), dst, di);
        case TIME_1970_MILLIS_64LE -> enc_uint64le(date.getTime(), dst, di);
        default -> throw new IllegalArgumentException("Unsupported time encoding");
        };
    }

    /*
     * Decode times
     */

    /**
     * Decodes a Date value according to the specified time encoding type.
     *
     * @param src the source byte array
     * @param si the starting index in the source array
     * @param enc the time encoding type (e.g., TIME_1970_SEC_32BE)
     * @return the decoded Date value
     */
    public static Date dec_time(final byte[] src, final int si, final int enc) {
        long t;

        return switch (enc) {
        case TIME_1970_SEC_32BE -> new Date(dec_uint32be(src, si) * 1000L);
        case TIME_1970_SEC_32LE -> new Date(dec_uint32le(src, si) * 1000L);
        case TIME_1904_SEC_32BE -> new Date(((dec_uint32be(src, si) & 0xFFFFFFFFL) - SEC_BETWEEEN_1904_AND_1970) * 1000L);
        case TIME_1904_SEC_32LE -> new Date(((dec_uint32le(src, si) & 0xFFFFFFFFL) - SEC_BETWEEEN_1904_AND_1970) * 1000L);
        case TIME_1601_NANOS_64BE -> {
            t = dec_uint64be(src, si);
            yield new Date(t / 10000L - SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601);
        }
        case TIME_1601_NANOS_64LE -> {
            t = dec_uint64le(src, si);
            yield new Date(t / 10000L - SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601);
        }
        case TIME_1970_MILLIS_64BE -> new Date(dec_uint64be(src, si));
        case TIME_1970_MILLIS_64LE -> new Date(dec_uint64le(src, si));
        default -> throw new IllegalArgumentException("Unsupported time encoding");
        };
    }

    /**
     * Encodes a String as UTF-8 bytes.
     *
     * @param str the String to encode
     * @param dst the destination byte array
     * @param di the starting index in the destination array
     * @param dlim the maximum index in the destination array
     * @return the number of bytes written
     */
    public static int enc_utf8(final String str, final byte[] dst, int di, final int dlim) {
        final int start = di;
        int ch;
        final int strlen = str.length();

        for (int i = 0; di < dlim && i < strlen; i++) {
            ch = str.charAt(i);
            if (ch >= 0x0001 && ch <= 0x007F) {
                dst[di] = (byte) ch;
                di++;
            } else {
                if (ch > 0x07FF) {
                    if (dlim - di < 3) {
                        break;
                    }
                    dst[di] = (byte) (0xE0 | ch >> 12 & 0x0F);
                    di++;
                    dst[di++] = (byte) (0x80 | ch >> 6 & 0x3F);
                } else {
                    if (dlim - di < 2) {
                        break;
                    }
                    dst[di] = (byte) (0xC0 | ch >> 6 & 0x1F);
                    di++;
                }
                dst[di++] = (byte) (0x80 | ch >> 0 & 0x3F);
            }
        }

        return di - start;
    }

    /**
     * Decodes a UTF-8 encoded string from a byte array.
     *
     * @param src the source byte array
     * @param si the starting index in the source array
     * @param slim the limit index in the source array
     * @return the decoded String
     * @throws IOException if a decoding error occurs
     */
    public static String dec_utf8(final byte[] src, int si, final int slim) throws IOException {
        final char[] uni = new char[slim - si];
        int ui, ch;

        for (ui = 0; si < slim && (ch = src[si++] & 0xFF) != 0; ui++) {
            if (ch < 0x80) {
                uni[ui] = (char) ch;
            } else if ((ch & 0xE0) == 0xC0) {
                if (slim - si < 2) {
                    break;
                }
                uni[ui] = (char) ((ch & 0x1F) << 6);
                ch = src[si] & 0xFF;
                si++;
                uni[ui] |= ch & 0x3F;
                if ((ch & 0xC0) != 0x80 || uni[ui] < 0x80) {
                    throw new IOException("Invalid UTF-8 sequence");
                }
            } else if ((ch & 0xF0) == 0xE0) {
                if (slim - si < 3) {
                    break;
                }
                uni[ui] = (char) ((ch & 0x0F) << 12);
                ch = src[si] & 0xFF;
                si++;
                if ((ch & 0xC0) != 0x80) {
                    throw new IOException("Invalid UTF-8 sequence");
                }
                uni[ui] |= (ch & 0x3F) << 6;
                ch = src[si++] & 0xFF;
                uni[ui] |= ch & 0x3F;
                if ((ch & 0xC0) != 0x80 || uni[ui] < 0x800) {
                    throw new IOException("Invalid UTF-8 sequence");
                }
            } else {
                throw new IOException("Unsupported UTF-8 sequence");
            }
        }

        return new String(uni, 0, ui);
    }

    /**
     * Decodes a UCS-2 little-endian encoded string from a byte array.
     *
     * @param src the source byte array
     * @param si the starting index in the source array
     * @param slim the limit index in the source array
     * @param buf the character buffer for decoding
     * @return the decoded String
     */
    public static String dec_ucs2le(final byte[] src, int si, final int slim, final char[] buf) {
        int bi;

        for (bi = 0; si + 1 < slim; bi++, si += 2) {
            buf[bi] = (char) dec_uint16le(src, si);
            if (buf[bi] == '\0') {
                break;
            }
        }

        return new String(buf, 0, bi);
    }
}
