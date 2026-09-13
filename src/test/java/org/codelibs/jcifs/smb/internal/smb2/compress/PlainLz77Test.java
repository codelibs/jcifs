/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.codelibs.jcifs.smb.internal.smb2.compress;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;

import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The two worked examples in MS-XCA 2.4, plus the cases they do not reach.
 */
class PlainLz77Test {

    private static byte[] hex(final String spaced) {
        final String[] parts = spaced.trim().split("\\s+");
        final byte[] out = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            out[i] = (byte) Integer.parseInt(parts[i], 16);
        }
        return out;
    }

    private static String decompress(final byte[] input, final int originalSize) throws Exception {
        return new String(PlainLz77.decompress(input, 0, input.length, originalSize), StandardCharsets.US_ASCII);
    }

    @Test
    @DisplayName("the specification's all-literal example")
    void decompressesTheLiteralExample() throws Exception {
        // 26 zero flag bits for 26 literals, then six one-bits of padding: 0x0000003F
        // read from the top down.
        final byte[] compressed = hex("3f 00 00 00 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a");

        assertEquals("abcdefghijklmnopqrstuvwxyz", decompress(compressed, 26));
    }

    @Test
    @DisplayName("the specification's long-match example, whose match is longer than its distance")
    void decompressesTheLongMatchExample() throws Exception {
        // abc, then a match of distance 3 and length 297. The length escapes through
        // the nibble (15) and the byte (255) to a 16-bit 294, which is 297 once the
        // encoding's own bias is taken back off.
        final byte[] compressed = hex("ff ff ff 1f 61 62 63 17 00 0f ff 26 01");

        final String expected = "abc".repeat(100);
        assertEquals(300, expected.length());
        assertEquals(expected, decompress(compressed, 300));
    }

    @Test
    @DisplayName("two consecutive matches share one nibble byte")
    void sharesTheNibbleByteBetweenTwoMatches() throws Exception {
        // Four literals, then two matches that both escape to a nibble. The first
        // takes the low half of the single nibble byte and the second takes the high
        // half of that same byte - so the byte appears once, between the two match
        // words, and the second match reads backwards into it.
        //
        // flags 0x0FFFFFFF: bits 31..28 clear for the literals, 27 and 26 set for the
        // matches, the rest padding. Each match word 0x001F is distance 4, length 7.
        // The nibble byte 0x32 gives the first match 2 and the second 3, so the
        // lengths are 2+7+3 = 12 and 3+7+3 = 13.
        final byte[] compressed = hex("ff ff ff 0f 61 62 63 64 1f 00 32 1f 00");

        // 4 literals + 12 + 13 = 29 bytes of "abcd" repeating.
        final String expected = "abcd".repeat(8).substring(0, 29);
        assertEquals("abcdabcdabcdabcdabcdabcdabcda", expected);
        assertEquals(expected, decompress(compressed, 29));
    }

    @Test
    @DisplayName("a match reaching back before the start is refused")
    void refusesAMatchBeforeTheStart() {
        // One literal, then a match of distance 4 with only one byte written.
        final byte[] compressed = hex("ff ff ff 7f 61 1f 00");

        assertThrows(SMBProtocolDecodingException.class, () -> PlainLz77.decompress(compressed, 0, compressed.length, 16));
    }

    @Test
    @DisplayName("data that does not produce the declared size is refused")
    void refusesAShortResult() {
        final byte[] compressed = hex("3f 00 00 00 61 62 63");

        assertThrows(SMBProtocolDecodingException.class, () -> PlainLz77.decompress(compressed, 0, compressed.length, 26));
    }

    @Test
    @DisplayName("a truncated indicator word is refused")
    void refusesATruncatedIndicator() {
        final byte[] compressed = hex("3f 00");

        assertThrows(SMBProtocolDecodingException.class, () -> PlainLz77.decompress(compressed, 0, compressed.length, 4));
    }

    @Test
    @DisplayName("a segment outside the message is refused")
    void refusesASegmentOutsideTheMessage() {
        final byte[] compressed = hex("3f 00 00 00 61");

        assertThrows(SMBProtocolDecodingException.class, () -> PlainLz77.decompress(compressed, 2, compressed.length, 1));
    }

    @Test
    @DisplayName("the segment is read from the offset it is given")
    void decompressesAtAnOffset() throws Exception {
        final byte[] framed = hex("de ad be ef 3f 00 00 00 61 62 63");

        final byte[] out = PlainLz77.decompress(framed, 4, framed.length - 4, 3);

        assertArrayEquals("abc".getBytes(StandardCharsets.US_ASCII), out);
    }
}
