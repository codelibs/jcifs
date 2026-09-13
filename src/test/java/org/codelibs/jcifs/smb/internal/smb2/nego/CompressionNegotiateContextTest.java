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
package org.codelibs.jcifs.smb.internal.smb2.nego;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Arrays;

import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CompressionNegotiateContextTest {

    @Test
    @DisplayName("the context type is 0x3")
    void contextTypeIsThree() {
        assertEquals(0x3, new CompressionNegotiateContext().getContextType());
    }

    @Test
    @DisplayName("the offer is a count, a zero padding, the flags and then the identifiers")
    void encodesThePreambleThenTheAlgorithms() {
        final CompressionNegotiateContext ctx =
                new CompressionNegotiateContext(null, new int[] { CompressionNegotiateContext.COMPRESSION_LZ77 });
        final byte[] dst = new byte[32];
        Arrays.fill(dst, (byte) 0xFF);

        final int written = ctx.encode(dst, 0);

        assertEquals(10, written);
        assertEquals(10, ctx.size(), "size has to cover what encode writes");
        assertArrayEquals(new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 2, 0 }, Arrays.copyOfRange(dst, 0, 10));
    }

    @Test
    @DisplayName("what the server selected is read back")
    void decodesTheServerSelection() throws Exception {
        // count 2, padding 0, flags 0, LZNT1 and Pattern_V1 - which is what Windows
        // Server 2025 answers when offered all five.
        final byte[] wire = { 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 4, 0 };
        final CompressionNegotiateContext ctx = new CompressionNegotiateContext();

        assertEquals(12, ctx.decode(wire, 0, wire.length));

        assertArrayEquals(new int[] { CompressionNegotiateContext.COMPRESSION_LZNT1, CompressionNegotiateContext.COMPRESSION_PATTERN_V1 },
                ctx.getAlgorithms());
        assertEquals(CompressionNegotiateContext.FLAG_NONE, ctx.getFlags());
        assertFalse(ctx.getFlags() == CompressionNegotiateContext.FLAG_CHAINED);
    }

    @Test
    @DisplayName("the chained flag is read back")
    void decodesTheChainedFlag() throws Exception {
        final byte[] wire = { 1, 0, 0, 0, 1, 0, 0, 0, 2, 0 };
        final CompressionNegotiateContext ctx = new CompressionNegotiateContext();

        ctx.decode(wire, 0, wire.length);

        assertEquals(CompressionNegotiateContext.FLAG_CHAINED, ctx.getFlags());
    }

    @Test
    @DisplayName("a context shorter than its own header is refused")
    void refusesAShortContext() {
        final byte[] wire = { 1, 0, 0, 0, 0, 0, 0 };
        assertThrows(SMBProtocolDecodingException.class, () -> new CompressionNegotiateContext().decode(wire, 0, wire.length));
    }

    @Test
    @DisplayName("a context naming no algorithm is refused")
    void refusesAnEmptySelection() {
        // MS-SMB2 3.2.5.2: CompressionAlgorithmCount of zero is an error.
        final byte[] wire = { 0, 0, 0, 0, 0, 0, 0, 0 };
        assertThrows(SMBProtocolDecodingException.class, () -> new CompressionNegotiateContext().decode(wire, 0, wire.length));
    }

    @Test
    @DisplayName("a context claiming more algorithms than it carries is refused")
    void refusesACountPastTheEnd() {
        final byte[] wire = { 4, 0, 0, 0, 0, 0, 0, 0, 2, 0 };
        assertThrows(SMBProtocolDecodingException.class, () -> new CompressionNegotiateContext().decode(wire, 0, wire.length));
    }

    @Test
    @DisplayName("an identifier at or above 32 is refused")
    void refusesAnOutOfRangeAlgorithm() {
        // MS-SMB2 3.2.5.2 names 32 as the limit.
        final byte[] wire = { 1, 0, 0, 0, 0, 0, 0, 0, 32, 0 };
        assertThrows(SMBProtocolDecodingException.class, () -> new CompressionNegotiateContext().decode(wire, 0, wire.length));
    }

    @Test
    @DisplayName("a repeated identifier is refused")
    void refusesADuplicate() {
        // MS-SMB2 3.2.5.2: a duplicate in the list is an error.
        final byte[] wire = { 2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0 };
        assertThrows(SMBProtocolDecodingException.class, () -> new CompressionNegotiateContext().decode(wire, 0, wire.length));
    }
}
