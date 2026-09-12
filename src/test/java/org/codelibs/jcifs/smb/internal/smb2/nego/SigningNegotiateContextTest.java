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

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * The SMB2_SIGNING_CAPABILITIES negotiate context (MS-SMB2 2.2.3.1.7).
 *
 * <p>
 * The data is a 2-byte SigningAlgorithmCount followed by that many 16-bit ids, ordered with the most preferred
 * first. The defined ids are 0x0000 HMAC-SHA256, 0x0001 AES-CMAC and 0x0002 AES-GMAC, which is also what Samba's
 * smb2_constants.h carries, so the two agree.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SigningNegotiateContext Tests")
class SigningNegotiateContextTest {

    @Mock
    private Configuration mockConfig;

    @Test
    @DisplayName("the context type is 0x0008")
    void testContextType() {
        assertEquals(0x0008, SigningNegotiateContext.NEGO_CTX_SIGNING_TYPE, "MS-SMB2 2.2.3.1.7 assigns type 0x0008");
        assertEquals(0x0008,
                new SigningNegotiateContext(mockConfig, new int[] { SigningNegotiateContext.SIGNING_ALGO_AES128_GMAC }).getContextType());
    }

    @Test
    @DisplayName("the algorithm ids match the specification")
    void testAlgorithmIds() {
        // Pinned as literals rather than referred through another constant: these are wire values, and the point
        // of the assertion is that they are these numbers and not some other numbering.
        assertEquals(0x0000, SigningNegotiateContext.SIGNING_ALGO_HMAC_SHA256, "HMAC-SHA256 is 0x0000");
        assertEquals(0x0001, SigningNegotiateContext.SIGNING_ALGO_AES128_CMAC, "AES-CMAC is 0x0001");
        assertEquals(0x0002, SigningNegotiateContext.SIGNING_ALGO_AES128_GMAC, "AES-GMAC is 0x0002");
    }

    @Test
    @DisplayName("encode writes the count then the ids, in the order given")
    void testEncode() {
        final int[] algos = { SigningNegotiateContext.SIGNING_ALGO_AES128_GMAC, SigningNegotiateContext.SIGNING_ALGO_AES128_CMAC };
        final SigningNegotiateContext ctx = new SigningNegotiateContext(mockConfig, algos);

        final byte[] buffer = new byte[64];
        final int written = ctx.encode(buffer, 0);

        assertEquals(2, SMBUtil.readInt2(buffer, 0), "SigningAlgorithmCount must be the number of ids");
        assertEquals(SigningNegotiateContext.SIGNING_ALGO_AES128_GMAC, SMBUtil.readInt2(buffer, 2), "the first id is the preferred one");
        assertEquals(SigningNegotiateContext.SIGNING_ALGO_AES128_CMAC, SMBUtil.readInt2(buffer, 4), "the second id follows it");
        assertEquals(6, written, "two bytes of count plus two ids of two bytes each");
    }

    @Test
    @DisplayName("decode reads back what encode wrote")
    void testDecodeRoundTrip() throws SMBProtocolDecodingException {
        final int[] algos = { SigningNegotiateContext.SIGNING_ALGO_HMAC_SHA256, SigningNegotiateContext.SIGNING_ALGO_AES128_GMAC,
                SigningNegotiateContext.SIGNING_ALGO_AES128_CMAC };
        final byte[] buffer = new byte[64];
        final int written = new SigningNegotiateContext(mockConfig, algos).encode(buffer, 0);

        final SigningNegotiateContext decoded = new SigningNegotiateContext();
        final int read = decoded.decode(buffer, 0, written);

        assertArrayEquals(algos, decoded.getSigningAlgos(), "the ids must survive a round trip in order");
        assertEquals(written, read, "decode must consume exactly what encode produced");
    }

    @Test
    @DisplayName("a server response naming one algorithm decodes to that algorithm")
    void testDecodeServerSelection() throws SMBProtocolDecodingException {
        // What a server actually sends back: the single algorithm it chose.
        final byte[] buffer = new byte[8];
        SMBUtil.writeInt2(1, buffer, 0);
        SMBUtil.writeInt2(SigningNegotiateContext.SIGNING_ALGO_AES128_GMAC, buffer, 2);

        final SigningNegotiateContext decoded = new SigningNegotiateContext();
        decoded.decode(buffer, 0, 4);

        assertArrayEquals(new int[] { SigningNegotiateContext.SIGNING_ALGO_AES128_GMAC }, decoded.getSigningAlgos());
    }

    @Test
    @DisplayName("size matches what encode writes")
    void testSize() {
        final SigningNegotiateContext ctx = new SigningNegotiateContext(mockConfig,
                new int[] { SigningNegotiateContext.SIGNING_ALGO_AES128_CMAC, SigningNegotiateContext.SIGNING_ALGO_AES128_GMAC });

        final byte[] buffer = new byte[64];
        final int written = ctx.encode(buffer, 0);

        // The encryption context reports a size two bytes larger than it writes, which is harmless only because
        // the wire length comes from encode's return value. Not repeating that here.
        assertEquals(written, ctx.size(), "size must agree with the number of bytes encode writes");
    }

    @Test
    @DisplayName("a count that runs past the buffer is rejected rather than read out of bounds")
    void testDecodeRejectsOverlongCount() {
        final byte[] buffer = new byte[8];
        SMBUtil.writeInt2(1000, buffer, 0);

        assertThrows(SMBProtocolDecodingException.class, () -> new SigningNegotiateContext().decode(buffer, 0, buffer.length),
                "a declared count larger than the buffer must fail decoding");
    }

    @Test
    @DisplayName("an empty algorithm array encodes a zero count without error")
    void testEncodeEmpty() {
        // The specification requires a count greater than zero, so the client never sends this; encoding it must
        // still not write past the count field, because a malformed response must not be able to steer the encoder.
        final byte[] buffer = new byte[64];
        final int written = new SigningNegotiateContext(mockConfig, new int[0]).encode(buffer, 0);

        assertEquals(0, SMBUtil.readInt2(buffer, 0), "an empty array encodes a zero count");
        assertEquals(2, written, "only the count field is written");
    }
}
