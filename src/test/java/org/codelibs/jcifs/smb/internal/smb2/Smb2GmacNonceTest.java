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
package org.codelibs.jcifs.smb.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The AES-GMAC nonce, which is derived entirely from the message being signed.
 *
 * <p>
 * MS-SMB2 3.1.4.1 states it as: 12 bytes, the "first 8 bytes are set to MessageId", then "if the sender is a
 * client, least significant bit is set to zero, otherwise set to 1. If the message is SMB2 CANCEL request, the
 * penultimate bit is set to 1, otherwise set to zero. Remaining 30 bits are set to zero." Section 3.1.5.1 says
 * verification uses the same syntax, and since the direction bit is read from each message's own header, one
 * construction serves signing a request and verifying a response.
 * </p>
 *
 * <p>
 * Samba computes the same thing - {@code SBVAL(iv, 0, msg_id)}, then {@code high_bits = flags &
 * SMB2_HDR_FLAG_REDIRECT} with {@code SMB2_HDR_FLAG_ASYNC} added for {@code SMB2_OP_CANCEL}, written at offset 8 -
 * where REDIRECT is 0x01 and ASYNC 0x02, so the two agree bit for bit. That agreement is why this is asserted
 * against literal expected bytes rather than against a second implementation of the same arithmetic: a test that
 * recomputed the layout would pass whatever the layout was.
 * </p>
 */
class Smb2GmacNonceTest {

    /** Offsets within the SMB2 header, as written by ServerMessageBlock2.writeHeaderWireFormat. */
    private static final int COMMAND_OFFSET = 12;
    private static final int FLAGS_OFFSET = 16;
    private static final int MID_OFFSET = 24;

    private static byte[] header(final long mid, final int flags, final int command) {
        final byte[] buf = new byte[Smb2Constants.SMB2_HEADER_LENGTH];
        SMBUtil.writeInt2(command, buf, COMMAND_OFFSET);
        SMBUtil.writeInt4(flags, buf, FLAGS_OFFSET);
        SMBUtil.writeInt8(mid, buf, MID_OFFSET);
        return buf;
    }

    @Test
    @DisplayName("a request nonce carries the message id and a zero direction bit")
    void requestNonce() {
        final byte[] buf = header(0x0102030405060708L, 0, ServerMessageBlock2.SMB2_QUERY_DIRECTORY);

        final byte[] nonce = Smb2SigningDigest.gmacNonce(buf, 0);

        assertEquals(12, nonce.length, "the GMAC nonce is 12 bytes");
        // MessageId little-endian, exactly as it sits in the header, then four bytes that are all zero for a
        // client-sent message that is not a CANCEL.
        assertArrayEquals(new byte[] { 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00 }, nonce,
                "a client request nonce is the message id followed by four zero bytes");
    }

    @Test
    @DisplayName("a response nonce sets the least significant bit of the trailing four bytes")
    void responseNonce() {
        final byte[] buf =
                header(0x0102030405060708L, ServerMessageBlock2.SMB2_FLAGS_SERVER_TO_REDIR, ServerMessageBlock2.SMB2_QUERY_DIRECTORY);

        final byte[] nonce = Smb2SigningDigest.gmacNonce(buf, 0);

        // "If the sender is a client, least significant bit is set to zero, otherwise set to 1." The bit is read
        // from the message's own flags, which is what lets the same code verify an incoming response.
        assertArrayEquals(new byte[] { 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00 }, nonce,
                "a response nonce sets bit 0 of the byte at offset 8");
    }

    @Test
    @DisplayName("a CANCEL request sets the penultimate bit, and only for CANCEL")
    void cancelNonce() {
        final byte[] cancel = header(0x1122334455667788L, 0, ServerMessageBlock2.SMB2_CANCEL);

        assertArrayEquals(new byte[] { (byte) 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x02, 0x00, 0x00, 0x00 },
                Smb2SigningDigest.gmacNonce(cancel, 0), "a CANCEL request sets bit 1 of the byte at offset 8");

        // Every other command must leave that bit clear, or the nonce for ordinary traffic is wrong.
        final byte[] echo = header(0x1122334455667788L, 0, ServerMessageBlock2.SMB2_ECHO);
        assertEquals(0, Smb2SigningDigest.gmacNonce(echo, 0)[8], "a non-CANCEL client request has no bits set at offset 8");
    }

    @Test
    @DisplayName("a CANCEL response sets both bits")
    void cancelResponseNonce() {
        final byte[] buf = header(0x00000000000000FFL, ServerMessageBlock2.SMB2_FLAGS_SERVER_TO_REDIR, ServerMessageBlock2.SMB2_CANCEL);

        // The two bits are independent, so the combination has to be checked as well: taking one as implying the
        // absence of the other would pass with an implementation that treated them as a single enum.
        assertEquals(0x03, Smb2SigningDigest.gmacNonce(buf, 0)[8], "a CANCEL response sets both bit 0 and bit 1");
    }

    @Test
    @DisplayName("the nonce is read from the message's own header, at whatever offset it sits")
    void nonceHonoursTheBufferOffset() {
        // Messages are signed in place inside a larger send buffer - ServerMessageBlock2 passes headerStart - so
        // reading the header from index zero would produce the wrong nonce for every compounded message after the
        // first, while the first one still verified.
        final byte[] framed = new byte[Smb2Constants.SMB2_HEADER_LENGTH + 96];
        final int off = 80;
        SMBUtil.writeInt2(ServerMessageBlock2.SMB2_READ, framed, off + COMMAND_OFFSET);
        SMBUtil.writeInt4(0, framed, off + FLAGS_OFFSET);
        SMBUtil.writeInt8(0x7766554433221100L, framed, off + MID_OFFSET);

        assertArrayEquals(new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0x00, 0x00, 0x00 },
                Smb2SigningDigest.gmacNonce(framed, off), "the nonce must come from the header at the given offset");
    }

    @Test
    @DisplayName("the remaining 30 bits are zero even when the header carries other flags")
    void unrelatedFlagsDoNotLeakIntoTheNonce() {
        // Only the direction bit and the CANCEL marker belong in the nonce. SIGNED is set on every signed message
        // and RELATED_OPERATIONS on every chained one, so leaking the flags word wholesale would corrupt the nonce
        // for ordinary traffic - and would do it in a way that still round trips against another jcifs client.
        final int noisy = ServerMessageBlock2.SMB2_FLAGS_SIGNED | ServerMessageBlock2.SMB2_FLAGS_RELATED_OPERATIONS
                | ServerMessageBlock2.SMB2_FLAGS_DFS_OPERATIONS | ServerMessageBlock2.SMB2_FLAGS_ASYNC_COMMAND;
        final byte[] buf = header(1L, noisy, ServerMessageBlock2.SMB2_CREATE);

        final byte[] nonce = Smb2SigningDigest.gmacNonce(buf, 0);
        assertEquals(0, nonce[8], "no unrelated flag may appear at offset 8");
        assertEquals(0, nonce[9], "byte 9 is reserved and must be zero");
        assertEquals(0, nonce[10], "byte 10 is reserved and must be zero");
        assertEquals(0, nonce[11], "byte 11 is reserved and must be zero");
    }
}
