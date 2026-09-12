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
package org.codelibs.jcifs.smb.internal.smb2.lock;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.util.Arrays;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateRequest;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The acknowledgement a client sends for an oplock break, MS-SMB2 2.2.24.1, and the reply it draws, 2.2.25.1. Both
 * are 24 byte bodies on the SMB2_OPLOCK_BREAK command, which is also how the break notification itself arrives - the
 * three are told apart by direction and structure size.
 */
class Smb2OplockBreakAcknowledgmentTest {

    private static final int SMB2_OPLOCK_BREAK = 0x12;

    private static final byte[] FILE_ID =
            { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27 };

    private final Configuration config = mock(Configuration.class);

    @Test
    @DisplayName("writes the 24 byte acknowledgement body of MS-SMB2 2.2.24.1")
    void testWireFormat() {
        final Smb2OplockBreakAcknowledgment ack = new Smb2OplockBreakAcknowledgment(this.config, FILE_ID, (byte) 0x00);
        final byte[] buffer = new byte[128];

        final int written = ack.writeBytesWireFormat(buffer, 0);

        assertEquals(24, written, "the acknowledgement body is 24 bytes");
        assertEquals(24, SMBUtil.readInt2(buffer, 0), "StructureSize");
        assertEquals(0x00, buffer[2], "OplockLevel");
        assertEquals(0, buffer[3], "Reserved");
        assertEquals(0, SMBUtil.readInt4(buffer, 4), "Reserved2");
        assertArrayEquals(FILE_ID, Arrays.copyOfRange(buffer, 8, 24), "FileId");
    }

    @Test
    @DisplayName("writes the acknowledgement at an offset without disturbing what is before it")
    void testWireFormatAtOffset() {
        final Smb2OplockBreakAcknowledgment ack = new Smb2OplockBreakAcknowledgment(this.config, FILE_ID, (byte) 0x01);
        final byte[] buffer = new byte[128];
        Arrays.fill(buffer, 0, 16, (byte) 0xEE);

        assertEquals(24, ack.writeBytesWireFormat(buffer, 16));

        assertEquals(24, SMBUtil.readInt2(buffer, 16), "StructureSize");
        assertEquals(0x01, buffer[18], "OplockLevel");
        assertArrayEquals(FILE_ID, Arrays.copyOfRange(buffer, 24, 40), "FileId");
        for (int i = 0; i < 16; i++) {
            assertEquals((byte) 0xEE, buffer[i], "byte " + i + " before the body was overwritten");
        }
    }

    @Test
    @DisplayName("is sent as SMB2_OPLOCK_BREAK and sized to header plus body")
    void testCommandAndSize() {
        final Smb2OplockBreakAcknowledgment ack = new Smb2OplockBreakAcknowledgment(this.config, FILE_ID, (byte) 0x00);

        assertEquals(SMB2_OPLOCK_BREAK, ack.getCommand(), "acknowledgements share the break command");
        assertEquals(Smb2Constants.SMB2_HEADER_LENGTH + 24, ack.size());
    }

    @Test
    @DisplayName("reads the 24 byte reply of MS-SMB2 2.2.25.1")
    void testResponseWireFormat() throws Exception {
        final Smb2OplockBreakResponse response = new Smb2OplockBreakResponse(this.config);
        final byte[] buffer = new byte[64];
        SMBUtil.writeInt2(24, buffer, 0);
        buffer[2] = 0x01;
        System.arraycopy(FILE_ID, 0, buffer, 8, 16);

        assertEquals(24, response.readBytesWireFormat(buffer, 0));

        assertEquals((byte) 0x01, response.getOplockLevel());
        assertArrayEquals(FILE_ID, response.getFileId());
    }

    @Test
    @DisplayName("a break from level II to none is not acknowledged")
    void testLevelTwoToNoneNeedsNoAcknowledgement() {
        // MS-SMB2 2.2.24.1: "A break from level II MUST transition to none. Thus, the client does not send a request
        // to the server because there is no question how the transition was made." Answering anyway is refused -
        // Samba does not arm its acknowledgement timer for a level II break and returns
        // STATUS_INVALID_OPLOCK_PROTOCOL.
        assertFalse(
                Smb2OplockBreakAcknowledgment.isRequired(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_II, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_NONE));
    }

    @Test
    @DisplayName("a break of an exclusive or batch oplock is acknowledged")
    void testExclusiveAndBatchBreaksAreAcknowledged() {
        assertTrue(Smb2OplockBreakAcknowledgment.isRequired(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_EXCLUSIVE,
                Smb2CreateRequest.SMB2_OPLOCK_LEVEL_II));
        assertTrue(Smb2OplockBreakAcknowledgment.isRequired(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_EXCLUSIVE,
                Smb2CreateRequest.SMB2_OPLOCK_LEVEL_NONE));
        assertTrue(Smb2OplockBreakAcknowledgment.isRequired(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH,
                Smb2CreateRequest.SMB2_OPLOCK_LEVEL_II));
        assertTrue(Smb2OplockBreakAcknowledgment.isRequired(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH,
                Smb2CreateRequest.SMB2_OPLOCK_LEVEL_NONE));
    }

    @Test
    @DisplayName("a break that does not lower the level is not acknowledged")
    void testUnchangedLevelNeedsNoAcknowledgement() {
        // Not a break at all. Answering it would echo a level 2.2.24.1 does not allow - only none and level II are
        // legal in an acknowledgement - and Samba rejects anything else outright.
        assertFalse(Smb2OplockBreakAcknowledgment.isRequired(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH,
                Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH));
        assertFalse(
                Smb2OplockBreakAcknowledgment.isRequired(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_II, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_II));
    }

    @Test
    @DisplayName("a break of an open that holds no oplock is not acknowledged")
    void testNoOplockHeldNeedsNoAcknowledgement() {
        // jcifs asks for no oplock on every create, so this is what a stray notification would find. 3.2.5.19.1 has
        // the client stop processing rather than answer.
        assertFalse(Smb2OplockBreakAcknowledgment.isRequired(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_NONE,
                Smb2CreateRequest.SMB2_OPLOCK_LEVEL_NONE));
        assertFalse(
                Smb2OplockBreakAcknowledgment.isRequired(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_NONE, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_II));
    }

    @Test
    @DisplayName("rejects a reply that is not 24 bytes")
    void testResponseRejectsOtherSizes() {
        final Smb2OplockBreakResponse response = new Smb2OplockBreakResponse(this.config);
        final byte[] buffer = new byte[64];
        SMBUtil.writeInt2(44, buffer, 0);

        final SMBProtocolDecodingException exception =
                assertThrows(SMBProtocolDecodingException.class, () -> response.readBytesWireFormat(buffer, 0));

        assertEquals("Expected structureSize = 24", exception.getMessage());
    }
}
