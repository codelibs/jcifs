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
package org.codelibs.jcifs.smb.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link SmbComNTCreateAndXResponse} class.
 *
 * <p>
 * The parameter words of an SMB_COM_NT_CREATE_ANDX response occupy 64 bytes once the four AndX
 * bytes have been consumed: OpLockLevel(1), FID(2), CreateAction(4), CreationTime(8),
 * LastAccessTime(8), LastWriteTime(8), LastChangeTime(8), ExtFileAttributes(4), AllocationSize(8),
 * EndOfFile(8), ResourceType(2), NMPipeStatus(2), Directory(1).
 * </p>
 */
public class SmbComNTCreateAndXResponseTest {

    /** Size of the parameter words that {@link SmbComNTCreateAndXResponse} decodes. */
    private static final int PARAMETER_WORDS_SIZE = 64;

    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        this.config = new PropertyConfiguration(new Properties());
    }

    /**
     * Lays out one set of parameter words at {@code offset} in a freshly allocated buffer.
     */
    private static byte[] parameterWords(final int offset, final byte oplockLevel, final int fid, final int createAction,
            final long creationTime, final long lastAccessTime, final long lastWriteTime, final long changeTime, final int attributes,
            final long allocationSize, final long endOfFile, final int fileType, final int deviceState, final boolean directory) {
        final byte[] buffer = new byte[offset + PARAMETER_WORDS_SIZE + 8];
        buffer[offset] = oplockLevel;
        SMBUtil.writeInt2(fid, buffer, offset + 1);
        SMBUtil.writeInt4(createAction, buffer, offset + 3);
        SMBUtil.writeTime(creationTime, buffer, offset + 7);
        SMBUtil.writeTime(lastAccessTime, buffer, offset + 15);
        SMBUtil.writeTime(lastWriteTime, buffer, offset + 23);
        SMBUtil.writeTime(changeTime, buffer, offset + 31);
        SMBUtil.writeInt4(attributes, buffer, offset + 39);
        SMBUtil.writeInt8(allocationSize, buffer, offset + 43);
        SMBUtil.writeInt8(endOfFile, buffer, offset + 51);
        SMBUtil.writeInt2(fileType, buffer, offset + 59);
        SMBUtil.writeInt2(deviceState, buffer, offset + 61);
        buffer[offset + 63] = directory ? (byte) 0x01 : (byte) 0x00;
        return buffer;
    }

    @Test
    @DisplayName("A response accepts the NT create AndX command code")
    public void shouldCarryTheNtCreateAndXCommand() {
        final SmbComNTCreateAndXResponse response = new SmbComNTCreateAndXResponse(this.config);

        assertEquals(0, response.getCommand(), "a bare response has no command until it is decoded");

        response.setCommand(ServerMessageBlock.SMB_COM_NT_CREATE_ANDX);
        assertEquals(ServerMessageBlock.SMB_COM_NT_CREATE_ANDX, response.getCommand());
    }

    @Test
    @DisplayName("Every documented parameter word field is decoded from its own offset")
    public void shouldDecodeAllParameterWords() {
        final long creationTime = 1_600_000_000_000L;
        final long lastAccessTime = 1_600_000_001_000L;
        final long lastWriteTime = 1_600_000_002_000L;
        final long changeTime = 1_600_000_003_000L;
        final byte[] buffer = parameterWords(5, (byte) SmbComNTCreateAndXResponse.BATCH_OPLOCK_GRANTED, 0x1234, 2, creationTime,
                lastAccessTime, lastWriteTime, changeTime, SmbConstants.ATTR_NORMAL, 0x0000_1000L, 0x0000_0ABCL, 1, 0x0007, true);

        final SmbComNTCreateAndXResponse response = new SmbComNTCreateAndXResponse(this.config);
        assertEquals(PARAMETER_WORDS_SIZE, response.readParameterWordsWireFormat(buffer, 5));

        assertEquals(SmbComNTCreateAndXResponse.BATCH_OPLOCK_GRANTED, response.getOplockLevel());
        assertEquals(0x1234, response.getFid());
        assertEquals(2, response.getCreateAction());
        assertEquals(creationTime, response.getCreationTime());
        assertEquals(lastAccessTime, response.getLastAccessTime());
        assertEquals(lastWriteTime, response.getLastWriteTime());
        assertEquals(SmbConstants.ATTR_NORMAL, response.getExtFileAttributes());
        assertEquals(0x0000_1000L, response.getAllocationSize());
        assertEquals(0x0000_0ABCL, response.getEndOfFile());
        assertEquals(1, response.getFileType());
        assertEquals(0x0007, response.getDeviceState());
        assertTrue(response.toString().contains("directory=true"));
    }

    @Test
    @DisplayName("The SmbBasicFileInfo view delegates to the decoded fields")
    public void shouldExposeTheBasicFileInfoView() {
        final long lastWriteTime = 1_700_000_000_000L;
        final byte[] buffer = parameterWords(0, (byte) 0, 1, 1, 1_500_000_000_000L, 1_600_000_000_000L, lastWriteTime, lastWriteTime,
                SmbConstants.ATTR_READONLY, 4096L, 1234L, 0, 0, false);

        final SmbComNTCreateAndXResponse response = new SmbComNTCreateAndXResponse(this.config);
        response.readParameterWordsWireFormat(buffer, 0);

        assertEquals(response.getExtFileAttributes(), response.getAttributes());
        assertEquals(response.getCreationTime(), response.getCreateTime());
        assertEquals(response.getEndOfFile(), response.getSize());
        assertEquals(lastWriteTime, response.getLastWriteTime());
    }

    @Test
    @DisplayName("A file size that needs the high half of the 64 bit field survives decoding")
    public void shouldDecodeSizesLargerThanFourGigabytes() {
        final long allocationSize = 0x0000_000A_1234_5678L;
        final long endOfFile = 0x0000_0003_9ABC_DEF0L;
        final byte[] buffer = parameterWords(0, (byte) 0, 0, 1, 1L, 1L, 1L, 1L, 0, allocationSize, endOfFile, 0, 0, false);

        final SmbComNTCreateAndXResponse response = new SmbComNTCreateAndXResponse(this.config);
        assertEquals(PARAMETER_WORDS_SIZE, response.readParameterWordsWireFormat(buffer, 0));

        assertEquals(allocationSize, response.getAllocationSize());
        assertEquals(endOfFile, response.getEndOfFile());
        assertEquals(endOfFile, response.getSize());
    }

    @Test
    @DisplayName("The widest int2 and int4 fields decode to their full range")
    public void shouldDecodeMaximumIntegerFields() {
        final byte[] buffer = new byte[PARAMETER_WORDS_SIZE];
        SMBUtil.writeInt2(0xFFFF, buffer, 1);
        SMBUtil.writeInt4(0xFFFF_FFFFL, buffer, 3);
        SMBUtil.writeInt4(0xFFFF_FFFFL, buffer, 39);
        SMBUtil.writeInt8(-1L, buffer, 43);
        SMBUtil.writeInt8(-1L, buffer, 51);
        SMBUtil.writeInt2(0xFFFF, buffer, 59);
        SMBUtil.writeInt2(0xFFFF, buffer, 61);
        buffer[63] = (byte) 0xFF;

        final SmbComNTCreateAndXResponse response = new SmbComNTCreateAndXResponse(this.config);
        assertEquals(PARAMETER_WORDS_SIZE, response.readParameterWordsWireFormat(buffer, 0));

        assertEquals(0xFFFF, response.getFid(), "the FID is an unsigned 16 bit field");
        assertEquals(0xFFFF, response.getFileType());
        assertEquals(0xFFFF, response.getDeviceState());
        assertEquals(-1, response.getCreateAction(), "int4 fields are read into a signed int");
        assertEquals(-1, response.getExtFileAttributes());
        assertEquals(-1L, response.getAllocationSize());
        assertTrue(response.toString().contains("directory=true"), "any non zero directory byte means a directory");
    }

    @Test
    @DisplayName("An all zero FILETIME decodes to the 1601 epoch expressed in Java time")
    public void shouldDecodeZeroFileTimes() {
        final byte[] buffer = new byte[PARAMETER_WORDS_SIZE];

        final SmbComNTCreateAndXResponse response = new SmbComNTCreateAndXResponse(this.config);
        assertEquals(PARAMETER_WORDS_SIZE, response.readParameterWordsWireFormat(buffer, 0));

        assertEquals(-SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601, response.getCreationTime());
        assertEquals(-SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601, response.getLastAccessTime());
        assertEquals(-SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601, response.getLastWriteTime());
        assertEquals(0, response.getFid());
        assertEquals(0L, response.getEndOfFile());
    }

    @Test
    @DisplayName("The extended flag is a plain accessor that starts out clear")
    public void shouldTrackTheExtendedFlag() {
        final SmbComNTCreateAndXResponse response = new SmbComNTCreateAndXResponse(this.config);

        assertFalse(response.isExtended());
        response.setExtended(true);
        assertTrue(response.isExtended());
    }

    @Test
    @DisplayName("A response never encodes anything and consumes no data bytes")
    public void shouldNotEncodeAnything() {
        final SmbComNTCreateAndXResponse response = new SmbComNTCreateAndXResponse(this.config);
        final byte[] dst = new byte[16];

        assertEquals(0, response.writeParameterWordsWireFormat(dst, 0));
        assertEquals(0, response.writeBytesWireFormat(dst, 0));
        assertEquals(0, response.readBytesWireFormat(new byte[16], 0));
        assertArrayEquals(new byte[16], dst);
    }

    @Test
    @DisplayName("toString names the message and does not throw")
    public void shouldRenderToString() {
        final byte[] buffer = parameterWords(0, (byte) 1, 7, 1, 1_600_000_000_000L, 1_600_000_000_000L, 1_600_000_000_000L,
                1_600_000_000_000L, SmbConstants.ATTR_ARCHIVE, 1024L, 512L, 0, 0, false);
        final SmbComNTCreateAndXResponse response = new SmbComNTCreateAndXResponse(this.config);
        response.readParameterWordsWireFormat(buffer, 0);

        final String rendered = response.toString();

        assertNotNull(rendered);
        assertTrue(rendered.startsWith("SmbComNTCreateAndXResponse["), rendered);
        assertTrue(rendered.contains("fid=7"), rendered);
        assertTrue(rendered.contains("endOfFile=512"), rendered);
        assertTrue(rendered.endsWith("]"), rendered);
    }
}
