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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
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
 * Tests for the {@link SmbComOpenAndXResponse} class.
 *
 * <p>
 * The parameter words of an SMB_COM_OPEN_ANDX response occupy 26 bytes once the four AndX bytes
 * have been consumed: FID(2), FileAttrs(2), LastWriteTime(4), FileDataSize(4), AccessRights(2),
 * ResourceType(2), NMPipeStatus(2), OpenResults(2) and six reserved bytes, of which the class reads
 * the first four back as the server FID.
 * </p>
 */
public class SmbComOpenAndXResponseTest {

    /** Size of the parameter words that {@link SmbComOpenAndXResponse} decodes. */
    private static final int PARAMETER_WORDS_SIZE = 26;

    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        this.config = new PropertyConfiguration(new Properties());
    }

    private static byte[] parameterWords(final int offset, final int fid, final int fileAttributes, final long lastWriteTimeSeconds,
            final long fileDataSize, final int grantedAccess, final int fileType, final int deviceState, final int action,
            final long serverFid) {
        final byte[] buffer = new byte[offset + PARAMETER_WORDS_SIZE + 4];
        SMBUtil.writeInt2(fid, buffer, offset);
        SMBUtil.writeInt2(fileAttributes, buffer, offset + 2);
        SMBUtil.writeInt4(lastWriteTimeSeconds, buffer, offset + 4);
        SMBUtil.writeInt4(fileDataSize, buffer, offset + 8);
        SMBUtil.writeInt2(grantedAccess, buffer, offset + 12);
        SMBUtil.writeInt2(fileType, buffer, offset + 14);
        SMBUtil.writeInt2(deviceState, buffer, offset + 16);
        SMBUtil.writeInt2(action, buffer, offset + 18);
        SMBUtil.writeInt4(serverFid, buffer, offset + 20);
        return buffer;
    }

    @Test
    @DisplayName("A response accepts the open AndX command code")
    public void shouldCarryTheOpenAndXCommand() {
        final SmbComOpenAndXResponse response = new SmbComOpenAndXResponse(this.config);

        assertEquals(0, response.getCommand(), "a bare response has no command until it is decoded");

        response.setCommand(ServerMessageBlock.SMB_COM_OPEN_ANDX);
        assertEquals(ServerMessageBlock.SMB_COM_OPEN_ANDX, response.getCommand());
    }

    @Test
    @DisplayName("A chained seek response is retained as the AndX of the response")
    public void shouldRetainTheChainedSeekResponse() {
        final SmbComSeekResponse andx = new SmbComSeekResponse(this.config);

        assertSame(andx, new SmbComOpenAndXResponse(this.config, andx).getAndx());
    }

    @Test
    @DisplayName("Every documented parameter word field is decoded from its own offset")
    public void shouldDecodeAllParameterWords() {
        final byte[] buffer = parameterWords(3, 0x1234, SmbConstants.ATTR_ARCHIVE, 1_600_000_000L, 0x0000_1000L, 0x0002, 0x0000, 0x0007,
                0x0001, 0x00AB_CDEF);

        final SmbComOpenAndXResponse response = new SmbComOpenAndXResponse(this.config);
        assertEquals(PARAMETER_WORDS_SIZE, response.readParameterWordsWireFormat(buffer, 3));

        assertEquals(0x1234, response.getFid());
        assertEquals(SmbConstants.ATTR_ARCHIVE, response.getFileAttributes());
        assertEquals(1_600_000_000_000L, response.getLastWriteTime(), "LastWriteTime is a UTime in whole seconds");
        assertEquals(0x1000, response.getDataSize());
        assertEquals(0x0002, response.getGrantedAccess());
        assertEquals(0x0000, response.getFileType());
        assertEquals(0x0007, response.getDeviceState());
        assertEquals(0x0001, response.getAction());
        assertEquals(0x00AB_CDEF, response.getServerFid());
    }

    @Test
    @DisplayName("The SmbBasicFileInfo view reports the data size and has no create or access time")
    public void shouldExposeTheBasicFileInfoView() {
        final byte[] buffer = parameterWords(0, 1, SmbConstants.ATTR_NORMAL, 1_000_000L, 4096L, 0, 0, 0, 1, 0);

        final SmbComOpenAndXResponse response = new SmbComOpenAndXResponse(this.config);
        response.readParameterWordsWireFormat(buffer, 0);

        assertEquals(response.getFileAttributes(), response.getAttributes());
        assertEquals(4096L, response.getSize());
        assertEquals(0L, response.getCreateTime(), "SMB_COM_OPEN_ANDX carries no creation time");
        assertEquals(0L, response.getLastAccessTime(), "SMB_COM_OPEN_ANDX carries no last access time");
    }

    @Test
    @DisplayName("An all zero parameter word block decodes to zeroes and still consumes 26 bytes")
    public void shouldDecodeZeroes() {
        final SmbComOpenAndXResponse response = new SmbComOpenAndXResponse(this.config);

        assertEquals(PARAMETER_WORDS_SIZE, response.readParameterWordsWireFormat(new byte[PARAMETER_WORDS_SIZE], 0));

        assertEquals(0, response.getFid());
        assertEquals(0L, response.getLastWriteTime());
        assertEquals(0, response.getDataSize());
        assertEquals(0, response.getServerFid());
    }

    @Test
    @DisplayName("The widest int2 fields decode to their full unsigned range")
    public void shouldDecodeMaximumInt2Fields() {
        final byte[] buffer = parameterWords(0, 0xFFFF, 0xFFFF, 0L, 0L, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0L);

        final SmbComOpenAndXResponse response = new SmbComOpenAndXResponse(this.config);
        assertEquals(PARAMETER_WORDS_SIZE, response.readParameterWordsWireFormat(buffer, 0));

        assertEquals(0xFFFF, response.getFid());
        assertEquals(0xFFFF, response.getFileAttributes());
        assertEquals(0xFFFF, response.getGrantedAccess());
        assertEquals(0xFFFF, response.getFileType());
        assertEquals(0xFFFF, response.getDeviceState());
        assertEquals(0xFFFF, response.getAction());
    }

    @Test
    @DisplayName("A LastWriteTime that needs the top bit of the UTime field is not read as a negative time")
    public void shouldDecodeAnUnsignedLastWriteTime() {
        final long seconds = 3_000_000_000L; // beyond Integer.MAX_VALUE, still a valid unsigned UTime
        final byte[] buffer = parameterWords(0, 1, 0, seconds, 0L, 0, 0, 0, 0, 0L);

        final SmbComOpenAndXResponse response = new SmbComOpenAndXResponse(this.config);
        response.readParameterWordsWireFormat(buffer, 0);

        assertEquals(seconds * 1000L, response.getLastWriteTime());
    }

    @Test
    @DisplayName("A data size that fills the unsigned 32 bit field is reported as a positive size")
    public void shouldDecodeAnUnsignedDataSize() {
        final byte[] buffer = parameterWords(0, 1, 0, 0L, 0xFFFF_FFFFL, 0, 0, 0, 0, 0L);

        final SmbComOpenAndXResponse response = new SmbComOpenAndXResponse(this.config);
        response.readParameterWordsWireFormat(buffer, 0);

        assertEquals(0xFFFF_FFFFL, response.getSize(), "FileDataSize is an unsigned 32 bit field");
    }

    @Test
    @DisplayName("A response never encodes anything and consumes no data bytes")
    public void shouldNotEncodeAnything() {
        final SmbComOpenAndXResponse response = new SmbComOpenAndXResponse(this.config);
        final byte[] dst = new byte[16];

        assertEquals(0, response.writeParameterWordsWireFormat(dst, 0));
        assertEquals(0, response.writeBytesWireFormat(dst, 0));
        assertEquals(0, response.readBytesWireFormat(new byte[16], 0));
        assertArrayEquals(new byte[16], dst);
    }

    @Test
    @DisplayName("toString names the message and does not throw")
    public void shouldRenderToString() {
        final byte[] buffer = parameterWords(0, 9, SmbConstants.ATTR_NORMAL, 1_600_000_000L, 128L, 2, 0, 0, 1, 0L);
        final SmbComOpenAndXResponse response = new SmbComOpenAndXResponse(this.config);
        response.readParameterWordsWireFormat(buffer, 0);

        final String rendered = response.toString();

        assertNotNull(rendered);
        assertTrue(rendered.startsWith("SmbComOpenAndXResponse["), rendered);
        assertTrue(rendered.contains("fid=9"), rendered);
        assertTrue(rendered.contains("dataSize=128"), rendered);
        assertTrue(rendered.endsWith("]"), rendered);
    }
}
