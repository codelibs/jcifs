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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
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
 * Tests for the {@link SmbComSetInformation} class.
 *
 * <p>
 * The parameter words of an SMB_COM_SET_INFORMATION request are FileAttributes(2),
 * LastWriteTime(4) and ten reserved bytes, sixteen in total. The data bytes are the 0x04 buffer
 * format byte followed by the NUL terminated file name.
 * </p>
 */
public class SmbComSetInformationTest {

    /** Size of the parameter words that {@link SmbComSetInformation} encodes. */
    private static final int PARAMETER_WORDS_SIZE = 16;

    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        this.config = new PropertyConfiguration(new Properties());
    }

    @Test
    @DisplayName("The command is SMB_COM_SET_INFORMATION")
    public void shouldUseSetInformationCommand() {
        assertEquals(ServerMessageBlock.SMB_COM_SET_INFORMATION, new SmbComSetInformation(this.config, "\\file.txt", 0, 0L).getCommand());
    }

    @Test
    @DisplayName("The file name passed to the constructor becomes the path of the request")
    public void shouldKeepTheFileNameAsPath() {
        assertEquals("\\dir\\file.txt", new SmbComSetInformation(this.config, "\\dir\\file.txt", 0, 0L).getPath());
    }

    @Test
    @DisplayName("The attributes and the last write time sit at their documented offsets")
    public void shouldWriteAllParameterWords() {
        final SmbComSetInformation request =
                new SmbComSetInformation(this.config, "\\file.txt", SmbConstants.ATTR_READONLY, 1_600_000_000_000L);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(SmbConstants.ATTR_READONLY, SMBUtil.readInt2(dst, 0));
        assertEquals(1_600_000_000, SMBUtil.readInt4(dst, 2), "LastWriteTime is a UTime in whole seconds");
        assertEquals(1_600_000_000_000L, SMBUtil.readUTime(dst, 2));
    }

    @Test
    @DisplayName("A zero modification time and zero attributes write sixteen zero bytes")
    public void shouldWriteZeroes() {
        final SmbComSetInformation request = new SmbComSetInformation(this.config, "\\file.txt", 0, 0L);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));
        assertArrayEquals(new byte[PARAMETER_WORDS_SIZE], dst);
    }

    @Test
    @DisplayName("The widest attributes fill the two byte field")
    public void shouldWriteMaximumAttributes() {
        final SmbComSetInformation request = new SmbComSetInformation(this.config, "\\file.txt", 0xFFFF, 0L);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        request.writeParameterWordsWireFormat(dst, 0);

        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 0));
    }

    @Test
    @DisplayName("A modification time past 2038 still fits the unsigned UTime field")
    public void shouldWriteATimeBeyondTheSignedRange() {
        final long mtime = 3_000_000_000_000L; // 3e9 seconds, past Integer.MAX_VALUE but inside an unsigned int
        final SmbComSetInformation request = new SmbComSetInformation(this.config, "\\file.txt", 0, mtime);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        request.writeParameterWordsWireFormat(dst, 0);

        assertEquals(mtime, SMBUtil.readUTime(dst, 2));
    }

    @Test
    @DisplayName("The ten reserved bytes are skipped rather than written")
    public void shouldLeaveTheReservedBytesUntouched() {
        // The transport hands in a buffer that BufferCacheImpl.releaseBuffer has already zeroed, so
        // skipping the reserved bytes still puts zeroes on the wire.
        final SmbComSetInformation request = new SmbComSetInformation(this.config, "\\file.txt", 0, 0L);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];
        Arrays.fill(dst, (byte) 0xEE);

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));

        final byte[] reserved = new byte[10];
        Arrays.fill(reserved, (byte) 0xEE);
        assertArrayEquals(reserved, Arrays.copyOfRange(dst, 6, 16));
    }

    @Test
    @DisplayName("The parameter words are written at the requested offset")
    public void shouldHonourTheWriteOffset() {
        final SmbComSetInformation request = new SmbComSetInformation(this.config, "\\file.txt", SmbConstants.ATTR_ARCHIVE, 1_000L);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE + 8];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 4));

        assertArrayEquals(new byte[4], Arrays.copyOfRange(dst, 0, 4), "nothing before the offset may be touched");
        assertEquals(SmbConstants.ATTR_ARCHIVE, SMBUtil.readInt2(dst, 4));
        assertEquals(1, SMBUtil.readInt4(dst, 6));
    }

    @Test
    @DisplayName("An OEM file name follows the 0x04 buffer format byte")
    public void shouldWriteAnOemFileName() {
        final SmbComSetInformation request = new SmbComSetInformation(this.config, "\\file.txt", 0, 0L);
        request.setUseUnicode(false);
        final byte[] dst = new byte[32];

        final int written = request.writeBytesWireFormat(dst, 0);

        assertEquals(1 + "\\file.txt".length() + 1, written);
        assertEquals(0x04, dst[0]);
        assertEquals("\\file.txt", new String(dst, 1, "\\file.txt".length(), StandardCharsets.US_ASCII));
        assertEquals(0x00, dst[1 + "\\file.txt".length()]);
    }

    @Test
    @DisplayName("A Unicode file name is word aligned after the buffer format byte")
    public void shouldWriteAUnicodeFileName() {
        final SmbComSetInformation request = new SmbComSetInformation(this.config, "AB", 0, 0L);
        request.setUseUnicode(true);
        final byte[] dst = new byte[32];

        final int written = request.writeBytesWireFormat(dst, 0);

        // buffer format byte, word alignment byte, "AB" in UTF-16LE, two byte terminator
        assertEquals(8, written);
        assertArrayEquals(new byte[] { 0x04, 0x00, 'A', 0x00, 'B', 0x00, 0x00, 0x00 }, Arrays.copyOfRange(dst, 0, 8));
    }

    @Test
    @DisplayName("A request never decodes anything")
    public void shouldReadNothing() {
        final SmbComSetInformation request = new SmbComSetInformation(this.config, "\\file.txt", 0, 0L);

        assertEquals(0, request.readParameterWordsWireFormat(new byte[32], 0));
        assertEquals(0, request.readBytesWireFormat(new byte[32], 0));
    }

    @Test
    @DisplayName("toString names the message and does not throw")
    public void shouldRenderToString() {
        final String rendered = new SmbComSetInformation(this.config, "\\file.txt", SmbConstants.ATTR_READONLY, 1234L).toString();

        assertNotNull(rendered);
        assertTrue(rendered.startsWith("SmbComSetInformation["), rendered);
        assertTrue(rendered.contains("filename=\\file.txt"), rendered);
        assertTrue(rendered.contains("fileAttributes=" + SmbConstants.ATTR_READONLY), rendered);
        assertTrue(rendered.contains("lastWriteTime=1234"), rendered);
        assertTrue(rendered.endsWith("]"), rendered);
    }
}
