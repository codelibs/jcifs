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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.smb1.SMB1SigningDigest;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * Tests for the {@link SmbComWrite} class.
 *
 * <p>
 * The parameter words of an SMB_COM_WRITE request are FID(2), CountOfBytesToWrite(2),
 * WriteOffsetInBytes(4) and EstimateOfRemainingBytesToBeWritten(2), ten bytes in total. The data
 * bytes are the 0x01 buffer format byte, a two byte data length and the payload.
 * </p>
 */
public class SmbComWriteTest {

    /** Size of the parameter words that {@link SmbComWrite} encodes. */
    private static final int PARAMETER_WORDS_SIZE = 10;

    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        this.config = new PropertyConfiguration(new Properties());
    }

    @Test
    @DisplayName("The command is SMB_COM_WRITE")
    public void shouldUseWriteCommand() {
        assertEquals(ServerMessageBlock.SMB_COM_WRITE, new SmbComWrite(this.config).getCommand());
        assertEquals(ServerMessageBlock.SMB_COM_WRITE, new SmbComWrite(this.config, 1, 0, 0, new byte[1], 0, 1).getCommand());
    }

    @Test
    @DisplayName("Every parameter word sits at its documented offset")
    public void shouldWriteAllParameterWords() {
        final SmbComWrite request = new SmbComWrite(this.config, 0x1234, 0x0000_1000, 0x0040, new byte[8], 0, 8);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0x1234, SMBUtil.readInt2(dst, 0));
        assertEquals(8, SMBUtil.readInt2(dst, 2), "the count is the length handed to the constructor");
        assertEquals(0x0000_1000, SMBUtil.readInt4(dst, 4));
        assertEquals(0x0040, SMBUtil.readInt2(dst, 8));
    }

    @Test
    @DisplayName("A zero valued request writes ten zero bytes")
    public void shouldWriteZeroes() {
        final SmbComWrite request = new SmbComWrite(this.config, 0, 0, 0, new byte[0], 0, 0);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));
        assertArrayEquals(new byte[PARAMETER_WORDS_SIZE], dst);
    }

    @Test
    @DisplayName("The widest FID, count and remaining fill their two byte fields")
    public void shouldWriteMaximumValues() {
        final SmbComWrite request = new SmbComWrite(this.config, 0xFFFF, 0, 0xFFFF, new byte[1], 0, 0xFFFF);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        request.writeParameterWordsWireFormat(dst, 0);

        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 0));
        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 2));
        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 8));
    }

    @Test
    @DisplayName("setParam truncates the offset to the 32 bits the wire format has room for")
    public void shouldTruncateTheOffsetInSetParam() {
        final SmbComWrite request = new SmbComWrite(this.config);
        request.setParam(0x0ABC, 0x0000_000A_1234_5678L, 0x0010, new byte[4], 0, 4);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0x0ABC, SMBUtil.readInt2(dst, 0));
        assertEquals(4, SMBUtil.readInt2(dst, 2));
        assertEquals(0x1234_5678, SMBUtil.readInt4(dst, 4), "SMB_COM_WRITE has no high offset field");
        assertEquals(0x0010, SMBUtil.readInt2(dst, 8));
    }

    @Test
    @DisplayName("An offset that fills the unsigned 32 bit field round trips through the int field")
    public void shouldWriteAnOffsetThatFillsTheField() {
        final SmbComWrite request = new SmbComWrite(this.config);
        request.setParam(1, 0xFFFF_FFFFL, 0, new byte[1], 0, 1);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        request.writeParameterWordsWireFormat(dst, 0);

        final byte[] expected = new byte[4];
        Arrays.fill(expected, (byte) 0xFF);
        assertArrayEquals(expected, Arrays.copyOfRange(dst, 4, 8));
    }

    @Test
    @DisplayName("setParam clears any signing digest left over from a recycled request")
    public void shouldClearTheDigestInSetParam() {
        final SmbComWrite request = new SmbComWrite(this.config);
        request.setDigest(Mockito.mock(SMB1SigningDigest.class));
        assertNotNull(request.getDigest());

        request.setParam(1, 0L, 0, new byte[1], 0, 1);

        assertNull(request.getDigest());
    }

    @Test
    @DisplayName("The parameter words are written at the requested offset")
    public void shouldHonourTheWriteOffset() {
        final SmbComWrite request = new SmbComWrite(this.config, 0x0102, 0x0304, 0x0506, new byte[2], 0, 2);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE + 8];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 4));

        assertArrayEquals(new byte[4], Arrays.copyOfRange(dst, 0, 4), "nothing before the offset may be touched");
        assertEquals(0x0102, SMBUtil.readInt2(dst, 4));
        assertEquals(0x0304, SMBUtil.readInt4(dst, 8));
        assertEquals(0x0506, SMBUtil.readInt2(dst, 12));
    }

    @Test
    @DisplayName("The data bytes are the 0x01 buffer format byte, the length and the payload")
    public void shouldWriteTheDataBytes() {
        final byte[] payload = { 0x10, 0x20, 0x30, 0x40, 0x50 };
        final SmbComWrite request = new SmbComWrite(this.config, 1, 0, 0, payload, 1, 3);
        final byte[] dst = new byte[16];

        final int written = request.writeBytesWireFormat(dst, 0);

        assertEquals(3 + 3, written);
        assertEquals(0x01, dst[0], "SMB_COM_WRITE data blocks start with buffer format 0x01");
        assertEquals(3, SMBUtil.readInt2(dst, 1));
        assertArrayEquals(new byte[] { 0x20, 0x30, 0x40 }, Arrays.copyOfRange(dst, 3, 6), "the payload is taken from the given offset");
    }

    @Test
    @DisplayName("A zero length write still emits the three byte data block header")
    public void shouldWriteAnEmptyDataBlock() {
        final SmbComWrite request = new SmbComWrite(this.config, 1, 0, 0, new byte[0], 0, 0);
        final byte[] dst = new byte[8];

        assertEquals(3, request.writeBytesWireFormat(dst, 0));

        assertEquals(0x01, dst[0]);
        assertEquals(0, SMBUtil.readInt2(dst, 1));
    }

    @Test
    @DisplayName("The data bytes are written at the requested offset")
    public void shouldHonourTheDataWriteOffset() {
        final byte[] payload = { 0x7F };
        final SmbComWrite request = new SmbComWrite(this.config, 1, 0, 0, payload, 0, 1);
        final byte[] dst = new byte[16];

        assertEquals(4, request.writeBytesWireFormat(dst, 5));

        assertArrayEquals(new byte[5], Arrays.copyOfRange(dst, 0, 5), "nothing before the offset may be touched");
        assertEquals(0x01, dst[5]);
        assertEquals(1, SMBUtil.readInt2(dst, 6));
        assertEquals(0x7F, dst[8]);
    }

    @Test
    @DisplayName("A request never decodes anything")
    public void shouldReadNothing() {
        final SmbComWrite request = new SmbComWrite(this.config);

        assertEquals(0, request.readParameterWordsWireFormat(new byte[16], 0));
        assertEquals(0, request.readBytesWireFormat(new byte[16], 0));
    }

    @Test
    @DisplayName("toString names the message and does not throw")
    public void shouldRenderToString() {
        final String rendered = new SmbComWrite(this.config, 7, 128, 64, new byte[4], 0, 4).toString();

        assertNotNull(rendered);
        assertTrue(rendered.startsWith("SmbComWrite["), rendered);
        assertTrue(rendered.contains("fid=7"), rendered);
        assertTrue(rendered.contains("count=4"), rendered);
        assertTrue(rendered.contains("offset=128"), rendered);
        assertTrue(rendered.contains("remaining=64"), rendered);
        assertTrue(rendered.endsWith("]"), rendered);
    }
}
