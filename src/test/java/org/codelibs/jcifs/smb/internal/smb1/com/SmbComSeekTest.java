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

import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link SmbComSeek} class.
 *
 * <p>
 * The parameter words of an SMB_COM_SEEK request are FID(2), Mode(2) and Offset(4), eight bytes in
 * total, and the request carries no data bytes.
 * </p>
 */
public class SmbComSeekTest {

    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        this.config = new PropertyConfiguration(new Properties());
    }

    @Test
    @DisplayName("The command is SMB_COM_SEEK")
    public void shouldUseSeekCommand() {
        assertEquals(ServerMessageBlock.SMB_COM_SEEK, new SmbComSeek(this.config, 1).getCommand());
    }

    @Test
    @DisplayName("The FID given to the constructor is the one written on the wire")
    public void shouldWriteTheConstructorFid() {
        final SmbComSeek request = new SmbComSeek(this.config, 0x1234);
        final byte[] dst = new byte[8];

        assertEquals(8, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0x1234, SMBUtil.readInt2(dst, 0));
        assertEquals(0, SMBUtil.readInt2(dst, 2));
        assertEquals(0, SMBUtil.readInt4(dst, 4));
    }

    @Test
    @DisplayName("FID, mode and offset are written at their documented offsets")
    public void shouldWriteAllParameterWords() {
        final SmbComSeek request = new SmbComSeek(this.config, 0);
        request.setFid(0x0AB1);
        request.setMode(2);
        request.setOffset(0x1234_5678L);
        final byte[] dst = new byte[8];

        assertEquals(8, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0x0AB1, SMBUtil.readInt2(dst, 0));
        assertEquals(2, SMBUtil.readInt2(dst, 2));
        assertEquals(0x1234_5678, SMBUtil.readInt4(dst, 4));
    }

    @Test
    @DisplayName("The parameter words are written at the requested offset")
    public void shouldHonourTheWriteOffset() {
        final SmbComSeek request = new SmbComSeek(this.config, 0x0102);
        request.setMode(1);
        request.setOffset(0x00FF_00FFL);
        final byte[] dst = new byte[16];

        assertEquals(8, request.writeParameterWordsWireFormat(dst, 4));

        assertArrayEquals(new byte[4], java.util.Arrays.copyOfRange(dst, 0, 4), "nothing before the offset may be touched");
        assertEquals(0x0102, SMBUtil.readInt2(dst, 4));
        assertEquals(1, SMBUtil.readInt2(dst, 6));
        assertEquals(0x00FF_00FF, SMBUtil.readInt4(dst, 8));
        assertArrayEquals(new byte[4], java.util.Arrays.copyOfRange(dst, 12, 16), "nothing past the parameter words may be touched");
    }

    @Test
    @DisplayName("A zero valued request writes eight zero bytes")
    public void shouldWriteZeroes() {
        final SmbComSeek request = new SmbComSeek(this.config, 0);
        final byte[] dst = new byte[8];

        assertEquals(8, request.writeParameterWordsWireFormat(dst, 0));
        assertArrayEquals(new byte[8], dst);
    }

    @Test
    @DisplayName("The widest FID, mode and offset fill their fields completely")
    public void shouldWriteMaximumValues() {
        final SmbComSeek request = new SmbComSeek(this.config, 0xFFFF);
        request.setMode(0xFFFF);
        request.setOffset(0xFFFF_FFFFL);
        final byte[] dst = new byte[8];

        assertEquals(8, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 0));
        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 2));
        assertEquals(-1, SMBUtil.readInt4(dst, 4), "0xFFFFFFFF reads back as a signed -1");
        final byte[] expected = new byte[8];
        java.util.Arrays.fill(expected, (byte) 0xFF);
        assertArrayEquals(expected, dst);
    }

    @Test
    @DisplayName("Only the low 32 bits of the offset fit in the SMB_COM_SEEK Offset field")
    public void shouldWriteOnlyTheLowHalfOfTheOffset() {
        final SmbComSeek request = new SmbComSeek(this.config, 1);
        request.setOffset(0x0000_000A_1234_5678L);
        final byte[] dst = new byte[8];

        assertEquals(8, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0x1234_5678, SMBUtil.readInt4(dst, 4), "SMB_COM_SEEK has no high offset field, the protocol truncates to 32 bits");
    }

    @Test
    @DisplayName("The request carries no data bytes and decodes nothing")
    public void shouldNeitherWriteNorReadBytes() throws SMBProtocolDecodingException {
        final SmbComSeek request = new SmbComSeek(this.config, 1);
        final byte[] dst = new byte[8];

        assertEquals(0, request.writeBytesWireFormat(dst, 0));
        assertEquals(0, request.readParameterWordsWireFormat(new byte[8], 0));
        assertEquals(0, request.readBytesWireFormat(new byte[8], 0));
        assertArrayEquals(new byte[8], dst);
    }

    @Test
    @DisplayName("toString does not throw")
    public void shouldRenderToString() {
        assertNotNull(new SmbComSeek(this.config, 3).toString());
    }
}
