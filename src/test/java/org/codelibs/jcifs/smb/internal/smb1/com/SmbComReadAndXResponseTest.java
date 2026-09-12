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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link SmbComReadAndXResponse} class.
 *
 * <p>
 * The parameter words of an SMB_COM_READ_ANDX response occupy 20 bytes once the four AndX bytes
 * have been consumed: Available(2), DataCompactionMode(2), Reserved(2), DataLength(2),
 * DataOffset(2), DataLengthHigh(2) and eight reserved bytes. The payload itself is copied straight
 * into the caller's buffer by the transport, so readBytesWireFormat never consumes anything.
 * </p>
 */
public class SmbComReadAndXResponseTest {

    /** Size of the parameter words that {@link SmbComReadAndXResponse} decodes. */
    private static final int PARAMETER_WORDS_SIZE = 20;

    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        this.config = new PropertyConfiguration(new Properties());
    }

    private static byte[] parameterWords(final int offset, final int available, final int dataCompactionMode, final int dataLength,
            final int dataOffset) {
        final byte[] buffer = new byte[offset + PARAMETER_WORDS_SIZE + 4];
        SMBUtil.writeInt2(available, buffer, offset);
        SMBUtil.writeInt2(dataCompactionMode, buffer, offset + 2);
        SMBUtil.writeInt2(dataLength, buffer, offset + 6);
        SMBUtil.writeInt2(dataOffset, buffer, offset + 8);
        return buffer;
    }

    @Test
    @DisplayName("A response accepts the read AndX command code")
    public void shouldCarryTheReadAndXCommand() {
        final SmbComReadAndXResponse response = new SmbComReadAndXResponse(this.config);

        assertEquals(0, response.getCommand(), "a bare response has no command until it is decoded");

        response.setCommand(ServerMessageBlock.SMB_COM_READ_ANDX);
        assertEquals(ServerMessageBlock.SMB_COM_READ_ANDX, response.getCommand());
    }

    @Test
    @DisplayName("The no argument constructor leaves the target buffer unset")
    public void shouldStartWithoutATargetBuffer() {
        final SmbComReadAndXResponse response = new SmbComReadAndXResponse(this.config);

        assertNull(response.getData());
        assertEquals(0, response.getOffset());
    }

    @Test
    @DisplayName("The target buffer and offset given to the constructor are exposed unchanged")
    public void shouldExposeTheConstructorBuffer() {
        final byte[] target = new byte[64];

        final SmbComReadAndXResponse response = new SmbComReadAndXResponse(this.config, target, 8);

        assertSame(target, response.getData());
        assertEquals(8, response.getOffset());
    }

    @Test
    @DisplayName("setParam replaces the target buffer and offset")
    public void shouldApplySetParam() {
        final byte[] target = new byte[64];
        final SmbComReadAndXResponse response = new SmbComReadAndXResponse(this.config);

        response.setParam(target, 16);

        assertSame(target, response.getData());
        assertEquals(16, response.getOffset());
    }

    @Test
    @DisplayName("adjustOffset moves the write position inside the target buffer")
    public void shouldAdjustTheOffset() {
        final SmbComReadAndXResponse response = new SmbComReadAndXResponse(this.config, new byte[64], 4);

        response.adjustOffset(10);
        assertEquals(14, response.getOffset());

        response.adjustOffset(-4);
        assertEquals(10, response.getOffset());
    }

    @Test
    @DisplayName("The data length and data offset are decoded from their documented offsets")
    public void shouldDecodeAllParameterWords() {
        final byte[] buffer = parameterWords(6, 0x1000, 0x0001, 0x0400, 0x003C);

        final SmbComReadAndXResponse response = new SmbComReadAndXResponse(this.config);
        assertEquals(PARAMETER_WORDS_SIZE, response.readParameterWordsWireFormat(buffer, 6));

        assertEquals(0x0400, response.getDataLength());
        assertEquals(0x003C, response.getDataOffset());
        assertTrue(response.toString().contains("dataCompactionMode=1"), "the compaction mode comes from offset 2");
    }

    @Test
    @DisplayName("An all zero parameter word block decodes to zeroes and still consumes 20 bytes")
    public void shouldDecodeZeroes() {
        final SmbComReadAndXResponse response = new SmbComReadAndXResponse(this.config);

        assertEquals(PARAMETER_WORDS_SIZE, response.readParameterWordsWireFormat(new byte[PARAMETER_WORDS_SIZE], 0));

        assertEquals(0, response.getDataLength());
        assertEquals(0, response.getDataOffset());
    }

    @Test
    @DisplayName("The widest data length and data offset decode to their full unsigned range")
    public void shouldDecodeMaximumInt2Fields() {
        final byte[] buffer = parameterWords(0, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF);

        final SmbComReadAndXResponse response = new SmbComReadAndXResponse(this.config);
        assertEquals(PARAMETER_WORDS_SIZE, response.readParameterWordsWireFormat(buffer, 0));

        assertEquals(0xFFFF, response.getDataLength());
        assertEquals(0xFFFF, response.getDataOffset());
    }

    @Test
    @DisplayName("The reserved words around the decoded fields are ignored")
    public void shouldIgnoreTheReservedWords() {
        final byte[] buffer = new byte[PARAMETER_WORDS_SIZE];
        java.util.Arrays.fill(buffer, (byte) 0xEE);
        SMBUtil.writeInt2(0x0200, buffer, 6);
        SMBUtil.writeInt2(0x003C, buffer, 8);

        final SmbComReadAndXResponse response = new SmbComReadAndXResponse(this.config);
        assertEquals(PARAMETER_WORDS_SIZE, response.readParameterWordsWireFormat(buffer, 0));

        assertEquals(0x0200, response.getDataLength());
        assertEquals(0x003C, response.getDataOffset());
    }

    @Test
    @DisplayName("A response never encodes anything and consumes no data bytes")
    public void shouldNotEncodeAnything() {
        final SmbComReadAndXResponse response = new SmbComReadAndXResponse(this.config);
        final byte[] dst = new byte[16];

        assertEquals(0, response.writeParameterWordsWireFormat(dst, 0));
        assertEquals(0, response.writeBytesWireFormat(dst, 0));
        assertEquals(0, response.readBytesWireFormat(new byte[16], 0), "the payload is copied by the transport, not here");
        assertArrayEquals(new byte[16], dst);
    }

    @Test
    @DisplayName("toString names the message and does not throw")
    public void shouldRenderToString() {
        final SmbComReadAndXResponse response = new SmbComReadAndXResponse(this.config);
        response.readParameterWordsWireFormat(parameterWords(0, 0, 0, 512, 60), 0);

        final String rendered = response.toString();

        assertNotNull(rendered);
        assertTrue(rendered.startsWith("SmbComReadAndXResponse["), rendered);
        assertTrue(rendered.contains("dataLength=512"), rendered);
        assertTrue(rendered.contains("dataOffset=60"), rendered);
        assertTrue(rendered.endsWith("]"), rendered);
    }
}
