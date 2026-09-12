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

import java.util.Arrays;
import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link SmbComReadAndX} class.
 *
 * <p>
 * The parameter words of an SMB_COM_READ_ANDX request occupy 20 bytes once the four AndX bytes have
 * been accounted for: FID(2), Offset(4), MaxCountOfBytesToReturn(2), MinCountOfBytesToReturn(2),
 * Timeout(4), Remaining(2) and OffsetHigh(4).
 * </p>
 */
public class SmbComReadAndXTest {

    /** Size of the parameter words that {@link SmbComReadAndX} encodes. */
    private static final int PARAMETER_WORDS_SIZE = 20;

    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        this.config = new PropertyConfiguration(new Properties());
    }

    @Test
    @DisplayName("The command is SMB_COM_READ_ANDX")
    public void shouldUseReadAndXCommand() {
        assertEquals(ServerMessageBlock.SMB_COM_READ_ANDX, new SmbComReadAndX(this.config).getCommand());
        assertEquals(ServerMessageBlock.SMB_COM_READ_ANDX, new SmbComReadAndX(this.config, 1, 0L, 1, null).getCommand());
    }

    @Test
    @DisplayName("A chained command is retained as the AndX of the request")
    public void shouldRetainTheChainedCommand() {
        final SmbComClose andx = new SmbComClose(this.config, 1, 0L);

        assertSame(andx, new SmbComReadAndX(this.config, 1, 0L, 1, andx).getAndx());
    }

    @Test
    @DisplayName("The parameterised constructor sets both the maximum and the minimum count")
    public void shouldSetBothCountsFromTheConstructor() {
        final SmbComReadAndX request = new SmbComReadAndX(this.config, 1, 0L, 4096, null);

        assertEquals(4096, request.getMaxCount());
        assertEquals(4096, request.getMinCount());
        assertEquals(0, request.getRemaining());
    }

    @Test
    @DisplayName("Every parameter word sits at its documented offset")
    public void shouldWriteAllParameterWords() {
        final SmbComReadAndX request = new SmbComReadAndX(this.config, 0x1234, 0x0000_1000L, 0x2000, null);
        request.setMinCount(0x0100);
        request.setRemaining(0x0040);
        request.setOpenTimeout(0x0001_0203);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0x1234, SMBUtil.readInt2(dst, 0));
        assertEquals(0x0000_1000, SMBUtil.readInt4(dst, 2));
        assertEquals(0x2000, SMBUtil.readInt2(dst, 6));
        assertEquals(0x0100, SMBUtil.readInt2(dst, 8));
        assertEquals(0x0001_0203, SMBUtil.readInt4(dst, 10));
        assertEquals(0x0040, SMBUtil.readInt2(dst, 14));
        assertEquals(0, SMBUtil.readInt4(dst, 16), "an offset below 4G leaves the high half zero");
    }

    @Test
    @DisplayName("The default open timeout is written as 0xFFFFFFFF")
    public void shouldWriteTheDefaultTimeout() {
        final SmbComReadAndX request = new SmbComReadAndX(this.config);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        request.writeParameterWordsWireFormat(dst, 0);

        assertEquals(-1, SMBUtil.readInt4(dst, 10));
        final byte[] expected = new byte[4];
        Arrays.fill(expected, (byte) 0xFF);
        assertArrayEquals(expected, Arrays.copyOfRange(dst, 10, 14));
    }

    @Test
    @DisplayName("setParam replaces the FID, the offset and both counts")
    public void shouldApplySetParam() {
        final SmbComReadAndX request = new SmbComReadAndX(this.config);
        request.setParam(0x0ABC, 0x0000_0200L, 0x0800);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0x0ABC, SMBUtil.readInt2(dst, 0));
        assertEquals(0x0200, SMBUtil.readInt4(dst, 2));
        assertEquals(0x0800, SMBUtil.readInt2(dst, 6));
        assertEquals(0x0800, SMBUtil.readInt2(dst, 8));
        assertEquals(0x0800, request.getMaxCount());
        assertEquals(0x0800, request.getMinCount());
    }

    @Test
    @DisplayName("An offset above four gigabytes is split across the low and the high offset field")
    public void shouldSplitALargeOffset() {
        final long offset = 0x0000_000A_1234_5678L;
        final SmbComReadAndX request = new SmbComReadAndX(this.config, 1, offset, 512, null);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0x1234_5678, SMBUtil.readInt4(dst, 2), "the low half goes into the Offset field");
        assertEquals(0x0000_000A, SMBUtil.readInt4(dst, 16), "the high half goes into the OffsetHigh field");
    }

    @Test
    @DisplayName("The largest positive offset fills both halves of the 64 bit offset")
    public void shouldWriteTheMaximumOffset() {
        final SmbComReadAndX request = new SmbComReadAndX(this.config, 0xFFFF, 0x7FFF_FFFF_FFFF_FFFFL, 0xFFFF, null);
        request.setRemaining(0xFFFF);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 0));
        assertEquals(-1, SMBUtil.readInt4(dst, 2));
        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 6));
        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 14));
        assertEquals(0x7FFF_FFFF, SMBUtil.readInt4(dst, 16));
    }

    @Test
    @DisplayName("A zero valued request writes zeroes except for the default timeout")
    public void shouldWriteZeroes() {
        final SmbComReadAndX request = new SmbComReadAndX(this.config, 0, 0L, 0, null);
        request.setOpenTimeout(0);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));
        assertArrayEquals(new byte[PARAMETER_WORDS_SIZE], dst);
    }

    @Test
    @DisplayName("The parameter words are written at the requested offset")
    public void shouldHonourTheWriteOffset() {
        final SmbComReadAndX request = new SmbComReadAndX(this.config, 0x0102, 0L, 0x0304, null);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE + 8];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 4));

        assertArrayEquals(new byte[4], Arrays.copyOfRange(dst, 0, 4), "nothing before the offset may be touched");
        assertEquals(0x0102, SMBUtil.readInt2(dst, 4));
        assertEquals(0x0304, SMBUtil.readInt2(dst, 10));
        assertArrayEquals(new byte[4], Arrays.copyOfRange(dst, 24, 28), "nothing past the parameter words may be touched");
    }

    @Test
    @DisplayName("Only a chained close is batched, and only up to the configured limit")
    public void shouldBatchOnlyClose() {
        final SmbComReadAndX request = new SmbComReadAndX(this.config);

        assertEquals(this.config.getBatchLimit("ReadAndX.Close"), request.getBatchLimit(this.config, ServerMessageBlock.SMB_COM_CLOSE));
        assertEquals(0, request.getBatchLimit(this.config, ServerMessageBlock.SMB_COM_WRITE_ANDX));
    }

    @Test
    @DisplayName("The request carries no data bytes and decodes nothing")
    public void shouldNeitherWriteNorReadBytes() {
        final SmbComReadAndX request = new SmbComReadAndX(this.config);
        final byte[] dst = new byte[8];

        assertEquals(0, request.writeBytesWireFormat(dst, 0));
        assertEquals(0, request.readParameterWordsWireFormat(new byte[8], 0));
        assertEquals(0, request.readBytesWireFormat(new byte[8], 0));
        assertArrayEquals(new byte[8], dst);
    }

    @Test
    @DisplayName("toString names the message and does not throw")
    public void shouldRenderToString() {
        final String rendered = new SmbComReadAndX(this.config, 7, 128L, 512, null).toString();

        assertNotNull(rendered);
        assertTrue(rendered.startsWith("SmbComReadAndX["), rendered);
        assertTrue(rendered.contains("fid=7"), rendered);
        assertTrue(rendered.contains("maxCount=512"), rendered);
        assertTrue(rendered.endsWith("]"), rendered);
    }
}
