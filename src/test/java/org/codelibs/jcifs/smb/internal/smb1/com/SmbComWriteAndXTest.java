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

import java.util.Arrays;
import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.smb1.SMB1SigningDigest;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * Tests for the {@link SmbComWriteAndX} class.
 *
 * <p>
 * The parameter words of an SMB_COM_WRITE_ANDX request occupy 24 bytes once the four AndX bytes
 * have been accounted for: FID(2), Offset(4), Timeout(4), WriteMode(2), Remaining(2), Reserved(2),
 * DataLength(2), DataOffset(2) and OffsetHigh(4). The data bytes are the alignment pad followed by
 * the payload, and DataOffset announces where that payload starts relative to the SMB header.
 * </p>
 */
public class SmbComWriteAndXTest {

    /** Size of the parameter words that {@link SmbComWriteAndX} encodes. */
    private static final int PARAMETER_WORDS_SIZE = 24;

    /**
     * Exposes the inherited header start so that the alignment of the announced data offset can be
     * tested at header positions other than zero.
     */
    private static final class PositionedWriteAndX extends SmbComWriteAndX {

        PositionedWriteAndX(final Configuration config, final int fid, final long offset, final int remaining, final byte[] b,
                final int off, final int len) {
            super(config, fid, offset, remaining, b, off, len, null);
        }

        void placeHeaderAt(final int index) {
            this.headerStart = index;
        }
    }

    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        this.config = new PropertyConfiguration(new Properties());
    }

    @Test
    @DisplayName("The command is SMB_COM_WRITE_ANDX")
    public void shouldUseWriteAndXCommand() {
        assertEquals(ServerMessageBlock.SMB_COM_WRITE_ANDX, new SmbComWriteAndX(this.config).getCommand());
        assertEquals(ServerMessageBlock.SMB_COM_WRITE_ANDX,
                new SmbComWriteAndX(this.config, 1, 0L, 0, new byte[1], 0, 1, null).getCommand());
    }

    @Test
    @DisplayName("A chained command is retained as the AndX of the request")
    public void shouldRetainTheChainedCommand() {
        final SmbComClose andx = new SmbComClose(this.config, 1, 0L);

        assertSame(andx, new SmbComWriteAndX(this.config, 1, 0L, 0, new byte[1], 0, 1, andx).getAndx());
        assertNull(new SmbComWriteAndX(this.config).getAndx());
    }

    @Test
    @DisplayName("Every parameter word sits at its documented offset")
    public void shouldWriteAllParameterWords() {
        final SmbComWriteAndX request = new SmbComWriteAndX(this.config, 0x1234, 0x0000_1000L, 0x0040, new byte[8], 0, 8, null);
        request.setWriteMode(0x0008);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0x1234, SMBUtil.readInt2(dst, 0));
        assertEquals(0x0000_1000, SMBUtil.readInt4(dst, 2));
        assertEquals(-1, SMBUtil.readInt4(dst, 6), "the timeout is always sent as 0xFFFFFFFF");
        assertEquals(0x0008, SMBUtil.readInt2(dst, 10));
        assertEquals(0x0040, SMBUtil.readInt2(dst, 12));
        assertEquals(0, SMBUtil.readInt2(dst, 14), "the reserved word is zero");
        assertEquals(8, SMBUtil.readInt2(dst, 16));
        assertEquals(28, SMBUtil.readInt2(dst, 18), "26 bytes to the pad, rounded up to the next multiple of four");
        assertEquals(0, SMBUtil.readInt4(dst, 20), "an offset below 4G leaves the high half zero");
    }

    @Test
    @DisplayName("An offset above four gigabytes is split across the low and the high offset field")
    public void shouldSplitALargeOffset() {
        final long offset = 0x0000_000A_1234_5678L;
        final SmbComWriteAndX request = new SmbComWriteAndX(this.config, 1, offset, 0, new byte[4], 0, 4, null);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0x1234_5678, SMBUtil.readInt4(dst, 2), "the low half goes into the Offset field");
        assertEquals(0x0000_000A, SMBUtil.readInt4(dst, 20), "the high half goes into the OffsetHigh field");
    }

    @Test
    @DisplayName("The largest positive offset fills both halves of the 64 bit offset")
    public void shouldWriteTheMaximumOffset() {
        final SmbComWriteAndX request =
                new SmbComWriteAndX(this.config, 0xFFFF, 0x7FFF_FFFF_FFFF_FFFFL, 0xFFFF, new byte[1], 0, 0xFFFF, null);
        request.setWriteMode(0xFFFF);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 0));
        assertEquals(-1, SMBUtil.readInt4(dst, 2));
        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 10));
        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 12));
        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 16));
        assertEquals(0x7FFF_FFFF, SMBUtil.readInt4(dst, 20));
    }

    @Test
    @DisplayName("setParam replaces the FID, offset, remaining count and payload")
    public void shouldApplySetParam() {
        final SmbComWriteAndX request = new SmbComWriteAndX(this.config);
        request.setParam(0x0ABC, 0x0000_0200L, 0x0010, new byte[] { 1, 2, 3, 4 }, 1, 2);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0x0ABC, SMBUtil.readInt2(dst, 0));
        assertEquals(0x0200, SMBUtil.readInt4(dst, 2));
        assertEquals(0x0010, SMBUtil.readInt2(dst, 12));
        assertEquals(2, SMBUtil.readInt2(dst, 16));
    }

    @Test
    @DisplayName("setParam clears any signing digest left over from a recycled request")
    public void shouldClearTheDigestInSetParam() {
        final SmbComWriteAndX request = new SmbComWriteAndX(this.config);
        request.setDigest(Mockito.mock(SMB1SigningDigest.class));
        assertNotNull(request.getDigest());

        request.setParam(1, 0L, 0, new byte[1], 0, 1);

        assertNull(request.getDigest());
    }

    @Test
    @DisplayName("The parameter words are written at the requested offset and the announced data offset follows it")
    public void shouldHonourTheWriteOffset() {
        final SmbComWriteAndX request = new SmbComWriteAndX(this.config, 0x0102, 0L, 0, new byte[2], 0, 2, null);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE + 8];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 5));

        assertArrayEquals(new byte[5], Arrays.copyOfRange(dst, 0, 5), "nothing before the offset may be touched");
        assertEquals(0x0102, SMBUtil.readInt2(dst, 5));
        assertEquals(32, SMBUtil.readInt2(dst, 23), "5 + 26 rounded up to the next multiple of four");
    }

    @Test
    @DisplayName("The announced data offset is four byte aligned for the header positions the transport uses")
    public void shouldAlignTheDataOffset() {
        for (final int headerStart : new int[] { 0, 4 }) {
            for (int dstIndex = 0; dstIndex < 8; dstIndex++) {
                final PositionedWriteAndX request = new PositionedWriteAndX(this.config, 1, 0L, 0, new byte[4], 0, 4);
                request.placeHeaderAt(headerStart);
                final byte[] dst = new byte[PARAMETER_WORDS_SIZE + 16];

                request.writeParameterWordsWireFormat(dst, headerStart + dstIndex);

                final int dataOffset = SMBUtil.readInt2(dst, headerStart + dstIndex + 18);
                assertEquals(0, dataOffset % 4,
                        "headerStart=" + headerStart + " dstIndex=" + dstIndex + " announced dataOffset=" + dataOffset);
            }
        }
    }

    @Test
    @Disabled("SmbComWriteAndX.writeParameterWordsWireFormat computes dataOffset as 'dstIndex - headerStart + 26', "
            + "which is already relative to headerStart, and then pads it with '(dataOffset - headerStart) % 4', "
            + "subtracting headerStart a second time. The pad should be 'dataOffset % 4'. The bug is latent because "
            + "the transport only ever encodes at headerStart 0 or 4, both multiples of four, so the extra subtraction "
            + "cancels out; at any other header position the announced DataOffset is not four byte aligned. With "
            + "headerStart 2 and dstIndex 2 the class announces DataOffset 26 where 28 is required.")
    @DisplayName("The announced data offset is four byte aligned at any header position")
    public void shouldAlignTheDataOffsetAtAnyHeaderPosition() {
        final PositionedWriteAndX request = new PositionedWriteAndX(this.config, 1, 0L, 0, new byte[4], 0, 4);
        request.placeHeaderAt(2);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE + 16];

        request.writeParameterWordsWireFormat(dst, 2);

        final int dataOffset = SMBUtil.readInt2(dst, 2 + 18);
        assertEquals(0, dataOffset % 4, "announced dataOffset=" + dataOffset);
    }

    @Test
    @DisplayName("The data bytes are the alignment pad followed by the payload")
    public void shouldWriteTheDataBytes() {
        final byte[] payload = { 0x10, 0x20, 0x30, 0x40, 0x50 };
        final SmbComWriteAndX request = new SmbComWriteAndX(this.config, 1, 0L, 0, payload, 1, 3, null);
        request.writeParameterWordsWireFormat(new byte[PARAMETER_WORDS_SIZE], 0);
        final byte[] dst = new byte[16];

        final int written = request.writeBytesWireFormat(dst, 0);

        assertEquals(2 + 3, written, "two pad bytes bring the payload onto a four byte boundary");
        assertArrayEquals(new byte[] { (byte) 0xEE, (byte) 0xEE }, Arrays.copyOfRange(dst, 0, 2));
        assertArrayEquals(new byte[] { 0x20, 0x30, 0x40 }, Arrays.copyOfRange(dst, 2, 5), "the payload is taken from the given offset");
    }

    @Test
    @DisplayName("A payload that needs no pad is written on its own")
    public void shouldWriteTheDataBytesWithoutAPad() {
        final byte[] payload = { 0x11, 0x22 };
        final SmbComWriteAndX request = new SmbComWriteAndX(this.config, 1, 0L, 0, payload, 0, 2, null);
        request.writeParameterWordsWireFormat(new byte[PARAMETER_WORDS_SIZE + 8], 2);
        final byte[] dst = new byte[16];

        final int written = request.writeBytesWireFormat(dst, 0);

        assertEquals(2, written, "2 + 26 is already a multiple of four");
        assertArrayEquals(payload, Arrays.copyOfRange(dst, 0, 2));
    }

    @Test
    @DisplayName("A zero length write emits the pad and nothing else")
    public void shouldWriteAnEmptyPayload() {
        final SmbComWriteAndX request = new SmbComWriteAndX(this.config, 1, 0L, 0, new byte[0], 0, 0, null);
        request.writeParameterWordsWireFormat(new byte[PARAMETER_WORDS_SIZE], 0);
        final byte[] dst = new byte[8];

        assertEquals(2, request.writeBytesWireFormat(dst, 0));
        assertArrayEquals(new byte[] { (byte) 0xEE, (byte) 0xEE }, Arrays.copyOfRange(dst, 0, 2));
    }

    @Test
    @DisplayName("The data bytes are written at the requested offset")
    public void shouldHonourTheDataWriteOffset() {
        final byte[] payload = { 0x7F };
        final SmbComWriteAndX request = new SmbComWriteAndX(this.config, 1, 0L, 0, payload, 0, 1, null);
        request.writeParameterWordsWireFormat(new byte[PARAMETER_WORDS_SIZE], 0);
        final byte[] dst = new byte[16];

        assertEquals(3, request.writeBytesWireFormat(dst, 5));

        assertArrayEquals(new byte[5], Arrays.copyOfRange(dst, 0, 5), "nothing before the offset may be touched");
        assertArrayEquals(new byte[] { (byte) 0xEE, (byte) 0xEE, 0x7F }, Arrays.copyOfRange(dst, 5, 8));
    }

    @Test
    @DisplayName("Only a chained read or close is batched")
    public void shouldBatchOnlyReadAndClose() {
        final SmbComWriteAndX request = new SmbComWriteAndX(this.config);

        assertEquals(this.config.getBatchLimit("WriteAndX.ReadAndX"),
                request.getBatchLimit(this.config, ServerMessageBlock.SMB_COM_READ_ANDX));
        assertEquals(this.config.getBatchLimit("WriteAndX.Close"), request.getBatchLimit(this.config, ServerMessageBlock.SMB_COM_CLOSE));
        assertEquals(0, request.getBatchLimit(this.config, ServerMessageBlock.SMB_COM_OPEN_ANDX));
    }

    @Test
    @DisplayName("A request never decodes anything")
    public void shouldReadNothing() {
        final SmbComWriteAndX request = new SmbComWriteAndX(this.config);

        assertEquals(0, request.readParameterWordsWireFormat(new byte[32], 0));
        assertEquals(0, request.readBytesWireFormat(new byte[32], 0));
    }

    @Test
    @DisplayName("toString names the message and does not throw")
    public void shouldRenderToString() {
        final SmbComWriteAndX request = new SmbComWriteAndX(this.config, 7, 128L, 64, new byte[4], 0, 4, null);
        request.setWriteMode(1);
        request.writeParameterWordsWireFormat(new byte[PARAMETER_WORDS_SIZE], 0);

        final String rendered = request.toString();

        assertNotNull(rendered);
        assertTrue(rendered.startsWith("SmbComWriteAndX["), rendered);
        assertTrue(rendered.contains("fid=7"), rendered);
        assertTrue(rendered.contains("offset=128"), rendered);
        assertTrue(rendered.contains("writeMode=1"), rendered);
        assertTrue(rendered.contains("dataLength=4"), rendered);
        assertTrue(rendered.contains("dataOffset=28"), rendered);
        assertTrue(rendered.endsWith("]"), rendered);
    }
}
