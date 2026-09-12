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

import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link LockingAndXRange} class.
 */
public class LockingAndXRangeTest {

    @Test
    @DisplayName("A short range occupies ten bytes")
    public void shouldReportShortRangeSize() {
        assertEquals(10, new LockingAndXRange(false).size());
    }

    @Test
    @DisplayName("A large-file range occupies twenty bytes")
    public void shouldReportLargeRangeSize() {
        assertEquals(20, new LockingAndXRange(true).size());
    }

    @Test
    @DisplayName("A short range decodes the fields the wire format defines")
    public void shouldDecodeShortRange() throws Exception {
        final byte[] buffer = new byte[10];
        SMBUtil.writeInt2(0x1234, buffer, 0);
        SMBUtil.writeInt4(0x00ABCDEFL, buffer, 2);
        SMBUtil.writeInt4(0x00001000L, buffer, 6);

        final LockingAndXRange range = new LockingAndXRange(false);
        assertEquals(10, range.decode(buffer, 0, buffer.length));

        assertEquals(0x1234, range.getPid());
        assertEquals(0x00ABCDEFL, range.getByteOffset());
        assertEquals(0x00001000L, range.getLengthInBytes());
    }

    @Test
    @DisplayName("A short range survives an encode and decode round trip")
    public void shouldRoundTripShortRange() throws Exception {
        final byte[] source = new byte[10];
        SMBUtil.writeInt2(0x4321, source, 0);
        SMBUtil.writeInt4(0x0000BEEFL, source, 2);
        SMBUtil.writeInt4(0x00000200L, source, 6);

        final LockingAndXRange decoded = new LockingAndXRange(false);
        decoded.decode(source, 0, source.length);

        final byte[] encoded = new byte[10];
        assertEquals(10, decoded.encode(encoded, 0));

        final LockingAndXRange again = new LockingAndXRange(false);
        again.decode(encoded, 0, encoded.length);

        assertEquals(decoded.getPid(), again.getPid());
        assertEquals(decoded.getByteOffset(), again.getByteOffset());
        assertEquals(decoded.getLengthInBytes(), again.getLengthInBytes());
    }

    @Test
    @Disabled("#108: LockingAndXRange.decode combines the halves of a 64-bit offset with 'boHigh << 32' where boHigh is an "
            + "int. A shift distance of 32 on an int is masked to zero, so the high half is not shifted at all and is "
            + "OR'd straight into the low half: an offset of 0x0000000A12345678 decodes as 0x1234567A. The length is "
            + "combined the same way. Both need the high half widened to long before the shift.")
    @DisplayName("A large-file range survives a round trip of an offset that needs more than 32 bits")
    public void shouldRoundTripLargeOffset() throws Exception {
        final long offset = 0x0000000A_12345678L;
        final long length = 0x00000003_9ABCDEF0L;

        final byte[] source = new byte[20];
        SMBUtil.writeInt2(0x0007, source, 0);
        SMBUtil.writeInt4(offset >> 32, source, 4);
        SMBUtil.writeInt4(offset & 0xFFFFFFFFL, source, 8);
        SMBUtil.writeInt4(length >> 32, source, 12);
        SMBUtil.writeInt4(length & 0xFFFFFFFFL, source, 16);

        final LockingAndXRange range = new LockingAndXRange(true);
        assertEquals(20, range.decode(source, 0, source.length));

        assertEquals(0x0007, range.getPid());
        assertEquals(offset, range.getByteOffset(), "the high and low halves of the offset should be recombined");
        assertEquals(length, range.getLengthInBytes(), "the high and low halves of the length should be recombined");

        final byte[] encoded = new byte[20];
        assertEquals(20, range.encode(encoded, 0));
        assertArrayEquals(source, encoded, "re-encoding what was decoded should reproduce the wire bytes");
    }

    @Test
    @DisplayName("A large-file range decodes an offset that fits in 32 bits")
    public void shouldDecodeLargeRangeWithSmallOffset() throws Exception {
        final long offset = 0x12345678L;
        final long length = 0x00000200L;

        final byte[] buffer = new byte[20];
        SMBUtil.writeInt2(0x0007, buffer, 0);
        SMBUtil.writeInt4(0L, buffer, 4);
        SMBUtil.writeInt4(offset, buffer, 8);
        SMBUtil.writeInt4(0L, buffer, 12);
        SMBUtil.writeInt4(length, buffer, 16);

        final LockingAndXRange range = new LockingAndXRange(true);
        assertEquals(20, range.decode(buffer, 0, buffer.length));

        assertEquals(0x0007, range.getPid());
        assertEquals(offset, range.getByteOffset());
        assertEquals(length, range.getLengthInBytes());
    }
}
