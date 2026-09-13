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
package org.codelibs.jcifs.smb.internal.smb2.create;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class QueryMaximalAccessRequestTest {

    @Test
    @DisplayName("the context is named MxAc")
    void nameIsMxAc() {
        assertArrayEquals("MxAc".getBytes(StandardCharsets.US_ASCII), new QueryMaximalAccessRequest().getName());
    }

    @Test
    @DisplayName("the name cannot be altered through the accessor")
    void nameIsNotShared() {
        final QueryMaximalAccessRequest request = new QueryMaximalAccessRequest();
        final byte[] first = request.getName();
        first[0] = 'X';
        assertArrayEquals("MxAc".getBytes(StandardCharsets.US_ASCII), request.getName(),
                "altering a returned name should not change the next one");
        assertNotSame(first, request.getName());
    }

    @Test
    @DisplayName("the request is the eight byte timestamp")
    void sizeIsTheTimestamp() {
        assertEquals(8, new QueryMaximalAccessRequest().size());
    }

    @Test
    @DisplayName("a zero timestamp is written over whatever the buffer already held")
    void encodeZeroesADirtyBuffer() {
        // The transport buffer is reused, so a request that only advanced the index
        // would send the previous message's bytes as its timestamp - and a non-zero
        // timestamp is exactly what lets a server skip the response.
        final byte[] dst = new byte[16];
        Arrays.fill(dst, (byte) 0xFF);

        final int written = new QueryMaximalAccessRequest().encode(dst, 4);

        assertEquals(8, written);
        assertArrayEquals(new byte[8], Arrays.copyOfRange(dst, 4, 12), "the timestamp should be eight zero bytes");
        assertEquals((byte) 0xFF, dst[3], "nothing before the offset should be touched");
        assertEquals((byte) 0xFF, dst[12], "nothing after the timestamp should be touched");
    }
}
