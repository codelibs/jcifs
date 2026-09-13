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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;

import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class QueryMaximalAccessResponseTest {

    /** QueryStatus 0, MaximalAccess 0x001F01FF, little endian. */
    private static final byte[] FULL_ACCESS = { 0x00, 0x00, 0x00, 0x00, (byte) 0xFF, 0x01, 0x1F, 0x00 };

    @Test
    @DisplayName("the context is named MxAc")
    void nameIsMxAc() {
        assertArrayEquals("MxAc".getBytes(StandardCharsets.US_ASCII), new QueryMaximalAccessResponse().getName());
    }

    @Test
    @DisplayName("the status and the access mask are read in that order")
    void decodesStatusThenMask() throws Exception {
        final QueryMaximalAccessResponse response = new QueryMaximalAccessResponse();

        assertEquals(8, response.decode(FULL_ACCESS, 0, FULL_ACCESS.length));

        assertEquals(0, response.getQueryStatus());
        assertEquals(0x001F01FF, response.getMaximalAccess());
    }

    @Test
    @DisplayName("the response is read from the offset it is given")
    void decodesAtAnOffset() throws Exception {
        final byte[] buffer = new byte[16];
        System.arraycopy(FULL_ACCESS, 0, buffer, 5, FULL_ACCESS.length);
        final QueryMaximalAccessResponse response = new QueryMaximalAccessResponse();

        assertEquals(8, response.decode(buffer, 5, 8));

        assertEquals(0x001F01FF, response.getMaximalAccess());
    }

    @Test
    @DisplayName("a failed query keeps its status, so the mask is not mistaken for an answer")
    void decodesAFailedQuery() throws Exception {
        // 0xC0000022 is STATUS_ACCESS_DENIED. A server that reports a failure here
        // has not computed an access mask, and what follows must not be read as one.
        final byte[] refused = { 0x22, 0x00, 0x00, (byte) 0xC0, 0x00, 0x00, 0x00, 0x00 };
        final QueryMaximalAccessResponse response = new QueryMaximalAccessResponse();

        response.decode(refused, 0, refused.length);

        assertEquals(0xC0000022, response.getQueryStatus());
    }

    @Test
    @DisplayName("a response shorter than the structure is refused rather than read past")
    void refusesAShortResponse() {
        final QueryMaximalAccessResponse response = new QueryMaximalAccessResponse();
        assertThrows(SMBProtocolDecodingException.class, () -> response.decode(FULL_ACCESS, 0, 7));
    }
}
