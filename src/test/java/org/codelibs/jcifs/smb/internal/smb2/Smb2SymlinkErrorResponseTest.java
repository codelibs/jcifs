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
package org.codelibs.jcifs.smb.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HexFormat;

import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link Smb2SymlinkErrorResponse}.
 *
 * The byte fixtures were captured from a Samba 4.23.8 server configured with
 * {@code follow symlinks = no} and {@code wide links = no}, which is the configuration that makes a
 * server answer STATUS_STOPPED_ON_SYMLINK rather than resolving the link itself.
 */
class Smb2SymlinkErrorResponseTest {

    /** {@code link-rel.txt -> target.txt}, requested over SMB 3.1.1, so wrapped in an error context. */
    private static final String REL_311 =
            "44000000000000004000000053594d4c0c0000a0340000000000140014001400010000007400610072006700650074002e007400780074007400610072006700650074002e00740078007400";

    /** The very same link requested over SMB 2.1, where the error context wrapper is absent. */
    private static final String REL_210 =
            "4000000053594d4c0c0000a0340000000000140014001400010000007400610072006700650074002e007400780074007400610072006700650074002e00740078007400";

    /** {@code linkdir/sub.txt} where {@code linkdir -> realdir}: the {@code \sub.txt} tail is unparsed. */
    private static final String UNPARSED_311 =
            "38000000000000003400000053594d4c0c0000a02800100000000e000e000e00010000007200650061006c006400690072007200650061006c00640069007200";

    /** {@code link-outside.txt -> /etc/hostname}: an absolute, non-UNC target. */
    private static final String ABSOLUTE_311 =
            "50000000000000004c00000053594d4c0c0000a04000000000001a001a001a00000000002f006500740063002f0068006f00730074006e0061006d0065002f006500740063002f0068006f00730074006e0061006d006500";

    /**
     * A response whose first error context honestly declares 68 bytes, but whose symbolic link
     * structure inflates SymLinkLength and ReparseDataLength and points SubstituteName past its own
     * path buffer, into the bytes that follow the context.
     */
    private static final String FORGED_TRAILING =
            "44000000000000005000000053594d4c0c0000a04400000028000800140014000100000074006100720067006500740"
                    + "02e007400780074007400610072006700650074002e007400780074004500560049004c000000000000000000";

    /** Two error contexts, where the symbolic link one is second: a SHARE_REDIRECT context precedes it. */
    private static final String SECOND_CONTEXT =
            "0400000053526472010203040000000038000000000000003400000053594d4c0c0000a02800000000000e000e000e00"
                    + "010000007200650061006c006400690072007200650061006c00640069007200";

    private static byte[] hex(final String s) {
        return HexFormat.of().parseHex(s.replace(" ", ""));
    }

    @Test
    @DisplayName("Decodes a relative link captured over SMB 3.1.1")
    void testRelativeWithErrorContext() throws Exception {
        final Smb2SymlinkErrorResponse r = Smb2SymlinkErrorResponse.decode(hex(REL_311), 1);
        assertEquals("target.txt", r.getSubstituteName());
        assertEquals("target.txt", r.getPrintName());
        assertTrue(r.isRelative());
        assertEquals(0, r.getUnparsedPathLength());
    }

    @Test
    @DisplayName("Decodes the same link captured over SMB 2.1, where no error context wraps it")
    void testRelativeWithoutErrorContext() throws Exception {
        final Smb2SymlinkErrorResponse r = Smb2SymlinkErrorResponse.decode(hex(REL_210), 0);
        assertEquals("target.txt", r.getSubstituteName());
        assertTrue(r.isRelative());
        assertEquals(0, r.getUnparsedPathLength());
    }

    @Test
    @DisplayName("SMB 2.1 and SMB 3.1.1 carry the same payload, so both decode alike")
    void testDialectsAgree() throws Exception {
        final Smb2SymlinkErrorResponse a = Smb2SymlinkErrorResponse.decode(hex(REL_311), 1);
        final Smb2SymlinkErrorResponse b = Smb2SymlinkErrorResponse.decode(hex(REL_210), 0);
        assertEquals(a.getSubstituteName(), b.getSubstituteName());
        assertEquals(a.isRelative(), b.isRelative());
        assertEquals(a.getUnparsedPathLength(), b.getUnparsedPathLength());
    }

    @Test
    @DisplayName("Reports the unparsed tail length when the link is a path component")
    void testUnparsedPathLength() throws Exception {
        final Smb2SymlinkErrorResponse r = Smb2SymlinkErrorResponse.decode(hex(UNPARSED_311), 1);
        assertEquals("realdir", r.getSubstituteName());
        assertTrue(r.isRelative());
        // "\sub.txt" is 8 UTF-16 characters that the server did not consume
        assertEquals(16, r.getUnparsedPathLength());
    }

    @Test
    @DisplayName("Decodes an absolute target and reports it as non-relative")
    void testAbsoluteTarget() throws Exception {
        final Smb2SymlinkErrorResponse r = Smb2SymlinkErrorResponse.decode(hex(ABSOLUTE_311), 1);
        assertEquals("/etc/hostname", r.getSubstituteName());
        assertFalse(r.isRelative());
    }

    @Test
    @DisplayName("Rejects a payload whose SymLinkErrorTag is not SYML")
    void testRejectsWrongErrorTag() {
        final byte[] b = hex(REL_311);
        b[8 + 4] ^= 0xFF; // corrupt the first byte of SymLinkErrorTag
        assertThrows(SMBProtocolDecodingException.class, () -> Smb2SymlinkErrorResponse.decode(b, 1));
    }

    @Test
    @DisplayName("Rejects a reparse tag other than IO_REPARSE_TAG_SYMLINK")
    void testRejectsWrongReparseTag() {
        final byte[] b = hex(REL_311);
        b[8 + 8] ^= 0xFF; // corrupt the first byte of ReparseTag
        assertThrows(SMBProtocolDecodingException.class, () -> Smb2SymlinkErrorResponse.decode(b, 1));
    }

    @Test
    @DisplayName("Rejects a truncated payload instead of reading out of bounds")
    void testRejectsTruncated() {
        final byte[] full = hex(REL_311);
        for (final int len : new int[] { 0, 4, 8, 16, 24, 36, full.length - 2 }) {
            final byte[] b = new byte[len];
            System.arraycopy(full, 0, b, 0, len);
            assertThrows(SMBProtocolDecodingException.class, () -> Smb2SymlinkErrorResponse.decode(b, 1),
                    "should have rejected a " + len + " byte payload");
        }
    }

    @Test
    @DisplayName("Rejects absent error data")
    void testRejectsNull() {
        assertThrows(SMBProtocolDecodingException.class, () -> Smb2SymlinkErrorResponse.decode(null, 1));
    }

    @Test
    @DisplayName("Rejects a name that claims to extend past the path buffer")
    void testRejectsNameOutOfBounds() {
        final byte[] b = hex(REL_311);
        // SubstituteNameLength sits 8 (context) + 18 bytes into the payload
        b[8 + 18] = (byte) 0xFF;
        b[8 + 19] = (byte) 0x7F;
        assertThrows(SMBProtocolDecodingException.class, () -> Smb2SymlinkErrorResponse.decode(b, 1));
    }

    @Test
    @DisplayName("Rejects a ReparseDataLength inconsistent with the payload")
    void testRejectsInconsistentReparseDataLength() {
        final byte[] b = hex(REL_311);
        // ReparseDataLength sits 8 (context) + 12 bytes into the payload
        b[8 + 12] = (byte) 0x08;
        b[8 + 13] = (byte) 0x00;
        assertThrows(SMBProtocolDecodingException.class, () -> Smb2SymlinkErrorResponse.decode(b, 1));
    }

    @Test
    @DisplayName("Bounds the payload by the declared lengths, not by whatever follows in the buffer")
    void testRejectsNameReachingPastTheDeclaredContext() {
        assertThrows(SMBProtocolDecodingException.class, () -> Smb2SymlinkErrorResponse.decode(hex(FORGED_TRAILING), 1),
                "a name pointing past the declared context must not be decoded from trailing bytes");
    }

    @Test
    @DisplayName("Finds the symbolic link context when it is not the first one")
    void testSymlinkContextNotFirst() throws Exception {
        final Smb2SymlinkErrorResponse r = Smb2SymlinkErrorResponse.decode(hex(SECOND_CONTEXT), 2);
        assertEquals("realdir", r.getSubstituteName());
        assertTrue(r.isRelative());
    }
}
