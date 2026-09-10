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
package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HexFormat;

import org.codelibs.jcifs.smb.internal.smb2.Smb2SymlinkErrorResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link SmbSymlinkException} and the STATUS_STOPPED_ON_SYMLINK entry it depends on.
 */
class SmbSymlinkExceptionTest {

    /** {@code link-rel.txt -> target.txt} as captured from Samba over SMB 3.1.1. */
    private static final String REL_311 =
            "44000000000000004000000053594d4c0c0000a0340000000000140014001400010000007400610072006700650074002e007400780074007400610072006700650074002e00740078007400";

    /** {@code link-outside.txt -> /etc/hostname}: an absolute target. */
    private static final String ABSOLUTE_311 =
            "50000000000000004c00000053594d4c0c0000a04000000000001a001a001a00000000002f006500740063002f0068006f00730074006e0061006d0065002f006500740063002f0068006f00730074006e0061006d006500";

    private static Smb2SymlinkErrorResponse decode(final String hex, final int contexts) throws Exception {
        return Smb2SymlinkErrorResponse.decode(HexFormat.of().parseHex(hex), contexts);
    }

    @Test
    @DisplayName("Records the code and message for STATUS_STOPPED_ON_SYMLINK")
    void testStatusIsKnown() {
        assertEquals(0x8000002D, NtStatus.NT_STATUS_STOPPED_ON_SYMLINK);
        final String message = SmbException.getMessageByCode(NtStatus.NT_STATUS_STOPPED_ON_SYMLINK);
        assertTrue(message.toLowerCase().contains("symbolic link"), "should describe the status, was: " + message);
        assertFalse(message.startsWith("0x"), "should no longer fall back to the raw code, was: " + message);
    }

    @Test
    @DisplayName("Keeps the NT status so existing handling still sees STATUS_STOPPED_ON_SYMLINK")
    void testPreservesNtStatus() throws Exception {
        final SmbSymlinkException e = new SmbSymlinkException("\\srv\\share\\link.txt", decode(REL_311, 1));
        assertEquals(NtStatus.NT_STATUS_STOPPED_ON_SYMLINK, e.getNtStatus());
        assertInstanceOf(SmbException.class, e, "callers catching SmbException must keep working");
    }

    @Test
    @DisplayName("Exposes a relative target and names it in the message")
    void testRelativeTarget() throws Exception {
        final SmbSymlinkException e = new SmbSymlinkException("\\srv\\share\\link-rel.txt", decode(REL_311, 1));
        assertEquals("target.txt", e.getSubstituteName());
        assertEquals("target.txt", e.getPrintName());
        assertTrue(e.isRelative());
        assertEquals(0, e.getUnparsedPathLength());
        assertEquals("\\srv\\share\\link-rel.txt", e.getPath());

        final String message = e.getMessage();
        assertTrue(message.contains("target.txt"), message);
        assertTrue(message.contains("\\srv\\share\\link-rel.txt"), message);
        assertTrue(message.contains("relative"), message);
    }

    @Test
    @DisplayName("Exposes an absolute target and says so in the message")
    void testAbsoluteTarget() throws Exception {
        final SmbSymlinkException e = new SmbSymlinkException("\\srv\\share\\link-outside.txt", decode(ABSOLUTE_311, 1));
        assertEquals("/etc/hostname", e.getSubstituteName());
        assertFalse(e.isRelative());
        assertTrue(e.getMessage().contains("absolute"), e.getMessage());
        assertTrue(e.getMessage().contains("/etc/hostname"), e.getMessage());
    }

    @Test
    @DisplayName("Tolerates an unknown request path")
    void testWithoutPath() throws Exception {
        final SmbSymlinkException e = new SmbSymlinkException(null, decode(REL_311, 1));
        assertEquals(null, e.getPath());
        assertTrue(e.getMessage().contains("target.txt"), e.getMessage());
    }
}
