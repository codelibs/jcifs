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
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The arithmetic behind following a symbolic link.
 *
 * <p>
 * This is the part a server cannot be asked about case by case, so it is pinned here instead: the
 * byte counts come from what Samba 4.22.10 and Windows Server 2025 actually sent, and the
 * normalisation cases cover forms neither fixture happens to contain.
 * </p>
 */
class SmbTreeConnectionSymlinkTest {

    private static final String SHARE = "\\server\\share";

    @Test
    @DisplayName("the link is replaced by what it points at")
    void replacesTheLinkWithItsTarget() {
        assertEquals(SHARE + "\\target.txt", SmbTreeConnection.resolveSymlink(SHARE + "\\link", "target.txt", true, 0));
    }

    @Test
    @DisplayName("a link is resolved against its own directory, not the share root")
    void resolvesAgainstTheLinksOwnDirectory() {
        assertEquals(SHARE + "\\dir\\target.txt", SmbTreeConnection.resolveSymlink(SHARE + "\\dir\\link", "target.txt", true, 0));
    }

    @Test
    @DisplayName("the tail the server did not consume is carried over")
    void keepsTheUnconsumedTail() {
        // "\inside.txt" is eleven characters, which is the 22 both servers reported.
        assertEquals(SHARE + "\\subdir\\inside.txt", SmbTreeConnection.resolveSymlink(SHARE + "\\link\\inside.txt", "subdir", true, 22));
    }

    @Test
    @DisplayName("a deeper tail is carried over whole")
    void keepsADeeperTail() {
        // "\deeper\still.txt" is seventeen characters, reported as 34.
        assertEquals(SHARE + "\\subdir\\deeper\\still.txt",
                SmbTreeConnection.resolveSymlink(SHARE + "\\link\\deeper\\still.txt", "subdir", true, 34));
    }

    @Test
    @DisplayName("a leading ./ in the target is dropped")
    void normalisesADotSegment() {
        assertEquals(SHARE + "\\target.txt", SmbTreeConnection.resolveSymlink(SHARE + "\\link", "./target.txt", true, 0));
    }

    @Test
    @DisplayName("a target written with forward slashes is accepted")
    void acceptsPosixSeparators() {
        assertEquals(SHARE + "\\a\\b.txt", SmbTreeConnection.resolveSymlink(SHARE + "\\link", "a/b.txt", true, 0));
    }

    @Test
    @DisplayName("a target may walk up out of its own directory")
    void walksUpWithDotDot() {
        assertEquals(SHARE + "\\sibling.txt", SmbTreeConnection.resolveSymlink(SHARE + "\\dir\\link", "../sibling.txt", true, 0));
    }

    @Test
    @DisplayName("but never out of the share")
    void refusesToClimbOutOfTheShare() {
        assertNull(SmbTreeConnection.resolveSymlink(SHARE + "\\link", "../elsewhere.txt", true, 0));
        assertNull(SmbTreeConnection.resolveSymlink(SHARE + "\\dir\\link", "../../../elsewhere.txt", true, 0));
    }

    @Test
    @DisplayName("an absolute target is not followed, in either server's spelling")
    void refusesAnAbsoluteTarget() {
        assertNull(SmbTreeConnection.resolveSymlink(SHARE + "\\link", "\\??\\C:\\smbit\\share\\target.txt", false, 0));
        assertNull(SmbTreeConnection.resolveSymlink(SHARE + "\\link", "/srv/outside/outside.txt", false, 0));
    }

    @Test
    @DisplayName("a malformed answer is refused rather than guessed at")
    void refusesMalformedInput() {
        assertNull(SmbTreeConnection.resolveSymlink(null, "target.txt", true, 0));
        assertNull(SmbTreeConnection.resolveSymlink(SHARE + "\\link", null, true, 0));
        assertNull(SmbTreeConnection.resolveSymlink(SHARE + "\\link", "", true, 0));
        assertNull(SmbTreeConnection.resolveSymlink(SHARE + "\\link", "target.txt", true, -2));
        // UnparsedPathLength is a UTF-16 byte count, so an odd value cannot be one
        assertNull(SmbTreeConnection.resolveSymlink(SHARE + "\\link", "target.txt", true, 3));
        // and it cannot name more than the path that was sent
        assertNull(SmbTreeConnection.resolveSymlink(SHARE + "\\link", "target.txt", true, 10000));
    }

    @Test
    @DisplayName("a path with no share to anchor against is refused")
    void refusesAPathThatIsNotUnderAShare() {
        assertNull(SmbTreeConnection.resolveSymlink("\\link", "target.txt", true, 0));
        assertNull(SmbTreeConnection.resolveSymlink("\\server\\link", "target.txt", true, 0));
    }

    @Test
    @DisplayName("a directory's trailing separator belongs to the tail, not to the link's name")
    void handlesTheTrailingSeparatorOfADirectory() {
        // A directory is addressed as "link-to-dir\" and the server still reports nothing
        // unconsumed. Taking the last separator literally would treat the link's own name as the
        // parent, and the target would then be appended to the link rather than replacing it.
        assertEquals(SHARE + "\\subdir\\", SmbTreeConnection.resolveSymlink(SHARE + "\\link\\", "subdir", true, 0));
        assertEquals(SHARE + "\\dir\\subdir\\", SmbTreeConnection.resolveSymlink(SHARE + "\\dir\\link\\", "subdir", true, 0));
    }
}
