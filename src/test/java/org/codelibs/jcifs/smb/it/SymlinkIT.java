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
package org.codelibs.jcifs.smb.it;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.SmbSymlinkException;
import org.codelibs.jcifs.smb.it.env.RequiresBackend;
import org.codelibs.jcifs.smb.it.env.SmbBackend;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Symlinks inside and across a share boundary.
 *
 * <p>
 * On the plain share the two backends behave differently and both are correct.
 * Samba resolves a symlink on the server, so the client sees an ordinary file.
 * Windows hands the reparse point back and expects the client to resolve it.
 * That is why those tests are split by backend instead of branching.
 * </p>
 *
 * <p>
 * The last group is not split, because it uses a share configured so that both
 * backends report the link rather than resolve it. That is the only arrangement
 * in which a client-side resolver is reachable at all, and it is what makes the
 * behaviour testable on every backend rather than on Windows alone.
 * </p>
 */
class SymlinkIT extends AbstractSmbIT {

    private static final String TARGET_CONTENTS = "target file contents\n";
    private static final String OUTSIDE_CONTENTS = "outside the share\n";

    private SmbFile shared(final String name) throws Exception {
        return new SmbFile(server().url(server().share(), name), server().context());
    }

    private static String read(final SmbFile file) throws Exception {
        try (InputStream in = file.getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    // ------------------------------------------------------------- Samba --

    @Test
    @RequiresBackend(SmbBackend.SAMBA)
    @DisplayName("Samba resolves a link inside the share before the client sees it")
    void sambaResolvesLinkInsideShare() throws Exception {
        try (SmbFile link = shared("link-to-file")) {
            assertTrue(link.exists(), "the link should look like an ordinary file");
            assertEquals(TARGET_CONTENTS, read(link));
        }
    }

    @Test
    @RequiresBackend(SmbBackend.SAMBA)
    @DisplayName("Samba resolves a relative link the same way")
    void sambaResolvesRelativeLink() throws Exception {
        try (SmbFile link = shared("link-relative")) {
            assertEquals(TARGET_CONTENTS, read(link));
        }
    }

    @Test
    @RequiresBackend(SmbBackend.SAMBA)
    @DisplayName("Samba resolves a link to a directory")
    void sambaResolvesLinkToDirectory() throws Exception {
        try (SmbFile link = new SmbFile(server().url(server().share(), "link-to-dir/"), server().context())) {
            assertTrue(link.isDirectory());
            try (SmbFile inside = new SmbFile(link, "inside.txt")) {
                assertTrue(inside.exists());
            }
        }
    }

    @Test
    @RequiresBackend(SmbBackend.SAMBA)
    @DisplayName("Samba follows a link that points outside the share when wide links are on")
    void sambaFollowsLinkOutsideShare() throws Exception {
        try (SmbFile link = shared("link-outside")) {
            assertEquals(OUTSIDE_CONTENTS, read(link));
        }
    }

    @Test
    @RequiresBackend(SmbBackend.SAMBA)
    @DisplayName("a link with no target is not visible over Samba")
    void sambaHidesBrokenLink() throws Exception {
        try (SmbFile link = shared("link-broken")) {
            assertFalse(link.exists());
        }
    }

    // ----------------------------------------------------------- Windows --

    @Test
    @RequiresBackend(SmbBackend.WINDOWS)
    @Disabled("#75: the client does not resolve reparse points. Windows returns STATUS_STOPPED_ON_SYMLINK "
            + "with the target in the error data; enable once jcifs follows it.")
    @DisplayName("reading through a link inside the share returns the target's contents")
    void windowsResolvesLinkInsideShare() throws Exception {
        try (SmbFile link = shared("link-to-file")) {
            assertEquals(TARGET_CONTENTS, read(link));
        }
    }

    @Test
    @RequiresBackend(SmbBackend.WINDOWS)
    @Disabled("#75: the client does not resolve reparse points. See windowsResolvesLinkInsideShare.")
    @DisplayName("a link to a directory can be listed through")
    void windowsResolvesLinkToDirectory() throws Exception {
        try (SmbFile link = new SmbFile(server().url(server().share(), "link-to-dir/"), server().context())) {
            assertTrue(link.isDirectory());
        }
    }

    // ------------------------------------------- the link-reporting share --
    //
    // Everything below runs on both backends, unlike the two groups above. The
    // share it uses is configured to hand the link back rather than resolve it,
    // which Windows does natively and Samba does from 4.22 onwards, and its
    // in-share links are all relative - the only form a client could ever
    // resolve, since an absolute target names a path in the server's own
    // namespace.
    //
    // These pin what a caller can rely on today. jCIFS does not follow links,
    // so every one of them ends in SmbSymlinkException carrying the target, and
    // that has to keep being true for any caller who has not opted into
    // following.

    private SmbFile reporting(final String name) throws Exception {
        return new SmbFile(server().url(server().symlinkShare(), name), server().context());
    }

    @Test
    @DisplayName("an ordinary file in the link-reporting share is unaffected")
    void ordinaryFileIsUnaffected() throws Exception {
        try (SmbFile file = reporting("target.txt")) {
            assertTrue(file.exists(), "a file that is not a link should behave normally");
            assertEquals(TARGET_CONTENTS, read(file));
        }
    }

    @Test
    @DisplayName("a link reports its target rather than resolving it")
    void linkReportsItsTarget() throws Exception {
        try (SmbFile link = reporting("link-to-file")) {
            final SmbSymlinkException e = assertThrows(SmbSymlinkException.class, link::exists);
            assertEquals("target.txt", e.getSubstituteName());
            assertTrue(e.isRelative(), "an in-share target is relative");
            assertEquals(0, e.getUnparsedPathLength(), "the link itself was requested, so nothing is left over");
            assertTrue(e.getPath().endsWith("\\link-to-file"), "the requested path is reported: " + e.getPath());
        }
    }

    @Test
    @DisplayName("reading a link fails the same way as looking at it")
    void readingALinkReportsTheTargetToo() throws Exception {
        try (SmbFile link = reporting("link-to-file")) {
            final SmbSymlinkException e = assertThrows(SmbSymlinkException.class, link::getInputStream);
            assertEquals("target.txt", e.getSubstituteName());
        }
    }

    @Test
    @DisplayName("a link to a directory is reported, not listed through")
    void linkToDirectoryIsReported() throws Exception {
        try (SmbFile link = reporting("link-to-dir/")) {
            final SmbSymlinkException e = assertThrows(SmbSymlinkException.class, link::list);
            assertEquals("subdir", e.getSubstituteName());
            assertTrue(e.isRelative());
        }
    }

    @Test
    @DisplayName("a path through a link names the tail the server did not consume")
    void pathThroughALinkReportsTheUnconsumedTail() throws Exception {
        try (SmbFile file = reporting("link-to-dir/inside.txt")) {
            final SmbSymlinkException e = assertThrows(SmbSymlinkException.class, file::exists);
            assertEquals("subdir", e.getSubstituteName(), "the target is the link's, not the whole path's");
            // UnparsedPathLength counts UTF-16 bytes of the part the server did not reach, and the
            // separator ahead of it counts. Resolving means replacing everything before this tail.
            assertEquals("\\inside.txt".length() * 2, e.getUnparsedPathLength());
        }
    }

    @Test
    @DisplayName("a deeper path through a link reports a correspondingly longer tail")
    void deeperPathThroughALinkReportsALongerTail() throws Exception {
        try (SmbFile file = reporting("link-to-dir/deeper/still.txt")) {
            final SmbSymlinkException e = assertThrows(SmbSymlinkException.class, file::exists);
            assertEquals("subdir", e.getSubstituteName());
            assertEquals("\\deeper\\still.txt".length() * 2, e.getUnparsedPathLength());
        }
    }

    @Test
    @DisplayName("a broken link is reported with its target rather than as missing")
    void brokenLinkIsReportedWithItsTarget() throws Exception {
        try (SmbFile link = reporting("link-broken")) {
            final SmbSymlinkException e = assertThrows(SmbSymlinkException.class, link::exists);
            assertEquals("missing.txt", e.getSubstituteName(), "the server names the target even though it does not exist");
            assertTrue(e.isRelative());
        }
    }

    @Test
    @DisplayName("a target outside the share is reported as absolute")
    void targetOutsideTheShareIsAbsolute() throws Exception {
        try (SmbFile link = reporting("link-outside")) {
            final SmbSymlinkException e = assertThrows(SmbSymlinkException.class, link::exists);
            assertFalse(e.isRelative(), "an absolute target is in the server's own namespace and cannot be resolved against this share: "
                    + e.getSubstituteName());
        }
    }
}
