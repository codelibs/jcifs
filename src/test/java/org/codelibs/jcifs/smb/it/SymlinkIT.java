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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.it.env.RequiresBackend;
import org.codelibs.jcifs.smb.it.env.SmbBackend;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Symlinks inside and across a share boundary.
 *
 * <p>
 * The two backends behave differently here and both are correct. Samba resolves
 * a symlink on the server, so the client sees an ordinary file. Windows hands
 * the reparse point back and expects the client to resolve it. That is why the
 * tests are split by backend instead of branching.
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
}
