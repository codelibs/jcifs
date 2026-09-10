/*
 * © 2025 CodeLibs, Inc.
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.context.SingletonContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Regression tests for issue #83: a child resolved below a resource that does not carry a trailing slash was glued to
 * the last segment of the parent path.
 */
class SmbFileResolveChildTest {

    private static CIFSContext context() {
        return SingletonContext.getInstance();
    }

    @Test
    @DisplayName("resolve() below a directory without a trailing slash yields a child, not a glued sibling")
    void testResolveChildOfDirectoryWithoutTrailingSlash() throws Exception {
        try (SmbFile root = new SmbFile("smb://host/testshare/", context());
                SmbFile nested = (SmbFile) root.resolve("nested");
                SmbFile child = (SmbFile) nested.resolve("a.txt")) {
            assertEquals("/testshare/nested", nested.getLocator().getURLPath());

            assertEquals("a.txt", child.getName());
            assertEquals("/testshare/nested/a.txt", child.getLocator().getURLPath());
            assertEquals("\\nested\\a.txt", child.getLocator().getUNCPath());
            assertEquals("smb://host/testshare/nested/a.txt", child.getURL().toString());
            assertEquals("smb://host/testshare/nested/a.txt", child.getCanonicalPath());
        }
    }

    @Test
    @DisplayName("enumerated children of a resource resolved without a trailing slash keep their own name")
    void testEnumeratedChildOfDirectoryWithoutTrailingSlash() throws Exception {
        try (SmbFile root = new SmbFile("smb://host/testshare/", context()); SmbFile nested = (SmbFile) root.resolve("nested")) {
            // this is what DirFileEntryAdapterIterator#adapt does for every directory entry
            try (SmbFile file = new SmbFile(nested, "a.txt", true, SmbConstants.TYPE_FILESYSTEM, 0, 0L, 0L, 0L, 0L);
                    SmbFile dir = new SmbFile(nested, "level2", true, SmbConstants.TYPE_FILESYSTEM, SmbConstants.ATTR_DIRECTORY, 0L, 0L, 0L,
                            0L)) {
                assertEquals("a.txt", file.getName());
                assertEquals("\\nested\\a.txt", file.getLocator().getUNCPath());
                assertEquals("smb://host/testshare/nested/a.txt", file.getURL().toString());

                assertEquals("level2/", dir.getName());
                assertEquals("\\nested\\level2\\", dir.getLocator().getUNCPath());
                assertEquals("smb://host/testshare/nested/level2/", dir.getURL().toString());
            }
        }
    }

    @Test
    @DisplayName("a resolve() chain below a share root keeps every segment")
    void testResolveChainKeepsEverySegment() throws Exception {
        try (SmbFile root = new SmbFile("smb://host/testshare/", context());
                SmbFile l1 = (SmbFile) root.resolve("nested");
                SmbFile l2 = (SmbFile) l1.resolve("level2");
                SmbFile l3 = (SmbFile) l2.resolve("level3")) {
            assertEquals("level3", l3.getName());
            assertEquals("/testshare/nested/level2/level3", l3.getLocator().getURLPath());
            assertEquals("\\nested\\level2\\level3", l3.getLocator().getUNCPath());
            assertEquals("smb://host/testshare/nested/level2/level3", l3.getURL().toString());
        }
    }

    @Test
    @DisplayName("resolving below a share URL without a trailing slash keeps the share")
    void testResolveBelowShareWithoutTrailingSlash() throws Exception {
        try (SmbFile share = new SmbFile("smb://host/testshare", context()); SmbFile child = (SmbFile) share.resolve("a.txt")) {
            assertEquals("a.txt", child.getName());
            assertEquals("testshare", child.getLocator().getShare());
            assertEquals("/testshare/a.txt", child.getLocator().getURLPath());
            assertEquals("\\a.txt", child.getLocator().getUNCPath());
            assertEquals("smb://host/testshare/a.txt", child.getURL().toString());
        }
    }

    @Test
    @DisplayName("an explicit trailing slash keeps working unchanged")
    void testResolveWithTrailingSlashUnchanged() throws Exception {
        try (SmbFile root = new SmbFile("smb://host/testshare/", context());
                SmbFile nested = (SmbFile) root.resolve("nested/");
                SmbFile child = (SmbFile) nested.resolve("a.txt")) {
            assertEquals("nested/", nested.getName());
            assertEquals("a.txt", child.getName());
            assertEquals("/testshare/nested/a.txt", child.getLocator().getURLPath());
            assertEquals("\\nested\\a.txt", child.getLocator().getUNCPath());
            assertEquals("smb://host/testshare/nested/a.txt", child.getURL().toString());
        }
    }
}
