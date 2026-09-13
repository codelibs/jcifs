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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * A resource found by listing a directory, opened again from nothing but its URL.
 *
 * <p>
 * A crawler does not keep the objects a listing returns. It records each child's
 * URL as text, queues it, and later builds a new {@link SmbFile} from that string -
 * on another thread, long after the directory it came from has been closed. What a
 * listing hands back therefore has to survive being written out with
 * {@code getURL().toExternalForm()} and parsed again; a name that round-trips only
 * while it stays inside one {@code SmbFile} is lost the moment it is queued.
 * </p>
 *
 * <p>
 * {@link SpecialNamesIT} shows that awkward names can be written, read and listed.
 * This class shows that the URL a listing produces for them leads back to the same
 * file.
 * </p>
 */
class ListedUrlIT extends AbstractSmbIT {

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    @ParameterizedTest
    @ValueSource(strings = { "日本語ファイル.txt", "with space.txt", "with+plus.txt", "with&amp.txt", "with%percent.txt", "with#hash.txt",
            "with;semicolon.txt", "with@at.txt", "with'apostrophe.txt", "with~tilde.txt" })
    @DisplayName("a listed file reopens from its URL")
    void listedFileReopensFromItsUrl(final String name) throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final String contents = "contents of " + name;
        writeFile(this.workDir, name, contents);

        final String url = listedUrl(this.workDir, name);
        try (SmbFile reopened = new SmbFile(url, context)) {
            assertEquals(name, reopened.getName(), "the listed URL " + url + " names a different file");
            assertTrue(reopened.isFile(), "the listed URL " + url + " does not lead to the file");
            assertEquals(contents, contentsOf(reopened));
        }
    }

    @Test
    @DisplayName("a tree walked by listed URLs alone reaches every file")
    void treeWalkedByListedUrlsReachesEveryFile() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile folder = new SmbFile(this.workDir, "日本語 フォルダ/");
        folder.mkdirs();
        final SmbFile nested = new SmbFile(folder, "sub dir+1/");
        nested.mkdirs();
        writeFile(this.workDir, "top.txt", "top");
        writeFile(folder, "中の ファイル.txt", "middle");
        writeFile(nested, "deep#1.txt", "deep");

        final Set<String> reached = new HashSet<>();
        final Deque<String> queue = new ArrayDeque<>();
        queue.add(this.workDir.getURL().toExternalForm());
        while (!queue.isEmpty()) {
            try (SmbFile resource = new SmbFile(queue.poll(), context)) {
                if (resource.isDirectory()) {
                    for (final SmbFile child : resource.listFiles()) {
                        queue.add(child.getURL().toExternalForm());
                    }
                } else {
                    reached.add(contentsOf(resource));
                }
            }
        }
        assertEquals(Set.of("top", "middle", "deep"), reached, "walking the tree by URL did not reach every file");
    }

    private static String listedUrl(final SmbFile dir, final String name) throws Exception {
        final SmbFile[] children = dir.listFiles();
        return Arrays.stream(children)
                .filter(child -> name.equals(child.getName()))
                .findFirst()
                .map(child -> child.getURL().toExternalForm())
                .orElseThrow(() -> new AssertionError(
                        "the listing did not contain " + name + ", it had " + Arrays.stream(children).map(SmbFile::getName).toList()));
    }

    private static String contentsOf(final SmbFile file) throws Exception {
        try (InputStream in = file.getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
