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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Random;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.it.env.DialectMatrix;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The two paths {@code copyTo} can take, and the boundary between them.
 *
 * <p>
 * {@code SmbCopyUtil.copyFile} asks the server to do the copy with
 * FSCTL_SRV_COPYCHUNK only when source and destination sit on the same tree;
 * otherwise it streams the bytes through the client. Every copy test in the
 * suite used one share, so the streaming half had never run. The chunk limits
 * the client starts with - a megabyte per chunk and sixteen megabytes per
 * request - also meant that a one-megabyte fixture never exercised more than a
 * single chunk.
 * </p>
 */
class CopyFallbackIT extends AbstractSmbIT {

    /** Past the client's 16 MB per-request limit, so the copy loop has to go round twice. */
    private static final int LARGE_SIZE = 20 * 1024 * 1024;

    /**
     * 2020-09-13, far enough in the past that a target stamped with the time of the copy cannot match it by
     * coincidence. Whole seconds, so no server's timestamp granularity can round it away.
     */
    private static final long STAMP = 1600000000000L;

    private SmbFile sourceDir;
    private SmbFile targetDir;

    @AfterEach
    void removeWorkDirs() {
        deleteQuietly(this.sourceDir);
        deleteQuietly(this.targetDir);
    }

    private static byte[] digest(final SmbFile file) throws Exception {
        final MessageDigest md = MessageDigest.getInstance("SHA-256");
        final byte[] buffer = new byte[64 * 1024];
        try (InputStream in = file.getInputStream()) {
            int read;
            while ((read = in.read(buffer)) > 0) {
                md.update(buffer, 0, read);
            }
        }
        return md.digest();
    }

    private SmbFile writeRandomFile(final SmbFile parent, final String name, final int size) throws Exception {
        final byte[] payload = new byte[size];
        new Random(size).nextBytes(payload);
        final SmbFile file = new SmbFile(parent, name);
        try (OutputStream out = file.getOutputStream()) {
            out.write(payload);
        }
        return file;
    }

    @DialectMatrix
    @DisplayName("a copy across two shares streams through the client and keeps the bytes")
    void copyAcrossSharesKeepsTheBytes(final DialectVersion dialect) throws Exception {
        final CIFSContext context = contextFor(dialect);
        this.sourceDir = createWorkDir(context, server().share());
        this.targetDir = createWorkDir(context, "users");

        final SmbFile source = writeFile(this.sourceDir, "cross.txt", "payload that crosses a share boundary");
        final SmbFile target = new SmbFile(this.targetDir, "cross.txt");

        source.copyTo(target);

        assertTrue(target.exists(), "the copy should have created the target");
        assertEquals(source.length(), target.length(), "the copy should be the same length");
        try (InputStream in = target.getInputStream()) {
            assertArrayEquals("payload that crosses a share boundary".getBytes(StandardCharsets.UTF_8), in.readAllBytes(),
                    "the copy should hold the same bytes");
        }
    }

    @Test
    @DisplayName("a copy larger than the per-request chunk limit keeps the bytes")
    void largeCopyWithinAShareKeepsTheBytes() throws Exception {
        final CIFSContext context = server().context();
        this.sourceDir = createWorkDir(context, server().share());

        final SmbFile source = writeRandomFile(this.sourceDir, "large-src.bin", LARGE_SIZE);
        final SmbFile target = new SmbFile(this.sourceDir, "large-dst.bin");

        source.copyTo(target);

        assertEquals(LARGE_SIZE, target.length(), "the copy should be the same length");
        assertArrayEquals(digest(source), digest(target), "the copy should be byte for byte identical");
    }

    @Test
    @DisplayName("a large copy across two shares keeps the bytes")
    void largeCopyAcrossSharesKeepsTheBytes() throws Exception {
        final CIFSContext context = server().context();
        this.sourceDir = createWorkDir(context, server().share());
        this.targetDir = createWorkDir(context, "users");

        final SmbFile source = writeRandomFile(this.sourceDir, "large-cross-src.bin", LARGE_SIZE);
        final SmbFile target = new SmbFile(this.targetDir, "large-cross-dst.bin");

        source.copyTo(target);

        assertEquals(LARGE_SIZE, target.length(), "the streamed copy should be the same length");
        assertArrayEquals(digest(source), digest(target), "the streamed copy should be byte for byte identical");
    }

    @Test
    @DisplayName("copying a directory copies what is under it")
    void copyingADirectoryCopiesItsContents() throws Exception {
        final CIFSContext context = server().context();
        this.sourceDir = createWorkDir(context, server().share());
        this.targetDir = createWorkDir(context, "users");

        writeFile(this.sourceDir, "top.txt", "top level");
        final SmbFile nested = new SmbFile(this.sourceDir, "nested/");
        nested.mkdirs();
        writeFile(nested, "deep.txt", "nested level");

        final SmbFile target = new SmbFile(this.targetDir, "copied/");
        this.sourceDir.copyTo(target);

        assertTrue(new SmbFile(target, "top.txt").exists(), "the top level file should have been copied");
        assertTrue(new SmbFile(target, "nested/deep.txt").exists(), "the nested file should have been copied");
        try (InputStream in = new SmbFile(target, "nested/deep.txt").getInputStream()) {
            assertArrayEquals("nested level".getBytes(StandardCharsets.UTF_8), in.readAllBytes(),
                    "the nested copy should hold the same bytes");
        }
    }

    @DialectMatrix
    @DisplayName("a copy over a longer existing target truncates it, within a share and across two")
    void copyOverAnExistingTargetTruncatesIt(final DialectVersion dialect) throws Exception {
        // A copy opens its target with O_TRUNC. A server-side copy writes the bytes itself, chunk by chunk, so a
        // path that loses the truncation leaves the tail of whatever was there before - and still reports success,
        // with the right bytes at the front. The length catches that; the byte comparison says the result is not
        // merely the right size.
        final CIFSContext context = contextFor(dialect);
        this.sourceDir = createWorkDir(context, server().share());
        this.targetDir = createWorkDir(context, "users");

        final String shortContents = "short";
        final byte[] expected = shortContents.getBytes(StandardCharsets.UTF_8);
        writeFile(this.sourceDir, "trunc-src.txt", shortContents);

        for (final SmbFile parent : new SmbFile[] { this.sourceDir, this.targetDir }) {
            final String where = parent == this.sourceDir ? "within a share" : "across two shares";
            writeFile(parent, "trunc-dst.txt", "a considerably longer body that must not survive being overwritten");

            // A fresh handle for the source each time: the instance a copy was made from has cached its size and
            // attributes, and the copy reads those to stamp the target.
            new SmbFile(this.sourceDir, "trunc-src.txt").copyTo(new SmbFile(parent, "trunc-dst.txt"));

            final SmbFile fresh = new SmbFile(parent, "trunc-dst.txt");
            assertEquals(expected.length, fresh.length(), "the copy should have truncated the existing target " + where);
            try (InputStream in = fresh.getInputStream()) {
                assertArrayEquals(expected, in.readAllBytes(), "the copy should hold only the source bytes " + where);
            }
        }

        // A copy that resolved the wrong source would be invisible above: both targets would simply hold the same
        // wrong bytes. This says the source itself was not the thing that changed.
        final SmbFile freshSource = new SmbFile(this.sourceDir, "trunc-src.txt");
        assertEquals(expected.length, freshSource.length(), "the copy should have left the source alone on " + dialect);
        try (InputStream in = freshSource.getInputStream()) {
            assertArrayEquals(expected, in.readAllBytes(), "the copy should have left the source's bytes alone on " + dialect);
        }
    }

    @Test
    @DisplayName("an empty file copies as an empty file, within a share and across two")
    void emptyFileCopiesAsEmpty() throws Exception {
        // Zero length takes its own branch in the server-side path: there is nothing to ask the server to copy, so
        // it creates the target and sets its metadata instead. Routing a new pair of trees through that path runs
        // this branch where it has never run before.
        final CIFSContext context = server().context();
        this.sourceDir = createWorkDir(context, server().share());
        this.targetDir = createWorkDir(context, "users");

        new SmbFile(this.sourceDir, "empty-src.txt").createNewFile();

        new SmbFile(this.sourceDir, "empty-src.txt").copyTo(new SmbFile(this.sourceDir, "empty-same.txt"));
        new SmbFile(this.sourceDir, "empty-src.txt").copyTo(new SmbFile(this.targetDir, "empty-cross.txt"));

        assertTrue(new SmbFile(this.sourceDir, "empty-same.txt").exists(), "an empty copy within a share should exist");
        assertEquals(0, new SmbFile(this.sourceDir, "empty-same.txt").length(), "an empty copy within a share should be empty");
        assertTrue(new SmbFile(this.targetDir, "empty-cross.txt").exists(), "an empty copy across shares should exist");
        assertEquals(0, new SmbFile(this.targetDir, "empty-cross.txt").length(), "an empty copy across shares should be empty");
    }

    @Test
    @DisplayName("a copy carries the source's modification time, within a share and across two")
    void copyPreservesTheModificationTime() throws Exception {
        // Both paths set the destination's basic information from the source once the bytes are there, which is
        // what stops a copy from looking freshly written. Asserting against a time set well in the past makes a
        // failure unambiguous: a path that skips it leaves the target stamped with now.
        final CIFSContext context = server().context();
        this.sourceDir = createWorkDir(context, server().share());
        this.targetDir = createWorkDir(context, "users");

        writeFile(this.sourceDir, "stamped-src.txt", "stamped");
        new SmbFile(this.sourceDir, "stamped-src.txt").setLastModified(STAMP);

        new SmbFile(this.sourceDir, "stamped-src.txt").copyTo(new SmbFile(this.sourceDir, "stamped-same.txt"));
        new SmbFile(this.sourceDir, "stamped-src.txt").copyTo(new SmbFile(this.targetDir, "stamped-cross.txt"));

        assertEquals(STAMP, new SmbFile(this.sourceDir, "stamped-same.txt").lastModified(),
                "a copy within a share should carry the source's modification time");
        assertEquals(STAMP, new SmbFile(this.targetDir, "stamped-cross.txt").lastModified(),
                "a copy across shares should carry the source's modification time");
    }
}
