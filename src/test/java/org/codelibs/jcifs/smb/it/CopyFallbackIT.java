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
}
