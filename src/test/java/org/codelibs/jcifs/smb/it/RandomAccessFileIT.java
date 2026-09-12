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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.SmbRandomAccessFile;
import org.codelibs.jcifs.smb.it.env.DialectMatrix;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@link SmbRandomAccessFile} beyond a single write-seek-read.
 *
 * <p>
 * The class carries the whole {@code DataInput}/{@code DataOutput} surface and a
 * {@code setLength} that sends FileEndOfFileInformation, but the suite only ever
 * exercised one small write and read back. Truncating and extending in
 * particular are server-side operations: the server decides what the bytes past
 * the old end contain.
 * </p>
 */
class RandomAccessFileIT extends AbstractSmbIT {

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    @DialectMatrix
    @DisplayName("setLength truncates a file")
    void setLengthTruncates(final DialectVersion dialect) throws Exception {
        final CIFSContext context = contextFor(dialect);
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "truncate.bin", "0123456789");

        try (SmbRandomAccessFile raf = file.openRandomAccess("rw")) {
            raf.setLength(4);
        }

        // Asked through a resource that has not cached anything yet, so this is
        // what the server holds rather than what the client remembered.
        try (SmbFile reopened = new SmbFile(this.workDir, "truncate.bin")) {
            assertEquals(4L, reopened.length(), "the server should have truncated the file");
        }

        try (SmbRandomAccessFile raf = file.openRandomAccess("r")) {
            final byte[] remaining = new byte[4];
            raf.readFully(remaining);
            assertArrayEquals("0123".getBytes(StandardCharsets.UTF_8), remaining, "truncation should keep the leading bytes");
        }
    }

    @Test
    @Disabled("SmbRandomAccessFile.length() delegates to SmbFile.length(), whose attribute cache setLength() never "
            + "invalidates, so the handle keeps reporting the length the file had before it was truncated until the "
            + "cache expires. java.io.RandomAccessFile reports the new length immediately.")
    @DisplayName("the handle reports the new length straight after setLength")
    void handleReportsTheNewLengthAfterSetLength() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "stale.bin", "0123456789");

        try (SmbRandomAccessFile raf = file.openRandomAccess("rw")) {
            raf.setLength(4);
            assertEquals(4L, raf.length(), "the handle should see the length it just set");
        }
    }

    @Test
    @DisplayName("setLength extends a file with zeroes")
    void setLengthExtendsWithZeroes() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "extend.bin", "abc");

        try (SmbRandomAccessFile raf = file.openRandomAccess("rw")) {
            raf.setLength(8);
        }
        assertEquals(8L, file.length(), "the server should have extended the file");

        try (SmbRandomAccessFile raf = file.openRandomAccess("r")) {
            final byte[] all = new byte[8];
            raf.readFully(all);
            assertArrayEquals("abc".getBytes(StandardCharsets.UTF_8), Arrays.copyOfRange(all, 0, 3), "the original bytes should survive");
            assertArrayEquals(new byte[5], Arrays.copyOfRange(all, 3, 8), "the bytes past the old end should read as zero");
        }
    }

    @Test
    @DisplayName("seek and readFully read from the requested offset")
    void seekAndReadFullyReadFromTheOffset() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "seek.bin", "0123456789");

        try (SmbRandomAccessFile raf = file.openRandomAccess("r")) {
            raf.seek(4);
            assertEquals(4L, raf.getFilePointer(), "the pointer should be where it was put");
            final byte[] tail = new byte[3];
            raf.readFully(tail);
            assertArrayEquals("456".getBytes(StandardCharsets.UTF_8), tail, "readFully should start at the seek position");
            assertEquals(7L, raf.getFilePointer(), "readFully should advance the pointer by what it read");
        }
    }

    @Test
    @DisplayName("skipBytes advances the pointer")
    void skipBytesAdvancesThePointer() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "skip.bin", "0123456789");

        try (SmbRandomAccessFile raf = file.openRandomAccess("r")) {
            assertEquals(6, raf.skipBytes(6), "skipBytes should report how far it moved");
            assertEquals(6L, raf.getFilePointer(), "the pointer should have moved by that much");
            assertEquals('6', raf.read(), "the next byte read should be the one after the skipped bytes");
        }
    }

    @Test
    @DisplayName("a write in the middle leaves the surrounding bytes alone")
    void writeInTheMiddleLeavesTheRestAlone() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "patch.bin", "0123456789");

        try (SmbRandomAccessFile raf = file.openRandomAccess("rw")) {
            raf.seek(3);
            raf.write("XY".getBytes(StandardCharsets.UTF_8));
        }

        assertEquals(10L, file.length(), "patching in the middle should not change the length");
        try (SmbRandomAccessFile raf = file.openRandomAccess("r")) {
            final byte[] all = new byte[10];
            raf.readFully(all);
            assertArrayEquals("012XY56789".getBytes(StandardCharsets.UTF_8), all, "only the patched bytes should have changed");
        }
    }

    @Test
    @DisplayName("the DataOutput and DataInput surface round trips")
    void dataSurfaceRoundTrips() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = new SmbFile(this.workDir, "data.bin");

        try (SmbRandomAccessFile raf = file.openRandomAccess("rw")) {
            raf.writeInt(0x01020304);
            raf.writeLong(0x0506070809000102L);
            raf.writeUTF("jcifs");
        }

        try (SmbRandomAccessFile raf = file.openRandomAccess("r")) {
            assertEquals(0x01020304, raf.readInt(), "the int should read back as written");
            assertEquals(0x0506070809000102L, raf.readLong(), "the long should read back as written");
            assertEquals("jcifs", raf.readUTF(), "the string should read back as written");
        }
    }
}
