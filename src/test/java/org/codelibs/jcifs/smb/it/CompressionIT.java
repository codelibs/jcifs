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

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Payloads survive a round trip whatever they are made of.
 *
 * <p>
 * These assert nothing about compression, and deliberately so: they are the net
 * under it. A message may be compressed or not, by either end, for reasons the
 * client does not control - so what a caller can rely on is that the bytes it
 * reads back are the bytes it wrote, for content that compresses well, content
 * that does not compress at all, and content too small to be worth compressing.
 * </p>
 *
 * <p>
 * The payload is larger than a single read or write request, so it spans several
 * messages. That matters here because compression applies per message: a defect
 * that only shows on the second message would otherwise go unseen.
 * </p>
 */
class CompressionIT extends AbstractSmbIT {

    /** Larger than the default one-mebibyte transfer size, so a transfer is several messages. */
    private static final int PAYLOAD = 2 * 1024 * 1024;

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    @Test
    @DisplayName("a payload that compresses well comes back byte for byte")
    void compressiblePayloadRoundTrips() throws Exception {
        assertRoundTrip("compressible.txt", compressible(PAYLOAD));
    }

    @Test
    @DisplayName("a payload that does not compress comes back byte for byte")
    void incompressiblePayloadRoundTrips() throws Exception {
        final byte[] payload = new byte[PAYLOAD];
        new Random(11).nextBytes(payload);
        assertRoundTrip("incompressible.bin", payload);
    }

    @Test
    @DisplayName("a payload too small to be worth compressing comes back byte for byte")
    void tinyPayloadRoundTrips() throws Exception {
        assertRoundTrip("tiny.txt", "x".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("an empty payload comes back empty")
    void emptyPayloadRoundTrips() throws Exception {
        assertRoundTrip("empty.txt", new byte[0]);
    }

    /**
     * Bytes that repeat, so that a server willing to compress has every reason to.
     */
    private static byte[] compressible(final int length) {
        final byte[] unit = "the quick brown fox jumps over the lazy dog ".getBytes(StandardCharsets.UTF_8);
        final byte[] payload = new byte[length];
        for (int i = 0; i < length; i++) {
            payload[i] = unit[i % unit.length];
        }
        return payload;
    }

    private void assertRoundTrip(final String name, final byte[] payload) throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = new SmbFile(this.workDir, name);

        try (OutputStream out = file.getOutputStream()) {
            out.write(payload);
        }

        assertEquals(payload.length, file.length(), "the file on the server should be the size that was written");

        final byte[] readBack = new byte[payload.length];
        try (InputStream in = file.getInputStream()) {
            int off = 0;
            int n;
            while (off < payload.length && (n = in.read(readBack, off, payload.length - off)) > 0) {
                off += n;
            }
            assertEquals(payload.length, off, "the whole file should have been read back");
            assertEquals(-1, in.read(), "there should be nothing after the payload");
        }

        assertArrayEquals(payload, readBack, "every byte should survive the round trip");
    }
}
