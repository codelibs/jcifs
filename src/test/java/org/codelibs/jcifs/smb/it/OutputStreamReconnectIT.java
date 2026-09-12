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
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.InputStream;
import java.util.Arrays;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.SmbFileOutputStream;
import org.codelibs.jcifs.smb.it.env.TcpRelay;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What a write does when the connection under it goes away.
 *
 * <p>
 * A stream whose connection drops reopens the file by path on the next write.
 * The reopen has to keep what the stream already wrote, because the stream
 * carries on at the position it had reached: reopening with a create
 * disposition that truncates leaves that part of the file as a hole, and
 * nothing reports it.
 * </p>
 */
class OutputStreamReconnectIT extends AbstractSmbIT {

    private static final int CHUNK_BYTES = 128 * 1024;

    private static final long DROP_TIMEOUT_SECONDS = 30;

    private String workDirName;

    @AfterEach
    void removeWorkDir() throws Exception {
        if (this.workDirName != null) {
            deleteQuietly(new SmbFile(server().url(server().share(), this.workDirName + "/"), server().context()));
        }
    }

    @Test
    @DisplayName("a write that outlives a dropped connection keeps the bytes written before the drop")
    void writeSurvivesDroppedConnection() throws Exception {
        final CIFSContext context = server().context();
        this.workDirName = "it-" + UUID.randomUUID();
        final byte[] beforeDrop = randomBytes(1);
        final byte[] afterDrop = randomBytes(2);

        try (TcpRelay relay = TcpRelay.to(server().host(), server().port())) {
            final String base = "smb://" + relay.host() + ":" + relay.port() + "/" + server().share() + "/" + this.workDirName + "/";
            try (SmbFile dir = new SmbFile(base, context)) {
                dir.mkdirs();
            }

            try (SmbFile file = new SmbFile(base + "reconnect.bin", context); SmbFileOutputStream out = file.openOutputStream()) {
                out.write(beforeDrop);
                relay.dropConnections();
                awaitDropped(out);
                out.write(afterDrop);
            }
        }

        // Read it back over a connection straight to the server, so only what reached the disk counts
        final byte[] expected = new byte[beforeDrop.length + afterDrop.length];
        System.arraycopy(beforeDrop, 0, expected, 0, beforeDrop.length);
        System.arraycopy(afterDrop, 0, expected, beforeDrop.length, afterDrop.length);
        try (SmbFile written = new SmbFile(server().url(server().share(), this.workDirName + "/reconnect.bin"), context);
                InputStream in = written.getInputStream()) {
            final byte[] actual = in.readAllBytes();
            assertArrayEquals(expected, actual, describe(expected, actual));
        }
    }

    /**
     * Waits until the client has noticed the closed socket.
     *
     * <p>
     * Without this the test could pass for the wrong reason: if the connection
     * were never really dropped, the stream would never reopen the file, and
     * the contents would be correct whether or not the reopen truncates.
     * </p>
     */
    private static void awaitDropped(final SmbFileOutputStream out) throws Exception {
        final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(DROP_TIMEOUT_SECONDS);
        while (out.isOpen() && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        assertFalse(out.isOpen(), "the connection was never dropped, so the reopen this test is about never happened");
    }

    private static byte[] randomBytes(final long seed) {
        final byte[] bytes = new byte[CHUNK_BYTES];
        new Random(seed).nextBytes(bytes);
        return bytes;
    }

    /**
     * Names what went wrong, since comparing two 256 KB arrays otherwise prints
     * only the first differing index.
     */
    private static String describe(final byte[] expected, final byte[] actual) {
        if (expected.length != actual.length) {
            return "the file is " + actual.length + " bytes, expected " + expected.length;
        }
        int zeroed = 0;
        for (int i = 0; i < expected.length; i++) {
            if (expected[i] != actual[i] && actual[i] == 0) {
                zeroed++;
            }
        }
        if (zeroed > 0) {
            return "the file has " + zeroed + " zero bytes where data was written, from offset " + Arrays.mismatch(expected, actual)
                    + "; the reopen after the drop truncated it";
        }
        return "the file came back different from what was written";
    }
}
