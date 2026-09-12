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
import static org.junit.jupiter.api.Assertions.fail;

import java.io.InputStream;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.SmbOplockProbe;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Holds a file open with an oplock and then opens it from somewhere else, which is the only way to make a real server
 * send an oplock break.
 *
 * <p>
 * A server that gets no acknowledgement does not fail the conflicting open, it waits out its break timeout - about
 * 35 seconds - and then breaks the oplock itself. So the acknowledgement shows up as the conflicting open returning
 * promptly, and its absence as that open stalling.
 * </p>
 */
class OplockBreakIT extends AbstractSmbIT {

    /** Comfortably below a server break timeout, comfortably above a round trip. */
    private static final long PROMPT_MILLIS = 15_000;

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    @Test
    @DisplayName("a broken oplock is acknowledged, so the conflicting open is not left waiting")
    void testBreakIsAcknowledged() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "oplock.txt", "oplock target");

        try (SmbOplockProbe probe = SmbOplockProbe.open(file, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH)) {
            // It is not enough that some oplock was granted, it has to be one whose break needs an acknowledgement.
            // An open registers itself holding the level it was granted, so had the server handed out level II here,
            // the open would already sit at level II and the check at the end of this test would pass without any
            // break having happened at all.
            assertEquals(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH, probe.grantedOplockLevel(),
                    "the server did not grant the batch oplock this test needs in order to provoke a break");

            final long elapsed = openFromAnotherConnection(file);

            assertTrue(elapsed < PROMPT_MILLIS, "the conflicting open took " + elapsed
                    + " ms, so the oplock break went unacknowledged and the server had to " + "wait out its break timeout");

            // The acknowledgement is sent on its own thread, and only a refused one lowers the level again, so the
            // level has to be read after that thread is done or a refusal could be missed.
            awaitAcknowledgement();

            // Timing alone cannot tell an accepted acknowledgement from a refused one: a server that refuses it
            // completes the break itself, so the conflicting open returns just as promptly either way. A refused
            // acknowledgement drops the open to NONE, an accepted break to level II leaves it at level II.
            assertEquals(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_II, probe.currentOplockLevel(),
                    "the open should hold the level the server broke to; NONE here means the acknowledgement was refused");
        }
    }

    /**
     * Waits for the thread that sends the acknowledgement to finish.
     *
     * <p>
     * The thread exists only while an acknowledgement is in flight, so its absence means the send has either
     * succeeded or failed and recorded that.
     * </p>
     */
    private static void awaitAcknowledgement() throws InterruptedException {
        final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        while (System.nanoTime() < deadline) {
            if (Thread.getAllStackTraces().keySet().stream().noneMatch(t -> t.isAlive() && "jcifs-oplock-break-ack".equals(t.getName()))) {
                return;
            }
            Thread.sleep(20);
        }
        fail("the oplock break acknowledgement was still in flight after 30 s");
    }

    /**
     * Opens the file over a second, separate connection and returns how long that took.
     *
     * <p>
     * {@code ssnLimit=1} keeps this off the pooled connection the probe is using, so the break really does cross
     * connections rather than being resolved inside one.
     * </p>
     */
    private long openFromAnotherConnection(final SmbFile file) throws Exception {
        final Properties properties = server().defaultProperties();
        properties.setProperty("jcifs.client.ssnLimit", "1");
        final CIFSContext other = server().context(properties);

        final long start = System.nanoTime();
        try (SmbFile conflicting = new SmbFile(file.getURL().toString(), other); InputStream in = conflicting.getInputStream()) {
            assertEquals('o', in.read(), "the conflicting open should read the file that was written");
        }
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
    }
}
