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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;
import java.util.concurrent.TimeUnit;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.SmbRandomAccessFile;
import org.codelibs.jcifs.smb.it.env.TcpRelay;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Byte range locks, which only say anything when a second open goes for the same range.
 *
 * <p>
 * A lock belongs to the open that took it, so a contending lock taken through the same handle would be granted no
 * matter what the first one did. Both tests here therefore contend from a separate connection, and
 * {@code ssnLimit=1} keeps that off the pooled connection the holder is using.
 * </p>
 */
class ByteRangeLockIT extends AbstractSmbIT {

    /** Generous, because it only bounds a wait that normally ends on the first attempt. */
    private static final long RELEASE_TIMEOUT_SECONDS = 30;

    private static final long POLL_MILLIS = 50;

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    @Test
    @DisplayName("an exclusive lock keeps another connection out of the range until it is released")
    void exclusiveLockKeepsAnotherConnectionOut() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "locked.bin", "0123456789");

        try (SmbRandomAccessFile holder = file.openRandomAccess("rw");
                SmbFile otherFile = otherConnection(file);
                SmbRandomAccessFile contender = otherFile.openRandomAccess("rw")) {

            holder.lock(0, 4, false);

            // An unheld range is granted, so a refusal here is what shows the lock reached the server and was
            // recorded, rather than having been built and dropped.
            assertFalse(contender.tryLock(0, 4, false), "another connection should not be given an exclusive range the holder has locked");

            // And the range has to come free again, which is what tells a real unlock apart from a no-op.
            holder.unlock(0, 4);
            assertTrue(contender.tryLock(0, 4, false), "the range should be available once the holder unlocked it");
            contender.unlock(0, 4);
        }
    }

    @Test
    @DisplayName("a shared lock still allows another shared lock on the same range")
    void sharedLocksCoexist() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "shared.bin", "0123456789");

        try (SmbRandomAccessFile holder = file.openRandomAccess("rw");
                SmbFile otherFile = otherConnection(file);
                SmbRandomAccessFile contender = otherFile.openRandomAccess("rw")) {

            holder.lock(0, 4, true);

            // Paired with the test above this pins the flag mapping: were shared and exclusive swapped, one of the
            // two tests would fail, whereas either one alone would pass with the wrong flag.
            assertTrue(contender.tryLock(0, 4, true), "a range held by a shared lock should take a second shared lock");

            contender.unlock(0, 4);
            holder.unlock(0, 4);
        }
    }

    @Test
    @DisplayName("a lock is gone once the connection under it drops, and the reopened handle holds no range")
    void lockDoesNotSurviveAReconnect() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "reconnect.bin", "0123456789");

        // The holder goes through the relay so its connection can be cut; the contender goes straight to the server
        // so it survives the cut. That also puts them on separate transports by construction rather than by
        // configuration, which is what makes the contention real.
        try (TcpRelay relay = TcpRelay.to(server().host(), server().port())) {
            final String viaRelay = "smb://" + relay.host() + ":" + relay.port() + file.getURL().getPath();

            try (SmbFile holderFile = new SmbFile(viaRelay, context);
                    SmbRandomAccessFile holder = holderFile.openRandomAccess("rw");
                    SmbFile contenderFile = otherConnection(file);
                    SmbRandomAccessFile contender = contenderFile.openRandomAccess("rw")) {

                holder.lock(0, 4, false);
                assertFalse(contender.tryLock(0, 4, false), "the range should be held while the holder's connection is up");

                relay.dropConnections();

                // A lock belongs to the open that took it, and a dropped connection is recovered by reopening the
                // path, which yields a new open holding nothing. Were the ranges replayed onto the reopened handle -
                // which is what a durable handle buys and the obvious "fix" to reach for - this would stay refused.
                assertTrue(awaitGranted(contender, 0, 4), "the lock should not have survived the drop");
                contender.unlock(0, 4);

                // And the holder's own reopened handle has no record of the range, so releasing it is an error
                // rather than a no-op. This is the caveat callers have to live with, stated as a test.
                assertThrows(SmbException.class, () -> holder.unlock(0, 4),
                        "unlocking a range the reopened handle never locked should fail");
            }
        }
    }

    /**
     * Waits for the range to become available, which needs the server to have noticed the dropped connection and
     * torn the holder's open down. Samba does this as soon as it sees the socket close - the relay closes the
     * server-facing side too - so this normally succeeds on the first attempt; the deadline is only insurance
     * against a slower server.
     */
    private static boolean awaitGranted(final SmbRandomAccessFile contender, final long position, final long size) throws Exception {
        final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(RELEASE_TIMEOUT_SECONDS);
        while (System.nanoTime() < deadline) {
            if (contender.tryLock(position, size, false)) {
                return true;
            }
            Thread.sleep(POLL_MILLIS);
        }
        return false;
    }

    /**
     * Opens the same file over a second, separate connection.
     */
    private SmbFile otherConnection(final SmbFile file) throws Exception {
        final Properties properties = server().defaultProperties();
        properties.setProperty("jcifs.client.ssnLimit", "1");
        return new SmbFile(file.getURL().toString(), server().context(properties));
    }
}
