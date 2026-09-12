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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.SmbRandomAccessFile;
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

    /**
     * Opens the same file over a second, separate connection.
     */
    private SmbFile otherConnection(final SmbFile file) throws Exception {
        final Properties properties = server().defaultProperties();
        properties.setProperty("jcifs.client.ssnLimit", "1");
        return new SmbFile(file.getURL().toString(), server().context(properties));
    }
}
