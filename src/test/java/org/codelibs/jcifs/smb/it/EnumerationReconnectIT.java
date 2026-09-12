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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.OutputStream;
import java.util.Properties;
import java.util.UUID;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CloseableIterator;
import org.codelibs.jcifs.smb.RuntimeCIFSException;
import org.codelibs.jcifs.smb.SmbResource;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.it.env.TcpRelay;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What a directory listing does when the connection under it goes away.
 *
 * <p>
 * A listing is fetched a page at a time, so a connection that drops partway
 * through leaves the caller with the entries fetched so far. Ending there
 * quietly is indistinguishable from a directory that really does hold only
 * those entries, which is the worst possible answer for anything that acts on
 * a listing - a crawler, a sync, a delete of everything that was not listed.
 * </p>
 *
 * <p>
 * The pages are made small with {@code jcifs.client.listSize} so a directory of
 * a few dozen files takes several round trips, leaving room to drop the
 * connection between two of them. Each test also checks how far the listing
 * got: a failure raised before the drop, or a listing that ran to the end,
 * would otherwise look like a pass.
 * </p>
 */
class EnumerationReconnectIT extends AbstractSmbIT {

    private static final int FILE_COUNT = 120;

    private static final int ENTRIES_BEFORE_DROP = 5;

    /** Small enough that a page holds only a handful of entries. */
    private static final String SMALL_PAGE_SIZE = "2048";

    private String workDirName;

    @AfterEach
    void removeWorkDir() throws Exception {
        if (this.workDirName != null) {
            deleteQuietly(new SmbFile(server().url(server().share(), this.workDirName + "/"), server().context()));
        }
    }

    @Test
    @DisplayName("children() reports a connection dropped mid-listing instead of ending early")
    void childrenReportsDroppedConnection() throws Exception {
        final CIFSContext context = pagedContext();
        createDirectoryOfFiles(context);
        final int[] seen = { 0 };

        try (TcpRelay relay = TcpRelay.to(server().host(), server().port()); SmbFile dir = new SmbFile(relayUrl(relay), context)) {
            assertThrows(RuntimeCIFSException.class, () -> {
                try (CloseableIterator<SmbResource> it = dir.children()) {
                    while (it.hasNext()) {
                        try (SmbResource entry = it.next()) {
                            seen[0]++;
                        }
                        if (seen[0] == ENTRIES_BEFORE_DROP) {
                            relay.dropConnections();
                        }
                    }
                }
                fail("the listing ended after " + seen[0] + " of " + FILE_COUNT + " entries without reporting the dropped connection");
            });
        }
        assertDroppedMidListing(seen[0]);
    }

    @Test
    @DisplayName("listFiles() reports a connection dropped mid-listing instead of returning a short array")
    void listFilesReportsDroppedConnection() throws Exception {
        final CIFSContext context = pagedContext();
        createDirectoryOfFiles(context);
        final int[] seen = { 0 };

        try (TcpRelay relay = TcpRelay.to(server().host(), server().port()); SmbFile dir = new SmbFile(relayUrl(relay), context)) {
            // The filter runs for every entry, which is the only way into the middle of a single listFiles call
            assertThrows(SmbException.class, () -> {
                final SmbFile[] listed = dir.listFiles(file -> {
                    seen[0]++;
                    if (seen[0] == ENTRIES_BEFORE_DROP) {
                        relay.dropConnections();
                    }
                    return true;
                });
                fail("listFiles returned " + listed.length + " of " + FILE_COUNT + " entries without reporting the dropped connection");
            });
        }
        assertDroppedMidListing(seen[0]);
    }

    /**
     * Checks the failure came from the drop rather than from something before it, such as a relay that never
     * connected, and that the listing had not already finished.
     */
    private static void assertDroppedMidListing(final int seen) {
        assertTrue(seen >= ENTRIES_BEFORE_DROP, "the listing failed after " + seen + " entries, before the connection was dropped");
        assertTrue(seen < FILE_COUNT, "the listing returned every entry, so the drop did not interrupt it");
    }

    /**
     * @return a context whose directory queries are small enough to need several round trips
     */
    private CIFSContext pagedContext() throws Exception {
        final Properties props = new Properties();
        props.setProperty("jcifs.client.listSize", SMALL_PAGE_SIZE);
        return server().context(props);
    }

    /**
     * @return the working directory's URL through the relay, taking the address from the relay itself so it matches
     *         whichever loopback address it bound
     */
    private String relayUrl(final TcpRelay relay) {
        return "smb://" + relay.host() + ":" + relay.port() + "/" + server().share() + "/" + this.workDirName + "/";
    }

    /**
     * Creates the directory and its files over a connection straight to the
     * server, so only the listing goes through the relay.
     */
    private void createDirectoryOfFiles(final CIFSContext context) throws Exception {
        this.workDirName = "it-" + UUID.randomUUID();
        try (SmbFile dir = new SmbFile(server().url(server().share(), this.workDirName + "/"), context)) {
            dir.mkdirs();
            for (int i = 0; i < FILE_COUNT; i++) {
                try (SmbFile file = new SmbFile(dir, String.format("entry-%03d.txt", i)); OutputStream out = file.getOutputStream()) {
                    out.write(('e' + i) & 0xFF);
                }
            }
        }
    }
}
