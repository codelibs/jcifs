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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.FileNotifyInformation;
import org.codelibs.jcifs.smb.SmbWatchHandle;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * SMB2 CHANGE_NOTIFY through {@link org.codelibs.jcifs.smb.SmbResource#watch}.
 *
 * <p>
 * Nothing else in the suite sends a CHANGE_NOTIFY, so this is the only cover for
 * a whole SMB2 command and for the blocking, cancellable request path it needs.
 * The watch is started before the change is made and read back on a worker
 * thread with a timeout, because {@code watch()} is sent with no timeout at all
 * and would otherwise hang the build if the server never answered.
 * </p>
 */
class ChangeNotifyIT extends AbstractSmbIT {

    /** Generous: the point is to fail rather than hang, not to measure latency. */
    private static final int TIMEOUT_SECONDS = 60;

    /** Long enough for the CHANGE_NOTIFY to reach the server before the change is made. */
    private static final long SETTLE_MILLIS = 1500L;

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    /**
     * Starts the watch, lets it reach the server, then runs {@code change}.
     */
    private List<FileNotifyInformation> watchWhile(final SmbWatchHandle handle, final Callable<Void> change) throws Exception {
        final ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            final Future<List<FileNotifyInformation>> watching = executor.submit(handle::watch);
            Thread.sleep(SETTLE_MILLIS);
            change.call();
            return watching.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("a new file is reported to a watcher")
    void newFileIsReported() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());

        try (SmbWatchHandle handle = this.workDir.watch(FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME, false)) {
            final List<FileNotifyInformation> events = watchWhile(handle, () -> {
                writeFile(this.workDir, "created.txt", "payload");
                return null;
            });
            assertFalse(events.isEmpty(), "the watcher should have been told about the new file");
            final FileNotifyInformation first = events.get(0);
            assertEquals(FileNotifyInformation.FILE_ACTION_ADDED, first.getAction(),
                    "unexpected action: " + first.getAction() + " for " + first.getFileName());
            assertEquals("created.txt", first.getFileName(), "the event should name the file that was created");
        }
    }

    @Test
    @DisplayName("a removed file is reported to a watcher")
    void removedFileIsReported() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile doomed = writeFile(this.workDir, "doomed.txt", "payload");

        try (SmbWatchHandle handle = this.workDir.watch(FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME, false)) {
            final List<FileNotifyInformation> events = watchWhile(handle, () -> {
                doomed.delete();
                return null;
            });
            assertFalse(events.isEmpty(), "the watcher should have been told about the removal");
            assertTrue(events.stream().anyMatch(e -> "doomed.txt".equals(e.getFileName())), "no event named the removed file: " + events);
        }
    }

    @Test
    @DisplayName("a recursive watch sees a change in a subdirectory")
    void recursiveWatchSeesASubdirectory() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile subdir = new SmbFile(this.workDir, "nested/");
        subdir.mkdirs();

        try (SmbWatchHandle handle = this.workDir.watch(FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME, true)) {
            final List<FileNotifyInformation> events = watchWhile(handle, () -> {
                writeFile(subdir, "deep.txt", "payload");
                return null;
            });
            assertFalse(events.isEmpty(), "the recursive watcher should have been told about the nested file");
            assertTrue(events.stream().anyMatch(e -> e.getFileName() != null && e.getFileName().endsWith("deep.txt")),
                    "no event named the nested file: " + events);
        }
    }

    /**
     * What separates {@code cancel()} from {@code close()}: both end a pending watch, but a cancel is answered with
     * STATUS_CANCELLED and leaves the open in place, so the directory can still be watched afterwards. A close is
     * answered - on Samba at least - with STATUS_NOTIFY_CLEANUP and an empty change set, and the open is gone.
     */
    @Test
    @DisplayName("cancel() ends a pending watch and leaves the file open")
    void cancelEndsAPendingWatch() throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());

        try (SmbWatchHandle handle = this.workDir.watch(FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME, false)) {
            final ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                final Future<List<FileNotifyInformation>> watching = executor.submit(handle::watch);
                Thread.sleep(SETTLE_MILLIS);
                assertFalse(watching.isDone(), "the watch already returned, so cancelling it would prove nothing");

                handle.cancel();

                assertNull(watching.get(TIMEOUT_SECONDS, TimeUnit.SECONDS),
                        "a cancelled watch reports itself cancelled, it does not return a change set");
            } finally {
                executor.shutdownNow();
            }

            final List<FileNotifyInformation> events = watchWhile(handle, () -> {
                writeFile(this.workDir, "after-cancel.txt", "payload");
                return null;
            });
            assertFalse(events.isEmpty(), "the open should have survived the cancel and still report changes");
        }
    }
}
