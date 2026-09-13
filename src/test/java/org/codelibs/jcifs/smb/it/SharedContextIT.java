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

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.context.BaseContext;
import org.codelibs.jcifs.smb.impl.NtlmPasswordAuthenticator;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * One context serving many threads at once.
 *
 * <p>
 * A crawler builds a single {@link BaseContext} when it starts and shares it
 * between all of its worker threads. For every URL a worker fetches it wraps that
 * context with {@code withCredentials} - a new wrapper each time - and opens a new
 * {@link SmbFile}. Every other test here drives a context from one thread, so
 * nothing else shows that the connections and sessions pooled behind a shared
 * context give each concurrent caller its own answers.
 * </p>
 */
class SharedContextIT extends AbstractSmbIT {

    private static final int FILES = 16;
    private static final int THREADS = 8;
    private static final int ROUNDS = 25;

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    @Test
    @DisplayName("threads sharing one context each read back the file they asked for")
    void threadsSharingOneContextReadTheirOwnFiles() throws Exception {
        this.workDir = createWorkDir(server().context(), server().share());
        final List<String> urls = new ArrayList<>();
        for (int i = 0; i < FILES; i++) {
            urls.add(writeFile(this.workDir, "file-" + i + ".txt", contentsFor(i)).getURL().toExternalForm());
        }

        final BaseContext shared = new BaseContext(new PropertyConfiguration(server().defaultProperties()));
        // A crawler configured without a domain passes an empty one rather than null.
        final String domain = server().domain() == null ? "" : server().domain();
        // Nothing is connected before the threads start, as when a crawler starts: they all reach an idle pool
        // together, and have to end up on one connection rather than each opening its own.
        final ExecutorService executor = Executors.newFixedThreadPool(THREADS);
        try {
            final CountDownLatch start = new CountDownLatch(1);
            final List<Future<?>> workers = new ArrayList<>();
            for (int t = 0; t < THREADS; t++) {
                final int worker = t;
                workers.add(executor.submit(() -> {
                    start.await();
                    for (int round = 0; round < ROUNDS; round++) {
                        final int index = (worker * 7 + round) % FILES;
                        final CIFSContext perRequest =
                                shared.withCredentials(new NtlmPasswordAuthenticator(domain, server().user(), server().password()));
                        try (SmbFile file = new SmbFile(urls.get(index), perRequest)) {
                            assertTrue(file.isFile(), urls.get(index) + " should be a file");
                            assertEquals(contentsFor(index).length(), file.length(), "wrong length for " + urls.get(index));
                            try (InputStream in = file.getInputStream()) {
                                assertEquals(contentsFor(index), new String(in.readAllBytes(), StandardCharsets.UTF_8),
                                        "wrong contents for " + urls.get(index));
                            }
                        }
                    }
                    return null;
                }));
            }
            start.countDown();
            for (final Future<?> worker : workers) {
                worker.get(2, TimeUnit.MINUTES);
            }
        } finally {
            executor.shutdownNow();
            shared.close();
        }
    }

    private static String contentsFor(final int index) {
        return "contents of file " + index + " " + "x".repeat(index * 97);
    }
}
