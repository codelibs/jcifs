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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.it.env.TcpRelay;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A server that stops answering while the connection stays up.
 *
 * <p>
 * Nothing on the wire ends a wait for a reply that is not coming: the socket is
 * healthy and the server has simply gone quiet. Two things can end it - the
 * response timeout, {@code jcifs.client.responseTimeout}, and the waiting thread
 * being interrupted. A crawler relies on both. It sets the timeout for every
 * fetch, and it enforces its own access timeout by interrupting the worker thread,
 * after which it carries on with the same context for the next URL.
 * </p>
 *
 * <p>
 * The server sits behind a {@link TcpRelay} that holds back what it sends. Each
 * test connects before holding anything, so what is held is a reply on a live
 * session rather than the negotiation.
 * </p>
 */
class StalledReplyIT extends AbstractSmbIT {

    private static final long SHORT_RESPONSE_TIMEOUT_MILLIS = 2_000;

    /** What a crawler configures; long enough that only an interrupt can end the wait inside the bound below. */
    private static final long LONG_RESPONSE_TIMEOUT_MILLIS = 30_000;

    /**
     * How long a wait that the short timeout ended may take. A request that times out is retried
     * ({@code jcifs.client.maxRequestRetries}) and the retry waits again, so this is a multiple of the timeout rather
     * than the timeout itself; it only has to be clearly shorter than a wait that nothing ended.
     */
    private static final long TIMED_OUT_BOUND_MILLIS = 30_000;

    private static final long INTERRUPT_BOUND_MILLIS = 5_000;

    @Test
    @DisplayName("the response timeout ends a wait for a reply that never comes")
    void responseTimeoutEndsTheWait() throws Exception {
        try (TcpRelay relay = TcpRelay.to(server().host(), server().port())) {
            final CIFSContext context = contextWithResponseTimeout(SHORT_RESPONSE_TIMEOUT_MILLIS);
            final String url = relayedUrl(relay, "target.txt");
            assertTrue(new SmbFile(url, context).exists(), "the fixture file should be reachable through the relay");

            relay.holdReplies();
            final long started = System.nanoTime();
            assertThrows(SmbException.class, () -> new SmbFile(url, context).exists(), "a request the server never answers should fail");
            final long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
            assertTrue(elapsed >= SHORT_RESPONSE_TIMEOUT_MILLIS / 2, "the request gave up after " + elapsed + " ms, before the timeout");
            assertTrue(elapsed < TIMED_OUT_BOUND_MILLIS,
                    "the request waited " + elapsed + " ms despite a " + SHORT_RESPONSE_TIMEOUT_MILLIS + " ms response timeout");

            relay.releaseReplies();
            assertTrue(new SmbFile(url, context).exists(), "the context should serve requests again once the server answers");
        }
    }

    @Test
    @DisplayName("interrupting a thread waiting for a reply ends the wait and leaves the context usable")
    void interruptEndsTheWait() throws Exception {
        try (TcpRelay relay = TcpRelay.to(server().host(), server().port())) {
            final CIFSContext context = contextWithResponseTimeout(LONG_RESPONSE_TIMEOUT_MILLIS);
            final String url = relayedUrl(relay, "target.txt");
            assertTrue(new SmbFile(url, context).exists(), "the fixture file should be reachable through the relay");

            relay.holdReplies();
            final AtomicReference<Throwable> failure = new AtomicReference<>();
            final AtomicBoolean returned = new AtomicBoolean();
            final Thread worker = new Thread(() -> {
                try {
                    new SmbFile(url, context).exists();
                    returned.set(true);
                } catch (final Throwable t) {
                    failure.set(t);
                }
            }, "stalled-reply-worker");
            worker.setDaemon(true);
            worker.start();
            awaitWaiting(worker);

            final long interrupted = System.nanoTime();
            worker.interrupt();
            worker.join(INTERRUPT_BOUND_MILLIS);
            final long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - interrupted);
            assertFalse(worker.isAlive(), () -> "the thread was still waiting " + elapsed + " ms after it was interrupted, at:\n"
                    + Arrays.stream(worker.getStackTrace()).map(frame -> "\tat " + frame).collect(Collectors.joining("\n")));
            assertFalse(returned.get(), "a request whose reply was held back should not have succeeded");
            assertNotNull(failure.get(), "the interrupted request should have failed");
            assertTrue(failure.get() instanceof SmbException, "unexpected failure: " + failure.get());

            relay.releaseReplies();
            assertTrue(new SmbFile(url, context).exists(), "the context should serve requests again after an interrupted one");
        }
    }

    private CIFSContext contextWithResponseTimeout(final long millis) throws Exception {
        final Properties props = new Properties();
        props.setProperty("jcifs.client.responseTimeout", String.valueOf(millis));
        return server().context(props);
    }

    private static String relayedUrl(final TcpRelay relay, final String path) {
        return "smb://" + relay.host() + ":" + relay.port() + "/" + server().share() + "/" + path;
    }

    /**
     * Waits until the thread is parked, which is where a request waiting for its
     * reply sits. Interrupting it any earlier would test whatever it was doing first.
     */
    private static void awaitWaiting(final Thread thread) throws InterruptedException {
        final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            final Thread.State state = thread.getState();
            if (state == Thread.State.WAITING || state == Thread.State.TIMED_WAITING) {
                return;
            }
            Thread.sleep(10);
        }
        throw new AssertionError("the request never started waiting; its thread is " + thread.getState());
    }
}
