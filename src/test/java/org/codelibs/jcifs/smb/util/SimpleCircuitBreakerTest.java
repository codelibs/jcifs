/*
 * © 2025 CodeLibs, Inc.
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.codelibs.jcifs.smb.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for SimpleCircuitBreaker
 */
public class SimpleCircuitBreakerTest {

    private SimpleCircuitBreaker circuitBreaker;

    @BeforeEach
    void setUp() {
        circuitBreaker = new SimpleCircuitBreaker("test", 3, 2, 100);
    }

    @Test
    @DisplayName("Test initial state is CLOSED")
    void testInitialState() {
        assertEquals(SimpleCircuitBreaker.State.CLOSED, circuitBreaker.getState());
        assertTrue(circuitBreaker.allowsRequests());
    }

    @Test
    @DisplayName("Test successful calls in CLOSED state")
    void testSuccessfulCalls() throws Exception {
        String result = circuitBreaker.call(() -> "success");
        assertEquals("success", result);
        assertEquals(SimpleCircuitBreaker.State.CLOSED, circuitBreaker.getState());

        SimpleCircuitBreaker.Statistics stats = circuitBreaker.getStatistics();
        assertEquals(1, stats.totalCalls);
        assertEquals(1, stats.totalSuccesses);
        assertEquals(0, stats.totalFailures);
        assertEquals(1.0, stats.successRate);
    }

    @Test
    @DisplayName("Test circuit opens after failure threshold")
    void testCircuitOpensAfterThreshold() {
        // Fail 3 times to open the circuit
        for (int i = 0; i < 3; i++) {
            try {
                circuitBreaker.call(() -> {
                    throw new RuntimeException("Test failure");
                });
            } catch (Exception e) {
                // Expected
            }
        }

        assertEquals(SimpleCircuitBreaker.State.OPEN, circuitBreaker.getState());
        assertFalse(circuitBreaker.allowsRequests());

        SimpleCircuitBreaker.Statistics stats = circuitBreaker.getStatistics();
        assertEquals(3, stats.totalFailures);
        assertEquals(3, stats.consecutiveFailures);
    }

    @Test
    @DisplayName("Test requests rejected when circuit is open")
    void testRequestsRejectedWhenOpen() {
        // Open the circuit
        circuitBreaker.tripBreaker();

        assertThrows(SimpleCircuitBreaker.CircuitBreakerOpenException.class, () -> circuitBreaker.call(() -> "should not execute"));

        SimpleCircuitBreaker.Statistics stats = circuitBreaker.getStatistics();
        assertEquals(1, stats.rejectedCalls);
    }

    @Test
    @DisplayName("Test fallback used when circuit is open")
    void testFallbackWhenOpen() throws Exception {
        // Open the circuit
        circuitBreaker.tripBreaker();

        String result = circuitBreaker.call(() -> "primary", () -> "fallback");

        assertEquals("fallback", result);
    }

    @Test
    @DisplayName("Test transition to HALF_OPEN after timeout")
    void testTransitionToHalfOpen() throws Exception {
        // Open the circuit
        circuitBreaker.tripBreaker();
        assertEquals(SimpleCircuitBreaker.State.OPEN, circuitBreaker.getState());

        // Wait for timeout
        Thread.sleep(150);

        // Next call should transition to HALF_OPEN
        String result = circuitBreaker.call(() -> "success");
        assertEquals("success", result);
        assertEquals(SimpleCircuitBreaker.State.HALF_OPEN, circuitBreaker.getState());
    }

    @Test
    @DisplayName("Test circuit closes after success threshold in HALF_OPEN")
    void testCircuitClosesAfterSuccessThreshold() throws Exception {
        // Open the circuit
        circuitBreaker.tripBreaker();

        // Wait for timeout
        Thread.sleep(150);

        // Two successful calls should close the circuit
        circuitBreaker.call(() -> "success1");
        assertEquals(SimpleCircuitBreaker.State.HALF_OPEN, circuitBreaker.getState());

        circuitBreaker.call(() -> "success2");
        assertEquals(SimpleCircuitBreaker.State.CLOSED, circuitBreaker.getState());
    }

    @Test
    @DisplayName("Test circuit reopens on failure in HALF_OPEN")
    void testCircuitReopensOnFailureInHalfOpen() throws Exception {
        // Open the circuit
        circuitBreaker.tripBreaker();

        // Wait for timeout
        Thread.sleep(150);

        // Single failure in HALF_OPEN should reopen
        try {
            circuitBreaker.call(() -> {
                throw new RuntimeException("Test failure");
            });
        } catch (Exception e) {
            // Expected
        }

        assertEquals(SimpleCircuitBreaker.State.OPEN, circuitBreaker.getState());
    }

    @Test
    @DisplayName("Test reset functionality")
    void testReset() {
        // Open the circuit
        circuitBreaker.tripBreaker();
        assertEquals(SimpleCircuitBreaker.State.OPEN, circuitBreaker.getState());

        // Reset
        circuitBreaker.reset();
        assertEquals(SimpleCircuitBreaker.State.CLOSED, circuitBreaker.getState());
        assertTrue(circuitBreaker.allowsRequests());

        SimpleCircuitBreaker.Statistics stats = circuitBreaker.getStatistics();
        assertEquals(0, stats.consecutiveFailures);
    }

    @Test
    @DisplayName("Test run method")
    void testRunMethod() throws Exception {
        AtomicInteger counter = new AtomicInteger(0);

        circuitBreaker.run(() -> counter.incrementAndGet());
        assertEquals(1, counter.get());

        SimpleCircuitBreaker.Statistics stats = circuitBreaker.getStatistics();
        assertEquals(1, stats.totalCalls);
        assertEquals(1, stats.totalSuccesses);
    }

    @Test
    @DisplayName("Test run method with failure")
    void testRunMethodWithFailure() {
        assertThrows(Exception.class, () -> circuitBreaker.run(() -> {
            throw new RuntimeException("Test failure");
        }));

        SimpleCircuitBreaker.Statistics stats = circuitBreaker.getStatistics();
        assertEquals(1, stats.totalCalls);
        assertEquals(1, stats.totalFailures);
    }

    @Test
    @DisplayName("Test invalid configuration")
    void testInvalidConfiguration() {
        assertThrows(IllegalArgumentException.class, () -> new SimpleCircuitBreaker("invalid", 0, 2, 100));
        assertThrows(IllegalArgumentException.class, () -> new SimpleCircuitBreaker("invalid", 3, 0, 100));
        assertThrows(IllegalArgumentException.class, () -> new SimpleCircuitBreaker("invalid", 3, 2, -1));
    }

    @Test
    @DisplayName("Test statistics toString")
    void testStatisticsToString() throws Exception {
        circuitBreaker.call(() -> "success");

        SimpleCircuitBreaker.Statistics stats = circuitBreaker.getStatistics();
        String str = stats.toString();

        assertNotNull(str);
        assertTrue(str.contains("test"));
        assertTrue(str.contains("CLOSED"));
        assertTrue(str.contains("100.00%"));
    }

    @Test
    @DisplayName("Test mixed success and failure pattern")
    void testMixedPattern() throws Exception {
        // Success
        circuitBreaker.call(() -> "success");

        // Two failures (not enough to open)
        for (int i = 0; i < 2; i++) {
            try {
                circuitBreaker.call(() -> {
                    throw new RuntimeException("Test failure");
                });
            } catch (Exception e) {
                // Expected
            }
        }

        // Still closed
        assertEquals(SimpleCircuitBreaker.State.CLOSED, circuitBreaker.getState());

        // Success resets consecutive failures
        circuitBreaker.call(() -> "success");

        SimpleCircuitBreaker.Statistics stats = circuitBreaker.getStatistics();
        assertEquals(0, stats.consecutiveFailures);
        assertEquals(SimpleCircuitBreaker.State.CLOSED, circuitBreaker.getState());
    }

    @RepeatedTest(10)
    @DisplayName("Test thread safety")
    void testThreadSafety() throws InterruptedException {
        SimpleCircuitBreaker breaker = new SimpleCircuitBreaker("concurrent", 5, 3, 100);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);

        // Create multiple threads
        Thread[] threads = new Thread[10];
        for (int i = 0; i < threads.length; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                for (int j = 0; j < 10; j++) {
                    try {
                        if ((index + j) % 3 == 0) {
                            // Some failures
                            breaker.call(() -> {
                                throw new RuntimeException("Test");
                            });
                        } else {
                            // Some successes
                            breaker.call(() -> "success");
                            successCount.incrementAndGet();
                        }
                    } catch (Exception e) {
                        failureCount.incrementAndGet();
                    }
                }
            });
        }

        // Start all threads
        for (Thread t : threads) {
            t.start();
        }

        // Wait for completion
        for (Thread t : threads) {
            t.join();
        }

        // Verify consistency
        SimpleCircuitBreaker.Statistics stats = breaker.getStatistics();
        assertEquals(successCount.get() + failureCount.get(), stats.totalSuccesses + stats.totalFailures + stats.rejectedCalls);
    }

    @Test
    @DisplayName("Test default constructor")
    void testDefaultConstructor() {
        SimpleCircuitBreaker defaultBreaker = new SimpleCircuitBreaker("default");
        assertEquals("default", defaultBreaker.getName());
        assertEquals(SimpleCircuitBreaker.State.CLOSED, defaultBreaker.getState());
    }
}