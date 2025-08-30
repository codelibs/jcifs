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
package jcifs.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jcifs.smb.SmbException;

/**
 * Test cases for AuthenticationRateLimiter
 */
public class AuthenticationRateLimiterTest {

    private AuthenticationRateLimiter rateLimiter;

    @BeforeEach
    public void setUp() {
        // Create rate limiter with test-friendly settings
        rateLimiter = new AuthenticationRateLimiter(3, // max attempts per account
                5, // max attempts per IP
                20, // max global attempts per minute
                Duration.ofSeconds(2), // short lockout for testing
                Duration.ofMinutes(1) // cleanup interval
        );
    }

    @AfterEach
    public void tearDown() {
        if (rateLimiter != null) {
            rateLimiter.close();
        }
    }

    @Test
    public void testNormalAuthentication() throws Exception {
        // Normal authentication should be allowed
        assertTrue(rateLimiter.checkAttempt("user1", "192.168.1.1"), "First attempt should be allowed");

        // Record success
        rateLimiter.recordSuccess("user1", "192.168.1.1");

        // Should still be allowed
        assertTrue(rateLimiter.checkAttempt("user1", "192.168.1.1"), "After success should be allowed");
    }

    @Test
    public void testAccountLockout() throws Exception {
        String username = "testuser";
        String ip = "192.168.1.2";

        // First attempts should be allowed
        assertTrue(rateLimiter.checkAttempt(username, ip));
        rateLimiter.recordFailure(username, ip);

        assertTrue(rateLimiter.checkAttempt(username, ip));
        rateLimiter.recordFailure(username, ip);

        assertTrue(rateLimiter.checkAttempt(username, ip));
        rateLimiter.recordFailure(username, ip);

        // After 3 failures, account should be locked
        try {
            rateLimiter.checkAttempt(username, ip);
            fail("Should throw SmbException for locked account");
        } catch (SmbException e) {
            assertTrue(e.getMessage().contains("locked out"), "Should indicate account lockout");
        }
    }

    @Test
    public void testIpRateLimit() throws Exception {
        String ip = "192.168.1.3";

        // Make attempts from same IP with different users
        for (int i = 1; i <= 5; i++) {
            assertTrue(rateLimiter.checkAttempt("user" + i, ip), "Attempt " + i + " should be allowed");
            rateLimiter.recordFailure("user" + i, ip);
        }

        // 6th attempt from same IP should be blocked
        assertFalse(rateLimiter.checkAttempt("user6", ip), "Should block after IP rate limit");
    }

    @Test
    public void testDifferentIpsIndependent() throws Exception {
        // Different IPs should have independent limits
        for (int i = 1; i <= 3; i++) {
            assertTrue(rateLimiter.checkAttempt("user1", "192.168.1." + i));
            rateLimiter.recordFailure("user1", "192.168.1." + i);
        }

        // All different IPs should still be allowed
        for (int i = 1; i <= 3; i++) {
            assertTrue(rateLimiter.checkAttempt("user2", "192.168.1." + i));
        }
    }

    @Test
    public void testGlobalRateLimit() throws Exception {
        // Make many attempts to trigger global rate limit
        for (int i = 1; i <= 20; i++) {
            assertTrue(rateLimiter.checkAttempt("user" + i, "192.168.1." + i), "Attempt " + i + " should be allowed");
        }

        // 21st attempt should be blocked by global rate limit
        assertFalse(rateLimiter.checkAttempt("user21", "192.168.1.21"), "Should block after global rate limit");
    }

    @Test
    public void testLockoutExpiry() throws Exception {
        String username = "expireuser";
        String ip = "192.168.1.4";

        // Lock out the account
        for (int i = 0; i < 3; i++) {
            assertTrue(rateLimiter.checkAttempt(username, ip));
            rateLimiter.recordFailure(username, ip);
        }

        // Should be locked out
        try {
            rateLimiter.checkAttempt(username, ip);
            fail("Should be locked out");
        } catch (SmbException e) {
            // Expected
        }

        // Wait for lockout to expire
        Thread.sleep(2100); // Lockout is 2 seconds in test setup

        // Should be allowed again
        assertTrue(rateLimiter.checkAttempt(username, ip), "Should be allowed after lockout expiry");
    }

    @Test
    public void testSuccessResetsCounter() throws Exception {
        String username = "resetuser";
        String ip = "192.168.1.5";

        // Two failures
        assertTrue(rateLimiter.checkAttempt(username, ip));
        rateLimiter.recordFailure(username, ip);

        assertTrue(rateLimiter.checkAttempt(username, ip));
        rateLimiter.recordFailure(username, ip);

        // Success should reset counter
        assertTrue(rateLimiter.checkAttempt(username, ip));
        rateLimiter.recordSuccess(username, ip);

        // Should be able to fail 3 more times before lockout
        for (int i = 0; i < 3; i++) {
            assertTrue(rateLimiter.checkAttempt(username, ip));
            rateLimiter.recordFailure(username, ip);
        }

        // Now should be locked out
        try {
            rateLimiter.checkAttempt(username, ip);
            fail("Should be locked out");
        } catch (SmbException e) {
            // Expected
        }
    }

    @Test
    public void testManualUnlock() throws Exception {
        String username = "manualuser";
        String ip = "192.168.1.6";

        // Lock out the account
        for (int i = 0; i < 3; i++) {
            assertTrue(rateLimiter.checkAttempt(username, ip));
            rateLimiter.recordFailure(username, ip);
        }

        // Should be locked out
        try {
            rateLimiter.checkAttempt(username, ip);
            fail("Should be locked out");
        } catch (SmbException e) {
            // Expected
        }

        // Manually unlock
        assertTrue(rateLimiter.unlockAccount(username), "Manual unlock should succeed");

        // Should be allowed again
        assertTrue(rateLimiter.checkAttempt(username, ip), "Should be allowed after manual unlock");
    }

    @Test
    public void testManualUnblockIp() throws Exception {
        String ip = "192.168.1.7";

        // Block the IP
        for (int i = 1; i <= 5; i++) {
            assertTrue(rateLimiter.checkAttempt("user" + i, ip));
            rateLimiter.recordFailure("user" + i, ip);
        }

        // Should be blocked
        assertFalse(rateLimiter.checkAttempt("user6", ip), "IP should be blocked");

        // Manually unblock
        assertTrue(rateLimiter.unblockIp(ip), "Manual unblock should succeed");

        // Should be allowed again
        assertTrue(rateLimiter.checkAttempt("user7", ip), "Should be allowed after manual unblock");
    }

    @Test
    public void testNullUsername() throws Exception {
        // Null username should be handled gracefully
        assertTrue(rateLimiter.checkAttempt(null, "192.168.1.8"), "Null username should be allowed");

        // Should not affect IP limiting
        rateLimiter.recordFailure(null, "192.168.1.8");
        assertTrue(rateLimiter.checkAttempt("realuser", "192.168.1.8"), "Should still track IP");
    }

    @Test
    public void testNullIp() throws Exception {
        // Null IP should be handled gracefully
        assertTrue(rateLimiter.checkAttempt("user1", null), "Null IP should be allowed");

        // Should not affect account limiting
        rateLimiter.recordFailure("user1", null);
        assertTrue(rateLimiter.checkAttempt("user1", "192.168.1.9"), "Should still track account");
    }

    @Test
    public void testStatistics() throws Exception {
        // Initially stats should be zero
        AuthenticationRateLimiter.RateLimiterStats stats = rateLimiter.getStats();
        assertEquals(0, stats.getTotalBlocked());
        assertEquals(0, stats.getAccountsLocked());
        assertEquals(0, stats.getIpsBlocked());

        // Create some activity
        String username = "statsuser";
        String ip = "192.168.1.10";

        // Lock out an account
        for (int i = 0; i < 3; i++) {
            rateLimiter.checkAttempt(username, ip);
            rateLimiter.recordFailure(username, ip);
        }

        // Try after lockout (will be blocked)
        try {
            rateLimiter.checkAttempt(username, ip);
        } catch (SmbException e) {
            // Expected
        }

        // Block an IP
        String ip2 = "192.168.1.11";
        for (int i = 1; i <= 5; i++) {
            rateLimiter.checkAttempt("user" + i, ip2);
            rateLimiter.recordFailure("user" + i, ip2);
        }
        rateLimiter.checkAttempt("user6", ip2); // Will be blocked

        // Check stats
        stats = rateLimiter.getStats();
        assertEquals(2, stats.getTotalBlocked()); // One for account, one for IP
        assertEquals(1, stats.getAccountsLocked());
        assertEquals(1, stats.getIpsBlocked());
        assertTrue(stats.getActiveAccounts() > 0);
        assertTrue(stats.getActiveIps() > 0);
    }

    @Test
    public void testReset() throws Exception {
        // Create some state
        String username = "resettest";
        String ip = "192.168.1.12";

        for (int i = 0; i < 2; i++) {
            rateLimiter.checkAttempt(username, ip);
            rateLimiter.recordFailure(username, ip);
        }

        // Should have some state
        AuthenticationRateLimiter.RateLimiterStats stats = rateLimiter.getStats();
        assertTrue(stats.getActiveAccounts() > 0);

        // Reset
        rateLimiter.reset();

        // State should be cleared
        stats = rateLimiter.getStats();
        assertEquals(0, stats.getTotalBlocked());
        assertEquals(0, stats.getAccountsLocked());
        assertEquals(0, stats.getIpsBlocked());
        assertEquals(0, stats.getActiveAccounts());
        assertEquals(0, stats.getActiveIps());

        // Should be able to start fresh
        for (int i = 0; i < 3; i++) {
            assertTrue(rateLimiter.checkAttempt(username, ip));
            rateLimiter.recordFailure(username, ip);
        }
    }

    @Test
    public void testConcurrentAccess() throws Exception {
        // Test thread safety with concurrent access
        // Use a separate rate limiter instance with higher limits for this test
        AuthenticationRateLimiter concurrentLimiter = new AuthenticationRateLimiter(5, // max attempts per account (higher than default 3)
                10, // max attempts per IP (higher than default 5)
                100, // max global attempts per minute (much higher than default 20)
                Duration.ofSeconds(2), Duration.ofMinutes(1));

        try {
            final int numThreads = 10;
            final int attemptsPerThread = 5;

            Thread[] threads = new Thread[numThreads];
            final AtomicInteger successfulThreads = new AtomicInteger(0);
            final AtomicInteger blockedAttempts = new AtomicInteger(0);
            final AtomicInteger exceptionCount = new AtomicInteger(0);

            for (int i = 0; i < numThreads; i++) {
                final int threadId = i;
                threads[i] = new Thread(() -> {
                    try {
                        int localFailures = 0;
                        for (int j = 0; j < attemptsPerThread; j++) {
                            boolean allowed = false;
                            try {
                                allowed = concurrentLimiter.checkAttempt("user" + threadId, "192.168.2." + threadId);
                            } catch (SmbException e) {
                                // Account locked out - this is expected behavior in concurrent scenario
                                blockedAttempts.incrementAndGet();
                                break; // Stop trying if account is locked
                            }

                            if (!allowed) {
                                // Rate limited but not locked out
                                blockedAttempts.incrementAndGet();
                                continue;
                            }

                            // Only record failure/success if the attempt was allowed
                            if (j % 2 == 0) {
                                concurrentLimiter.recordFailure("user" + threadId, "192.168.2." + threadId);
                                localFailures++;
                                // Prevent lockout by resetting after 3 failures
                                if (localFailures >= 3) {
                                    concurrentLimiter.recordSuccess("user" + threadId, "192.168.2." + threadId);
                                    localFailures = 0;
                                }
                            } else {
                                concurrentLimiter.recordSuccess("user" + threadId, "192.168.2." + threadId);
                                localFailures = 0; // Reset on success
                            }

                            Thread.sleep(5); // Small delay to spread out requests
                        }
                        successfulThreads.incrementAndGet();
                    } catch (Exception e) {
                        exceptionCount.incrementAndGet();
                        e.printStackTrace();
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

            // Verify thread safety - no unexpected exceptions
            assertEquals(0, exceptionCount.get(), "Should not have unexpected exceptions");

            // At least some threads should complete successfully
            assertTrue(successfulThreads.get() > 0, "At least some threads should complete successfully");

            // The rate limiter should still be functional after concurrent access
            assertTrue(concurrentLimiter.checkAttempt("finaluser", "192.168.3.1"),
                    "Rate limiter should still be functional after concurrent operations");

            // Verify that the rate limiter tracked some activity
            AuthenticationRateLimiter.RateLimiterStats stats = concurrentLimiter.getStats();
            assertTrue(stats.getActiveAccounts() > 0 || stats.getActiveIps() > 0, "Should have tracked some activity");
        } finally {
            concurrentLimiter.close();
        }
    }

    @Test
    public void testAutoCloseableInterface() throws Exception {
        // Test that rate limiter implements AutoCloseable correctly
        try (AuthenticationRateLimiter autoLimiter = new AuthenticationRateLimiter()) {
            assertTrue(autoLimiter.checkAttempt("user", "192.168.1.13"));
        }
        // Should auto-close without issues
    }
}
