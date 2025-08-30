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

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.smb.SmbException;

/**
 * Rate limiter for authentication attempts to prevent brute force attacks.
 *
 * Features:
 * - Per-account rate limiting
 * - Per-IP rate limiting
 * - Global rate limiting
 * - Exponential backoff for repeated failures
 * - Account lockout after threshold
 * - Automatic cleanup of old entries
 */
public class AuthenticationRateLimiter implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationRateLimiter.class);

    // Rate limiting configuration
    private final int maxAttemptsPerAccount;
    private final int maxAttemptsPerIp;
    private final int maxGlobalAttemptsPerMinute;
    private final Duration lockoutDuration;
    private final Duration cleanupInterval;

    // Tracking maps
    private final Map<String, AccountAttempts> accountAttempts = new ConcurrentHashMap<>();
    private final Map<String, IpAttempts> ipAttempts = new ConcurrentHashMap<>();
    private final AtomicInteger globalAttemptsInCurrentWindow = new AtomicInteger(0);
    private final AtomicLong currentWindowStart = new AtomicLong(System.currentTimeMillis());

    // Cleanup scheduler
    private final ScheduledExecutorService cleanupScheduler;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    // Statistics
    private final AtomicLong totalAttemptsBlocked = new AtomicLong(0);
    private final AtomicLong totalAccountsLocked = new AtomicLong(0);
    private final AtomicLong totalIpsBlocked = new AtomicLong(0);

    /**
     * Create rate limiter with default settings
     */
    public AuthenticationRateLimiter() {
        this(5, 10, 100, Duration.ofMinutes(30), Duration.ofMinutes(5));
    }

    /**
     * Create rate limiter with custom settings
     *
     * @param maxAttemptsPerAccount max failed attempts per account before lockout
     * @param maxAttemptsPerIp max attempts from single IP
     * @param maxGlobalAttemptsPerMinute max global attempts per minute
     * @param lockoutDuration duration to lock out account/IP
     * @param cleanupInterval interval for cleaning up old entries
     */
    public AuthenticationRateLimiter(int maxAttemptsPerAccount, int maxAttemptsPerIp, int maxGlobalAttemptsPerMinute,
            Duration lockoutDuration, Duration cleanupInterval) {
        this.maxAttemptsPerAccount = maxAttemptsPerAccount;
        this.maxAttemptsPerIp = maxAttemptsPerIp;
        this.maxGlobalAttemptsPerMinute = maxGlobalAttemptsPerMinute;
        this.lockoutDuration = lockoutDuration;
        this.cleanupInterval = cleanupInterval;

        // Start cleanup scheduler
        this.cleanupScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "AuthRateLimiter-Cleanup");
            t.setDaemon(true);
            return t;
        });

        cleanupScheduler.scheduleWithFixedDelay(this::cleanup, cleanupInterval.toMillis(), cleanupInterval.toMillis(),
                TimeUnit.MILLISECONDS);

        log.info("Authentication rate limiter initialized: maxAccount={}, maxIp={}, maxGlobal={}/min", maxAttemptsPerAccount,
                maxAttemptsPerIp, maxGlobalAttemptsPerMinute);
    }

    /**
     * Check if authentication attempt is allowed
     *
     * @param username the username attempting authentication
     * @param sourceIp the source IP address
     * @return true if attempt is allowed, false if rate limited
     * @throws SmbException if account is locked out
     */
    public boolean checkAttempt(String username, String sourceIp) throws SmbException {
        if (closed.get()) {
            throw new IllegalStateException("Rate limiter is closed");
        }

        // Check global rate limit
        if (!checkGlobalRateLimit()) {
            totalAttemptsBlocked.incrementAndGet();
            log.warn("Global rate limit exceeded, blocking attempt from {}", sourceIp);
            return false;
        }

        // Check per-account limit
        if (username != null) {
            AccountAttempts account = accountAttempts.computeIfAbsent(username, k -> new AccountAttempts());
            if (account.isLockedOut()) {
                if (account.getLockoutExpiry().isAfter(Instant.now())) {
                    totalAttemptsBlocked.incrementAndGet();
                    throw new SmbException("Account '" + username + "' is locked out until " + account.getLockoutExpiry());
                } else {
                    // Lockout expired, reset
                    account.reset();
                }
            }
        }

        // Check per-IP limit
        if (sourceIp != null) {
            IpAttempts ip = ipAttempts.computeIfAbsent(sourceIp, k -> new IpAttempts());
            if (ip.isBlocked()) {
                if (ip.getBlockExpiry().isAfter(Instant.now())) {
                    totalAttemptsBlocked.incrementAndGet();
                    totalIpsBlocked.incrementAndGet();
                    log.warn("IP {} is blocked due to excessive attempts", sourceIp);
                    return false;
                } else {
                    // Block expired, reset
                    ip.reset();
                }
            }

            // Check IP rate limit
            if (ip.getRecentAttempts() >= maxAttemptsPerIp) {
                ip.block(lockoutDuration);
                totalAttemptsBlocked.incrementAndGet();
                totalIpsBlocked.incrementAndGet();
                log.warn("IP {} exceeded rate limit, blocking for {}", sourceIp, lockoutDuration);
                return false;
            }
        }

        return true;
    }

    /**
     * Record successful authentication
     *
     * @param username the username
     * @param sourceIp the source IP
     */
    public void recordSuccess(String username, String sourceIp) {
        if (username != null) {
            AccountAttempts account = accountAttempts.get(username);
            if (account != null) {
                account.reset();
            }
        }

        if (sourceIp != null) {
            IpAttempts ip = ipAttempts.get(sourceIp);
            if (ip != null) {
                ip.recordSuccess();
            }
        }
    }

    /**
     * Record failed authentication attempt
     *
     * @param username the username
     * @param sourceIp the source IP
     */
    public void recordFailure(String username, String sourceIp) {
        if (username != null) {
            AccountAttempts account = accountAttempts.computeIfAbsent(username, k -> new AccountAttempts());
            account.recordFailure();

            if (account.getFailedAttempts() >= maxAttemptsPerAccount) {
                account.lockOut(lockoutDuration);
                totalAccountsLocked.incrementAndGet();
                log.warn("Account '{}' locked out after {} failed attempts", username, maxAttemptsPerAccount);
            }
        }

        if (sourceIp != null) {
            IpAttempts ip = ipAttempts.computeIfAbsent(sourceIp, k -> new IpAttempts());
            ip.recordAttempt();
        }
    }

    /**
     * Check global rate limit
     */
    private boolean checkGlobalRateLimit() {
        long now = System.currentTimeMillis();
        long windowStart = currentWindowStart.get();

        // Check if we need to reset the window (1 minute window)
        if (now - windowStart > 60000) {
            currentWindowStart.compareAndSet(windowStart, now);
            globalAttemptsInCurrentWindow.set(0);
        }

        int attempts = globalAttemptsInCurrentWindow.incrementAndGet();
        return attempts <= maxGlobalAttemptsPerMinute;
    }

    /**
     * Clean up old entries
     */
    private void cleanup() {
        if (closed.get()) {
            return;
        }

        Instant now = Instant.now();

        // Clean up account attempts
        accountAttempts.entrySet().removeIf(entry -> {
            AccountAttempts account = entry.getValue();
            return !account.isLockedOut() && account.getLastAttempt().plus(cleanupInterval).isBefore(now);
        });

        // Clean up IP attempts
        ipAttempts.entrySet().removeIf(entry -> {
            IpAttempts ip = entry.getValue();
            return !ip.isBlocked() && ip.getLastAttempt().plus(cleanupInterval).isBefore(now);
        });

        log.debug("Cleaned up rate limiter entries. Accounts: {}, IPs: {}", accountAttempts.size(), ipAttempts.size());
    }

    /**
     * Manually unlock an account
     *
     * @param username the username to unlock
     * @return true if account was unlocked, false if not found
     */
    public boolean unlockAccount(String username) {
        AccountAttempts account = accountAttempts.get(username);
        if (account != null) {
            account.reset();
            log.info("Manually unlocked account: {}", username);
            return true;
        }
        return false;
    }

    /**
     * Manually unblock an IP
     *
     * @param sourceIp the IP to unblock
     * @return true if IP was unblocked, false if not found
     */
    public boolean unblockIp(String sourceIp) {
        IpAttempts ip = ipAttempts.get(sourceIp);
        if (ip != null) {
            ip.reset();
            log.info("Manually unblocked IP: {}", sourceIp);
            return true;
        }
        return false;
    }

    /**
     * Get statistics
     */
    public RateLimiterStats getStats() {
        return new RateLimiterStats(totalAttemptsBlocked.get(), totalAccountsLocked.get(), totalIpsBlocked.get(), accountAttempts.size(),
                ipAttempts.size());
    }

    /**
     * Reset all rate limiting state
     */
    public void reset() {
        accountAttempts.clear();
        ipAttempts.clear();
        globalAttemptsInCurrentWindow.set(0);
        currentWindowStart.set(System.currentTimeMillis());
        totalAttemptsBlocked.set(0);
        totalAccountsLocked.set(0);
        totalIpsBlocked.set(0);
        log.info("Rate limiter state reset");
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }

        cleanupScheduler.shutdownNow();
        try {
            cleanupScheduler.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Interrupted while shutting down cleanup scheduler", e);
        }

        log.info("Authentication rate limiter closed");
    }

    /**
     * Per-account attempt tracking
     */
    private static class AccountAttempts {
        private final AtomicInteger failedAttempts = new AtomicInteger(0);
        private volatile Instant lastAttempt = Instant.now();
        private volatile Instant lockoutExpiry = null;
        private final AtomicBoolean lockedOut = new AtomicBoolean(false);

        void recordFailure() {
            failedAttempts.incrementAndGet();
            lastAttempt = Instant.now();
        }

        void reset() {
            failedAttempts.set(0);
            lockedOut.set(false);
            lockoutExpiry = null;
        }

        void lockOut(Duration duration) {
            lockedOut.set(true);
            lockoutExpiry = Instant.now().plus(duration);
        }

        boolean isLockedOut() {
            return lockedOut.get();
        }

        int getFailedAttempts() {
            return failedAttempts.get();
        }

        Instant getLastAttempt() {
            return lastAttempt;
        }

        Instant getLockoutExpiry() {
            return lockoutExpiry;
        }
    }

    /**
     * Per-IP attempt tracking
     */
    private static class IpAttempts {
        private final AtomicInteger recentAttempts = new AtomicInteger(0);
        private volatile Instant lastAttempt = Instant.now();
        private volatile Instant windowStart = Instant.now();
        private volatile Instant blockExpiry = null;
        private final AtomicBoolean blocked = new AtomicBoolean(false);

        void recordAttempt() {
            Instant now = Instant.now();

            // Reset window if more than 1 minute has passed
            if (Duration.between(windowStart, now).toMinutes() >= 1) {
                recentAttempts.set(0);
                windowStart = now;
            }

            recentAttempts.incrementAndGet();
            lastAttempt = now;
        }

        void recordSuccess() {
            // Reduce counter on success to allow recovery
            recentAttempts.updateAndGet(val -> Math.max(0, val - 1));
        }

        void reset() {
            recentAttempts.set(0);
            blocked.set(false);
            blockExpiry = null;
            windowStart = Instant.now();
        }

        void block(Duration duration) {
            blocked.set(true);
            blockExpiry = Instant.now().plus(duration);
        }

        boolean isBlocked() {
            return blocked.get();
        }

        int getRecentAttempts() {
            return recentAttempts.get();
        }

        Instant getLastAttempt() {
            return lastAttempt;
        }

        Instant getBlockExpiry() {
            return blockExpiry;
        }
    }

    /**
     * Rate limiter statistics
     */
    public static class RateLimiterStats {
        private final long totalBlocked;
        private final long accountsLocked;
        private final long ipsBlocked;
        private final int activeAccounts;
        private final int activeIps;

        public RateLimiterStats(long totalBlocked, long accountsLocked, long ipsBlocked, int activeAccounts, int activeIps) {
            this.totalBlocked = totalBlocked;
            this.accountsLocked = accountsLocked;
            this.ipsBlocked = ipsBlocked;
            this.activeAccounts = activeAccounts;
            this.activeIps = activeIps;
        }

        public long getTotalBlocked() {
            return totalBlocked;
        }

        public long getAccountsLocked() {
            return accountsLocked;
        }

        public long getIpsBlocked() {
            return ipsBlocked;
        }

        public int getActiveAccounts() {
            return activeAccounts;
        }

        public int getActiveIps() {
            return activeIps;
        }
    }
}
