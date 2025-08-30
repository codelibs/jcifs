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

import java.util.Deque;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;

/**
 * Circuit breaker pattern implementation for SMB operations.
 * Prevents cascading failures by temporarily blocking requests to a failing service.
 *
 * The circuit breaker has three states:
 * - CLOSED: Normal operation, requests pass through
 * - OPEN: Service is failing, requests are blocked
 * - HALF_OPEN: Testing if service has recovered
 */
public class SmbCircuitBreaker {

    private static final Logger log = LoggerFactory.getLogger(SmbCircuitBreaker.class);

    /**
     * Circuit breaker states
     */
    public enum State {
        /**
         * Normal operation - requests pass through
         */
        CLOSED,

        /**
         * Service is failing - requests are blocked
         */
        OPEN,

        /**
         * Testing if service has recovered
         */
        HALF_OPEN
    }

    private final String name;
    private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);
    private final AtomicInteger failureCount = new AtomicInteger(0);
    private final AtomicInteger successCount = new AtomicInteger(0);
    private final AtomicLong lastFailureTime = new AtomicLong(0);
    private final AtomicLong lastStateChangeTime = new AtomicLong(System.currentTimeMillis());

    // Metrics tracking
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong totalFailures = new AtomicLong(0);
    private final AtomicLong totalSuccesses = new AtomicLong(0);
    private final AtomicLong totalCircuitOpenRejections = new AtomicLong(0);
    private final AtomicLong totalTimeInOpen = new AtomicLong(0);
    private final AtomicLong openStateStartTime = new AtomicLong(0);

    // Event listeners
    private final List<CircuitBreakerListener> listeners = new CopyOnWriteArrayList<>();

    // Configuration
    private volatile int failureThreshold;
    private final int successThreshold;
    private final long resetTimeoutMillis;
    private final long halfOpenMaxAttempts;
    private final AtomicInteger halfOpenAttempts = new AtomicInteger(0);

    // Dynamic threshold adjustment
    private final boolean dynamicThresholdEnabled;
    private final ScheduledExecutorService scheduler;
    private volatile ScheduledFuture<?> thresholdAdjustmentTask;
    private final Deque<Long> responseTimeHistory = new ConcurrentLinkedDeque<>();
    private final AtomicLong avgResponseTime = new AtomicLong(0);
    private final AtomicLong p95ResponseTime = new AtomicLong(0);

    // Backpressure support
    private final boolean backpressureEnabled;
    private final int maxConcurrentRequests;
    private final Semaphore requestSemaphore;
    private final AtomicInteger activeRequests = new AtomicInteger(0);
    private final AtomicLong totalBackpressureRejections = new AtomicLong(0);

    // Enhanced metrics
    private final AtomicLong minResponseTime = new AtomicLong(Long.MAX_VALUE);
    private final AtomicLong maxResponseTime = new AtomicLong(0);
    private final AtomicInteger consecutiveFailures = new AtomicInteger(0);
    private final AtomicInteger consecutiveSuccesses = new AtomicInteger(0);

    // Hystrix-style windowed statistics
    private final RollingWindow rollingWindow = new RollingWindow(10, 1000); // 10 buckets, 1 second each

    /**
     * Create a circuit breaker with default settings
     *
     * @param name circuit breaker name for logging
     */
    public SmbCircuitBreaker(String name) {
        this(name, 5, 3, 60000, 3, false, false, 100);
    }

    /**
     * Create a circuit breaker with custom settings
     *
     * @param name circuit breaker name for logging
     * @param failureThreshold number of failures before opening
     * @param successThreshold number of successes in half-open before closing
     * @param resetTimeoutMillis time to wait before attempting reset (ms)
     * @param halfOpenMaxAttempts max attempts in half-open state
     */
    public SmbCircuitBreaker(String name, int failureThreshold, int successThreshold, long resetTimeoutMillis, long halfOpenMaxAttempts) {
        this(name, failureThreshold, successThreshold, resetTimeoutMillis, halfOpenMaxAttempts, false, false, 100);
    }

    public SmbCircuitBreaker(String name, int failureThreshold, int successThreshold, long resetTimeoutMillis, long halfOpenMaxAttempts,
            boolean dynamicThresholdEnabled, boolean backpressureEnabled, int maxConcurrentRequests) {
        this.name = name;
        this.failureThreshold = failureThreshold;
        this.successThreshold = successThreshold;
        this.resetTimeoutMillis = resetTimeoutMillis;
        this.halfOpenMaxAttempts = halfOpenMaxAttempts;
        this.dynamicThresholdEnabled = dynamicThresholdEnabled;
        this.backpressureEnabled = backpressureEnabled;
        this.maxConcurrentRequests = maxConcurrentRequests;
        this.requestSemaphore = backpressureEnabled ? new Semaphore(maxConcurrentRequests, true) : null;

        // Initialize scheduler for dynamic threshold adjustment
        this.scheduler =
                dynamicThresholdEnabled ? Executors.newScheduledThreadPool(1, r -> new Thread(r, "SmbCircuitBreaker-" + name)) : null;

        // Start dynamic threshold adjustment if enabled
        if (dynamicThresholdEnabled) {
            startDynamicThresholdAdjustment();
        }

        log.info("Created circuit breaker '{}' with failureThreshold={}, dynamicThreshold={}, backpressure={}", name, failureThreshold,
                dynamicThresholdEnabled, backpressureEnabled);
    }

    /**
     * Execute an operation with circuit breaker protection
     *
     * @param <T> return type
     * @param operation the operation to execute
     * @return operation result
     * @throws CIFSException if circuit is open or operation fails
     */
    public <T> T executeWithCircuitBreaker(Supplier<T> operation) throws CIFSException {
        // Backpressure control
        if (backpressureEnabled && requestSemaphore != null) {
            if (!requestSemaphore.tryAcquire()) {
                totalBackpressureRejections.incrementAndGet();
                throw new CIFSException("Circuit breaker '" + name + "' rejected request due to backpressure");
            }
        }

        long startTime = System.nanoTime();
        boolean semaphoreAcquired = backpressureEnabled && requestSemaphore != null;

        try {
            activeRequests.incrementAndGet();

            State currentState = state.get();

            // Check if we should attempt reset
            if (currentState == State.OPEN && shouldAttemptReset()) {
                log.debug("[{}] Attempting to reset circuit breaker from OPEN to HALF_OPEN", name);
                transitionTo(State.HALF_OPEN);
                currentState = State.HALF_OPEN;
            }

            // Block if circuit is open
            if (currentState == State.OPEN) {
                totalRequests.incrementAndGet();
                totalCircuitOpenRejections.incrementAndGet();
                rollingWindow.recordFailure();

                // Notify listeners
                for (CircuitBreakerListener listener : listeners) {
                    try {
                        listener.onCallRejected(this);
                    } catch (Exception ex) {
                        log.warn("Listener threw exception", ex);
                    }
                }

                throw new CircuitOpenException("Circuit breaker '" + name + "' is open");
            }

            totalRequests.incrementAndGet();

            // Check half-open attempt limit
            if (currentState == State.HALF_OPEN) {
                int attempts = halfOpenAttempts.incrementAndGet();
                if (attempts > halfOpenMaxAttempts) {
                    log.warn("[{}] Exceeded max attempts in HALF_OPEN state, reopening circuit", name);
                    transitionTo(State.OPEN);
                    throw new CircuitOpenException("Circuit breaker '" + name + "' reopened after max attempts");
                }
            }

            try {
                T result = operation.get();
                long responseTime = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
                onSuccess(responseTime);
                return result;
            } catch (Exception e) {
                long responseTime = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
                onFailure(e, responseTime);
                if (e instanceof CIFSException) {
                    throw (CIFSException) e;
                }
                throw new CIFSException("Circuit breaker operation failed", e);
            }
        } finally {
            activeRequests.decrementAndGet();
            if (semaphoreAcquired) {
                requestSemaphore.release();
            }
        }
    }

    /**
     * Execute an operation with circuit breaker protection and custom error handling
     *
     * @param <T> return type
     * @param operation the operation to execute
     * @param isFailure custom failure detection
     * @return operation result
     * @throws CIFSException if circuit is open or operation fails
     */
    public <T> T executeWithCircuitBreaker(Supplier<T> operation, java.util.function.Predicate<Exception> isFailure) throws CIFSException {
        State currentState = state.get();

        if (currentState == State.OPEN && shouldAttemptReset()) {
            transitionTo(State.HALF_OPEN);
            currentState = State.HALF_OPEN;
        }

        if (currentState == State.OPEN) {
            throw new CircuitOpenException("Circuit breaker '" + name + "' is open");
        }

        try {
            T result = operation.get();
            onSuccess();
            return result;
        } catch (Exception e) {
            if (isFailure.test(e)) {
                onFailure(e);
            } else {
                // Not considered a failure for circuit breaker purposes
                log.debug("[{}] Exception not counted as circuit breaker failure: {}", name, e.getMessage());
            }

            if (e instanceof CIFSException) {
                throw (CIFSException) e;
            }
            throw new CIFSException("Circuit breaker operation failed", e);
        }
    }

    private void onSuccess() {
        onSuccess(0);
    }

    private void onSuccess(long responseTimeMs) {
        State currentState = state.get();
        totalSuccesses.incrementAndGet();
        consecutiveSuccesses.incrementAndGet();
        consecutiveFailures.set(0);

        // Track response time metrics
        if (responseTimeMs > 0) {
            updateResponseTimeMetrics(responseTimeMs);
        }

        rollingWindow.recordSuccess(responseTimeMs);

        if (currentState == State.HALF_OPEN) {
            int successes = successCount.incrementAndGet();
            log.debug("[{}] Success in HALF_OPEN state ({}/{})", name, successes, successThreshold);

            if (successes >= successThreshold) {
                log.info("[{}] Circuit breaker closing after {} successful attempts", name, successes);
                transitionTo(State.CLOSED);
            }
        } else if (currentState == State.CLOSED) {
            // Reset failure count on success in closed state
            failureCount.set(0);
        }

        // Notify listeners
        for (CircuitBreakerListener listener : listeners) {
            try {
                listener.onSuccess(this);
            } catch (Exception ex) {
                log.warn("Listener threw exception", ex);
            }
        }
    }

    private void onFailure(Exception e) {
        onFailure(e, 0);
    }

    private void onFailure(Exception e, long responseTimeMs) {
        State currentState = state.get();
        lastFailureTime.set(System.currentTimeMillis());
        totalFailures.incrementAndGet();
        consecutiveFailures.incrementAndGet();
        consecutiveSuccesses.set(0);

        // Track response time metrics even for failures
        if (responseTimeMs > 0) {
            updateResponseTimeMetrics(responseTimeMs);
        }

        rollingWindow.recordFailure();

        // Dynamic threshold adjustment based on failure patterns
        if (dynamicThresholdEnabled) {
            adjustThresholdBasedOnMetrics();
        }

        if (currentState == State.HALF_OPEN) {
            log.warn("[{}] Failure in HALF_OPEN state, reopening circuit: {}", name, e.getMessage());
            transitionTo(State.OPEN);
        } else if (currentState == State.CLOSED) {
            int failures = failureCount.incrementAndGet();
            int currentThreshold = this.failureThreshold;
            log.debug("[{}] Failure in CLOSED state ({}/{}): {}", name, failures, currentThreshold, e.getMessage());

            if (failures >= currentThreshold) {
                log.error("[{}] Circuit breaker opening after {} failures (threshold={})", name, failures, currentThreshold);
                transitionTo(State.OPEN);
            }
        }

        // Notify listeners
        for (CircuitBreakerListener listener : listeners) {
            try {
                listener.onFailure(this, e);
            } catch (Exception ex) {
                log.warn("Listener threw exception", ex);
            }
        }
    }

    private boolean shouldAttemptReset() {
        long timeSinceLastFailure = System.currentTimeMillis() - lastFailureTime.get();
        return timeSinceLastFailure >= resetTimeoutMillis;
    }

    private void transitionTo(State newState) {
        State oldState = state.getAndSet(newState);
        lastStateChangeTime.set(System.currentTimeMillis());

        if (oldState != newState) {
            log.info("[{}] Circuit breaker state transition: {} -> {}", name, oldState, newState);

            // Track time in open state
            if (oldState == State.OPEN && openStateStartTime.get() > 0) {
                totalTimeInOpen.addAndGet(System.currentTimeMillis() - openStateStartTime.get());
                openStateStartTime.set(0);
            }

            if (newState == State.OPEN) {
                openStateStartTime.set(System.currentTimeMillis());
            }

            // Reset counters based on transition
            switch (newState) {
            case CLOSED:
                failureCount.set(0);
                successCount.set(0);
                halfOpenAttempts.set(0);
                break;
            case OPEN:
                successCount.set(0);
                halfOpenAttempts.set(0);
                break;
            case HALF_OPEN:
                successCount.set(0);
                halfOpenAttempts.set(0);
                break;
            }

            // Notify listeners
            for (CircuitBreakerListener listener : listeners) {
                try {
                    listener.onStateChange(this, oldState, newState);
                } catch (Exception ex) {
                    log.warn("Listener threw exception", ex);
                }
            }
        }
    }

    /**
     * Get current circuit breaker state
     *
     * @return current state
     */
    public State getState() {
        return state.get();
    }

    /**
     * Get circuit breaker name
     *
     * @return name
     */
    public String getName() {
        return name;
    }

    /**
     * Get current failure count
     *
     * @return failure count
     */
    public int getFailureCount() {
        return failureCount.get();
    }

    /**
     * Get current success count (in HALF_OPEN state)
     *
     * @return success count
     */
    public int getSuccessCount() {
        return successCount.get();
    }

    /**
     * Get time since last state change
     *
     * @return milliseconds since last state change
     */
    public long getTimeSinceLastStateChange() {
        return System.currentTimeMillis() - lastStateChangeTime.get();
    }

    /**
     * Manually reset the circuit breaker to closed state
     */
    public void reset() {
        log.info("[{}] Manually resetting circuit breaker to CLOSED", name);
        transitionTo(State.CLOSED);
    }

    /**
     * Manually trip the circuit breaker to open state
     */
    public void trip() {
        log.info("[{}] Manually tripping circuit breaker to OPEN", name);
        transitionTo(State.OPEN);
    }

    /**
     * Get current failure threshold (may be dynamically adjusted)
     *
     * @return current failure threshold
     */
    public int getCurrentFailureThreshold() {
        return failureThreshold;
    }

    /**
     * Update failure threshold (for dynamic adjustment)
     *
     * @param newThreshold the new failure threshold
     */
    public void updateFailureThreshold(int newThreshold) {
        if (newThreshold > 0) {
            int oldThreshold = this.failureThreshold;
            this.failureThreshold = newThreshold;
            log.debug("[{}] Dynamic threshold adjustment: {} -> {}", name, oldThreshold, newThreshold);
        }
    }

    /**
     * Get current active requests count
     *
     * @return number of active requests
     */
    public int getActiveRequests() {
        return activeRequests.get();
    }

    /**
     * Get average response time
     *
     * @return average response time in milliseconds
     */
    public long getAverageResponseTime() {
        return avgResponseTime.get();
    }

    /**
     * Get 95th percentile response time
     *
     * @return 95th percentile response time in milliseconds
     */
    public long getP95ResponseTime() {
        return p95ResponseTime.get();
    }

    /**
     * Get minimum response time
     *
     * @return minimum response time in milliseconds
     */
    public long getMinResponseTime() {
        long min = minResponseTime.get();
        return min == Long.MAX_VALUE ? 0 : min;
    }

    /**
     * Get maximum response time
     *
     * @return maximum response time in milliseconds
     */
    public long getMaxResponseTime() {
        return maxResponseTime.get();
    }

    /**
     * Close circuit breaker and cleanup resources
     */
    public void close() {
        if (thresholdAdjustmentTask != null) {
            thresholdAdjustmentTask.cancel(false);
        }
        if (scheduler != null) {
            scheduler.shutdown();
        }
        log.info("[{}] Circuit breaker closed and resources cleaned up", name);
    }

    private void startDynamicThresholdAdjustment() {
        thresholdAdjustmentTask = scheduler.scheduleWithFixedDelay(this::performDynamicThresholdAdjustment, 30, 30, TimeUnit.SECONDS);
        log.debug("[{}] Started dynamic threshold adjustment task", name);
    }

    private void performDynamicThresholdAdjustment() {
        try {
            RollingWindow.WindowMetrics metrics = rollingWindow.getMetrics();
            double failureRate = metrics.getFailureRate();
            long avgResponseTime = metrics.getAverageResponseTime();

            // Adjust threshold based on failure rate and response time trends
            int currentThreshold = this.failureThreshold;
            int newThreshold = currentThreshold;

            // If failure rate is high but response time is normal, be more lenient
            if (failureRate > 0.5 && avgResponseTime < 5000) {
                newThreshold = Math.min(currentThreshold + 2, 15);
            }
            // If failure rate is moderate but response time is very high, be stricter
            else if (failureRate > 0.2 && avgResponseTime > 10000) {
                newThreshold = Math.max(currentThreshold - 1, 2);
            }
            // If system is performing well, be more lenient
            else if (failureRate < 0.1 && avgResponseTime < 1000) {
                newThreshold = Math.min(currentThreshold + 1, 10);
            }

            if (newThreshold != currentThreshold) {
                updateFailureThreshold(newThreshold);
            }
        } catch (Exception e) {
            log.warn("[{}] Error during dynamic threshold adjustment: {}", name, e.getMessage());
        }
    }

    private void adjustThresholdBasedOnMetrics() {
        // Immediate adjustment based on failure patterns
        int consecutiveFailureCount = consecutiveFailures.get();
        if (consecutiveFailureCount > 10) {
            // Many consecutive failures, be stricter
            int newThreshold = Math.max(this.failureThreshold - 1, 2);
            if (newThreshold != this.failureThreshold) {
                updateFailureThreshold(newThreshold);
            }
        }
    }

    private void updateResponseTimeMetrics(long responseTimeMs) {
        // Update min/max
        long currentMin = minResponseTime.get();
        while (responseTimeMs < currentMin) {
            if (minResponseTime.compareAndSet(currentMin, responseTimeMs)) {
                break;
            }
            currentMin = minResponseTime.get();
        }

        long currentMax = maxResponseTime.get();
        while (responseTimeMs > currentMax) {
            if (maxResponseTime.compareAndSet(currentMax, responseTimeMs)) {
                break;
            }
            currentMax = maxResponseTime.get();
        }

        // Add to history for percentile calculation
        responseTimeHistory.addLast(responseTimeMs);
        if (responseTimeHistory.size() > 1000) { // Keep last 1000 measurements
            responseTimeHistory.removeFirst();
        }

        // Calculate moving average (simple approach)
        if (!responseTimeHistory.isEmpty()) {
            long sum = responseTimeHistory.stream().mapToLong(Long::longValue).sum();
            avgResponseTime.set(sum / responseTimeHistory.size());

            // Calculate 95th percentile
            long[] sortedTimes = responseTimeHistory.stream().mapToLong(Long::longValue).sorted().toArray();
            int p95Index = (int) Math.ceil(0.95 * sortedTimes.length) - 1;
            p95Index = Math.max(0, Math.min(p95Index, sortedTimes.length - 1));
            p95ResponseTime.set(sortedTimes[p95Index]);
        }
    }

    /**
     * Exception thrown when circuit breaker is open
     */
    public static class CircuitOpenException extends CIFSException {
        private static final long serialVersionUID = 1L;

        public CircuitOpenException(String message) {
            super(message);
        }
    }

    /**
     * Circuit breaker event listener interface
     */
    public interface CircuitBreakerListener {
        /**
         * Called when circuit state changes
         *
         * @param circuitBreaker the circuit breaker
         * @param fromState previous state
         * @param toState new state
         */
        void onStateChange(SmbCircuitBreaker circuitBreaker, State fromState, State toState);

        /**
         * Called when a request succeeds
         *
         * @param circuitBreaker the circuit breaker
         */
        void onSuccess(SmbCircuitBreaker circuitBreaker);

        /**
         * Called when a request fails
         *
         * @param circuitBreaker the circuit breaker
         * @param exception the failure exception
         */
        void onFailure(SmbCircuitBreaker circuitBreaker, Exception exception);

        /**
         * Called when circuit breaker rejects a request
         *
         * @param circuitBreaker the circuit breaker
         */
        void onCallRejected(SmbCircuitBreaker circuitBreaker);
    }

    /**
     * Add a listener for circuit breaker events
     *
     * @param listener the listener to add
     */
    public void addListener(CircuitBreakerListener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    /**
     * Remove a listener
     *
     * @param listener the listener to remove
     */
    public void removeListener(CircuitBreakerListener listener) {
        listeners.remove(listener);
    }

    /**
     * Get circuit breaker metrics
     *
     * @return metrics snapshot
     */
    public CircuitBreakerMetrics getMetrics() {
        // Calculate time in open state
        long timeInOpen = totalTimeInOpen.get();
        if (state.get() == State.OPEN && openStateStartTime.get() > 0) {
            timeInOpen += System.currentTimeMillis() - openStateStartTime.get();
        }

        return new CircuitBreakerMetrics(name, state.get(), totalRequests.get(), totalSuccesses.get(), totalFailures.get(),
                totalCircuitOpenRejections.get(), failureCount.get(), successCount.get(), timeInOpen, getTimeSinceLastStateChange(),
                calculateSuccessRate(), calculateAvailability());
    }

    /**
     * Calculate success rate
     *
     * @return success rate as percentage (0-100)
     */
    private double calculateSuccessRate() {
        long total = totalRequests.get();
        if (total == 0) {
            return 100.0;
        }
        return (totalSuccesses.get() * 100.0) / total;
    }

    /**
     * Calculate availability
     *
     * @return availability as percentage (0-100)
     */
    private double calculateAvailability() {
        long total = totalRequests.get();
        if (total == 0) {
            return 100.0;
        }
        long accepted = total - totalCircuitOpenRejections.get();
        return (accepted * 100.0) / total;
    }

    /**
     * Circuit breaker metrics snapshot (Java 17 Record)
     */
    public static record CircuitBreakerMetrics(String name, State currentState, long totalRequests, long totalSuccesses, long totalFailures,
            long totalRejections, int currentFailureCount, int currentSuccessCount, long totalTimeInOpenMillis,
            long timeSinceLastStateChangeMillis, double successRate, double availability) {

        @Override
        public String toString() {
            return String.format(
                    "CircuitBreakerMetrics[name=%s, state=%s, requests=%d, successes=%d, "
                            + "failures=%d, rejections=%d, successRate=%.2f%%, availability=%.2f%%]",
                    name, currentState, totalRequests, totalSuccesses, totalFailures, totalRejections, successRate, availability);
        }
    }

    /**
     * Hystrix-style rolling window for time-based metrics collection
     */
    private static class RollingWindow {
        private final int numberOfBuckets;
        private final long bucketSizeInMillis;
        private final WindowBucket[] buckets;
        private volatile int currentBucketIndex = 0;
        private volatile long lastBucketTime = System.currentTimeMillis();

        public RollingWindow(int numberOfBuckets, long bucketSizeInMillis) {
            this.numberOfBuckets = numberOfBuckets;
            this.bucketSizeInMillis = bucketSizeInMillis;
            this.buckets = new WindowBucket[numberOfBuckets];
            for (int i = 0; i < numberOfBuckets; i++) {
                buckets[i] = new WindowBucket();
            }
        }

        public synchronized void recordSuccess(long responseTimeMs) {
            getCurrentBucket().recordSuccess(responseTimeMs);
        }

        public synchronized void recordFailure() {
            getCurrentBucket().recordFailure();
        }

        public synchronized WindowMetrics getMetrics() {
            long now = System.currentTimeMillis();
            long windowStartTime = now - (numberOfBuckets * bucketSizeInMillis);

            long totalRequests = 0;
            long totalFailures = 0;
            long totalResponseTime = 0;
            long minResponseTime = Long.MAX_VALUE;
            long maxResponseTime = 0;

            for (WindowBucket bucket : buckets) {
                if (bucket.getLastUpdateTime() >= windowStartTime) {
                    totalRequests += bucket.getRequestCount();
                    totalFailures += bucket.getFailureCount();
                    totalResponseTime += bucket.getTotalResponseTime();

                    if (bucket.getMinResponseTime() < minResponseTime) {
                        minResponseTime = bucket.getMinResponseTime();
                    }
                    if (bucket.getMaxResponseTime() > maxResponseTime) {
                        maxResponseTime = bucket.getMaxResponseTime();
                    }
                }
            }

            double failureRate = totalRequests > 0 ? (double) totalFailures / totalRequests : 0.0;
            long averageResponseTime = totalRequests > 0 ? totalResponseTime / totalRequests : 0;

            if (minResponseTime == Long.MAX_VALUE) {
                minResponseTime = 0;
            }

            return new WindowMetrics(totalRequests, totalFailures, failureRate, averageResponseTime, minResponseTime, maxResponseTime);
        }

        private WindowBucket getCurrentBucket() {
            long now = System.currentTimeMillis();

            // Check if we need to advance to next bucket
            if (now - lastBucketTime >= bucketSizeInMillis) {
                currentBucketIndex = (currentBucketIndex + 1) % numberOfBuckets;
                buckets[currentBucketIndex].reset(now);
                lastBucketTime = now;
            }

            return buckets[currentBucketIndex];
        }

        public static class WindowMetrics {
            private final long totalRequests;
            private final long totalFailures;
            private final double failureRate;
            private final long averageResponseTime;
            private final long minResponseTime;
            private final long maxResponseTime;

            public WindowMetrics(long totalRequests, long totalFailures, double failureRate, long averageResponseTime, long minResponseTime,
                    long maxResponseTime) {
                this.totalRequests = totalRequests;
                this.totalFailures = totalFailures;
                this.failureRate = failureRate;
                this.averageResponseTime = averageResponseTime;
                this.minResponseTime = minResponseTime;
                this.maxResponseTime = maxResponseTime;
            }

            public long getTotalRequests() {
                return totalRequests;
            }

            public long getTotalFailures() {
                return totalFailures;
            }

            public double getFailureRate() {
                return failureRate;
            }

            public long getAverageResponseTime() {
                return averageResponseTime;
            }

            public long getMinResponseTime() {
                return minResponseTime;
            }

            public long getMaxResponseTime() {
                return maxResponseTime;
            }
        }

        private static class WindowBucket {
            private volatile long requestCount = 0;
            private volatile long failureCount = 0;
            private volatile long totalResponseTime = 0;
            private volatile long minResponseTime = Long.MAX_VALUE;
            private volatile long maxResponseTime = 0;
            private volatile long lastUpdateTime = System.currentTimeMillis();

            public synchronized void recordSuccess(long responseTimeMs) {
                requestCount++;
                if (responseTimeMs > 0) {
                    totalResponseTime += responseTimeMs;
                    if (responseTimeMs < minResponseTime) {
                        minResponseTime = responseTimeMs;
                    }
                    if (responseTimeMs > maxResponseTime) {
                        maxResponseTime = responseTimeMs;
                    }
                }
                lastUpdateTime = System.currentTimeMillis();
            }

            public synchronized void recordFailure() {
                requestCount++;
                failureCount++;
                lastUpdateTime = System.currentTimeMillis();
            }

            public synchronized void reset(long timestamp) {
                requestCount = 0;
                failureCount = 0;
                totalResponseTime = 0;
                minResponseTime = Long.MAX_VALUE;
                maxResponseTime = 0;
                lastUpdateTime = timestamp;
            }

            public long getRequestCount() {
                return requestCount;
            }

            public long getFailureCount() {
                return failureCount;
            }

            public long getTotalResponseTime() {
                return totalResponseTime;
            }

            public long getMinResponseTime() {
                return minResponseTime;
            }

            public long getMaxResponseTime() {
                return maxResponseTime;
            }

            public long getLastUpdateTime() {
                return lastUpdateTime;
            }
        }
    }
}
