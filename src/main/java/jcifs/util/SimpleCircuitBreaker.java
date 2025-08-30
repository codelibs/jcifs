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

import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simplified circuit breaker implementation for SMB operations.
 * Thread-safe and lock-free implementation to prevent cascading failures.
 *
 * Features:
 * - Simple state management (CLOSED, OPEN, HALF_OPEN)
 * - Lock-free atomic operations
 * - Configurable thresholds and timeouts
 * - No complex dependencies
 */
public class SimpleCircuitBreaker {

    private static final Logger log = LoggerFactory.getLogger(SimpleCircuitBreaker.class);

    /**
     * Circuit breaker states
     */
    public enum State {
        CLOSED, // Normal operation
        OPEN, // Failing, requests blocked
        HALF_OPEN // Testing recovery
    }

    private final String name;
    private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);
    private final AtomicInteger consecutiveFailures = new AtomicInteger(0);
    private final AtomicInteger halfOpenSuccesses = new AtomicInteger(0);
    private final AtomicLong lastFailureTime = new AtomicLong(0);
    private final AtomicLong stateChangeTime = new AtomicLong(System.currentTimeMillis());

    // Statistics
    private final AtomicLong totalCalls = new AtomicLong(0);
    private final AtomicLong totalFailures = new AtomicLong(0);
    private final AtomicLong totalSuccesses = new AtomicLong(0);
    private final AtomicLong rejectedCalls = new AtomicLong(0);

    // Configuration
    private final int failureThreshold;
    private final int successThreshold;
    private final long timeoutMillis;

    /**
     * Creates a simple circuit breaker with default settings
     *
     * @param name the circuit breaker name
     */
    public SimpleCircuitBreaker(String name) {
        this(name, 5, 3, 30000L); // 5 failures, 3 successes, 30 second timeout
    }

    /**
     * Creates a simple circuit breaker
     *
     * @param name the circuit breaker name
     * @param failureThreshold number of consecutive failures to open circuit
     * @param successThreshold number of successes in half-open to close circuit
     * @param timeoutMillis timeout before attempting to close open circuit
     */
    public SimpleCircuitBreaker(String name, int failureThreshold, int successThreshold, long timeoutMillis) {
        this.name = name;
        this.failureThreshold = failureThreshold;
        this.successThreshold = successThreshold;
        this.timeoutMillis = timeoutMillis;

        if (failureThreshold < 1) {
            throw new IllegalArgumentException("Failure threshold must be at least 1");
        }
        if (successThreshold < 1) {
            throw new IllegalArgumentException("Success threshold must be at least 1");
        }
        if (timeoutMillis < 0) {
            throw new IllegalArgumentException("Timeout must be non-negative");
        }
    }

    /**
     * Execute a callable through the circuit breaker
     *
     * @param <T> return type
     * @param callable the callable to execute
     * @return the result
     * @throws Exception if execution fails or circuit is open
     */
    public <T> T call(Callable<T> callable) throws Exception {
        return call(callable, null);
    }

    /**
     * Execute a callable through the circuit breaker with fallback
     *
     * @param <T> return type
     * @param callable the callable to execute
     * @param fallback fallback supplier if circuit is open
     * @return the result or fallback value
     * @throws Exception if execution fails and no fallback provided
     */
    public <T> T call(Callable<T> callable, Callable<T> fallback) throws Exception {
        totalCalls.incrementAndGet();

        State currentState = evaluateState();

        if (currentState == State.OPEN) {
            rejectedCalls.incrementAndGet();
            if (fallback != null) {
                log.debug("Circuit breaker {} is open, using fallback", name);
                return fallback.call();
            }
            throw new CircuitBreakerOpenException("Circuit breaker " + name + " is open");
        }

        try {
            T result = callable.call();
            onSuccess();
            return result;
        } catch (Exception e) {
            onFailure();
            throw e;
        }
    }

    /**
     * Execute a runnable through the circuit breaker
     *
     * @param runnable the runnable to execute
     * @throws Exception if execution fails or circuit is open
     */
    public void run(Runnable runnable) throws Exception {
        call(() -> {
            runnable.run();
            return null;
        });
    }

    /**
     * Evaluate and potentially update the circuit breaker state
     *
     * @return current state after evaluation
     */
    private State evaluateState() {
        State current = state.get();

        if (current == State.OPEN) {
            long timeSinceLastFailure = System.currentTimeMillis() - lastFailureTime.get();
            if (timeSinceLastFailure > timeoutMillis) {
                if (state.compareAndSet(State.OPEN, State.HALF_OPEN)) {
                    stateChangeTime.set(System.currentTimeMillis());
                    halfOpenSuccesses.set(0);
                    log.info("Circuit breaker {} transitioning from OPEN to HALF_OPEN", name);
                    return State.HALF_OPEN;
                }
                // Another thread changed the state, re-evaluate
                return state.get();
            }
        }

        return current;
    }

    /**
     * Handle successful call
     */
    private void onSuccess() {
        totalSuccesses.incrementAndGet();
        consecutiveFailures.set(0);

        State current = state.get();

        if (current == State.HALF_OPEN) {
            int successes = halfOpenSuccesses.incrementAndGet();
            if (successes >= successThreshold) {
                if (state.compareAndSet(State.HALF_OPEN, State.CLOSED)) {
                    stateChangeTime.set(System.currentTimeMillis());
                    log.info("Circuit breaker {} closed after {} successful attempts", name, successes);
                }
            }
        }
    }

    /**
     * Handle failed call
     */
    private void onFailure() {
        totalFailures.incrementAndGet();
        lastFailureTime.set(System.currentTimeMillis());

        State current = state.get();

        if (current == State.HALF_OPEN) {
            // Single failure in half-open state reopens the circuit
            if (state.compareAndSet(State.HALF_OPEN, State.OPEN)) {
                stateChangeTime.set(System.currentTimeMillis());
                consecutiveFailures.set(1);
                log.warn("Circuit breaker {} reopened due to failure in HALF_OPEN state", name);
            }
        } else if (current == State.CLOSED) {
            int failures = consecutiveFailures.incrementAndGet();
            if (failures >= failureThreshold) {
                if (state.compareAndSet(State.CLOSED, State.OPEN)) {
                    stateChangeTime.set(System.currentTimeMillis());
                    log.warn("Circuit breaker {} opened after {} consecutive failures", name, failures);
                }
            }
        }
    }

    /**
     * Get current state
     *
     * @return current state
     */
    public State getState() {
        evaluateState(); // Ensure state is current
        return state.get();
    }

    /**
     * Reset the circuit breaker
     */
    public void reset() {
        state.set(State.CLOSED);
        consecutiveFailures.set(0);
        halfOpenSuccesses.set(0);
        lastFailureTime.set(0);
        stateChangeTime.set(System.currentTimeMillis());
        log.info("Circuit breaker {} reset", name);
    }

    /**
     * Force the circuit to open
     */
    public void tripBreaker() {
        State previous = state.getAndSet(State.OPEN);
        if (previous != State.OPEN) {
            stateChangeTime.set(System.currentTimeMillis());
            lastFailureTime.set(System.currentTimeMillis());
            log.warn("Circuit breaker {} manually tripped", name);
        }
    }

    /**
     * Get circuit breaker statistics
     *
     * @return statistics
     */
    public Statistics getStatistics() {
        return new Statistics(name, getState(), totalCalls.get(), totalSuccesses.get(), totalFailures.get(), rejectedCalls.get(),
                consecutiveFailures.get(), getSuccessRate());
    }

    /**
     * Calculate success rate
     *
     * @return success rate (0.0 to 1.0)
     */
    private double getSuccessRate() {
        long total = totalCalls.get();
        if (total == 0) {
            return 1.0;
        }
        return (double) totalSuccesses.get() / total;
    }

    /**
     * Check if circuit breaker allows requests
     *
     * @return true if requests are allowed
     */
    public boolean allowsRequests() {
        State current = evaluateState();
        return current != State.OPEN;
    }

    /**
     * Get the circuit breaker name
     *
     * @return name
     */
    public String getName() {
        return name;
    }

    /**
     * Circuit breaker statistics
     */
    public static class Statistics {
        public final String name;
        public final State state;
        public final long totalCalls;
        public final long totalSuccesses;
        public final long totalFailures;
        public final long rejectedCalls;
        public final int consecutiveFailures;
        public final double successRate;

        public Statistics(String name, State state, long totalCalls, long totalSuccesses, long totalFailures, long rejectedCalls,
                int consecutiveFailures, double successRate) {
            this.name = name;
            this.state = state;
            this.totalCalls = totalCalls;
            this.totalSuccesses = totalSuccesses;
            this.totalFailures = totalFailures;
            this.rejectedCalls = rejectedCalls;
            this.consecutiveFailures = consecutiveFailures;
            this.successRate = successRate;
        }

        @Override
        public String toString() {
            return String.format("CircuitBreaker[%s] State=%s, Calls=%d, Success=%.2f%%, Rejected=%d", name, state, totalCalls,
                    successRate * 100, rejectedCalls);
        }
    }

    /**
     * Exception thrown when circuit breaker is open
     */
    public static class CircuitBreakerOpenException extends Exception {
        private static final long serialVersionUID = 1L;

        public CircuitBreakerOpenException(String message) {
            super(message);
        }
    }
}
