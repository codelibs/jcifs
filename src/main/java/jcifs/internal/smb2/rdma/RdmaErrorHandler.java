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
package jcifs.internal.smb2.rdma;

import java.io.IOException;
import java.net.SocketException;
import java.net.SocketTimeoutException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * RDMA error handling and recovery logic.
 *
 * This class provides centralized error handling for RDMA operations,
 * including retry logic and fallback mechanisms.
 */
public class RdmaErrorHandler {

    private static final Logger log = LoggerFactory.getLogger(RdmaErrorHandler.class);

    private final RdmaStatistics statistics;
    private final int maxRetries;
    private final long retryDelayMs;

    /**
     * Create new RDMA error handler
     *
     * @param statistics statistics tracker
     * @param maxRetries maximum number of retries for recoverable errors
     * @param retryDelayMs delay between retries in milliseconds
     */
    public RdmaErrorHandler(RdmaStatistics statistics, int maxRetries, long retryDelayMs) {
        this.statistics = statistics;
        this.maxRetries = maxRetries;
        this.retryDelayMs = retryDelayMs;
    }

    /**
     * Create error handler with default settings
     *
     * @param statistics statistics tracker
     */
    public RdmaErrorHandler(RdmaStatistics statistics) {
        this(statistics, 3, 1000); // 3 retries with 1 second delay
    }

    /**
     * Handle RDMA connection error and attempt recovery
     *
     * @param connection RDMA connection that encountered error
     * @param error the error that occurred
     * @return true if error was handled and connection recovered, false if fallback needed
     */
    public boolean handleRdmaError(RdmaConnection connection, Exception error) {
        log.warn("RDMA error occurred: {}", error.getMessage());
        statistics.recordError();

        if (isRecoverableError(error)) {
            return attemptRecovery(connection, error);
        } else {
            log.error("Non-recoverable RDMA error, fallback required", error);
            return false;
        }
    }

    /**
     * Attempt to recover from a recoverable RDMA error
     *
     * @param connection RDMA connection to recover
     * @param error the original error
     * @return true if recovery succeeded, false otherwise
     */
    private boolean attemptRecovery(RdmaConnection connection, Exception error) {
        int retryCount = 0;

        while (retryCount < maxRetries) {
            retryCount++;
            log.info("Attempting RDMA connection recovery (attempt {} of {})", retryCount, maxRetries);

            try {
                // Wait before retry
                if (retryDelayMs > 0) {
                    Thread.sleep(retryDelayMs);
                }

                // Attempt to reset the connection
                connection.reset();

                // Verify connection is working
                if (connection.getState() == RdmaConnection.RdmaConnectionState.ESTABLISHED) {
                    log.info("RDMA connection recovery successful after {} attempts", retryCount);
                    return true;
                }

            } catch (Exception recoveryError) {
                log.warn("RDMA recovery attempt {} failed: {}", retryCount, recoveryError.getMessage());

                // If this was the last attempt, log the full error
                if (retryCount >= maxRetries) {
                    log.error("All RDMA recovery attempts failed", recoveryError);
                }
            }
        }

        log.error("Failed to recover RDMA connection after {} attempts, fallback required", maxRetries);
        return false;
    }

    /**
     * Determine if an error is recoverable
     *
     * @param error the error to check
     * @return true if error might be recoverable, false otherwise
     */
    private boolean isRecoverableError(Exception error) {
        // Timeout errors are often recoverable
        if (error instanceof SocketTimeoutException) {
            return true;
        }

        // Some socket errors might be recoverable
        if (error instanceof SocketException) {
            String message = error.getMessage();
            if (message != null) {
                message = message.toLowerCase();
                // Connection reset, network unreachable, etc. might be temporary
                return message.contains("connection reset") || message.contains("network unreachable")
                        || message.contains("host unreachable") || message.contains("timeout");
            }
            return true; // Generic socket errors might be recoverable
        }

        // Generic IO exceptions might be recoverable
        if (error instanceof IOException) {
            String message = error.getMessage();
            if (message != null) {
                message = message.toLowerCase();
                return message.contains("retry") || message.contains("temporary") || message.contains("timeout")
                        || message.contains("connection");
            }
            return false; // Unknown IO errors are likely not recoverable
        }

        // Runtime exceptions and other errors are likely not recoverable
        return false;
    }

    /**
     * Check if error suggests fallback to TCP is needed
     *
     * @param error the error to check
     * @return true if TCP fallback is recommended
     */
    public boolean shouldFallbackToTcp(Exception error) {
        // Hardware errors suggest RDMA is not working
        if (error.getMessage() != null) {
            String message = error.getMessage().toLowerCase();
            if (message.contains("hardware") || message.contains("device not found") || message.contains("driver")
                    || message.contains("not supported") || message.contains("capability")) {
                return true;
            }
        }

        // If we've had many errors, consider fallback
        double errorRate = statistics.getErrorRate();
        if (errorRate > 0.1) { // More than 10% error rate
            log.warn("High RDMA error rate ({:.1f}%), TCP fallback recommended", errorRate * 100);
            return true;
        }

        return false;
    }

    /**
     * Execute an RDMA operation with automatic retry and error handling
     *
     * @param operation the operation to execute
     * @param connection the RDMA connection to use
     * @return operation result
     * @throws IOException if operation fails after all retries
     */
    public <T> T executeWithRetry(RdmaOperation<T> operation, RdmaConnection connection) throws IOException {
        Exception lastError = null;
        int retryCount = 0;

        while (retryCount <= maxRetries) {
            try {
                return operation.execute();
            } catch (Exception error) {
                lastError = error;
                statistics.recordError();

                if (retryCount >= maxRetries || !isRecoverableError(error)) {
                    break;
                }

                log.debug("RDMA operation failed (attempt {} of {}), retrying: {}", retryCount + 1, maxRetries + 1, error.getMessage());

                // Attempt recovery if needed
                if (!handleRdmaError(connection, error)) {
                    break; // Recovery failed, don't retry
                }

                retryCount++;

                // Wait before retry
                if (retryDelayMs > 0) {
                    try {
                        Thread.sleep(retryDelayMs);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted during retry delay", e);
                    }
                }
            }
        }

        // All retries failed
        if (lastError instanceof IOException) {
            throw (IOException) lastError;
        } else {
            throw new IOException("RDMA operation failed after " + (retryCount + 1) + " attempts", lastError);
        }
    }

    /**
     * Functional interface for RDMA operations that can be retried
     */
    @FunctionalInterface
    public interface RdmaOperation<T> {
        T execute() throws Exception;
    }
}
