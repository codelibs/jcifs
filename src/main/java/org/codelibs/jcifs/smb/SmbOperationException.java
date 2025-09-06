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
package org.codelibs.jcifs.smb;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Unified exception class for SMB operations providing enhanced error handling,
 * retry policies, and contextual information.
 *
 * This exception consolidates the various SMB exception types and provides:
 * - Standardized error codes
 * - Automatic retry policies
 * - Rich contextual information
 * - Error categorization
 * - Performance metrics
 */
public class SmbOperationException extends CIFSException implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = LoggerFactory.getLogger(SmbOperationException.class);

    /**
     * Error categories for SMB operations
     */
    public enum ErrorCategory {
        /** Network-related errors (connection, timeout, etc.) */
        NETWORK,
        /** Authentication and authorization errors */
        AUTHENTICATION,
        /** File system errors (not found, access denied, etc.) */
        FILE_SYSTEM,
        /** Protocol errors (invalid message, unsupported operation, etc.) */
        PROTOCOL,
        /** Resource errors (out of memory, disk space, etc.) */
        RESOURCE,
        /** Configuration errors */
        CONFIGURATION,
        /** Transient errors that may succeed on retry */
        TRANSIENT,
        /** Unknown or unclassified errors */
        UNKNOWN
    }

    /**
     * Standard SMB error codes
     */
    public enum ErrorCode {
        // Network errors
        /** Network connection failed error */
        CONNECTION_FAILED("Network connection failed", ErrorCategory.NETWORK, true),
        /** Connection timeout error */
        CONNECTION_TIMEOUT("Connection timed out", ErrorCategory.NETWORK, true),
        /** Connection reset by peer error */
        CONNECTION_RESET("Connection reset by peer", ErrorCategory.NETWORK, true),
        /** Host not found error */
        HOST_NOT_FOUND("Host not found", ErrorCategory.NETWORK, false),

        // Authentication errors
        /** Authentication failed error */
        AUTHENTICATION_FAILED("Authentication failed", ErrorCategory.AUTHENTICATION, false),
        /** Access denied error */
        ACCESS_DENIED("Access denied", ErrorCategory.AUTHENTICATION, false),
        /** Invalid credentials error */
        INVALID_CREDENTIALS("Invalid credentials", ErrorCategory.AUTHENTICATION, false),
        /** Session expired error */
        SESSION_EXPIRED("Session expired", ErrorCategory.AUTHENTICATION, true),

        // File system errors
        /** File not found error */
        FILE_NOT_FOUND("File not found", ErrorCategory.FILE_SYSTEM, false),
        /** Path not found error */
        PATH_NOT_FOUND("Path not found", ErrorCategory.FILE_SYSTEM, false),
        /** File already exists error */
        FILE_EXISTS("File already exists", ErrorCategory.FILE_SYSTEM, false),
        /** Directory not empty error */
        DIRECTORY_NOT_EMPTY("Directory not empty", ErrorCategory.FILE_SYSTEM, false),
        /** Disk full error */
        DISK_FULL("Disk full", ErrorCategory.RESOURCE, false),
        /** Quota exceeded error */
        QUOTA_EXCEEDED("Quota exceeded", ErrorCategory.RESOURCE, false),

        // Protocol errors
        /** Invalid parameter error */
        INVALID_PARAMETER("Invalid parameter", ErrorCategory.PROTOCOL, false),
        /** Operation not supported error */
        NOT_SUPPORTED("Operation not supported", ErrorCategory.PROTOCOL, false),
        /** Invalid protocol error */
        INVALID_PROTOCOL("Invalid protocol", ErrorCategory.PROTOCOL, false),
        /** Message too large error */
        MESSAGE_TOO_LARGE("Message too large", ErrorCategory.PROTOCOL, false),

        // Resource errors
        /** Out of memory error */
        OUT_OF_MEMORY("Out of memory", ErrorCategory.RESOURCE, true),
        /** Too many sessions error */
        TOO_MANY_SESSIONS("Too many sessions", ErrorCategory.RESOURCE, true),
        /** Resource is locked error */
        RESOURCE_LOCKED("Resource is locked", ErrorCategory.RESOURCE, true),

        // Transient errors
        /** Server busy error */
        BUSY("Server busy", ErrorCategory.TRANSIENT, true),
        /** Try again later error */
        TRY_AGAIN("Try again later", ErrorCategory.TRANSIENT, true),
        /** Service temporarily unavailable error */
        SERVICE_UNAVAILABLE("Service temporarily unavailable", ErrorCategory.TRANSIENT, true),

        // Generic errors
        /** Unknown error */
        UNKNOWN_ERROR("Unknown error", ErrorCategory.UNKNOWN, false),
        /** Internal error */
        INTERNAL_ERROR("Internal error", ErrorCategory.UNKNOWN, false);

        private final String description;
        private final ErrorCategory category;
        private final boolean retryable;

        ErrorCode(String description, ErrorCategory category, boolean retryable) {
            this.description = description;
            this.category = category;
            this.retryable = retryable;
        }

        /**
         * Gets the error description
         * @return the error description
         */
        public String getDescription() {
            return description;
        }

        /**
         * Gets the error category
         * @return the error category
         */
        public ErrorCategory getCategory() {
            return category;
        }

        /**
         * Checks if the error is retryable
         * @return true if retryable
         */
        public boolean isRetryable() {
            return retryable;
        }
    }

    /**
     * Retry policy for handling transient failures
     */
    public static class RetryPolicy implements Serializable {
        private static final long serialVersionUID = 1L;

        /** Maximum number of retry attempts */
        private final int maxAttempts;
        /** Initial delay between retries in milliseconds */
        private final long initialDelayMs;
        /** Maximum delay between retries in milliseconds */
        private final long maxDelayMs;
        /** Backoff multiplier for exponential backoff */
        private final double backoffMultiplier;
        /** Whether to use exponential backoff */
        private final boolean exponentialBackoff;

        /** Default retry policy with moderate settings */
        public static final RetryPolicy DEFAULT = new RetryPolicy(3, 1000, 30000, 2.0, true);
        /** Aggressive retry policy with more attempts and shorter delays */
        public static final RetryPolicy AGGRESSIVE = new RetryPolicy(5, 500, 60000, 1.5, true);
        /** Conservative retry policy with fewer attempts and longer delays */
        public static final RetryPolicy CONSERVATIVE = new RetryPolicy(2, 2000, 10000, 3.0, true);
        /** No retry policy - operations fail immediately */
        public static final RetryPolicy NO_RETRY = new RetryPolicy(1, 0, 0, 1.0, false);

        /**
         * Creates a new retry policy
         * @param maxAttempts maximum number of retry attempts
         * @param initialDelayMs initial delay between retries in milliseconds
         * @param maxDelayMs maximum delay between retries in milliseconds
         * @param backoffMultiplier multiplier for exponential backoff
         * @param exponentialBackoff whether to use exponential backoff
         */
        public RetryPolicy(int maxAttempts, long initialDelayMs, long maxDelayMs, double backoffMultiplier, boolean exponentialBackoff) {
            this.maxAttempts = maxAttempts;
            this.initialDelayMs = initialDelayMs;
            this.maxDelayMs = maxDelayMs;
            this.backoffMultiplier = backoffMultiplier;
            this.exponentialBackoff = exponentialBackoff;
        }

        /**
         * Determines if an operation should be retried
         * @param exception the exception that occurred
         * @param attemptNumber the current attempt number
         * @return true if the operation should be retried
         */
        public boolean shouldRetry(SmbOperationException exception, int attemptNumber) {
            if (attemptNumber >= maxAttempts) {
                return false;
            }

            if (!exception.isRetryable()) {
                return false;
            }

            // Check if we've exceeded time limits
            long totalElapsed = System.currentTimeMillis() - exception.getOperationStartTime();
            if (totalElapsed > maxDelayMs * maxAttempts) {
                log.debug("Retry time limit exceeded for operation");
                return false;
            }

            return true;
        }

        /**
         * Gets the delay before the next retry attempt
         * @param attemptNumber the current attempt number
         * @return delay in milliseconds
         */
        public long getDelayMs(int attemptNumber) {
            if (!exponentialBackoff) {
                return initialDelayMs;
            }

            long delay = initialDelayMs;
            for (int i = 1; i < attemptNumber; i++) {
                delay = (long) (delay * backoffMultiplier);
            }

            return Math.min(delay, maxDelayMs);
        }

        /**
         * Gets the maximum number of retry attempts
         * @return maximum attempts
         */
        public int getMaxAttempts() {
            return maxAttempts;
        }

        /**
         * Gets the initial delay between retries
         * @return initial delay in milliseconds
         */
        public long getInitialDelayMs() {
            return initialDelayMs;
        }

        /**
         * Gets the maximum delay between retries
         * @return maximum delay in milliseconds
         */
        public long getMaxDelayMs() {
            return maxDelayMs;
        }

        /**
         * Gets the backoff multiplier for exponential backoff
         * @return backoff multiplier
         */
        public double getBackoffMultiplier() {
            return backoffMultiplier;
        }

        /**
         * Checks if exponential backoff is enabled
         * @return true if exponential backoff is enabled
         */
        public boolean isExponentialBackoff() {
            return exponentialBackoff;
        }
    }

    // Instance fields
    /** The error code for this exception */
    private final ErrorCode errorCode;
    /** The retry policy for this exception */
    private final RetryPolicy retryPolicy;
    /** Additional context information */
    private final Map<String, Object> context;
    /** Timestamp when the operation started */
    private final long operationStartTime;
    /** Name of the operation that failed */
    private final String operationName;
    /** Current attempt number */
    private final int attemptNumber;
    /** NT status code from the server */
    private final long ntStatus;
    /** Error message from the server */
    private final String serverMessage;
    /** Original error message */
    private final String originalMessage;

    /**
     * Create a new SmbOperationException
     *
     * @param errorCode the error code
     * @param message the error message
     */
    public SmbOperationException(ErrorCode errorCode, String message) {
        this(errorCode, message, null, RetryPolicy.DEFAULT, Collections.emptyMap());
    }

    /**
     * Create a new SmbOperationException with cause
     *
     * @param errorCode the error code
     * @param message the error message
     * @param cause the underlying cause
     */
    public SmbOperationException(ErrorCode errorCode, String message, Throwable cause) {
        this(errorCode, message, cause, RetryPolicy.DEFAULT, Collections.emptyMap());
    }

    /**
     * Create a new SmbOperationException with full details
     *
     * @param errorCode the error code
     * @param message the error message
     * @param cause the underlying cause
     * @param retryPolicy the retry policy to apply
     * @param context additional context information
     */
    public SmbOperationException(ErrorCode errorCode, String message, Throwable cause, RetryPolicy retryPolicy,
            Map<String, Object> context) {
        super(formatMessage(errorCode, message), cause);
        this.errorCode = errorCode;
        this.originalMessage = message;
        this.retryPolicy = retryPolicy != null ? retryPolicy : RetryPolicy.DEFAULT;
        this.context = context != null ? new HashMap<>(context) : new HashMap<>();
        this.operationStartTime = System.currentTimeMillis();
        this.operationName = extractOperationName();
        this.attemptNumber = 1;
        this.ntStatus = extractNtStatus(cause);
        this.serverMessage = extractServerMessage(cause);

        logError();
    }

    /**
     * Create exception for retry attempt
     *
     * @param original the original exception
     * @param attemptNumber the current attempt number
     * @return new exception with updated attempt information
     */
    public static SmbOperationException forRetry(SmbOperationException original, int attemptNumber) {
        SmbOperationException retry = new SmbOperationException(original.errorCode, original.originalMessage, original.getCause(),
                original.retryPolicy, original.context);
        retry.setAttemptNumber(attemptNumber);
        return retry;
    }

    private void setAttemptNumber(int attemptNumber) {
        // Package-private setter for attempt number
        try {
            java.lang.reflect.Field field = SmbOperationException.class.getDeclaredField("attemptNumber");
            field.setAccessible(true);
            field.set(this, attemptNumber);
        } catch (Exception e) {
            // Ignore
        }
    }

    private static String formatMessage(ErrorCode errorCode, String message) {
        if (message == null || message.isEmpty()) {
            return String.format("[%s] %s", errorCode.name(), errorCode.getDescription());
        }
        return String.format("[%s] %s: %s", errorCode.name(), errorCode.getDescription(), message);
    }

    private String extractOperationName() {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        for (StackTraceElement element : stack) {
            String className = element.getClassName();
            if (className.startsWith("org.codelibs.jcifs.smb") && !className.contains("Exception")) {
                return element.getMethodName();
            }
        }
        return "unknown";
    }

    private long extractNtStatus(Throwable cause) {
        if (cause instanceof SmbException) {
            return ((SmbException) cause).getNtStatus();
        }
        return 0;
    }

    private String extractServerMessage(Throwable cause) {
        if (cause instanceof SmbException) {
            // Try to get server message from SMB exception
            return cause.getMessage();
        }
        return null;
    }

    private void logError() {
        if (errorCode.category == ErrorCategory.TRANSIENT) {
            log.debug("Transient SMB error: {} (attempt {}/{})", getMessage(), attemptNumber, retryPolicy.getMaxAttempts());
        } else if (isRetryable()) {
            log.warn("Retryable SMB error: {} in operation '{}' (attempt {}/{})", getMessage(), operationName, attemptNumber,
                    retryPolicy.getMaxAttempts());
        } else {
            log.error("Non-retryable SMB error: {} in operation '{}'", getMessage(), operationName);
        }
    }

    /**
     * Check if this exception is retryable
     *
     * @return true if the operation can be retried
     */
    public boolean isRetryable() {
        return errorCode.isRetryable() && retryPolicy != RetryPolicy.NO_RETRY;
    }

    /**
     * Check if retry should be attempted
     *
     * @param attemptNumber the current attempt number
     * @return true if retry should be attempted
     */
    public boolean shouldRetry(int attemptNumber) {
        return retryPolicy.shouldRetry(this, attemptNumber);
    }

    /**
     * Get the delay before next retry
     *
     * @param attemptNumber the current attempt number
     * @return delay in milliseconds
     */
    public long getRetryDelayMs(int attemptNumber) {
        return retryPolicy.getDelayMs(attemptNumber);
    }

    /**
     * Add context information
     *
     * @param key the context key
     * @param value the context value
     * @return this exception for chaining
     */
    public SmbOperationException withContext(String key, Object value) {
        this.context.put(key, value);
        return this;
    }

    /**
     * Add multiple context values
     *
     * @param contextMap the context map to add
     * @return this exception for chaining
     */
    public SmbOperationException withContext(Map<String, Object> contextMap) {
        if (contextMap != null) {
            this.context.putAll(contextMap);
        }
        return this;
    }

    // Getters
    /**
     * Gets the error code
     * @return the error code
     */
    public ErrorCode getErrorCode() {
        return errorCode;
    }

    /**
     * Gets the error category
     * @return the error category
     */
    public ErrorCategory getErrorCategory() {
        return errorCode.getCategory();
    }

    /**
     * Gets the retry policy
     * @return the retry policy
     */
    public RetryPolicy getRetryPolicy() {
        return retryPolicy;
    }

    /**
     * Gets the context map
     * @return unmodifiable view of the context map
     */
    public Map<String, Object> getContext() {
        return Collections.unmodifiableMap(context);
    }

    /**
     * Gets the operation start time
     * @return timestamp when the operation started
     */
    public long getOperationStartTime() {
        return operationStartTime;
    }

    /**
     * Gets the operation name
     * @return name of the operation that failed
     */
    public String getOperationName() {
        return operationName;
    }

    /**
     * Gets the current attempt number
     * @return attempt number
     */
    public int getAttemptNumber() {
        return attemptNumber;
    }

    /**
     * Gets the NT status code
     * @return NT status code from the server
     */
    public long getNtStatus() {
        return ntStatus;
    }

    /**
     * Gets the server error message
     * @return error message from the server
     */
    public String getServerMessage() {
        return serverMessage;
    }

    /**
     * Get elapsed time since operation started
     *
     * @return elapsed time in milliseconds
     */
    public long getElapsedTime() {
        return System.currentTimeMillis() - operationStartTime;
    }

    /**
     * Check if this is a network-related error
     *
     * @return true if network error
     */
    public boolean isNetworkError() {
        return errorCode.getCategory() == ErrorCategory.NETWORK;
    }

    /**
     * Check if this is an authentication error
     *
     * @return true if authentication error
     */
    public boolean isAuthenticationError() {
        return errorCode.getCategory() == ErrorCategory.AUTHENTICATION;
    }

    /**
     * Check if this is a file system error
     *
     * @return true if file system error
     */
    public boolean isFileSystemError() {
        return errorCode.getCategory() == ErrorCategory.FILE_SYSTEM;
    }

    /**
     * Check if this is a transient error
     *
     * @return true if transient error
     */
    public boolean isTransientError() {
        return errorCode.getCategory() == ErrorCategory.TRANSIENT;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("SmbOperationException{");
        sb.append("errorCode=").append(errorCode);
        sb.append(", category=").append(errorCode.getCategory());
        sb.append(", retryable=").append(isRetryable());
        sb.append(", attempt=").append(attemptNumber);
        sb.append(", operation='").append(operationName).append('\'');

        if (ntStatus != 0) {
            sb.append(", ntStatus=0x").append(Long.toHexString(ntStatus));
        }

        if (!context.isEmpty()) {
            sb.append(", context=").append(context);
        }

        sb.append(", elapsed=").append(getElapsedTime()).append("ms");
        sb.append('}');

        return sb.toString();
    }
}
