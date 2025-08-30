/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package jcifs;

import java.util.HashMap;
import java.util.Map;

/**
 * Base exception class for all SMB-related exceptions
 *
 * This class provides a consistent exception handling mechanism
 * with proper error context and recovery information.
 */
public class SmbException extends CIFSException {

    private static final long serialVersionUID = 1L;

    /**
     * Error severity levels
     */
    public enum Severity {
        RECOVERABLE, // Can retry the operation
        TRANSIENT, // Temporary error, retry after delay
        PERMANENT, // Operation cannot succeed
        FATAL // Connection or session must be terminated
    }

    /**
     * Error categories
     */
    public enum Category {
        AUTHENTICATION, AUTHORIZATION, NETWORK, PROTOCOL, RESOURCE, CONFIGURATION, ENCRYPTION, TIMEOUT, IO, UNKNOWN
    }

    private final int errorCode;
    private final Severity severity;
    private final Category category;
    private final Map<String, Object> context;
    private final long timestamp;
    private String recoveryHint;

    /**
     * Creates an SMB exception with detailed context
     *
     * @param message the error message
     * @param errorCode the SMB error code
     * @param severity the error severity
     * @param category the error category
     */
    public SmbException(String message, int errorCode, Severity severity, Category category) {
        super(message);
        this.errorCode = errorCode;
        this.severity = severity;
        this.category = category;
        this.context = new HashMap<>();
        this.timestamp = System.currentTimeMillis();
    }

    /**
     * Creates an SMB exception with cause
     *
     * @param message the error message
     * @param errorCode the SMB error code
     * @param severity the error severity
     * @param category the error category
     * @param cause the cause exception
     */
    public SmbException(String message, int errorCode, Severity severity, Category category, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.severity = severity;
        this.category = category;
        this.context = new HashMap<>();
        this.timestamp = System.currentTimeMillis();
    }

    /**
     * Creates an SMB exception with default severity
     *
     * @param message the error message
     * @param errorCode the SMB error code
     * @param category the error category
     */
    public SmbException(String message, int errorCode, Category category) {
        this(message, errorCode, Severity.PERMANENT, category);
    }

    /**
     * Adds context information to the exception
     *
     * @param key the context key
     * @param value the context value
     * @return this exception for chaining
     */
    public SmbException withContext(String key, Object value) {
        this.context.put(key, value);
        return this;
    }

    /**
     * Sets a recovery hint for the error
     *
     * @param hint the recovery hint
     * @return this exception for chaining
     */
    public SmbException withRecoveryHint(String hint) {
        this.recoveryHint = hint;
        return this;
    }

    /**
     * Gets the SMB error code
     *
     * @return the error code
     */
    public int getErrorCode() {
        return errorCode;
    }

    /**
     * Gets the error severity
     *
     * @return the severity
     */
    public Severity getSeverity() {
        return severity;
    }

    /**
     * Gets the error category
     *
     * @return the category
     */
    public Category getCategory() {
        return category;
    }

    /**
     * Gets the error context
     *
     * @return the context map
     */
    public Map<String, Object> getContext() {
        return new HashMap<>(context);
    }

    /**
     * Gets a specific context value
     *
     * @param key the context key
     * @return the context value or null
     */
    public Object getContextValue(String key) {
        return context.get(key);
    }

    /**
     * Gets the error timestamp
     *
     * @return the timestamp
     */
    public long getTimestamp() {
        return timestamp;
    }

    /**
     * Gets the recovery hint
     *
     * @return the recovery hint or null
     */
    public String getRecoveryHint() {
        return recoveryHint;
    }

    /**
     * Checks if the error is recoverable
     *
     * @return true if recoverable
     */
    public boolean isRecoverable() {
        return severity == Severity.RECOVERABLE || severity == Severity.TRANSIENT;
    }

    /**
     * Checks if retry should be attempted
     *
     * @return true if retry is recommended
     */
    public boolean shouldRetry() {
        return severity == Severity.RECOVERABLE || severity == Severity.TRANSIENT;
    }

    /**
     * Gets recommended retry delay in milliseconds
     *
     * @return retry delay or 0 if no retry
     */
    public long getRetryDelay() {
        switch (severity) {
        case RECOVERABLE:
            return 100; // Immediate retry with small delay
        case TRANSIENT:
            return 5000; // Wait 5 seconds
        default:
            return 0; // No retry
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append("[code=").append(errorCode);
        sb.append(", severity=").append(severity);
        sb.append(", category=").append(category);
        sb.append(", message=").append(getMessage());

        if (recoveryHint != null) {
            sb.append(", hint=").append(recoveryHint);
        }

        if (!context.isEmpty()) {
            sb.append(", context=").append(context);
        }

        sb.append("]");
        return sb.toString();
    }
}
