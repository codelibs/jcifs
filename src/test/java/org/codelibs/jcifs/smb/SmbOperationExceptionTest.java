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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for SmbOperationException
 */
@DisplayName("SmbOperationException Tests")
public class SmbOperationExceptionTest {

    private SmbOperationException exception;

    @BeforeEach
    void setUp() {
        exception = null;
    }

    @Test
    @DisplayName("Should create exception with error code and message")
    void testBasicCreation() {
        // When
        exception = new SmbOperationException(SmbOperationException.ErrorCode.FILE_NOT_FOUND, "test.txt");

        // Then
        assertNotNull(exception);
        assertEquals(SmbOperationException.ErrorCode.FILE_NOT_FOUND, exception.getErrorCode());
        assertTrue(exception.getMessage().contains("FILE_NOT_FOUND"));
        assertTrue(exception.getMessage().contains("test.txt"));
        assertEquals(SmbOperationException.ErrorCategory.FILE_SYSTEM, exception.getErrorCategory());
        assertFalse(exception.isRetryable());
    }

    @Test
    @DisplayName("Should create exception with cause")
    void testCreationWithCause() {
        // Given
        Exception cause = new RuntimeException("Original error");

        // When
        exception = new SmbOperationException(SmbOperationException.ErrorCode.CONNECTION_FAILED, "Failed to connect", cause);

        // Then
        assertEquals(cause, exception.getCause());
        assertEquals(SmbOperationException.ErrorCategory.NETWORK, exception.getErrorCategory());
        assertTrue(exception.isRetryable());
    }

    @Test
    @DisplayName("Should handle retry policy correctly")
    void testRetryPolicy() {
        // Given
        SmbOperationException.RetryPolicy policy = new SmbOperationException.RetryPolicy(3, 1000, 10000, 2.0, true);

        exception = new SmbOperationException(SmbOperationException.ErrorCode.CONNECTION_TIMEOUT, "Timeout occurred", null, policy, null);

        // When/Then - Should retry for attempts 1 and 2
        assertTrue(exception.shouldRetry(1));
        assertTrue(exception.shouldRetry(2));
        assertFalse(exception.shouldRetry(3)); // Max attempts reached

        // Verify exponential backoff
        assertEquals(1000, exception.getRetryDelayMs(1));
        assertEquals(2000, exception.getRetryDelayMs(2));
        assertEquals(4000, exception.getRetryDelayMs(3));
    }

    @Test
    @DisplayName("Should handle no retry policy")
    void testNoRetryPolicy() {
        // When
        exception = new SmbOperationException(SmbOperationException.ErrorCode.AUTHENTICATION_FAILED, "Bad credentials", null,
                SmbOperationException.RetryPolicy.NO_RETRY, null);

        // Then
        assertFalse(exception.isRetryable());
        assertFalse(exception.shouldRetry(1));
        assertEquals(0, exception.getRetryDelayMs(1));
    }

    @Test
    @DisplayName("Should add and retrieve context information")
    void testContextInformation() {
        // Given
        Map<String, Object> initialContext = new HashMap<>();
        initialContext.put("host", "server.example.com");
        initialContext.put("port", 445);

        exception = new SmbOperationException(SmbOperationException.ErrorCode.ACCESS_DENIED, "Permission denied", null,
                SmbOperationException.RetryPolicy.DEFAULT, initialContext);

        // When
        exception.withContext("path", "/share/file.txt").withContext("user", "testuser");

        // Then
        Map<String, Object> context = exception.getContext();
        assertEquals("server.example.com", context.get("host"));
        assertEquals(445, context.get("port"));
        assertEquals("/share/file.txt", context.get("path"));
        assertEquals("testuser", context.get("user"));
    }

    @Test
    @DisplayName("Should identify error categories correctly")
    void testErrorCategories() {
        // Network error
        exception = new SmbOperationException(SmbOperationException.ErrorCode.CONNECTION_RESET, "Connection lost");
        assertTrue(exception.isNetworkError());
        assertFalse(exception.isAuthenticationError());
        assertFalse(exception.isFileSystemError());
        assertFalse(exception.isTransientError());

        // Authentication error
        exception = new SmbOperationException(SmbOperationException.ErrorCode.INVALID_CREDENTIALS, "Bad password");
        assertFalse(exception.isNetworkError());
        assertTrue(exception.isAuthenticationError());
        assertFalse(exception.isFileSystemError());
        assertFalse(exception.isTransientError());

        // File system error
        exception = new SmbOperationException(SmbOperationException.ErrorCode.PATH_NOT_FOUND, "Directory missing");
        assertFalse(exception.isNetworkError());
        assertFalse(exception.isAuthenticationError());
        assertTrue(exception.isFileSystemError());
        assertFalse(exception.isTransientError());

        // Transient error
        exception = new SmbOperationException(SmbOperationException.ErrorCode.SERVICE_UNAVAILABLE, "Server busy");
        assertFalse(exception.isNetworkError());
        assertFalse(exception.isAuthenticationError());
        assertFalse(exception.isFileSystemError());
        assertTrue(exception.isTransientError());
    }

    @Test
    @DisplayName("Should track elapsed time")
    void testElapsedTime() throws InterruptedException {
        // Given
        exception = new SmbOperationException(SmbOperationException.ErrorCode.BUSY, "Server busy");

        // When
        Thread.sleep(100);

        // Then
        assertTrue(exception.getElapsedTime() >= 100);
        assertTrue(exception.getElapsedTime() < 200);
    }

    @Test
    @DisplayName("Should create retry exception correctly")
    void testRetryException() {
        // Given
        SmbOperationException original = new SmbOperationException(SmbOperationException.ErrorCode.CONNECTION_TIMEOUT, "Timeout");
        original.withContext("attempt", 1);

        // When
        SmbOperationException retry = SmbOperationException.forRetry(original, 2);

        // Then
        assertEquals(original.getErrorCode(), retry.getErrorCode());
        assertEquals(original.getMessage(), retry.getMessage());
        assertEquals(original.getCause(), retry.getCause());
        assertNotNull(retry.getContext());
    }

    @Test
    @DisplayName("Should format message correctly")
    void testMessageFormatting() {
        // With custom message
        exception = new SmbOperationException(SmbOperationException.ErrorCode.FILE_EXISTS, "document.pdf already exists");
        assertTrue(exception.getMessage().contains("FILE_EXISTS"));
        assertTrue(exception.getMessage().contains("File already exists"));
        assertTrue(exception.getMessage().contains("document.pdf already exists"));

        // Without custom message
        exception = new SmbOperationException(SmbOperationException.ErrorCode.DISK_FULL, null);
        assertTrue(exception.getMessage().contains("DISK_FULL"));
        assertTrue(exception.getMessage().contains("Disk full"));
    }

    @Test
    @DisplayName("Should have correct retryable flags for error codes")
    void testErrorCodeRetryableFlags() {
        // Retryable errors
        assertTrue(SmbOperationException.ErrorCode.CONNECTION_FAILED.isRetryable());
        assertTrue(SmbOperationException.ErrorCode.CONNECTION_TIMEOUT.isRetryable());
        assertTrue(SmbOperationException.ErrorCode.CONNECTION_RESET.isRetryable());
        assertTrue(SmbOperationException.ErrorCode.SESSION_EXPIRED.isRetryable());
        assertTrue(SmbOperationException.ErrorCode.OUT_OF_MEMORY.isRetryable());
        assertTrue(SmbOperationException.ErrorCode.TOO_MANY_SESSIONS.isRetryable());
        assertTrue(SmbOperationException.ErrorCode.RESOURCE_LOCKED.isRetryable());
        assertTrue(SmbOperationException.ErrorCode.BUSY.isRetryable());
        assertTrue(SmbOperationException.ErrorCode.TRY_AGAIN.isRetryable());
        assertTrue(SmbOperationException.ErrorCode.SERVICE_UNAVAILABLE.isRetryable());

        // Non-retryable errors
        assertFalse(SmbOperationException.ErrorCode.HOST_NOT_FOUND.isRetryable());
        assertFalse(SmbOperationException.ErrorCode.AUTHENTICATION_FAILED.isRetryable());
        assertFalse(SmbOperationException.ErrorCode.ACCESS_DENIED.isRetryable());
        assertFalse(SmbOperationException.ErrorCode.INVALID_CREDENTIALS.isRetryable());
        assertFalse(SmbOperationException.ErrorCode.FILE_NOT_FOUND.isRetryable());
        assertFalse(SmbOperationException.ErrorCode.PATH_NOT_FOUND.isRetryable());
        assertFalse(SmbOperationException.ErrorCode.FILE_EXISTS.isRetryable());
        assertFalse(SmbOperationException.ErrorCode.DIRECTORY_NOT_EMPTY.isRetryable());
        assertFalse(SmbOperationException.ErrorCode.DISK_FULL.isRetryable());
        assertFalse(SmbOperationException.ErrorCode.QUOTA_EXCEEDED.isRetryable());
        assertFalse(SmbOperationException.ErrorCode.INVALID_PARAMETER.isRetryable());
        assertFalse(SmbOperationException.ErrorCode.NOT_SUPPORTED.isRetryable());
        assertFalse(SmbOperationException.ErrorCode.INVALID_PROTOCOL.isRetryable());
        assertFalse(SmbOperationException.ErrorCode.MESSAGE_TOO_LARGE.isRetryable());
        assertFalse(SmbOperationException.ErrorCode.UNKNOWN_ERROR.isRetryable());
        assertFalse(SmbOperationException.ErrorCode.INTERNAL_ERROR.isRetryable());
    }

    @Test
    @DisplayName("Should test predefined retry policies")
    void testPredefinedRetryPolicies() {
        // DEFAULT policy
        SmbOperationException.RetryPolicy defaultPolicy = SmbOperationException.RetryPolicy.DEFAULT;
        assertEquals(3, defaultPolicy.getMaxAttempts());
        assertEquals(1000, defaultPolicy.getInitialDelayMs());
        assertEquals(30000, defaultPolicy.getMaxDelayMs());
        assertEquals(2.0, defaultPolicy.getBackoffMultiplier());
        assertTrue(defaultPolicy.isExponentialBackoff());

        // AGGRESSIVE policy
        SmbOperationException.RetryPolicy aggressivePolicy = SmbOperationException.RetryPolicy.AGGRESSIVE;
        assertEquals(5, aggressivePolicy.getMaxAttempts());
        assertEquals(500, aggressivePolicy.getInitialDelayMs());
        assertEquals(60000, aggressivePolicy.getMaxDelayMs());
        assertEquals(1.5, aggressivePolicy.getBackoffMultiplier());
        assertTrue(aggressivePolicy.isExponentialBackoff());

        // CONSERVATIVE policy
        SmbOperationException.RetryPolicy conservativePolicy = SmbOperationException.RetryPolicy.CONSERVATIVE;
        assertEquals(2, conservativePolicy.getMaxAttempts());
        assertEquals(2000, conservativePolicy.getInitialDelayMs());
        assertEquals(10000, conservativePolicy.getMaxDelayMs());
        assertEquals(3.0, conservativePolicy.getBackoffMultiplier());
        assertTrue(conservativePolicy.isExponentialBackoff());

        // NO_RETRY policy
        SmbOperationException.RetryPolicy noRetryPolicy = SmbOperationException.RetryPolicy.NO_RETRY;
        assertEquals(1, noRetryPolicy.getMaxAttempts());
        assertEquals(0, noRetryPolicy.getInitialDelayMs());
        assertEquals(0, noRetryPolicy.getMaxDelayMs());
        assertEquals(1.0, noRetryPolicy.getBackoffMultiplier());
        assertFalse(noRetryPolicy.isExponentialBackoff());
    }

    @Test
    @DisplayName("Should limit retry delay to maximum")
    void testMaxDelayLimit() {
        // Given
        SmbOperationException.RetryPolicy policy = new SmbOperationException.RetryPolicy(10, 1000, 5000, 2.0, true);

        // When - Calculate delays for increasing attempts
        long delay1 = policy.getDelayMs(1);
        long delay2 = policy.getDelayMs(2);
        long delay3 = policy.getDelayMs(3);
        long delay4 = policy.getDelayMs(4);
        long delay10 = policy.getDelayMs(10);

        // Then
        assertEquals(1000, delay1);
        assertEquals(2000, delay2);
        assertEquals(4000, delay3);
        assertEquals(5000, delay4); // Capped at max
        assertEquals(5000, delay10); // Still capped
    }

    @Test
    @DisplayName("Should handle non-exponential backoff")
    void testConstantBackoff() {
        // Given
        SmbOperationException.RetryPolicy policy = new SmbOperationException.RetryPolicy(5, 2000, 10000, 1.0, false);

        // When
        long delay1 = policy.getDelayMs(1);
        long delay2 = policy.getDelayMs(2);
        long delay3 = policy.getDelayMs(3);

        // Then - All delays should be the same
        assertEquals(2000, delay1);
        assertEquals(2000, delay2);
        assertEquals(2000, delay3);
    }

    @Test
    @DisplayName("Should provide meaningful toString output")
    void testToString() {
        // Given
        exception = new SmbOperationException(SmbOperationException.ErrorCode.ACCESS_DENIED, "Cannot access share");
        exception.withContext("share", "\\\\server\\share");
        exception.withContext("user", "john");

        // When
        String str = exception.toString();

        // Then
        assertNotNull(str);
        assertTrue(str.contains("SmbOperationException"));
        assertTrue(str.contains("ACCESS_DENIED"));
        assertTrue(str.contains("AUTHENTICATION"));
        assertTrue(str.contains("retryable=false"));
        assertTrue(str.contains("attempt=1"));
        assertTrue(str.contains("context="));
        assertTrue(str.contains("elapsed="));
    }

    @Test
    @DisplayName("Should handle context with null values")
    void testNullContext() {
        // When
        exception = new SmbOperationException(SmbOperationException.ErrorCode.UNKNOWN_ERROR, "Something went wrong", null, null, null);

        // Then
        assertNotNull(exception.getContext());
        assertTrue(exception.getContext().isEmpty());

        // Adding null context should be safe
        exception.withContext(null);
        assertTrue(exception.getContext().isEmpty());
    }

    @Test
    @DisplayName("Should be serializable")
    void testSerialization() throws Exception {
        // Given
        Map<String, Object> context = new HashMap<>();
        context.put("key1", "value1");
        context.put("key2", 123);

        exception = new SmbOperationException(SmbOperationException.ErrorCode.FILE_NOT_FOUND, "test.txt not found",
                new RuntimeException("cause"), SmbOperationException.RetryPolicy.AGGRESSIVE, context);

        // When - Serialize
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(baos);
        oos.writeObject(exception);
        oos.close();

        // And deserialize
        java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(baos.toByteArray());
        java.io.ObjectInputStream ois = new java.io.ObjectInputStream(bais);
        SmbOperationException deserialized = (SmbOperationException) ois.readObject();
        ois.close();

        // Then
        assertNotNull(deserialized);
        assertEquals(exception.getErrorCode(), deserialized.getErrorCode());
        assertEquals(exception.getMessage(), deserialized.getMessage());
        assertEquals(exception.getContext().get("key1"), deserialized.getContext().get("key1"));
        assertEquals(exception.getContext().get("key2"), deserialized.getContext().get("key2"));
    }
}