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

import java.util.regex.Pattern;

/**
 * Comprehensive input validation utility for SMB protocol implementation.
 * Provides validation methods to prevent buffer overflows, injection attacks,
 * and other security vulnerabilities.
 */
public final class InputValidator {

    private InputValidator() {
        // Utility class
    }

    // Maximum sizes for various SMB fields (based on protocol specifications)
    /** Maximum length for SMB path (Windows MAX_PATH) */
    public static final int MAX_SMB_PATH_LENGTH = 32767; // Windows MAX_PATH
    /** Maximum length for username */
    public static final int MAX_USERNAME_LENGTH = 256;
    /** Maximum length for domain name */
    public static final int MAX_DOMAIN_LENGTH = 255;
    /** Maximum length for share name */
    public static final int MAX_SHARE_NAME_LENGTH = 80;
    /** Maximum buffer size for SMB1 (64KB) */
    public static final int MAX_BUFFER_SIZE = 65536; // 64KB default max buffer
    /** Maximum buffer size for SMB2/3 (8MB) */
    public static final int MAX_SMB2_BUFFER_SIZE = 8388608; // 8MB for SMB2/3
    /** Maximum number of credits */
    public static final int MAX_CREDITS = 65535;

    // Patterns for validation
    private static final Pattern VALID_USERNAME = Pattern.compile("^[a-zA-Z0-9._\\-@]+$");
    private static final Pattern VALID_DOMAIN = Pattern.compile("^[a-zA-Z0-9._\\-]+$");
    private static final Pattern VALID_SHARE = Pattern.compile("^[a-zA-Z0-9._\\-$]+$");
    private static final Pattern PATH_TRAVERSAL = Pattern.compile("\\.\\.[\\\\/]");
    private static final Pattern INVALID_PATH_CHARS = Pattern.compile("[\\x00-\\x1f\"*:<>?|]");

    /**
     * Validates buffer size to prevent overflow
     *
     * @param size the buffer size to validate
     * @param maxSize the maximum allowed size
     * @param fieldName the field name for error reporting
     * @throws IllegalArgumentException if size is invalid
     */
    public static void validateBufferSize(int size, int maxSize, String fieldName) {
        if (size < 0) {
            throw new IllegalArgumentException(fieldName + " size cannot be negative: " + size);
        }
        if (size > maxSize) {
            throw new IllegalArgumentException(fieldName + " size exceeds maximum (" + maxSize + "): " + size);
        }
    }

    /**
     * Validates buffer size for SMB2/3
     *
     * @param size the buffer size to validate
     * @param fieldName the field name for error reporting
     * @throws IllegalArgumentException if size is invalid
     */
    public static void validateSmb2BufferSize(long size, String fieldName) {
        if (size < 0) {
            throw new IllegalArgumentException(fieldName + " size cannot be negative: " + size);
        }
        if (size > MAX_SMB2_BUFFER_SIZE) {
            throw new IllegalArgumentException(fieldName + " size exceeds SMB2 maximum (" + MAX_SMB2_BUFFER_SIZE + "): " + size);
        }
    }

    /**
     * Validates array bounds for safe copying
     *
     * @param src source array
     * @param srcOffset source offset
     * @param dst destination array
     * @param dstOffset destination offset
     * @param length copy length
     * @throws IllegalArgumentException if bounds are invalid
     */
    public static void validateArrayBounds(byte[] src, int srcOffset, byte[] dst, int dstOffset, int length) {
        if (src == null || dst == null) {
            throw new IllegalArgumentException("Arrays cannot be null");
        }
        if (srcOffset < 0 || dstOffset < 0 || length < 0) {
            throw new IllegalArgumentException("Offsets and length must be non-negative");
        }
        if (srcOffset + length > src.length) {
            throw new IllegalArgumentException(
                    "Source array bounds exceeded: offset=" + srcOffset + ", length=" + length + ", array.length=" + src.length);
        }
        if (dstOffset + length > dst.length) {
            throw new IllegalArgumentException(
                    "Destination array bounds exceeded: offset=" + dstOffset + ", length=" + length + ", array.length=" + dst.length);
        }
    }

    /**
     * Validates SMB path to prevent traversal attacks
     *
     * @param path the path to validate
     * @throws IllegalArgumentException if path is invalid
     */
    public static void validateSmbPath(String path) {
        if (path == null) {
            throw new IllegalArgumentException("Path cannot be null");
        }
        if (path.length() > MAX_SMB_PATH_LENGTH) {
            throw new IllegalArgumentException("Path exceeds maximum length: " + path.length());
        }
        if (PATH_TRAVERSAL.matcher(path).find()) {
            throw new IllegalArgumentException("Path contains directory traversal sequences: " + path);
        }
        if (INVALID_PATH_CHARS.matcher(path).find()) {
            throw new IllegalArgumentException("Path contains invalid characters: " + path);
        }
    }

    /**
     * Validates and normalizes SMB path
     *
     * @param path the path to normalize
     * @return normalized path
     */
    public static String normalizeSmbPath(String path) {
        validateSmbPath(path);

        // Normalize slashes
        path = path.replace('/', '\\');

        // Remove redundant slashes
        path = path.replaceAll("\\\\+", "\\\\");

        // Remove trailing slash unless it's root
        if (path.length() > 1 && path.endsWith("\\")) {
            path = path.substring(0, path.length() - 1);
        }

        return path;
    }

    /**
     * Validates username
     *
     * @param username the username to validate
     * @throws IllegalArgumentException if username is invalid
     */
    public static void validateUsername(String username) {
        if (username == null) {
            return; // Null username allowed for anonymous
        }
        if (username.length() > MAX_USERNAME_LENGTH) {
            throw new IllegalArgumentException("Username exceeds maximum length: " + username.length());
        }
        if (!username.isEmpty() && !VALID_USERNAME.matcher(username).matches()) {
            throw new IllegalArgumentException("Username contains invalid characters: " + username);
        }
    }

    /**
     * Validates domain name
     *
     * @param domain the domain to validate
     * @throws IllegalArgumentException if domain is invalid
     */
    public static void validateDomain(String domain) {
        if (domain == null) {
            return; // Null domain allowed
        }
        if (domain.length() > MAX_DOMAIN_LENGTH) {
            throw new IllegalArgumentException("Domain exceeds maximum length: " + domain.length());
        }
        if (!domain.isEmpty() && !VALID_DOMAIN.matcher(domain).matches()) {
            throw new IllegalArgumentException("Domain contains invalid characters: " + domain);
        }
    }

    /**
     * Validates share name
     *
     * @param share the share name to validate
     * @throws IllegalArgumentException if share name is invalid
     */
    public static void validateShareName(String share) {
        if (share == null || share.isEmpty()) {
            throw new IllegalArgumentException("Share name cannot be null or empty");
        }
        if (share.length() > MAX_SHARE_NAME_LENGTH) {
            throw new IllegalArgumentException("Share name exceeds maximum length: " + share.length());
        }
        if (!VALID_SHARE.matcher(share).matches()) {
            throw new IllegalArgumentException("Share name contains invalid characters: " + share);
        }
    }

    /**
     * Validates integer for safe arithmetic operations
     *
     * @param a first operand
     * @param b second operand
     * @param operation the operation name
     * @throws ArithmeticException if operation would overflow
     */
    public static void validateIntegerAddition(int a, int b, String operation) {
        long result = (long) a + (long) b;
        if (result > Integer.MAX_VALUE || result < Integer.MIN_VALUE) {
            throw new ArithmeticException(operation + " would cause integer overflow: " + a + " + " + b);
        }
    }

    /**
     * Validates integer multiplication for safe arithmetic
     *
     * @param a first operand
     * @param b second operand
     * @param operation the operation name
     * @throws ArithmeticException if operation would overflow
     */
    public static void validateIntegerMultiplication(int a, int b, String operation) {
        long result = (long) a * (long) b;
        if (result > Integer.MAX_VALUE || result < Integer.MIN_VALUE) {
            throw new ArithmeticException(operation + " would cause integer overflow: " + a + " * " + b);
        }
    }

    /**
     * Safe integer addition with overflow check
     *
     * @param a first operand
     * @param b second operand
     * @return sum of a and b
     * @throws ArithmeticException if overflow occurs
     */
    public static int safeAdd(int a, int b) {
        validateIntegerAddition(a, b, "Addition");
        return a + b;
    }

    /**
     * Safe integer multiplication with overflow check
     *
     * @param a first operand
     * @param b second operand
     * @return product of a and b
     * @throws ArithmeticException if overflow occurs
     */
    public static int safeMultiply(int a, int b) {
        validateIntegerMultiplication(a, b, "Multiplication");
        return a * b;
    }

    /**
     * Validates SMB credits value
     *
     * @param credits the credits value to validate
     * @throws IllegalArgumentException if credits value is invalid
     */
    public static void validateCredits(int credits) {
        if (credits < 0) {
            throw new IllegalArgumentException("Credits cannot be negative: " + credits);
        }
        if (credits > MAX_CREDITS) {
            throw new IllegalArgumentException("Credits exceed maximum (" + MAX_CREDITS + "): " + credits);
        }
    }

    /**
     * Validates a string is not null or empty
     *
     * @param value the string to validate
     * @param fieldName the field name for error reporting
     * @return the validated string
     * @throws IllegalArgumentException if string is null or empty
     */
    public static String requireNonEmpty(String value, String fieldName) {
        if (value == null) {
            throw new IllegalArgumentException(fieldName + " cannot be null");
        }
        if (value.trim().isEmpty()) {
            throw new IllegalArgumentException(fieldName + " cannot be empty");
        }
        return value;
    }

    /**
     * Validates array is not null and has expected length
     *
     * @param array the array to validate
     * @param expectedLength the expected length
     * @param fieldName the field name for error reporting
     * @throws IllegalArgumentException if array is invalid
     */
    public static void validateArrayLength(byte[] array, int expectedLength, String fieldName) {
        if (array == null) {
            throw new IllegalArgumentException(fieldName + " cannot be null");
        }
        if (array.length != expectedLength) {
            throw new IllegalArgumentException(fieldName + " must be " + expectedLength + " bytes, got " + array.length);
        }
    }

    /**
     * Validates a port number
     *
     * @param port the port number to validate
     * @throws IllegalArgumentException if port is invalid
     */
    public static void validatePort(int port) {
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Invalid port number: " + port);
        }
    }

    /**
     * Validates timeout value
     *
     * @param timeout timeout in milliseconds
     * @param fieldName the field name for error reporting
     * @throws IllegalArgumentException if timeout is invalid
     */
    public static void validateTimeout(long timeout, String fieldName) {
        if (timeout < 0) {
            throw new IllegalArgumentException(fieldName + " cannot be negative: " + timeout);
        }
        if (timeout > 3600000L) { // Max 1 hour
            throw new IllegalArgumentException(fieldName + " exceeds maximum (1 hour): " + timeout);
        }
    }

    /**
     * Sanitizes a string for safe logging (removes control characters)
     *
     * @param input the string to sanitize
     * @return sanitized string safe for logging
     */
    public static String sanitizeForLogging(String input) {
        if (input == null) {
            return "null";
        }
        // Remove control characters and limit length
        String sanitized = input.replaceAll("[\\x00-\\x1f]", "");
        if (sanitized.length() > 1000) {
            sanitized = sanitized.substring(0, 997) + "...";
        }
        return sanitized;
    }

    /**
     * Validates that a value is within the specified range
     *
     * @param value the value to check
     * @param min minimum value (inclusive)
     * @param max maximum value (inclusive)
     * @param fieldName field name for error reporting
     * @throws IllegalArgumentException if value is out of range
     */
    public static void validateRange(long value, long min, long max, String fieldName) {
        if (value < min || value > max) {
            throw new IllegalArgumentException(fieldName + " must be between " + min + " and " + max + ", got " + value);
        }
    }
}
