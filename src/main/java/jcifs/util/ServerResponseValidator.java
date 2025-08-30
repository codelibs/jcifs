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

import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.smb.SmbException;

/**
 * Validator for SMB server responses to prevent buffer overflow and injection attacks.
 *
 * Features:
 * - Buffer bounds checking
 * - Integer overflow prevention
 * - Size validation
 * - Protocol compliance checking
 * - Malformed response detection
 */
public class ServerResponseValidator {

    private static final Logger log = LoggerFactory.getLogger(ServerResponseValidator.class);

    // Protocol limits
    private static final int MAX_SMB_MESSAGE_SIZE = 16 * 1024 * 1024; // 16MB max for SMB3
    private static final int MAX_SMB1_MESSAGE_SIZE = 65535; // 64KB for SMB1
    private static final int MIN_SMB_HEADER_SIZE = 32;
    private static final int MAX_PATH_COMPONENT_SIZE = 255;
    private static final int MAX_PATH_SIZE = 32767;

    // Statistics
    private final AtomicLong totalValidations = new AtomicLong(0);
    private final AtomicLong failedValidations = new AtomicLong(0);
    private final AtomicLong bufferOverflowsPrevented = new AtomicLong(0);
    private final AtomicLong integerOverflowsPrevented = new AtomicLong(0);

    /**
     * Validate SMB response buffer bounds
     *
     * @param buffer the buffer to validate
     * @param expectedSize expected minimum size
     * @param maxSize maximum allowed size
     * @throws SmbException if validation fails
     */
    public void validateBuffer(byte[] buffer, int expectedSize, int maxSize) throws SmbException {
        totalValidations.incrementAndGet();

        if (buffer == null) {
            failedValidations.incrementAndGet();
            throw new SmbException("Response buffer is null");
        }

        if (buffer.length < expectedSize) {
            failedValidations.incrementAndGet();
            bufferOverflowsPrevented.incrementAndGet();
            log.warn("Response buffer too small: {} < {}", buffer.length, expectedSize);
            throw new SmbException("Response buffer too small: " + buffer.length + " < " + expectedSize);
        }

        if (buffer.length > maxSize) {
            failedValidations.incrementAndGet();
            bufferOverflowsPrevented.incrementAndGet();
            log.warn("Response buffer too large: {} > {}", buffer.length, maxSize);
            throw new SmbException("Response buffer exceeds maximum: " + buffer.length + " > " + maxSize);
        }
    }

    /**
     * Validate buffer access bounds
     *
     * @param buffer the buffer
     * @param offset offset to access
     * @param length length to read
     * @throws SmbException if access would exceed bounds
     */
    public void validateBufferAccess(byte[] buffer, int offset, int length) throws SmbException {
        totalValidations.incrementAndGet();

        if (buffer == null) {
            failedValidations.incrementAndGet();
            throw new SmbException("Buffer is null");
        }

        if (offset < 0) {
            failedValidations.incrementAndGet();
            bufferOverflowsPrevented.incrementAndGet();
            throw new SmbException("Negative offset: " + offset);
        }

        if (length < 0) {
            failedValidations.incrementAndGet();
            bufferOverflowsPrevented.incrementAndGet();
            throw new SmbException("Negative length: " + length);
        }

        // Check for integer overflow
        if (offset > buffer.length - length) {
            failedValidations.incrementAndGet();
            bufferOverflowsPrevented.incrementAndGet();
            log.warn("Buffer access out of bounds: offset={}, length={}, buffer.length={}", offset, length, buffer.length);
            throw new SmbException("Buffer access out of bounds");
        }
    }

    /**
     * Safely add integers checking for overflow
     *
     * @param a first value
     * @param b second value
     * @return sum
     * @throws SmbException if overflow would occur
     */
    public int safeAdd(int a, int b) throws SmbException {
        totalValidations.incrementAndGet();

        long result = (long) a + (long) b;
        if (result > Integer.MAX_VALUE || result < Integer.MIN_VALUE) {
            failedValidations.incrementAndGet();
            integerOverflowsPrevented.incrementAndGet();
            log.warn("Integer overflow in addition: {} + {} = {}", a, b, result);
            throw new SmbException("Integer overflow detected");
        }
        return (int) result;
    }

    /**
     * Safely multiply integers checking for overflow
     *
     * @param a first value
     * @param b second value
     * @return product
     * @throws SmbException if overflow would occur
     */
    public int safeMultiply(int a, int b) throws SmbException {
        totalValidations.incrementAndGet();

        long result = (long) a * (long) b;
        if (result > Integer.MAX_VALUE || result < Integer.MIN_VALUE) {
            failedValidations.incrementAndGet();
            integerOverflowsPrevented.incrementAndGet();
            log.warn("Integer overflow in multiplication: {} * {} = {}", a, b, result);
            throw new SmbException("Integer overflow detected");
        }
        return (int) result;
    }

    /**
     * Validate SMB message size
     *
     * @param size the message size
     * @param isSmb1 whether this is SMB1 protocol
     * @throws SmbException if size is invalid
     */
    public void validateMessageSize(int size, boolean isSmb1) throws SmbException {
        totalValidations.incrementAndGet();

        if (size < MIN_SMB_HEADER_SIZE) {
            failedValidations.incrementAndGet();
            throw new SmbException("Message size too small: " + size);
        }

        int maxSize = isSmb1 ? MAX_SMB1_MESSAGE_SIZE : MAX_SMB_MESSAGE_SIZE;
        if (size > maxSize) {
            failedValidations.incrementAndGet();
            log.warn("Message size exceeds maximum: {} > {}", size, maxSize);
            throw new SmbException("Message size exceeds maximum: " + size + " > " + maxSize);
        }
    }

    /**
     * Validate string from server response
     *
     * @param str string to validate
     * @param maxLength maximum allowed length
     * @param fieldName field name for error messages
     * @throws SmbException if string is invalid
     */
    public void validateString(String str, int maxLength, String fieldName) throws SmbException {
        totalValidations.incrementAndGet();

        if (str == null) {
            return; // Null strings are allowed
        }

        if (str.length() > maxLength) {
            failedValidations.incrementAndGet();
            log.warn("{} exceeds maximum length: {} > {}", fieldName, str.length(), maxLength);
            throw new SmbException(fieldName + " exceeds maximum length: " + str.length());
        }

        // Check for null bytes
        if (str.indexOf('\0') != -1) {
            failedValidations.incrementAndGet();
            log.warn("{} contains null bytes", fieldName);
            throw new SmbException(fieldName + " contains null bytes");
        }

        // Check for control characters
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (c < 0x20 && c != '\t' && c != '\r' && c != '\n') {
                failedValidations.incrementAndGet();
                log.warn("{} contains control characters", fieldName);
                throw new SmbException(fieldName + " contains control characters");
            }
        }
    }

    /**
     * Validate path from server response
     *
     * @param path path to validate
     * @throws SmbException if path is invalid
     */
    public void validatePath(String path) throws SmbException {
        totalValidations.incrementAndGet();

        if (path == null || path.isEmpty()) {
            return; // Empty paths allowed
        }

        // Check overall path length
        if (path.length() > MAX_PATH_SIZE) {
            failedValidations.incrementAndGet();
            log.warn("Path exceeds maximum length: {}", path.length());
            throw new SmbException("Path exceeds maximum length");
        }

        // Check for directory traversal
        if (path.contains("..") || path.contains("./") || path.contains(".\\")) {
            failedValidations.incrementAndGet();
            log.warn("Path contains traversal sequences: {}", sanitizeForLog(path));
            throw new SmbException("Path contains directory traversal");
        }

        // Check individual components
        String[] components = path.split("[/\\\\]");
        for (String component : components) {
            if (component.length() > MAX_PATH_COMPONENT_SIZE) {
                failedValidations.incrementAndGet();
                log.warn("Path component exceeds maximum length: {}", component.length());
                throw new SmbException("Path component too long");
            }
        }
    }

    /**
     * Validate file size from server
     *
     * @param size file size
     * @throws SmbException if size is invalid
     */
    public void validateFileSize(long size) throws SmbException {
        totalValidations.incrementAndGet();

        if (size < 0) {
            failedValidations.incrementAndGet();
            log.warn("Negative file size: {}", size);
            throw new SmbException("Invalid file size: " + size);
        }

        // Reasonable upper limit (1TB)
        long maxSize = 1099511627776L;
        if (size > maxSize) {
            failedValidations.incrementAndGet();
            log.warn("File size exceeds reasonable limit: {} > {}", size, maxSize);
            throw new SmbException("File size exceeds limit: " + size);
        }
    }

    /**
     * Validate offset and length for file operations
     *
     * @param offset file offset
     * @param length operation length
     * @param fileSize total file size
     * @throws SmbException if parameters are invalid
     */
    public void validateFileOperation(long offset, long length, long fileSize) throws SmbException {
        totalValidations.incrementAndGet();

        if (offset < 0) {
            failedValidations.incrementAndGet();
            throw new SmbException("Negative offset: " + offset);
        }

        if (length < 0) {
            failedValidations.incrementAndGet();
            throw new SmbException("Negative length: " + length);
        }

        if (fileSize < 0) {
            failedValidations.incrementAndGet();
            throw new SmbException("Invalid file size: " + fileSize);
        }

        // Check for overflow
        if (offset > Long.MAX_VALUE - length) {
            failedValidations.incrementAndGet();
            integerOverflowsPrevented.incrementAndGet();
            throw new SmbException("Integer overflow in file operation");
        }

        // Check bounds
        if (offset + length > fileSize) {
            failedValidations.incrementAndGet();
            log.warn("File operation exceeds file size: offset={}, length={}, size={}", offset, length, fileSize);
            throw new SmbException("File operation exceeds file bounds");
        }
    }

    /**
     * Validate SMB header fields
     *
     * @param protocolId protocol identifier
     * @param structureSize structure size field
     * @param command command code
     * @throws SmbException if header is invalid
     */
    public void validateSmbHeader(int protocolId, int structureSize, int command) throws SmbException {
        totalValidations.incrementAndGet();

        // Check SMB1 signature
        if (protocolId == 0x424D53FF) { // 0xFF 'S' 'M' 'B'
            // SMB1
            if (structureSize < 32 || structureSize > 65535) {
                failedValidations.incrementAndGet();
                throw new SmbException("Invalid SMB1 header size: " + structureSize);
            }
        }
        // Check SMB2/3 signature
        else if (protocolId == 0x424D53FE) { // 0xFE 'S' 'M' 'B'
            // SMB2/3
            if (structureSize != 64) {
                failedValidations.incrementAndGet();
                throw new SmbException("Invalid SMB2 header size: " + structureSize);
            }
        } else {
            failedValidations.incrementAndGet();
            log.warn("Invalid SMB protocol ID: 0x{}", Integer.toHexString(protocolId));
            throw new SmbException("Invalid SMB protocol identifier");
        }

        // Validate command is in valid range
        if (command < 0 || command > 255) {
            failedValidations.incrementAndGet();
            throw new SmbException("Invalid command code: " + command);
        }
    }

    /**
     * Validate array size before allocation
     *
     * @param size array size to allocate
     * @param elementSize size of each element
     * @param maxElements maximum allowed elements
     * @throws SmbException if allocation would be too large
     */
    public void validateArrayAllocation(int size, int elementSize, int maxElements) throws SmbException {
        totalValidations.incrementAndGet();

        if (size < 0) {
            failedValidations.incrementAndGet();
            throw new SmbException("Negative array size: " + size);
        }

        if (elementSize < 1) {
            failedValidations.incrementAndGet();
            throw new SmbException("Invalid element size: " + elementSize);
        }

        if (size > maxElements) {
            failedValidations.incrementAndGet();
            log.warn("Array size exceeds maximum: {} > {}", size, maxElements);
            throw new SmbException("Array size exceeds maximum: " + size);
        }

        // Check total memory allocation
        long totalSize = (long) size * (long) elementSize;
        long maxAllocation = 100 * 1024 * 1024; // 100MB max

        if (totalSize > maxAllocation) {
            failedValidations.incrementAndGet();
            log.warn("Array allocation too large: {} bytes", totalSize);
            throw new SmbException("Array allocation exceeds limit");
        }
    }

    /**
     * Get validation statistics
     */
    public ValidationStats getStats() {
        return new ValidationStats(totalValidations.get(), failedValidations.get(), bufferOverflowsPrevented.get(),
                integerOverflowsPrevented.get());
    }

    /**
     * Reset statistics
     */
    public void resetStats() {
        totalValidations.set(0);
        failedValidations.set(0);
        bufferOverflowsPrevented.set(0);
        integerOverflowsPrevented.set(0);
    }

    /**
     * Sanitize string for safe logging
     */
    private String sanitizeForLog(String str) {
        if (str == null) {
            return "null";
        }

        // Truncate long strings
        if (str.length() > 100) {
            str = str.substring(0, 100) + "...";
        }

        // Remove control characters
        return str.replaceAll("[\\x00-\\x1F\\x7F]", "?");
    }

    /**
     * Validation statistics
     */
    public static class ValidationStats {
        private final long totalValidations;
        private final long failedValidations;
        private final long bufferOverflowsPrevented;
        private final long integerOverflowsPrevented;

        public ValidationStats(long totalValidations, long failedValidations, long bufferOverflowsPrevented,
                long integerOverflowsPrevented) {
            this.totalValidations = totalValidations;
            this.failedValidations = failedValidations;
            this.bufferOverflowsPrevented = bufferOverflowsPrevented;
            this.integerOverflowsPrevented = integerOverflowsPrevented;
        }

        public long getTotalValidations() {
            return totalValidations;
        }

        public long getFailedValidations() {
            return failedValidations;
        }

        public long getBufferOverflowsPrevented() {
            return bufferOverflowsPrevented;
        }

        public long getIntegerOverflowsPrevented() {
            return integerOverflowsPrevented;
        }

        public double getFailureRate() {
            return totalValidations > 0 ? (double) failedValidations / totalValidations : 0;
        }
    }
}
