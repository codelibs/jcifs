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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for InputValidator
 */
public class InputValidatorTest {

    @Test
    @DisplayName("Test valid buffer size validation")
    void testValidBufferSize() {
        assertDoesNotThrow(() -> InputValidator.validateBufferSize(100, 1000, "test"));
        assertDoesNotThrow(() -> InputValidator.validateBufferSize(0, 1000, "test"));
        assertDoesNotThrow(() -> InputValidator.validateBufferSize(1000, 1000, "test"));
    }

    @Test
    @DisplayName("Test invalid buffer size validation")
    void testInvalidBufferSize() {
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateBufferSize(-1, 1000, "test"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateBufferSize(1001, 1000, "test"));
    }

    @Test
    @DisplayName("Test SMB2 buffer size validation")
    void testSmb2BufferSize() {
        assertDoesNotThrow(() -> InputValidator.validateSmb2BufferSize(1000000L, "test"));
        assertDoesNotThrow(() -> InputValidator.validateSmb2BufferSize(InputValidator.MAX_SMB2_BUFFER_SIZE, "test"));

        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateSmb2BufferSize(-1L, "test"));
        assertThrows(IllegalArgumentException.class,
                () -> InputValidator.validateSmb2BufferSize(InputValidator.MAX_SMB2_BUFFER_SIZE + 1, "test"));
    }

    @Test
    @DisplayName("Test array bounds validation")
    void testArrayBounds() {
        byte[] src = new byte[100];
        byte[] dst = new byte[100];

        assertDoesNotThrow(() -> InputValidator.validateArrayBounds(src, 0, dst, 0, 100));
        assertDoesNotThrow(() -> InputValidator.validateArrayBounds(src, 50, dst, 50, 50));

        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateArrayBounds(null, 0, dst, 0, 10));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateArrayBounds(src, 0, null, 0, 10));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateArrayBounds(src, -1, dst, 0, 10));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateArrayBounds(src, 0, dst, -1, 10));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateArrayBounds(src, 0, dst, 0, -1));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateArrayBounds(src, 50, dst, 0, 60));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateArrayBounds(src, 0, dst, 50, 60));
    }

    @ParameterizedTest
    @DisplayName("Test path traversal detection")
    @ValueSource(strings = { "../etc/passwd", "..\\windows\\system32", "folder/../../../etc", "test/../../root", "..\\..\\..\\windows" })
    void testPathTraversal(String path) {
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateSmbPath(path));
    }

    @ParameterizedTest
    @DisplayName("Test valid SMB paths")
    @ValueSource(strings = { "\\\\server\\share\\file.txt", "folder\\subfolder\\file.doc", "Documents\\Reports\\2024", "file.txt", "" })
    void testValidSmbPaths(String path) {
        assertDoesNotThrow(() -> InputValidator.validateSmbPath(path));
    }

    @ParameterizedTest
    @DisplayName("Test invalid path characters")
    @ValueSource(strings = { "file:name.txt", "file<name>.txt", "file|name.txt", "file*name.txt", "file?name.txt", "file\"name.txt" })
    void testInvalidPathCharacters(String path) {
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateSmbPath(path));
    }

    @Test
    @DisplayName("Test path normalization")
    void testPathNormalization() {
        assertEquals("\\server\\share\\file.txt", InputValidator.normalizeSmbPath("/server/share/file.txt"));
        assertEquals("\\server\\share\\file.txt", InputValidator.normalizeSmbPath("\\server\\\\share\\\\file.txt"));
        assertEquals("\\server\\share", InputValidator.normalizeSmbPath("\\server\\share\\"));
        assertEquals("\\", InputValidator.normalizeSmbPath("\\"));
    }

    @ParameterizedTest
    @DisplayName("Test valid usernames")
    @ValueSource(strings = { "user", "user123", "user.name", "user-name", "user_name", "user@domain.com" })
    void testValidUsernames(String username) {
        assertDoesNotThrow(() -> InputValidator.validateUsername(username));
    }

    @ParameterizedTest
    @DisplayName("Test invalid usernames")
    @ValueSource(strings = { "user name", // space
            "user#name", // invalid character
            "user$name" // invalid character
    })
    void testInvalidUsernames(String username) {
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateUsername(username));
    }

    @Test
    @DisplayName("Test username length validation")
    void testUsernameLengthValidation() {
        String longUsername = "a".repeat(InputValidator.MAX_USERNAME_LENGTH + 1);
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateUsername(longUsername));
    }

    @ParameterizedTest
    @DisplayName("Test valid domains")
    @ValueSource(strings = { "domain", "domain.local", "sub.domain.com", "domain-01", "domain_test" })
    void testValidDomains(String domain) {
        assertDoesNotThrow(() -> InputValidator.validateDomain(domain));
    }

    @Test
    @DisplayName("Test safe integer addition")
    void testSafeAddition() {
        assertEquals(100, InputValidator.safeAdd(50, 50));
        assertEquals(0, InputValidator.safeAdd(-50, 50));

        assertThrows(ArithmeticException.class, () -> InputValidator.safeAdd(Integer.MAX_VALUE, 1));
        assertThrows(ArithmeticException.class, () -> InputValidator.safeAdd(Integer.MIN_VALUE, -1));
    }

    @Test
    @DisplayName("Test safe integer multiplication")
    void testSafeMultiplication() {
        assertEquals(100, InputValidator.safeMultiply(10, 10));
        assertEquals(-100, InputValidator.safeMultiply(10, -10));

        assertThrows(ArithmeticException.class, () -> InputValidator.safeMultiply(Integer.MAX_VALUE, 2));
        assertThrows(ArithmeticException.class, () -> InputValidator.safeMultiply(Integer.MIN_VALUE, 2));
    }

    @Test
    @DisplayName("Test credits validation")
    void testCreditsValidation() {
        assertDoesNotThrow(() -> InputValidator.validateCredits(0));
        assertDoesNotThrow(() -> InputValidator.validateCredits(100));
        assertDoesNotThrow(() -> InputValidator.validateCredits(InputValidator.MAX_CREDITS));

        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateCredits(-1));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateCredits(InputValidator.MAX_CREDITS + 1));
    }

    @ParameterizedTest
    @DisplayName("Test valid share names")
    @ValueSource(strings = { "share", "share$", "SHARE", "share123", "share-name", "share_name", "share.name" })
    void testValidShareNames(String share) {
        assertDoesNotThrow(() -> InputValidator.validateShareName(share));
    }

    @Test
    @DisplayName("Test port validation")
    void testPortValidation() {
        assertDoesNotThrow(() -> InputValidator.validatePort(445));
        assertDoesNotThrow(() -> InputValidator.validatePort(139));
        assertDoesNotThrow(() -> InputValidator.validatePort(1));
        assertDoesNotThrow(() -> InputValidator.validatePort(65535));

        assertThrows(IllegalArgumentException.class, () -> InputValidator.validatePort(0));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validatePort(-1));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validatePort(65536));
    }

    @Test
    @DisplayName("Test timeout validation")
    void testTimeoutValidation() {
        assertDoesNotThrow(() -> InputValidator.validateTimeout(1000L, "test"));
        assertDoesNotThrow(() -> InputValidator.validateTimeout(0L, "test"));
        assertDoesNotThrow(() -> InputValidator.validateTimeout(3600000L, "test"));

        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateTimeout(-1L, "test"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateTimeout(3600001L, "test"));
    }

    @Test
    @DisplayName("Test string sanitization for logging")
    void testSanitizeForLogging() {
        // Test null input
        assertEquals("null", InputValidator.sanitizeForLogging(null));

        // Test normal string without control characters
        assertEquals("test", InputValidator.sanitizeForLogging("test"));

        // Test removal of control characters (they are removed, not replaced with spaces)
        assertEquals("teststring", InputValidator.sanitizeForLogging("test\0string"));
        assertEquals("teststring", InputValidator.sanitizeForLogging("test\nstring"));
        assertEquals("teststring", InputValidator.sanitizeForLogging("test\rstring"));
        assertEquals("teststring", InputValidator.sanitizeForLogging("test\tstring"));

        // Test long string truncation
        String longString = "a".repeat(1100);
        String sanitized = InputValidator.sanitizeForLogging(longString);
        assertEquals(1000, sanitized.length());
        assertTrue(sanitized.endsWith("..."));
    }

    @Test
    @DisplayName("Test require non-empty validation")
    void testRequireNonEmpty() {
        assertEquals("test", InputValidator.requireNonEmpty("test", "field"));

        assertThrows(IllegalArgumentException.class, () -> InputValidator.requireNonEmpty(null, "field"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.requireNonEmpty("", "field"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.requireNonEmpty("   ", "field"));
    }

    @Test
    @DisplayName("Test array length validation")
    void testArrayLengthValidation() {
        byte[] array = new byte[16];
        assertDoesNotThrow(() -> InputValidator.validateArrayLength(array, 16, "test"));

        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateArrayLength(null, 16, "test"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateArrayLength(array, 15, "test"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateArrayLength(array, 17, "test"));
    }

    @ParameterizedTest
    @DisplayName("Test range validation")
    @CsvSource({ "50, 0, 100, true", "0, 0, 100, true", "100, 0, 100, true", "-1, 0, 100, false", "101, 0, 100, false" })
    void testRangeValidation(long value, long min, long max, boolean valid) {
        if (valid) {
            assertDoesNotThrow(() -> InputValidator.validateRange(value, min, max, "test"));
        } else {
            assertThrows(IllegalArgumentException.class, () -> InputValidator.validateRange(value, min, max, "test"));
        }
    }
}