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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.codelibs.jcifs.smb.SmbException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test cases for ServerResponseValidator
 */
public class ServerResponseValidatorTest {

    private ServerResponseValidator validator;

    @BeforeEach
    public void setUp() {
        validator = new ServerResponseValidator();
    }

    @Test
    public void testValidBuffer() throws Exception {
        byte[] buffer = new byte[1024];
        validator.validateBuffer(buffer, 100, 2048);
        // Should pass without exception
    }

    @Test
    public void testNullBuffer() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateBuffer(null, 100, 1024);
        });
    }

    @Test
    public void testBufferTooSmall() throws Exception {
        byte[] buffer = new byte[50];
        assertThrows(SmbException.class, () -> {
            validator.validateBuffer(buffer, 100, 1024);
        });
    }

    @Test
    public void testBufferTooLarge() throws Exception {
        byte[] buffer = new byte[2048];
        assertThrows(SmbException.class, () -> {
            validator.validateBuffer(buffer, 100, 1024);
        });
    }

    @Test
    public void testValidBufferAccess() throws Exception {
        byte[] buffer = new byte[100];
        validator.validateBufferAccess(buffer, 10, 20);
        // Should pass without exception
    }

    @Test
    public void testBufferAccessNullBuffer() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateBufferAccess(null, 0, 10);
        });
    }

    @Test
    public void testBufferAccessNegativeOffset() throws Exception {
        byte[] buffer = new byte[100];
        assertThrows(SmbException.class, () -> {
            validator.validateBufferAccess(buffer, -1, 10);
        });
    }

    @Test
    public void testBufferAccessNegativeLength() throws Exception {
        byte[] buffer = new byte[100];
        assertThrows(SmbException.class, () -> {
            validator.validateBufferAccess(buffer, 10, -1);
        });
    }

    @Test
    public void testBufferAccessOutOfBounds() throws Exception {
        byte[] buffer = new byte[100];
        assertThrows(SmbException.class, () -> {
            validator.validateBufferAccess(buffer, 90, 20);
        });
    }

    @Test
    public void testBufferAccessIntegerOverflow() throws Exception {
        byte[] buffer = new byte[100];
        assertThrows(SmbException.class, () -> {
            validator.validateBufferAccess(buffer, Integer.MAX_VALUE - 5, 10);
        });
    }

    @Test
    public void testSafeAdd() throws Exception {
        assertEquals(10, validator.safeAdd(5, 5));
        assertEquals(0, validator.safeAdd(-5, 5));
        assertEquals(-10, validator.safeAdd(-5, -5));
    }

    @Test
    public void testSafeAddOverflow() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.safeAdd(Integer.MAX_VALUE, 1);
        });
    }

    @Test
    public void testSafeAddUnderflow() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.safeAdd(Integer.MIN_VALUE, -1);
        });
    }

    @Test
    public void testSafeMultiply() throws Exception {
        assertEquals(20, validator.safeMultiply(4, 5));
        assertEquals(-20, validator.safeMultiply(-4, 5));
        assertEquals(0, validator.safeMultiply(0, 1000));
    }

    @Test
    public void testSafeMultiplyOverflow() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.safeMultiply(Integer.MAX_VALUE, 2);
        });
    }

    @Test
    public void testSafeMultiplyLargeValues() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.safeMultiply(100000, 100000);
        });
    }

    @Test
    public void testValidMessageSize() throws Exception {
        validator.validateMessageSize(1024, false);
        validator.validateMessageSize(65535, true);
        validator.validateMessageSize(1048576, false); // 1MB for SMB2
    }

    @Test
    public void testMessageSizeTooSmall() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateMessageSize(20, false);
        });
    }

    @Test
    public void testSmb1MessageSizeTooLarge() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateMessageSize(65536, true);
        });
    }

    @Test
    public void testSmb2MessageSizeTooLarge() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateMessageSize(17 * 1024 * 1024, false);
        });
    }

    @Test
    public void testValidString() throws Exception {
        validator.validateString("normal string", 100, "test");
        validator.validateString(null, 100, "test"); // Null should be allowed
        // Should pass without exception
    }

    @Test
    public void testStringTooLong() throws Exception {
        String longString = "a".repeat(300);
        assertThrows(SmbException.class, () -> {
            validator.validateString(longString, 255, "test");
        });
    }

    @Test
    public void testStringWithNullBytes() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateString("test\0string", 100, "test");
        });
    }

    @Test
    public void testStringWithControlChars() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateString("test\u0001string", 100, "test");
        });
    }

    @Test
    public void testStringWithAllowedWhitespace() throws Exception {
        validator.validateString("test\tstring", 100, "test");
        validator.validateString("test\r\nstring", 100, "test");
        // Should pass without exception
    }

    @Test
    public void testValidPath() throws Exception {
        validator.validatePath("\\share\\folder\\file.txt");
        validator.validatePath("C:\\Windows\\System32");
        validator.validatePath(null); // Null should be allowed
        validator.validatePath(""); // Empty should be allowed
    }

    @Test
    public void testPathTooLong() throws Exception {
        String longPath = "\\share" + "\\folder".repeat(5000);
        assertThrows(SmbException.class, () -> {
            validator.validatePath(longPath);
        });
    }

    @Test
    public void testPathWithTraversal() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validatePath("\\share\\..\\..\\etc\\passwd");
        });
    }

    @Test
    public void testPathWithDotSlash() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validatePath("\\share\\./system");
        });
    }

    @Test
    public void testPathComponentTooLong() throws Exception {
        String longComponent = "a".repeat(256);
        assertThrows(SmbException.class, () -> {
            validator.validatePath("\\share\\" + longComponent);
        });
    }

    @Test
    public void testValidFileSize() throws Exception {
        validator.validateFileSize(0);
        validator.validateFileSize(1024);
        validator.validateFileSize(1073741824L); // 1GB
    }

    @Test
    public void testNegativeFileSize() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateFileSize(-1);
        });
    }

    @Test
    public void testFileSizeTooLarge() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateFileSize(2L * 1099511627776L); // 2TB
        });
    }

    @Test
    public void testValidFileOperation() throws Exception {
        validator.validateFileOperation(0, 1024, 10000);
        validator.validateFileOperation(5000, 1000, 10000);
    }

    @Test
    public void testFileOperationNegativeOffset() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateFileOperation(-1, 100, 1000);
        });
    }

    @Test
    public void testFileOperationNegativeLength() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateFileOperation(10, -1, 1000);
        });
    }

    @Test
    public void testFileOperationExceedsBounds() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateFileOperation(900, 200, 1000);
        });
    }

    @Test
    public void testFileOperationOverflow() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateFileOperation(Long.MAX_VALUE - 100, 200, Long.MAX_VALUE);
        });
    }

    @Test
    public void testValidSmbHeader() throws Exception {
        // SMB1 header
        validator.validateSmbHeader(0x424D53FF, 32, 0x72);

        // SMB2 header
        validator.validateSmbHeader(0x424D53FE, 64, 0x00);
    }

    @Test
    public void testInvalidProtocolId() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateSmbHeader(0xDEADBEEF, 64, 0x00);
        });
    }

    @Test
    public void testInvalidSmb1HeaderSize() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateSmbHeader(0x424D53FF, 20, 0x00);
        });
    }

    @Test
    public void testInvalidSmb2HeaderSize() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateSmbHeader(0x424D53FE, 32, 0x00);
        });
    }

    @Test
    public void testInvalidCommand() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateSmbHeader(0x424D53FF, 32, 256);
        });
    }

    @Test
    public void testValidArrayAllocation() throws Exception {
        validator.validateArrayAllocation(100, 10, 1000);
        validator.validateArrayAllocation(0, 10, 1000); // Zero size should be allowed
    }

    @Test
    public void testArrayAllocationNegativeSize() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateArrayAllocation(-1, 10, 1000);
        });
    }

    @Test
    public void testArrayAllocationInvalidElementSize() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateArrayAllocation(100, 0, 1000);
        });
    }

    @Test
    public void testArrayAllocationExceedsMax() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateArrayAllocation(2000, 10, 1000);
        });
    }

    @Test
    public void testArrayAllocationMemoryLimit() throws Exception {
        assertThrows(SmbException.class, () -> {
            validator.validateArrayAllocation(1000000, 200, 1000000); // 200MB
        });
    }

    @Test
    public void testStatistics() throws Exception {
        // Reset stats
        validator.resetStats();

        ServerResponseValidator.ValidationStats stats = validator.getStats();
        assertEquals(0, stats.getTotalValidations());
        assertEquals(0, stats.getFailedValidations());

        // Perform some validations
        try {
            validator.validateBuffer(new byte[100], 50, 200);
        } catch (SmbException e) {
            // Ignore
        }

        try {
            validator.validateBuffer(null, 50, 200); // Will fail
        } catch (SmbException e) {
            // Expected
        }

        try {
            validator.safeAdd(Integer.MAX_VALUE, 1); // Will fail
        } catch (SmbException e) {
            // Expected
        }

        stats = validator.getStats();
        assertTrue(stats.getTotalValidations() > 0);
        assertTrue(stats.getFailedValidations() > 0);
        assertTrue(stats.getFailureRate() > 0);
        assertTrue(stats.getFailureRate() <= 1.0);
    }

    @Test
    public void testBufferOverflowPrevention() throws Exception {
        validator.resetStats();

        // Trigger buffer overflow prevention
        try {
            byte[] buffer = new byte[10];
            validator.validateBufferAccess(buffer, 5, 10);
        } catch (SmbException e) {
            // Expected
        }

        ServerResponseValidator.ValidationStats stats = validator.getStats();
        assertTrue(stats.getBufferOverflowsPrevented() > 0);
    }

    @Test
    public void testIntegerOverflowPrevention() throws Exception {
        validator.resetStats();

        // Trigger integer overflow prevention
        try {
            validator.safeAdd(Integer.MAX_VALUE, Integer.MAX_VALUE);
        } catch (SmbException e) {
            // Expected
        }

        try {
            validator.safeMultiply(Integer.MAX_VALUE, 2);
        } catch (SmbException e) {
            // Expected
        }

        ServerResponseValidator.ValidationStats stats = validator.getStats();
        assertTrue(stats.getIntegerOverflowsPrevented() > 0);
    }

    @Test
    public void testBoundaryValues() throws Exception {
        // Test boundary values for safe operations
        assertEquals(Integer.MAX_VALUE, validator.safeAdd(Integer.MAX_VALUE, 0));
        assertEquals(Integer.MIN_VALUE, validator.safeAdd(Integer.MIN_VALUE, 0));
        assertEquals(0, validator.safeMultiply(0, Integer.MAX_VALUE));
        assertEquals(1, validator.safeMultiply(1, 1));

        // Test exact buffer boundaries
        byte[] buffer = new byte[100];
        validator.validateBufferAccess(buffer, 0, 100); // Exactly full buffer
        validator.validateBufferAccess(buffer, 100, 0); // Zero length at end
    }
}
