package org.codelibs.jcifs.smb.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Test class for SMBSigningDigest interface
 * Tests the contract and behavior of signing and verification methods
 */
class SMBSigningDigestTest {

    @Mock
    private SMBSigningDigest signingDigest;

    @Mock
    private CommonServerMessageBlock request;

    @Mock
    private CommonServerMessageBlock response;

    @Mock
    private CommonServerMessageBlock message;

    private byte[] testData;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testData = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    }

    @Test
    @DisplayName("Test sign method with valid parameters")
    void testSignWithValidParameters() {
        // Arrange
        int offset = 0;
        int length = testData.length;

        // Act
        signingDigest.sign(testData, offset, length, request, response);

        // Assert
        verify(signingDigest, times(1)).sign(testData, offset, length, request, response);
    }

    @Test
    @DisplayName("Test sign method with different offsets")
    void testSignWithDifferentOffsets() {
        // Arrange
        byte[] largeData = new byte[100];
        for (int i = 0; i < largeData.length; i++) {
            largeData[i] = (byte) i;
        }

        // Test with different offsets
        int[] offsets = { 0, 10, 50, 90 };

        for (int offset : offsets) {
            // Act
            signingDigest.sign(largeData, offset, 10, request, response);

            // Assert
            verify(signingDigest).sign(largeData, offset, 10, request, response);
        }

        // Verify method was called correct number of times
        verify(signingDigest, times(offsets.length)).sign(any(byte[].class), anyInt(), anyInt(), any(CommonServerMessageBlock.class),
                any(CommonServerMessageBlock.class));
    }

    @Test
    @DisplayName("Test verify method returns true for valid signature")
    void testVerifyReturnsTrue() {
        // Arrange
        int offset = 0;
        int length = testData.length;
        int extraPad = 0;
        when(signingDigest.verify(testData, offset, length, extraPad, message)).thenReturn(true);

        // Act
        boolean result = signingDigest.verify(testData, offset, length, extraPad, message);

        // Assert
        assertTrue(result, "Verify should return true for valid signature");
        verify(signingDigest, times(1)).verify(testData, offset, length, extraPad, message);
    }

    @Test
    @DisplayName("Test verify method returns false for invalid signature")
    void testVerifyReturnsFalse() {
        // Arrange
        int offset = 0;
        int length = testData.length;
        int extraPad = 0;
        when(signingDigest.verify(testData, offset, length, extraPad, message)).thenReturn(false);

        // Act
        boolean result = signingDigest.verify(testData, offset, length, extraPad, message);

        // Assert
        assertFalse(result, "Verify should return false for invalid signature");
        verify(signingDigest, times(1)).verify(testData, offset, length, extraPad, message);
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 2, 4, 8, 16 })
    @DisplayName("Test verify method with different extra padding values")
    void testVerifyWithDifferentExtraPadding(int extraPad) {
        // Arrange
        int offset = 0;
        int length = testData.length;
        when(signingDigest.verify(testData, offset, length, extraPad, message)).thenReturn(true);

        // Act
        boolean result = signingDigest.verify(testData, offset, length, extraPad, message);

        // Assert
        assertTrue(result);
        verify(signingDigest).verify(testData, offset, length, extraPad, message);
    }

    @Test
    @DisplayName("Test sign method with null request and response")
    void testSignWithNullMessages() {
        // Arrange
        int offset = 0;
        int length = testData.length;

        // Act
        signingDigest.sign(testData, offset, length, null, null);

        // Assert
        verify(signingDigest, times(1)).sign(testData, offset, length, null, null);
    }

    @Test
    @DisplayName("Test verify method with null message")
    void testVerifyWithNullMessage() {
        // Arrange
        int offset = 0;
        int length = testData.length;
        int extraPad = 0;
        when(signingDigest.verify(testData, offset, length, extraPad, null)).thenReturn(false);

        // Act
        boolean result = signingDigest.verify(testData, offset, length, extraPad, null);

        // Assert
        assertFalse(result);
        verify(signingDigest, times(1)).verify(testData, offset, length, extraPad, null);
    }

    @Test
    @DisplayName("Test sign method with empty data array")
    void testSignWithEmptyData() {
        // Arrange
        byte[] emptyData = new byte[0];
        int offset = 0;
        int length = 0;

        // Act
        signingDigest.sign(emptyData, offset, length, request, response);

        // Assert
        verify(signingDigest, times(1)).sign(emptyData, offset, length, request, response);
    }

    @Test
    @DisplayName("Test verify method with empty data array")
    void testVerifyWithEmptyData() {
        // Arrange
        byte[] emptyData = new byte[0];
        int offset = 0;
        int length = 0;
        int extraPad = 0;
        when(signingDigest.verify(emptyData, offset, length, extraPad, message)).thenReturn(false);

        // Act
        boolean result = signingDigest.verify(emptyData, offset, length, extraPad, message);

        // Assert
        assertFalse(result);
        verify(signingDigest, times(1)).verify(emptyData, offset, length, extraPad, message);
    }

    @Test
    @DisplayName("Test sign method with large data array")
    void testSignWithLargeData() {
        // Arrange
        byte[] largeData = new byte[65536]; // 64KB
        for (int i = 0; i < largeData.length; i++) {
            largeData[i] = (byte) (i % 256);
        }
        int offset = 1024;
        int length = 32768; // 32KB

        // Act
        signingDigest.sign(largeData, offset, length, request, response);

        // Assert
        verify(signingDigest, times(1)).sign(largeData, offset, length, request, response);
    }

    @Test
    @DisplayName("Test verify method with large data array")
    void testVerifyWithLargeData() {
        // Arrange
        byte[] largeData = new byte[65536]; // 64KB
        for (int i = 0; i < largeData.length; i++) {
            largeData[i] = (byte) (i % 256);
        }
        int offset = 1024;
        int length = 32768; // 32KB
        int extraPad = 4;
        when(signingDigest.verify(largeData, offset, length, extraPad, message)).thenReturn(true);

        // Act
        boolean result = signingDigest.verify(largeData, offset, length, extraPad, message);

        // Assert
        assertTrue(result);
        verify(signingDigest, times(1)).verify(largeData, offset, length, extraPad, message);
    }

    @Test
    @DisplayName("Test multiple sign operations in sequence")
    void testMultipleSignOperations() {
        // Arrange
        int iterations = 10;

        // Act
        for (int i = 0; i < iterations; i++) {
            signingDigest.sign(testData, i, testData.length - i, request, response);
        }

        // Assert
        verify(signingDigest, times(iterations)).sign(any(byte[].class), anyInt(), anyInt(), any(CommonServerMessageBlock.class),
                any(CommonServerMessageBlock.class));
    }

    @Test
    @DisplayName("Test multiple verify operations with mixed results")
    void testMultipleVerifyOperations() {
        // Arrange
        when(signingDigest.verify(any(byte[].class), anyInt(), anyInt(), anyInt(), any())).thenReturn(true, false, true, false, true);

        // Act & Assert
        assertTrue(signingDigest.verify(testData, 0, 8, 0, message));
        assertFalse(signingDigest.verify(testData, 0, 8, 0, message));
        assertTrue(signingDigest.verify(testData, 0, 8, 0, message));
        assertFalse(signingDigest.verify(testData, 0, 8, 0, message));
        assertTrue(signingDigest.verify(testData, 0, 8, 0, message));

        verify(signingDigest, times(5)).verify(any(byte[].class), anyInt(), anyInt(), anyInt(), any());
    }

    @Test
    @DisplayName("Test sign method invocation with argument capture")
    void testSignMethodArgumentCapture() {
        // Arrange
        ArgumentCaptor<byte[]> dataCaptor = ArgumentCaptor.forClass(byte[].class);
        ArgumentCaptor<Integer> offsetCaptor = ArgumentCaptor.forClass(Integer.class);
        ArgumentCaptor<Integer> lengthCaptor = ArgumentCaptor.forClass(Integer.class);

        int offset = 2;
        int length = 5;

        // Act
        signingDigest.sign(testData, offset, length, request, response);

        // Assert
        verify(signingDigest).sign(dataCaptor.capture(), offsetCaptor.capture(), lengthCaptor.capture(), eq(request), eq(response));

        assertArrayEquals(testData, dataCaptor.getValue());
        assertEquals(offset, offsetCaptor.getValue());
        assertEquals(length, lengthCaptor.getValue());
    }

    @Test
    @DisplayName("Test verify method invocation with argument capture")
    void testVerifyMethodArgumentCapture() {
        // Arrange
        ArgumentCaptor<byte[]> dataCaptor = ArgumentCaptor.forClass(byte[].class);
        ArgumentCaptor<Integer> offsetCaptor = ArgumentCaptor.forClass(Integer.class);
        ArgumentCaptor<Integer> lengthCaptor = ArgumentCaptor.forClass(Integer.class);
        ArgumentCaptor<Integer> extraPadCaptor = ArgumentCaptor.forClass(Integer.class);

        int offset = 3;
        int length = 4;
        int extraPad = 2;
        when(signingDigest.verify(any(), anyInt(), anyInt(), anyInt(), any())).thenReturn(true);

        // Act
        signingDigest.verify(testData, offset, length, extraPad, message);

        // Assert
        verify(signingDigest).verify(dataCaptor.capture(), offsetCaptor.capture(), lengthCaptor.capture(), extraPadCaptor.capture(),
                eq(message));

        assertArrayEquals(testData, dataCaptor.getValue());
        assertEquals(offset, offsetCaptor.getValue());
        assertEquals(length, lengthCaptor.getValue());
        assertEquals(extraPad, extraPadCaptor.getValue());
    }
}
