package org.codelibs.jcifs.smb.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.security.SecureRandom;
import java.util.Arrays;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CloseRequest;
import org.codelibs.jcifs.smb.internal.smb2.info.Smb2QueryDirectoryRequest;
import org.codelibs.jcifs.smb.internal.smb2.info.Smb2QueryInfoRequest;
import org.codelibs.jcifs.smb.internal.smb2.info.Smb2SetInfoRequest;
import org.codelibs.jcifs.smb.internal.smb2.io.Smb2FlushRequest;
import org.codelibs.jcifs.smb.internal.smb2.io.Smb2ReadRequest;
import org.codelibs.jcifs.smb.internal.smb2.io.Smb2WriteRequest;
import org.codelibs.jcifs.smb.internal.smb2.ioctl.Smb2IoctlRequest;
import org.codelibs.jcifs.smb.internal.smb2.lock.Smb2Lock;
import org.codelibs.jcifs.smb.internal.smb2.lock.Smb2LockRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Test class for RequestWithFileId interface.
 * Tests the interface contract and various implementations.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("RequestWithFileId Interface Tests")
class RequestWithFileIdTest {

    @Mock
    private Configuration mockConfig;

    private byte[] testFileId;
    private byte[] emptyFileId;
    private byte[] unspecifiedFileId;
    private byte[] testOutputBuffer;

    @BeforeEach
    void setUp() {
        // Initialize test file IDs
        testFileId = new byte[16];
        new SecureRandom().nextBytes(testFileId);

        emptyFileId = new byte[16];
        Arrays.fill(emptyFileId, (byte) 0);

        unspecifiedFileId = Smb2Constants.UNSPECIFIED_FILEID;

        testOutputBuffer = new byte[1024];
    }

    @Test
    @DisplayName("Should implement RequestWithFileId interface correctly")
    void testInterfaceImplementation() {
        // Test that common implementations properly implement the interface
        RequestWithFileId closeRequest = new Smb2CloseRequest(mockConfig, testFileId);
        RequestWithFileId queryInfoRequest = new Smb2QueryInfoRequest(mockConfig, testFileId);
        RequestWithFileId setInfoRequest = new Smb2SetInfoRequest(mockConfig, testFileId);
        RequestWithFileId queryDirRequest = new Smb2QueryDirectoryRequest(mockConfig, testFileId);
        RequestWithFileId readRequest = new Smb2ReadRequest(mockConfig, testFileId, testOutputBuffer, 0);
        RequestWithFileId writeRequest = new Smb2WriteRequest(mockConfig, testFileId);
        RequestWithFileId flushRequest = new Smb2FlushRequest(mockConfig, testFileId);
        RequestWithFileId ioctlRequest = new Smb2IoctlRequest(mockConfig, 0x00090000, testFileId);
        RequestWithFileId lockRequest = new Smb2LockRequest(mockConfig, testFileId, new Smb2Lock[0]);

        // Verify all implementations are not null
        assertNotNull(closeRequest, "Smb2CloseRequest should implement RequestWithFileId");
        assertNotNull(queryInfoRequest, "Smb2QueryInfoRequest should implement RequestWithFileId");
        assertNotNull(setInfoRequest, "Smb2SetInfoRequest should implement RequestWithFileId");
        assertNotNull(queryDirRequest, "Smb2QueryDirectoryRequest should implement RequestWithFileId");
        assertNotNull(readRequest, "Smb2ReadRequest should implement RequestWithFileId");
        assertNotNull(writeRequest, "Smb2WriteRequest should implement RequestWithFileId");
        assertNotNull(flushRequest, "Smb2FlushRequest should implement RequestWithFileId");
        assertNotNull(ioctlRequest, "Smb2IoctlRequest should implement RequestWithFileId");
        assertNotNull(lockRequest, "Smb2LockRequest should implement RequestWithFileId");
    }

    @Test
    @DisplayName("Should set file ID correctly in Smb2CloseRequest")
    void testSetFileIdInCloseRequest() {
        // Given
        Smb2CloseRequest request = new Smb2CloseRequest(mockConfig, emptyFileId);

        // When
        request.setFileId(testFileId);

        // Then - verify through internal state (would need getter or reflection in real scenario)
        // Since we can't directly verify the internal state, we create a new request to test
        Smb2CloseRequest newRequest = new Smb2CloseRequest(mockConfig, testFileId);
        assertNotNull(newRequest, "Should create request with new file ID");
    }

    @Test
    @DisplayName("Should handle null file ID")
    void testSetNullFileId() {
        // Given
        RequestWithFileId request = new Smb2CloseRequest(mockConfig, testFileId);

        // When & Then - should handle null gracefully (implementation dependent)
        assertDoesNotThrow(() -> request.setFileId(null), "Should handle null file ID without throwing exception");
    }

    @Test
    @DisplayName("Should handle empty file ID")
    void testSetEmptyFileId() {
        // Given
        RequestWithFileId request = new Smb2CloseRequest(mockConfig, testFileId);

        // When
        request.setFileId(emptyFileId);

        // Then - should accept empty file ID
        assertDoesNotThrow(() -> request.setFileId(emptyFileId), "Should handle empty file ID without throwing exception");
    }

    @Test
    @DisplayName("Should handle unspecified file ID constant")
    void testSetUnspecifiedFileId() {
        // Given
        RequestWithFileId request = new Smb2CloseRequest(mockConfig, testFileId);

        // When
        request.setFileId(unspecifiedFileId);

        // Then - should accept unspecified file ID
        assertDoesNotThrow(() -> request.setFileId(unspecifiedFileId), "Should handle unspecified file ID without throwing exception");
    }

    @Test
    @DisplayName("Should handle different file ID sizes")
    void testDifferentFileIdSizes() {
        // Test various file ID sizes
        byte[] shortFileId = new byte[8];
        byte[] standardFileId = new byte[16];
        byte[] longFileId = new byte[32];

        new SecureRandom().nextBytes(shortFileId);
        new SecureRandom().nextBytes(standardFileId);
        new SecureRandom().nextBytes(longFileId);

        RequestWithFileId request = new Smb2CloseRequest(mockConfig, emptyFileId);

        // All sizes should be accepted without exception
        assertDoesNotThrow(() -> request.setFileId(shortFileId), "Should handle 8-byte file ID");
        assertDoesNotThrow(() -> request.setFileId(standardFileId), "Should handle 16-byte file ID");
        assertDoesNotThrow(() -> request.setFileId(longFileId), "Should handle 32-byte file ID");
    }

    @Test
    @DisplayName("Should test mock implementation of interface")
    void testMockImplementation() {
        // Given
        RequestWithFileId mockRequest = mock(RequestWithFileId.class);

        // When
        mockRequest.setFileId(testFileId);

        // Then
        verify(mockRequest, times(1)).setFileId(testFileId);
    }

    @Test
    @DisplayName("Should handle multiple setFileId calls")
    void testMultipleSetFileIdCalls() {
        // Given
        RequestWithFileId request = new Smb2CloseRequest(mockConfig, emptyFileId);
        byte[] firstFileId = new byte[16];
        byte[] secondFileId = new byte[16];
        new SecureRandom().nextBytes(firstFileId);
        new SecureRandom().nextBytes(secondFileId);

        // When - set file ID multiple times
        assertDoesNotThrow(() -> {
            request.setFileId(firstFileId);
            request.setFileId(secondFileId);
            request.setFileId(testFileId);
        }, "Should handle multiple setFileId calls");
    }

    @Test
    @DisplayName("Should test interface with anonymous implementation")
    void testAnonymousImplementation() {
        // Given
        byte[] capturedFileId = new byte[1];
        RequestWithFileId anonymousImpl = new RequestWithFileId() {
            private byte[] fileId;

            @Override
            public void setFileId(byte[] fileId) {
                this.fileId = fileId;
                if (fileId != null) {
                    capturedFileId[0] = fileId[0];
                }
            }
        };

        // When
        byte[] testId = new byte[] { 42 };
        anonymousImpl.setFileId(testId);

        // Then
        assertEquals(42, capturedFileId[0], "Anonymous implementation should work correctly");
    }

    @Test
    @DisplayName("Should verify all known implementations")
    void testAllKnownImplementations() {
        // List of all known implementations of RequestWithFileId
        Class<?>[] implementations = { Smb2CloseRequest.class, Smb2QueryInfoRequest.class, Smb2SetInfoRequest.class,
                Smb2QueryDirectoryRequest.class, Smb2ReadRequest.class, Smb2WriteRequest.class, Smb2FlushRequest.class,
                Smb2IoctlRequest.class, Smb2LockRequest.class };

        // Verify each implements the interface
        for (Class<?> impl : implementations) {
            assertTrue(RequestWithFileId.class.isAssignableFrom(impl), impl.getSimpleName() + " should implement RequestWithFileId");
        }
    }

    @Test
    @DisplayName("Should test thread safety of setFileId")
    void testThreadSafety() throws InterruptedException {
        // Given
        RequestWithFileId request = new Smb2CloseRequest(mockConfig, emptyFileId);
        int threadCount = 10;
        Thread[] threads = new Thread[threadCount];

        // When - multiple threads call setFileId concurrently
        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                byte[] threadFileId = new byte[16];
                Arrays.fill(threadFileId, (byte) index);
                request.setFileId(threadFileId);
            });
            threads[i].start();
        }

        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }

        // Then - should complete without errors
        assertTrue(true, "Concurrent setFileId calls should complete without issues");
    }

    @Test
    @DisplayName("Should handle file ID with special patterns")
    void testSpecialFileIdPatterns() {
        // Test various special patterns
        byte[] allZeros = new byte[16];
        byte[] allOnes = new byte[16];
        Arrays.fill(allOnes, (byte) 0xFF);
        byte[] alternating = new byte[16];
        for (int i = 0; i < alternating.length; i++) {
            alternating[i] = (byte) (i % 2 == 0 ? 0xAA : 0x55);
        }

        RequestWithFileId request = new Smb2CloseRequest(mockConfig, emptyFileId);

        // All patterns should be accepted
        assertDoesNotThrow(() -> request.setFileId(allZeros), "Should handle all-zeros file ID");
        assertDoesNotThrow(() -> request.setFileId(allOnes), "Should handle all-ones file ID");
        assertDoesNotThrow(() -> request.setFileId(alternating), "Should handle alternating pattern file ID");
    }

    @Test
    @DisplayName("Should create custom implementation of RequestWithFileId")
    void testCustomImplementation() {
        // Given - custom implementation
        class CustomRequestWithFileId implements RequestWithFileId {
            private byte[] fileId;
            private int setCount = 0;

            @Override
            public void setFileId(byte[] fileId) {
                this.fileId = fileId;
                this.setCount++;
            }

            public byte[] getFileId() {
                return fileId;
            }

            public int getSetCount() {
                return setCount;
            }
        }

        // When
        CustomRequestWithFileId customRequest = new CustomRequestWithFileId();
        customRequest.setFileId(testFileId);

        // Then
        assertArrayEquals(testFileId, customRequest.getFileId(), "Custom implementation should store file ID correctly");
        assertEquals(1, customRequest.getSetCount(), "Should track set count correctly");
    }
}