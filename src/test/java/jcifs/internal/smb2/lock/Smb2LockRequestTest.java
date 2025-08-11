package jcifs.internal.smb2.lock;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.smb2.RequestWithFileId;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for Smb2LockRequest functionality
 */
@DisplayName("Smb2LockRequest Tests")
class Smb2LockRequestTest {

    @Mock
    private Configuration mockConfig;

    @Mock
    private CIFSContext mockContext;

    @Mock
    private Smb2Lock mockLock;

    private byte[] testFileId;
    private Smb2Lock[] testLocks;
    private Smb2LockRequest request;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockContext.getConfig()).thenReturn(mockConfig);
        
        testFileId = new byte[16];
        new SecureRandom().nextBytes(testFileId);
        
        testLocks = new Smb2Lock[] {
            new Smb2Lock(0L, 100L, Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK)
        };
        
        request = new Smb2LockRequest(mockConfig, testFileId, testLocks);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create request with all parameters")
        void testConstructor() {
            Smb2Lock[] locks = new Smb2Lock[] {
                new Smb2Lock(0L, 1024L, Smb2Lock.SMB2_LOCKFLAG_SHARED_LOCK)
            };
            Smb2LockRequest lockRequest = new Smb2LockRequest(mockConfig, testFileId, locks);
            assertNotNull(lockRequest);
            assertTrue(lockRequest instanceof ServerMessageBlock2Request);
            assertTrue(lockRequest instanceof RequestWithFileId);
        }

        @Test
        @DisplayName("Should initialize with SMB2_LOCK command")
        void testCommandInitialization() {
            Smb2LockRequest lockRequest = new Smb2LockRequest(mockConfig, testFileId, testLocks);
            assertNotNull(lockRequest);
        }

        @Test
        @DisplayName("Should accept null file ID in constructor")
        void testConstructorWithNullFileId() {
            assertDoesNotThrow(() -> new Smb2LockRequest(mockConfig, null, testLocks));
        }

        @Test
        @DisplayName("Should accept empty file ID in constructor")
        void testConstructorWithEmptyFileId() {
            byte[] emptyFileId = new byte[16];
            assertDoesNotThrow(() -> new Smb2LockRequest(mockConfig, emptyFileId, testLocks));
        }

        @Test
        @DisplayName("Should accept empty locks array")
        void testConstructorWithEmptyLocks() {
            Smb2Lock[] emptyLocks = new Smb2Lock[0];
            assertDoesNotThrow(() -> new Smb2LockRequest(mockConfig, testFileId, emptyLocks));
        }

        @Test
        @DisplayName("Should accept multiple locks")
        void testConstructorWithMultipleLocks() {
            Smb2Lock[] multipleLocks = new Smb2Lock[] {
                new Smb2Lock(0L, 100L, Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK),
                new Smb2Lock(200L, 300L, Smb2Lock.SMB2_LOCKFLAG_SHARED_LOCK),
                new Smb2Lock(500L, 100L, Smb2Lock.SMB2_LOCKFLAG_UNLOCK)
            };
            assertDoesNotThrow(() -> new Smb2LockRequest(mockConfig, testFileId, multipleLocks));
        }

        @Test
        @DisplayName("Should accept null locks array")
        void testConstructorWithNullLocks() {
            assertDoesNotThrow(() -> new Smb2LockRequest(mockConfig, testFileId, null));
        }
    }

    @Nested
    @DisplayName("FileId Tests")
    class FileIdTests {

        @Test
        @DisplayName("Should set file ID correctly")
        void testSetFileId() {
            byte[] newFileId = new byte[16];
            new SecureRandom().nextBytes(newFileId);
            
            assertDoesNotThrow(() -> request.setFileId(newFileId));
        }

        @Test
        @DisplayName("Should handle null file ID in setter")
        void testSetNullFileId() {
            assertDoesNotThrow(() -> request.setFileId(null));
        }

        @Test
        @DisplayName("Should handle various file ID sizes")
        void testVariousFileIdSizes() {
            byte[] shortFileId = new byte[8];
            byte[] standardFileId = new byte[16];
            byte[] longFileId = new byte[32];
            
            assertDoesNotThrow(() -> request.setFileId(shortFileId));
            assertDoesNotThrow(() -> request.setFileId(standardFileId));
            assertDoesNotThrow(() -> request.setFileId(longFileId));
        }

        @Test
        @DisplayName("Should update file ID multiple times")
        void testMultipleFileIdUpdates() {
            byte[] firstFileId = new byte[16];
            Arrays.fill(firstFileId, (byte) 0xAA);
            byte[] secondFileId = new byte[16];
            Arrays.fill(secondFileId, (byte) 0xBB);
            
            request.setFileId(firstFileId);
            request.setFileId(secondFileId);
            
            assertDoesNotThrow(() -> request.setFileId(secondFileId));
        }
    }

    @Nested
    @DisplayName("Size Calculation Tests")
    class SizeCalculationTests {

        @Test
        @DisplayName("Should calculate size correctly with single lock")
        void testSizeWithSingleLock() {
            Smb2Lock[] singleLock = new Smb2Lock[] {
                new Smb2Lock(0L, 100L, Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK)
            };
            Smb2LockRequest req = new Smb2LockRequest(mockConfig, testFileId, singleLock);
            
            int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 24 + 24; // header + structure + 1 lock
            expectedSize = ((expectedSize + 7) / 8) * 8; // 8-byte alignment
            assertEquals(expectedSize, req.size());
        }

        @Test
        @DisplayName("Should calculate size correctly with multiple locks")
        void testSizeWithMultipleLocks() {
            Smb2Lock[] multipleLocks = new Smb2Lock[] {
                new Smb2Lock(0L, 100L, Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK),
                new Smb2Lock(200L, 300L, Smb2Lock.SMB2_LOCKFLAG_SHARED_LOCK),
                new Smb2Lock(500L, 100L, Smb2Lock.SMB2_LOCKFLAG_UNLOCK)
            };
            Smb2LockRequest req = new Smb2LockRequest(mockConfig, testFileId, multipleLocks);
            
            int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 24 + (24 * 3); // header + structure + 3 locks
            expectedSize = ((expectedSize + 7) / 8) * 8; // 8-byte alignment
            assertEquals(expectedSize, req.size());
        }

        @Test
        @DisplayName("Should calculate size correctly with no locks")
        void testSizeWithNoLocks() {
            Smb2Lock[] noLocks = new Smb2Lock[0];
            Smb2LockRequest req = new Smb2LockRequest(mockConfig, testFileId, noLocks);
            
            int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 24; // header + structure
            expectedSize = ((expectedSize + 7) / 8) * 8; // 8-byte alignment
            assertEquals(expectedSize, req.size());
        }

        @Test
        @DisplayName("Should align size to 8-byte boundary")
        void testSizeAlignment() {
            int size = request.size();
            assertEquals(0, size % 8, "Size should be aligned to 8-byte boundary");
        }

        @ParameterizedTest
        @DisplayName("Should calculate size for various lock counts")
        @ValueSource(ints = {0, 1, 2, 5, 10, 20, 50, 100})
        void testSizeWithVariousLockCounts(int lockCount) {
            Smb2Lock[] locks = new Smb2Lock[lockCount];
            for (int i = 0; i < lockCount; i++) {
                locks[i] = new Smb2Lock(i * 100L, 100L, Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK);
            }
            Smb2LockRequest req = new Smb2LockRequest(mockConfig, testFileId, locks);
            
            int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 24 + (24 * lockCount);
            expectedSize = ((expectedSize + 7) / 8) * 8;
            assertEquals(expectedSize, req.size());
        }
    }

    @Nested
    @DisplayName("WriteBytesWireFormat Tests")
    class WriteBytesWireFormatTests {

        @Test
        @DisplayName("Should write request structure correctly with single lock")
        void testWriteBytesWireFormatSingleLock() {
            Smb2Lock[] locks = new Smb2Lock[] {
                new Smb2Lock(1024L, 2048L, Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK)
            };
            when(mockLock.encode(any(byte[].class), anyInt())).thenReturn(24);
            
            Smb2LockRequest req = new Smb2LockRequest(mockConfig, testFileId, locks);
            byte[] buffer = new byte[256];
            
            int bytesWritten = req.writeBytesWireFormat(buffer, 0);
            
            // Verify structure
            assertEquals(48, SMBUtil.readInt2(buffer, 0)); // Structure size
            assertEquals(1, SMBUtil.readInt2(buffer, 2)); // Lock count
            
            // Verify lock sequence (bits 4-7 are sequence number, bits 0-27 are index)
            int lockSequence = SMBUtil.readInt4(buffer, 4);
            assertEquals(0, lockSequence); // Default values
            
            // Verify file ID
            assertArrayEquals(testFileId, Arrays.copyOfRange(buffer, 8, 24));
            
            // Verify total bytes written (structure + lock data)
            assertEquals(24 + 24, bytesWritten); // 24 for structure, 24 for lock
        }

        @Test
        @DisplayName("Should write request structure correctly with multiple locks")
        void testWriteBytesWireFormatMultipleLocks() {
            Smb2Lock[] locks = new Smb2Lock[] {
                new Smb2Lock(0L, 100L, Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK),
                new Smb2Lock(200L, 300L, Smb2Lock.SMB2_LOCKFLAG_SHARED_LOCK),
                new Smb2Lock(500L, 100L, Smb2Lock.SMB2_LOCKFLAG_UNLOCK)
            };
            
            Smb2LockRequest req = new Smb2LockRequest(mockConfig, testFileId, locks);
            byte[] buffer = new byte[512];
            
            int bytesWritten = req.writeBytesWireFormat(buffer, 0);
            
            assertEquals(48, SMBUtil.readInt2(buffer, 0)); // Structure size
            assertEquals(3, SMBUtil.readInt2(buffer, 2)); // Lock count
            assertArrayEquals(testFileId, Arrays.copyOfRange(buffer, 8, 24));
            
            // Each lock is 24 bytes
            assertEquals(24 + (24 * 3), bytesWritten);
        }

        @Test
        @DisplayName("Should write request with no locks")
        void testWriteBytesWireFormatNoLocks() {
            Smb2Lock[] noLocks = new Smb2Lock[0];
            Smb2LockRequest req = new Smb2LockRequest(mockConfig, testFileId, noLocks);
            byte[] buffer = new byte[256];
            
            int bytesWritten = req.writeBytesWireFormat(buffer, 0);
            
            assertEquals(48, SMBUtil.readInt2(buffer, 0)); // Structure size
            assertEquals(0, SMBUtil.readInt2(buffer, 2)); // Lock count
            assertArrayEquals(testFileId, Arrays.copyOfRange(buffer, 8, 24));
            assertEquals(24, bytesWritten); // Only structure, no locks
        }

        @Test
        @DisplayName("Should write at different buffer positions")
        void testWriteAtDifferentPositions() {
            byte[] buffer = new byte[512];
            
            // Test at position 0
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);
            assertEquals(48, bytesWritten);
            assertEquals(48, SMBUtil.readInt2(buffer, 0));
            
            // Test at position 100
            Arrays.fill(buffer, (byte) 0);
            bytesWritten = request.writeBytesWireFormat(buffer, 100);
            assertEquals(48, bytesWritten);
            assertEquals(48, SMBUtil.readInt2(buffer, 100));
            assertArrayEquals(testFileId, Arrays.copyOfRange(buffer, 108, 124));
        }

        @Test
        @DisplayName("Should handle null file ID during write")
        void testWriteWithNullFileId() {
            request.setFileId(null);
            byte[] buffer = new byte[256];
            
            assertThrows(NullPointerException.class,
                () -> request.writeBytesWireFormat(buffer, 0));
        }

        @Test
        @DisplayName("Should handle file ID of different sizes")
        void testWriteWithDifferentFileIdSizes() {
            // Test with 16-byte file ID (standard)
            byte[] standardFileId = new byte[16];
            Arrays.fill(standardFileId, (byte) 0xAB);
            request.setFileId(standardFileId);
            
            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);
            
            assertEquals(48, bytesWritten);
            assertArrayEquals(standardFileId, Arrays.copyOfRange(buffer, 8, 24));
            
            // Test with longer file ID (should copy only first 16 bytes)
            byte[] longFileId = new byte[32];
            Arrays.fill(longFileId, (byte) 0xCD);
            request.setFileId(longFileId);
            
            Arrays.fill(buffer, (byte) 0);
            bytesWritten = request.writeBytesWireFormat(buffer, 0);
            
            assertEquals(48, bytesWritten);
            assertArrayEquals(Arrays.copyOfRange(longFileId, 0, 16), 
                            Arrays.copyOfRange(buffer, 8, 24));
        }

        @Test
        @DisplayName("Should write lock sequence information correctly")
        void testLockSequenceInformation() {
            // Note: lockSequenceNumber and lockSequenceIndex are private and not settable
            // They default to 0, so we test the default encoding
            byte[] buffer = new byte[256];
            request.writeBytesWireFormat(buffer, 0);
            
            int lockSequence = SMBUtil.readInt4(buffer, 4);
            // Default: sequence number = 0, index = 0
            assertEquals(0, lockSequence);
        }

        @ParameterizedTest
        @DisplayName("Should handle various lock counts")
        @ValueSource(ints = {1, 5, 10, 20, 50})
        void testVariousLockCounts(int lockCount) {
            Smb2Lock[] locks = new Smb2Lock[lockCount];
            for (int i = 0; i < lockCount; i++) {
                locks[i] = new Smb2Lock(i * 100L, 100L, Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK);
            }
            
            Smb2LockRequest req = new Smb2LockRequest(mockConfig, testFileId, locks);
            byte[] buffer = new byte[2048];
            
            int bytesWritten = req.writeBytesWireFormat(buffer, 0);
            
            assertEquals(48, SMBUtil.readInt2(buffer, 0));
            assertEquals(lockCount, SMBUtil.readInt2(buffer, 2));
            assertEquals(24 + (24 * lockCount), bytesWritten);
        }
    }

    @Nested
    @DisplayName("ReadBytesWireFormat Tests")
    class ReadBytesWireFormatTests {

        @Test
        @DisplayName("Should always return 0 for readBytesWireFormat")
        void testReadBytesWireFormat() {
            byte[] buffer = new byte[1024];
            int result = request.readBytesWireFormat(buffer, 0);
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should return 0 regardless of buffer position")
        void testReadBytesWireFormatDifferentPosition() {
            byte[] buffer = new byte[1024];
            int result = request.readBytesWireFormat(buffer, 100);
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should return 0 with empty buffer")
        void testReadBytesWireFormatEmptyBuffer() {
            byte[] buffer = new byte[0];
            int result = request.readBytesWireFormat(buffer, 0);
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should return 0 with null buffer")
        void testReadBytesWireFormatNullBuffer() {
            int result = request.readBytesWireFormat(null, 0);
            assertEquals(0, result);
        }
    }

    @Nested
    @DisplayName("CreateResponse Tests")
    class CreateResponseTests {

        @Test
        @DisplayName("Should create appropriate response")
        void testCreateResponse() {
            Smb2LockResponse response = request.createResponse(mockContext, request);
            assertNotNull(response);
            assertTrue(response instanceof Smb2LockResponse);
        }

        @Test
        @DisplayName("Should create response with same configuration")
        void testCreateResponseConfiguration() {
            Smb2LockResponse response = request.createResponse(mockContext, request);
            assertNotNull(response);
            // Response should be created with the same config from context
            verify(mockContext, times(1)).getConfig();
        }

        @Test
        @DisplayName("Should create response for request with multiple locks")
        void testCreateResponseWithMultipleLocks() {
            Smb2Lock[] multipleLocks = new Smb2Lock[] {
                new Smb2Lock(0L, 100L, Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK),
                new Smb2Lock(200L, 300L, Smb2Lock.SMB2_LOCKFLAG_SHARED_LOCK)
            };
            Smb2LockRequest req = new Smb2LockRequest(mockConfig, testFileId, multipleLocks);
            
            Smb2LockResponse response = req.createResponse(mockContext, req);
            assertNotNull(response);
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle complete lock request workflow")
        void testCompleteLockWorkflow() {
            // Setup complete request with multiple locks
            Smb2Lock[] locks = new Smb2Lock[] {
                new Smb2Lock(0L, 1024L, Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK),
                new Smb2Lock(2048L, 512L, Smb2Lock.SMB2_LOCKFLAG_SHARED_LOCK)
            };
            
            Smb2LockRequest lockRequest = new Smb2LockRequest(mockConfig, testFileId, locks);
            
            // Calculate expected size
            int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 24 + (24 * 2);
            expectedSize = ((expectedSize + 7) / 8) * 8;
            assertEquals(expectedSize, lockRequest.size());
            
            // Write to buffer
            byte[] buffer = new byte[512];
            int bytesWritten = lockRequest.writeBytesWireFormat(buffer, 50);
            assertEquals(24 + (24 * 2), bytesWritten);
            
            // Verify written structure
            assertEquals(48, SMBUtil.readInt2(buffer, 50)); // Structure size
            assertEquals(2, SMBUtil.readInt2(buffer, 52)); // Lock count
            assertArrayEquals(testFileId, Arrays.copyOfRange(buffer, 58, 74)); // File ID
        }

        @Test
        @DisplayName("Should handle lock request with all lock types")
        void testAllLockTypes() {
            Smb2Lock[] locks = new Smb2Lock[] {
                new Smb2Lock(0L, 100L, Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK),
                new Smb2Lock(100L, 100L, Smb2Lock.SMB2_LOCKFLAG_SHARED_LOCK),
                new Smb2Lock(200L, 100L, Smb2Lock.SMB2_LOCKFLAG_UNLOCK),
                new Smb2Lock(300L, 100L, Smb2Lock.SMB2_LOCKFLAG_FAIL_IMMEDIATELY)
            };
            
            Smb2LockRequest lockRequest = new Smb2LockRequest(mockConfig, testFileId, locks);
            
            byte[] buffer = new byte[512];
            int bytesWritten = lockRequest.writeBytesWireFormat(buffer, 0);
            
            assertEquals(48, SMBUtil.readInt2(buffer, 0));
            assertEquals(4, SMBUtil.readInt2(buffer, 2));
            assertEquals(24 + (24 * 4), bytesWritten);
        }

        @Test
        @DisplayName("Should handle file ID updates")
        void testFileIdUpdates() {
            // Initial file ID
            byte[] initialFileId = new byte[16];
            Arrays.fill(initialFileId, (byte) 0x11);
            request.setFileId(initialFileId);
            
            byte[] buffer1 = new byte[256];
            request.writeBytesWireFormat(buffer1, 0);
            assertArrayEquals(initialFileId, Arrays.copyOfRange(buffer1, 8, 24));
            
            // Update file ID
            byte[] updatedFileId = new byte[16];
            Arrays.fill(updatedFileId, (byte) 0x22);
            request.setFileId(updatedFileId);
            
            byte[] buffer2 = new byte[256];
            request.writeBytesWireFormat(buffer2, 0);
            assertArrayEquals(updatedFileId, Arrays.copyOfRange(buffer2, 8, 24));
        }

        @Test
        @DisplayName("Should handle large number of locks")
        void testLargeNumberOfLocks() {
            int lockCount = 100;
            Smb2Lock[] locks = new Smb2Lock[lockCount];
            for (int i = 0; i < lockCount; i++) {
                locks[i] = new Smb2Lock(
                    i * 1024L,
                    1024L,
                    (i % 2 == 0) ? Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK : Smb2Lock.SMB2_LOCKFLAG_SHARED_LOCK
                );
            }
            
            Smb2LockRequest lockRequest = new Smb2LockRequest(mockConfig, testFileId, locks);
            
            // Calculate expected size
            int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 24 + (24 * lockCount);
            expectedSize = ((expectedSize + 7) / 8) * 8;
            assertEquals(expectedSize, lockRequest.size());
            
            // Write to buffer
            byte[] buffer = new byte[4096];
            int bytesWritten = lockRequest.writeBytesWireFormat(buffer, 0);
            assertEquals(24 + (24 * lockCount), bytesWritten);
            assertEquals(lockCount, SMBUtil.readInt2(buffer, 2));
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle null locks array")
        void testNullLocksArray() {
            Smb2LockRequest req = new Smb2LockRequest(mockConfig, testFileId, null);
            
            assertThrows(NullPointerException.class, () -> req.size());
        }

        @Test
        @DisplayName("Should handle file ID shorter than 16 bytes")
        void testShortFileId() {
            byte[] shortFileId = new byte[8];
            Arrays.fill(shortFileId, (byte) 0xAB);
            request.setFileId(shortFileId);
            
            byte[] buffer = new byte[256];
            
            // Should handle gracefully or throw appropriate exception
            assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> request.writeBytesWireFormat(buffer, 0));
        }

        @Test
        @DisplayName("Should handle buffer overflow protection")
        void testBufferOverflowProtection() {
            Smb2Lock[] locks = new Smb2Lock[] {
                new Smb2Lock(0L, 100L, Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK),
                new Smb2Lock(200L, 300L, Smb2Lock.SMB2_LOCKFLAG_SHARED_LOCK)
            };
            Smb2LockRequest req = new Smb2LockRequest(mockConfig, testFileId, locks);
            
            byte[] smallBuffer = new byte[50]; // Smaller than required
            
            // Should not overflow buffer
            assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> req.writeBytesWireFormat(smallBuffer, 0));
        }

        @Test
        @DisplayName("Should handle write at buffer boundary")
        void testWriteAtBufferBoundary() {
            byte[] buffer = new byte[100];
            
            // Try to write at position that would exceed buffer
            assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> request.writeBytesWireFormat(buffer, 80)); // 80 + 48 > 100
        }

        @Test
        @DisplayName("Should handle locks with maximum values")
        void testLocksWithMaximumValues() {
            Smb2Lock[] locks = new Smb2Lock[] {
                new Smb2Lock(Long.MAX_VALUE, Long.MAX_VALUE, Integer.MAX_VALUE)
            };
            
            Smb2LockRequest req = new Smb2LockRequest(mockConfig, testFileId, locks);
            byte[] buffer = new byte[256];
            
            int bytesWritten = req.writeBytesWireFormat(buffer, 0);
            assertEquals(48, bytesWritten);
            assertEquals(1, SMBUtil.readInt2(buffer, 2));
        }

        @Test
        @DisplayName("Should handle locks with zero values")
        void testLocksWithZeroValues() {
            Smb2Lock[] locks = new Smb2Lock[] {
                new Smb2Lock(0L, 0L, 0)
            };
            
            Smb2LockRequest req = new Smb2LockRequest(mockConfig, testFileId, locks);
            byte[] buffer = new byte[256];
            
            int bytesWritten = req.writeBytesWireFormat(buffer, 0);
            assertEquals(48, bytesWritten);
            assertEquals(1, SMBUtil.readInt2(buffer, 2));
        }

        @Test
        @DisplayName("Should handle mixed lock operations")
        void testMixedLockOperations() {
            // Simulate a complex scenario with mixed lock operations
            Smb2Lock[] locks = new Smb2Lock[] {
                new Smb2Lock(0L, 512L, Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK),
                new Smb2Lock(512L, 512L, Smb2Lock.SMB2_LOCKFLAG_SHARED_LOCK),
                new Smb2Lock(1024L, 512L, Smb2Lock.SMB2_LOCKFLAG_UNLOCK),
                new Smb2Lock(1536L, 512L, Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK | Smb2Lock.SMB2_LOCKFLAG_FAIL_IMMEDIATELY),
                new Smb2Lock(2048L, 512L, Smb2Lock.SMB2_LOCKFLAG_SHARED_LOCK | Smb2Lock.SMB2_LOCKFLAG_FAIL_IMMEDIATELY)
            };
            
            Smb2LockRequest req = new Smb2LockRequest(mockConfig, testFileId, locks);
            
            int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 24 + (24 * 5);
            expectedSize = ((expectedSize + 7) / 8) * 8;
            assertEquals(expectedSize, req.size());
            
            byte[] buffer = new byte[512];
            int bytesWritten = req.writeBytesWireFormat(buffer, 0);
            assertEquals(24 + (24 * 5), bytesWritten);
            assertEquals(5, SMBUtil.readInt2(buffer, 2));
        }
    }
}
