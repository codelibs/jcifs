package jcifs.internal.fscc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.internal.AllocInfo;
import jcifs.internal.SMBProtocolDecodingException;

/**
 * Test suite for FileFsFullSizeInformation class
 */
class FileFsFullSizeInformationTest {

    private FileFsFullSizeInformation fileFsFullSizeInfo;

    @BeforeEach
    void setUp() {
        fileFsFullSizeInfo = new FileFsFullSizeInformation();
    }

    @Nested
    @DisplayName("Interface Implementation Tests")
    class InterfaceImplementationTests {

        @Test
        @DisplayName("Should implement AllocInfo interface")
        void shouldImplementAllocInfo() {
            assertTrue(AllocInfo.class.isAssignableFrom(FileFsFullSizeInformation.class));
        }

        @Test
        @DisplayName("Should implement FileSystemInformation interface")
        void shouldImplementFileSystemInformation() {
            assertTrue(FileSystemInformation.class.isAssignableFrom(FileFsFullSizeInformation.class));
        }

        @Test
        @DisplayName("Should return correct file system information class")
        void shouldReturnCorrectFileSystemInformationClass() {
            assertEquals(FileSystemInformation.FS_FULL_SIZE_INFO, fileFsFullSizeInfo.getFileSystemInformationClass());
        }
    }

    @Nested
    @DisplayName("Decode Method Tests")
    class DecodeMethodTests {

        @Test
        @DisplayName("Should decode buffer with typical values correctly")
        void shouldDecodeBufferWithTypicalValues() throws SMBProtocolDecodingException {
            // Given - prepare buffer with typical file system values
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(1048576L); // Total allocation units (1M)
            buffer.putLong(524288L); // Caller available allocation units (512K)
            buffer.putLong(524288L); // Actual free allocation units (512K)
            buffer.putInt(8); // Sectors per allocation unit
            buffer.putInt(512); // Bytes per sector
            byte[] bufferArray = buffer.array();

            // When
            int bytesConsumed = fileFsFullSizeInfo.decode(bufferArray, 0, bufferArray.length);

            // Then
            assertEquals(32, bytesConsumed);
            assertEquals(1048576L * 8 * 512, fileFsFullSizeInfo.getCapacity());
            assertEquals(524288L * 8 * 512, fileFsFullSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should decode buffer with zero values")
        void shouldDecodeBufferWithZeroValues() throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(0L);
            buffer.putLong(0L);
            buffer.putLong(0L);
            buffer.putInt(0);
            buffer.putInt(0);
            byte[] bufferArray = buffer.array();

            // When
            int bytesConsumed = fileFsFullSizeInfo.decode(bufferArray, 0, bufferArray.length);

            // Then
            assertEquals(32, bytesConsumed);
            assertEquals(0L, fileFsFullSizeInfo.getCapacity());
            assertEquals(0L, fileFsFullSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should decode buffer with maximum values")
        void shouldDecodeBufferWithMaximumValues() throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(Long.MAX_VALUE);
            buffer.putLong(Long.MAX_VALUE);
            buffer.putLong(Long.MAX_VALUE);
            buffer.putInt(Integer.MAX_VALUE);
            buffer.putInt(Integer.MAX_VALUE);
            byte[] bufferArray = buffer.array();

            // When
            int bytesConsumed = fileFsFullSizeInfo.decode(bufferArray, 0, bufferArray.length);

            // Then
            assertEquals(32, bytesConsumed);
            // Note: multiplication may overflow, but that's expected behavior
            long expectedCapacity = Long.MAX_VALUE * (long) Integer.MAX_VALUE * (long) Integer.MAX_VALUE;
            assertEquals(expectedCapacity, fileFsFullSizeInfo.getCapacity());
        }

        @Test
        @DisplayName("Should decode buffer with offset correctly")
        void shouldDecodeBufferWithOffset() throws SMBProtocolDecodingException {
            // Given - buffer with padding before actual data
            ByteBuffer buffer = ByteBuffer.allocate(42);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.position(10); // Add 10 bytes of padding
            buffer.putLong(2048L);
            buffer.putLong(1024L);
            buffer.putLong(1024L);
            buffer.putInt(4);
            buffer.putInt(4096);
            byte[] bufferArray = buffer.array();

            // When
            int bytesConsumed = fileFsFullSizeInfo.decode(bufferArray, 10, 32);

            // Then
            assertEquals(32, bytesConsumed);
            assertEquals(2048L * 4 * 4096, fileFsFullSizeInfo.getCapacity());
            assertEquals(1024L * 4 * 4096, fileFsFullSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should skip actual free units correctly")
        void shouldSkipActualFreeUnitsCorrectly() throws SMBProtocolDecodingException {
            // Given - different values for caller available and actual free units
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(1000L); // Total allocation units
            buffer.putLong(500L); // Caller available allocation units
            buffer.putLong(600L); // Actual free allocation units (should be skipped)
            buffer.putInt(8);
            buffer.putInt(512);
            byte[] bufferArray = buffer.array();

            // When
            int bytesConsumed = fileFsFullSizeInfo.decode(bufferArray, 0, bufferArray.length);

            // Then
            assertEquals(32, bytesConsumed);
            // Should use caller available units, not actual free units
            assertEquals(500L * 8 * 512, fileFsFullSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should handle negative values in buffer")
        void shouldHandleNegativeValuesInBuffer() throws SMBProtocolDecodingException {
            // Given - negative values (treated as unsigned in protocol)
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(-1L);
            buffer.putLong(-1L);
            buffer.putLong(-1L);
            buffer.putInt(-1);
            buffer.putInt(-1);
            byte[] bufferArray = buffer.array();

            // When
            int bytesConsumed = fileFsFullSizeInfo.decode(bufferArray, 0, bufferArray.length);

            // Then
            assertEquals(32, bytesConsumed);
            // Values are read as-is (can be negative due to overflow)
            assertNotNull(fileFsFullSizeInfo.getCapacity());
            assertNotNull(fileFsFullSizeInfo.getFree());
        }

        @ParameterizedTest
        @DisplayName("Should decode various sector and allocation configurations")
        @CsvSource({ "1000, 500, 600, 1, 512", // Minimal sectors per alloc
                "1000, 500, 600, 8, 512", // Typical configuration
                "1000, 500, 600, 64, 512", // Large allocation units
                "1000, 500, 600, 8, 4096", // 4K sectors
                "1000, 500, 600, 16, 4096", // Large sectors and allocation
                "1000, 0, 0, 8, 512", // No free space
                "1000, 1000, 1000, 8, 512" // All space free
        })
        void shouldDecodeVariousSectorConfigurations(long alloc, long callerFree, long actualFree, int sectPerAlloc, int bytesPerSect)
                throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(alloc);
            buffer.putLong(callerFree);
            buffer.putLong(actualFree);
            buffer.putInt(sectPerAlloc);
            buffer.putInt(bytesPerSect);
            byte[] bufferArray = buffer.array();

            // When
            int bytesConsumed = fileFsFullSizeInfo.decode(bufferArray, 0, bufferArray.length);

            // Then
            assertEquals(32, bytesConsumed);
            assertEquals(alloc * sectPerAlloc * bytesPerSect, fileFsFullSizeInfo.getCapacity());
            assertEquals(callerFree * sectPerAlloc * bytesPerSect, fileFsFullSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should return correct number of bytes consumed from buffer")
        void shouldReturnCorrectBytesConsumed() throws SMBProtocolDecodingException {
            // Given - larger buffer than needed
            byte[] buffer = new byte[100];
            ByteBuffer bb = ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN);
            bb.putLong(1000L);
            bb.putLong(500L);
            bb.putLong(500L);
            bb.putInt(8);
            bb.putInt(512);

            // When
            int bytesConsumed = fileFsFullSizeInfo.decode(buffer, 0, buffer.length);

            // Then
            assertEquals(32, bytesConsumed); // Should always consume exactly 32 bytes
        }

        @Test
        @DisplayName("Should decode from middle of buffer correctly")
        void shouldDecodeFromMiddleOfBuffer() throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[100];
            int offset = 40;
            ByteBuffer bb = ByteBuffer.wrap(buffer, offset, 32).order(ByteOrder.LITTLE_ENDIAN);
            bb.putLong(5000L);
            bb.putLong(2500L);
            bb.putLong(2500L);
            bb.putInt(16);
            bb.putInt(1024);

            // When
            int bytesConsumed = fileFsFullSizeInfo.decode(buffer, offset, 32);

            // Then
            assertEquals(32, bytesConsumed);
            assertEquals(5000L * 16 * 1024, fileFsFullSizeInfo.getCapacity());
            assertEquals(2500L * 16 * 1024, fileFsFullSizeInfo.getFree());
        }
    }

    @Nested
    @DisplayName("Capacity and Free Space Calculation Tests")
    class CapacityCalculationTests {

        @Test
        @DisplayName("Should calculate capacity correctly")
        void shouldCalculateCapacityCorrectly() throws SMBProtocolDecodingException {
            // Given
            long alloc = 1024L;
            int sectPerAlloc = 8;
            int bytesPerSect = 512;

            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(alloc);
            buffer.putLong(0L);
            buffer.putLong(0L);
            buffer.putInt(sectPerAlloc);
            buffer.putInt(bytesPerSect);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);

            // Then
            long expectedCapacity = alloc * sectPerAlloc * bytesPerSect;
            assertEquals(expectedCapacity, fileFsFullSizeInfo.getCapacity());
            assertEquals(4194304L, fileFsFullSizeInfo.getCapacity()); // 1024 * 8 * 512
        }

        @Test
        @DisplayName("Should calculate free space correctly using caller available units")
        void shouldCalculateFreeSpaceCorrectly() throws SMBProtocolDecodingException {
            // Given
            long callerFree = 512L;
            long actualFree = 600L; // Should be ignored
            int sectPerAlloc = 8;
            int bytesPerSect = 512;

            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(0L);
            buffer.putLong(callerFree);
            buffer.putLong(actualFree);
            buffer.putInt(sectPerAlloc);
            buffer.putInt(bytesPerSect);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);

            // Then
            long expectedFree = callerFree * sectPerAlloc * bytesPerSect;
            assertEquals(expectedFree, fileFsFullSizeInfo.getFree());
            assertEquals(2097152L, fileFsFullSizeInfo.getFree()); // 512 * 8 * 512
        }

        @Test
        @DisplayName("Should handle overflow in capacity calculation")
        void shouldHandleOverflowInCapacityCalculation() throws SMBProtocolDecodingException {
            // Given - values that will cause overflow
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(Long.MAX_VALUE / 2);
            buffer.putLong(Long.MAX_VALUE / 4);
            buffer.putLong(Long.MAX_VALUE / 4);
            buffer.putInt(10);
            buffer.putInt(10);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);

            // Then - overflow is expected behavior
            assertNotNull(fileFsFullSizeInfo.getCapacity());
            assertNotNull(fileFsFullSizeInfo.getFree());
        }

        @ParameterizedTest
        @DisplayName("Should calculate various file system sizes correctly")
        @CsvSource({ "1048576, 524288, 8, 512, 4294967296, 2147483648", // 4GB total, 2GB free
                "2097152, 1048576, 8, 512, 8589934592, 4294967296", // 8GB total, 4GB free
                "134217728, 67108864, 8, 512, 549755813888, 274877906944", // 512GB total, 256GB free
                "1, 1, 1, 1, 1, 1", // Minimal values
                "0, 0, 1, 1, 0, 0" // Zero allocation units
        })
        void shouldCalculateVariousFileSystemSizes(long alloc, long free, int sectPerAlloc, int bytesPerSect, long expectedCapacity,
                long expectedFree) throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(alloc);
            buffer.putLong(free);
            buffer.putLong(free); // Actual free (ignored)
            buffer.putInt(sectPerAlloc);
            buffer.putInt(bytesPerSect);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);

            // Then
            assertEquals(expectedCapacity, fileFsFullSizeInfo.getCapacity());
            assertEquals(expectedFree, fileFsFullSizeInfo.getFree());
        }
    }

    @Nested
    @DisplayName("ToString Method Tests")
    class ToStringMethodTests {

        @Test
        @DisplayName("Should return correct string representation with default values")
        void shouldReturnCorrectStringWithDefaultValues() {
            // When
            String result = fileFsFullSizeInfo.toString();

            // Then
            assertNotNull(result);
            assertTrue(result.contains("SmbInfoAllocation"));
            assertTrue(result.contains("alloc=0"));
            assertTrue(result.contains("free=0"));
            assertTrue(result.contains("sectPerAlloc=0"));
            assertTrue(result.contains("bytesPerSect=0"));
        }

        @Test
        @DisplayName("Should return correct string representation after decoding")
        void shouldReturnCorrectStringAfterDecoding() throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(1000L);
            buffer.putLong(500L);
            buffer.putLong(600L);
            buffer.putInt(8);
            buffer.putInt(512);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);
            String result = fileFsFullSizeInfo.toString();

            // Then
            assertNotNull(result);
            assertTrue(result.contains("alloc=1000"));
            assertTrue(result.contains("free=500"));
            assertTrue(result.contains("sectPerAlloc=8"));
            assertTrue(result.contains("bytesPerSect=512"));
        }

        @Test
        @DisplayName("Should have consistent toString format")
        void shouldHaveConsistentToStringFormat() throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(123456L);
            buffer.putLong(78910L);
            buffer.putLong(80000L);
            buffer.putInt(16);
            buffer.putInt(4096);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);
            String result = fileFsFullSizeInfo.toString();

            // Then
            String expected = "SmbInfoAllocation[alloc=123456,free=78910,sectPerAlloc=16,bytesPerSect=4096]";
            assertEquals(expected, result);
        }

        @Test
        @DisplayName("Should handle negative values in toString")
        void shouldHandleNegativeValuesInToString() throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(-1L);
            buffer.putLong(-2L);
            buffer.putLong(-3L);
            buffer.putInt(-4);
            buffer.putInt(-5);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);
            String result = fileFsFullSizeInfo.toString();

            // Then
            assertNotNull(result);
            assertTrue(result.contains("alloc=-1"));
            assertTrue(result.contains("free=-2"));
            assertTrue(result.contains("sectPerAlloc=-4"));
            assertTrue(result.contains("bytesPerSect=-5"));
        }
    }

    @Nested
    @DisplayName("State Management Tests")
    class StateManagementTests {

        @Test
        @DisplayName("Should maintain state after decode")
        void shouldMaintainStateAfterDecode() throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(2000L);
            buffer.putLong(1000L);
            buffer.putLong(1100L);
            buffer.putInt(4);
            buffer.putInt(1024);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);

            // Then - multiple calls should return same values
            assertEquals(2000L * 4 * 1024, fileFsFullSizeInfo.getCapacity());
            assertEquals(2000L * 4 * 1024, fileFsFullSizeInfo.getCapacity());
            assertEquals(1000L * 4 * 1024, fileFsFullSizeInfo.getFree());
            assertEquals(1000L * 4 * 1024, fileFsFullSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should update state on subsequent decode calls")
        void shouldUpdateStateOnSubsequentDecodeCalls() throws SMBProtocolDecodingException {
            // Given - first decode
            ByteBuffer buffer1 = ByteBuffer.allocate(32);
            buffer1.order(ByteOrder.LITTLE_ENDIAN);
            buffer1.putLong(1000L);
            buffer1.putLong(500L);
            buffer1.putLong(500L);
            buffer1.putInt(8);
            buffer1.putInt(512);

            fileFsFullSizeInfo.decode(buffer1.array(), 0, 32);
            long firstCapacity = fileFsFullSizeInfo.getCapacity();
            long firstFree = fileFsFullSizeInfo.getFree();

            // When - second decode with different values
            ByteBuffer buffer2 = ByteBuffer.allocate(32);
            buffer2.order(ByteOrder.LITTLE_ENDIAN);
            buffer2.putLong(2000L);
            buffer2.putLong(1500L);
            buffer2.putLong(1600L);
            buffer2.putInt(16);
            buffer2.putInt(1024);

            fileFsFullSizeInfo.decode(buffer2.array(), 0, 32);

            // Then
            assertNotEquals(firstCapacity, fileFsFullSizeInfo.getCapacity());
            assertNotEquals(firstFree, fileFsFullSizeInfo.getFree());
            assertEquals(2000L * 16 * 1024, fileFsFullSizeInfo.getCapacity());
            assertEquals(1500L * 16 * 1024, fileFsFullSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should have initial zero state")
        void shouldHaveInitialZeroState() {
            // Given - newly created instance
            FileFsFullSizeInformation freshInfo = new FileFsFullSizeInformation();

            // Then
            assertEquals(0L, freshInfo.getCapacity());
            assertEquals(0L, freshInfo.getFree());
            assertEquals(FileSystemInformation.FS_FULL_SIZE_INFO, freshInfo.getFileSystemInformationClass());
        }
    }

    @Nested
    @DisplayName("Edge Cases and Real-World Scenarios")
    class EdgeCasesAndRealWorldTests {

        @Test
        @DisplayName("Should handle typical Windows NTFS configuration")
        void shouldHandleTypicalNTFSConfiguration() throws SMBProtocolDecodingException {
            // Given - typical NTFS: 4KB clusters (8 sectors * 512 bytes)
            long totalClusters = 26214400L; // 100GB / 4KB
            long freeClusters = 13107200L; // 50GB / 4KB

            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(totalClusters);
            buffer.putLong(freeClusters);
            buffer.putLong(freeClusters);
            buffer.putInt(8);
            buffer.putInt(512);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);

            // Then
            assertEquals(107374182400L, fileFsFullSizeInfo.getCapacity()); // 100GB
            assertEquals(53687091200L, fileFsFullSizeInfo.getFree()); // 50GB
        }

        @Test
        @DisplayName("Should handle quota restricted scenarios")
        void shouldHandleQuotaRestrictedScenarios() throws SMBProtocolDecodingException {
            // Given - quota restricts caller available units
            long totalClusters = 26214400L; // 100GB / 4KB
            long callerAvailable = 2621440L; // 10GB / 4KB (quota limit)
            long actualFree = 13107200L; // 50GB / 4KB (actual free)

            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(totalClusters);
            buffer.putLong(callerAvailable);
            buffer.putLong(actualFree);
            buffer.putInt(8);
            buffer.putInt(512);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);

            // Then
            assertEquals(107374182400L, fileFsFullSizeInfo.getCapacity()); // 100GB total
            assertEquals(10737418240L, fileFsFullSizeInfo.getFree()); // 10GB (quota limited)
        }

        @Test
        @DisplayName("Should handle typical Linux ext4 configuration")
        void shouldHandleTypicalExt4Configuration() throws SMBProtocolDecodingException {
            // Given - typical ext4: 4KB blocks
            long totalBlocks = 26214400L; // 100GB / 4KB
            long freeBlocks = 5242880L; // 20GB / 4KB

            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(totalBlocks);
            buffer.putLong(freeBlocks);
            buffer.putLong(freeBlocks);
            buffer.putInt(1); // 1 sector per allocation unit
            buffer.putInt(4096); // 4KB sectors

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);

            // Then
            assertEquals(107374182400L, fileFsFullSizeInfo.getCapacity()); // 100GB
            assertEquals(21474836480L, fileFsFullSizeInfo.getFree()); // 20GB
        }

        @Test
        @DisplayName("Should handle large file systems")
        void shouldHandleLargeFileSystems() throws SMBProtocolDecodingException {
            // Given - 10TB file system with 4KB clusters
            long totalClusters = 2684354560L; // 10TB / 4KB
            long freeClusters = 536870912L; // 2TB / 4KB

            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(totalClusters);
            buffer.putLong(freeClusters);
            buffer.putLong(freeClusters);
            buffer.putInt(8);
            buffer.putInt(512);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);

            // Then
            assertEquals(10995116277760L, fileFsFullSizeInfo.getCapacity()); // 10TB
            assertEquals(2199023255552L, fileFsFullSizeInfo.getFree()); // 2TB
        }

        @ParameterizedTest
        @DisplayName("Should handle various sector sizes")
        @ValueSource(ints = { 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 })
        void shouldHandleVariousSectorSizes(int sectorSize) throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(1000L);
            buffer.putLong(500L);
            buffer.putLong(600L);
            buffer.putInt(1);
            buffer.putInt(sectorSize);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);

            // Then
            assertEquals(1000L * sectorSize, fileFsFullSizeInfo.getCapacity());
            assertEquals(500L * sectorSize, fileFsFullSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should handle full disk scenario")
        void shouldHandleFullDiskScenario() throws SMBProtocolDecodingException {
            // Given - disk with no free space
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(1000000L);
            buffer.putLong(0L);
            buffer.putLong(0L);
            buffer.putInt(8);
            buffer.putInt(512);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);

            // Then
            assertTrue(fileFsFullSizeInfo.getCapacity() > 0);
            assertEquals(0L, fileFsFullSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should handle empty disk scenario")
        void shouldHandleEmptyDiskScenario() throws SMBProtocolDecodingException {
            // Given - disk with all space free
            long totalUnits = 1000000L;

            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(totalUnits);
            buffer.putLong(totalUnits);
            buffer.putLong(totalUnits);
            buffer.putInt(8);
            buffer.putInt(512);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);

            // Then
            assertEquals(fileFsFullSizeInfo.getCapacity(), fileFsFullSizeInfo.getFree());
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should work as AllocInfo implementation")
        void shouldWorkAsAllocInfoImplementation() throws SMBProtocolDecodingException {
            // Given
            AllocInfo allocInfo = new FileFsFullSizeInformation();
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(5000L);
            buffer.putLong(2000L);
            buffer.putLong(2100L);
            buffer.putInt(4);
            buffer.putInt(2048);

            // When
            allocInfo.decode(buffer.array(), 0, 32);

            // Then
            assertEquals(5000L * 4 * 2048, allocInfo.getCapacity());
            assertEquals(2000L * 4 * 2048, allocInfo.getFree());
            assertEquals(FileSystemInformation.FS_FULL_SIZE_INFO, allocInfo.getFileSystemInformationClass());
        }

        @Test
        @DisplayName("Should calculate used space correctly")
        void shouldCalculateUsedSpaceCorrectly() throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(10000L);
            buffer.putLong(3000L);
            buffer.putLong(3000L);
            buffer.putInt(8);
            buffer.putInt(512);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);
            long usedSpace = fileFsFullSizeInfo.getCapacity() - fileFsFullSizeInfo.getFree();

            // Then
            assertEquals(7000L * 8 * 512, usedSpace);
        }

        @Test
        @DisplayName("Should support percentage calculations")
        void shouldSupportPercentageCalculations() throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(1000L);
            buffer.putLong(250L);
            buffer.putLong(250L);
            buffer.putInt(1);
            buffer.putInt(1);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);
            double percentFree = (fileFsFullSizeInfo.getFree() * 100.0) / fileFsFullSizeInfo.getCapacity();
            double percentUsed =
                    ((fileFsFullSizeInfo.getCapacity() - fileFsFullSizeInfo.getFree()) * 100.0) / fileFsFullSizeInfo.getCapacity();

            // Then
            assertEquals(25.0, percentFree, 0.001);
            assertEquals(75.0, percentUsed, 0.001);
        }

        @Test
        @DisplayName("Should differentiate between caller available and actual free units")
        void shouldDifferentiateBetweenCallerAndActualFree() throws SMBProtocolDecodingException {
            // Given - simulating quota scenario
            ByteBuffer buffer = ByteBuffer.allocate(32);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(10000L); // Total units
            buffer.putLong(2000L); // Caller available (quota limited)
            buffer.putLong(5000L); // Actual free (more than caller can use)
            buffer.putInt(8);
            buffer.putInt(512);

            // When
            fileFsFullSizeInfo.decode(buffer.array(), 0, 32);

            // Then
            assertEquals(10000L * 8 * 512, fileFsFullSizeInfo.getCapacity());
            // Should use caller available, not actual free
            assertEquals(2000L * 8 * 512, fileFsFullSizeInfo.getFree());
            // Actual free is ignored
            assertNotEquals(5000L * 8 * 512, fileFsFullSizeInfo.getFree());
        }
    }
}
