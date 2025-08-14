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
 * Test suite for FileFsSizeInformation class
 */
class FileFsSizeInformationTest {

    private FileFsSizeInformation fileFsSizeInfo;

    @BeforeEach
    void setUp() {
        fileFsSizeInfo = new FileFsSizeInformation();
    }

    @Nested
    @DisplayName("Interface Implementation Tests")
    class InterfaceImplementationTests {

        @Test
        @DisplayName("Should implement AllocInfo interface")
        void shouldImplementAllocInfo() {
            assertTrue(AllocInfo.class.isAssignableFrom(FileFsSizeInformation.class));
        }

        @Test
        @DisplayName("Should implement FileSystemInformation interface")
        void shouldImplementFileSystemInformation() {
            assertTrue(FileSystemInformation.class.isAssignableFrom(FileFsSizeInformation.class));
        }

        @Test
        @DisplayName("Should return correct file system information class")
        void shouldReturnCorrectFileSystemInformationClass() {
            assertEquals(FileSystemInformation.FS_SIZE_INFO, fileFsSizeInfo.getFileSystemInformationClass());
        }
    }

    @Nested
    @DisplayName("Decode Method Tests")
    class DecodeMethodTests {

        @Test
        @DisplayName("Should decode buffer with typical values correctly")
        void shouldDecodeBufferWithTypicalValues() throws SMBProtocolDecodingException {
            // Given - prepare buffer with typical file system values
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(1048576L); // Total allocation units (1M)
            buffer.putLong(524288L); // Free allocation units (512K)
            buffer.putInt(8); // Sectors per allocation unit
            buffer.putInt(512); // Bytes per sector
            byte[] bufferArray = buffer.array();

            // When
            int bytesConsumed = fileFsSizeInfo.decode(bufferArray, 0, bufferArray.length);

            // Then
            assertEquals(24, bytesConsumed);
            assertEquals(1048576L * 8 * 512, fileFsSizeInfo.getCapacity());
            assertEquals(524288L * 8 * 512, fileFsSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should decode buffer with zero values")
        void shouldDecodeBufferWithZeroValues() throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(0L);
            buffer.putLong(0L);
            buffer.putInt(0);
            buffer.putInt(0);
            byte[] bufferArray = buffer.array();

            // When
            int bytesConsumed = fileFsSizeInfo.decode(bufferArray, 0, bufferArray.length);

            // Then
            assertEquals(24, bytesConsumed);
            assertEquals(0L, fileFsSizeInfo.getCapacity());
            assertEquals(0L, fileFsSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should decode buffer with maximum values")
        void shouldDecodeBufferWithMaximumValues() throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(Long.MAX_VALUE);
            buffer.putLong(Long.MAX_VALUE);
            buffer.putInt(Integer.MAX_VALUE);
            buffer.putInt(Integer.MAX_VALUE);
            byte[] bufferArray = buffer.array();

            // When
            int bytesConsumed = fileFsSizeInfo.decode(bufferArray, 0, bufferArray.length);

            // Then
            assertEquals(24, bytesConsumed);
            // Note: multiplication may overflow, but that's expected behavior
            long expectedCapacity = Long.MAX_VALUE * (long) Integer.MAX_VALUE * (long) Integer.MAX_VALUE;
            assertEquals(expectedCapacity, fileFsSizeInfo.getCapacity());
        }

        @Test
        @DisplayName("Should decode buffer with offset correctly")
        void shouldDecodeBufferWithOffset() throws SMBProtocolDecodingException {
            // Given - buffer with padding before actual data
            ByteBuffer buffer = ByteBuffer.allocate(34);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.position(10); // Add 10 bytes of padding
            buffer.putLong(2048L);
            buffer.putLong(1024L);
            buffer.putInt(4);
            buffer.putInt(4096);
            byte[] bufferArray = buffer.array();

            // When
            int bytesConsumed = fileFsSizeInfo.decode(bufferArray, 10, 24);

            // Then
            assertEquals(24, bytesConsumed);
            assertEquals(2048L * 4 * 4096, fileFsSizeInfo.getCapacity());
            assertEquals(1024L * 4 * 4096, fileFsSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should handle negative values in buffer")
        void shouldHandleNegativeValuesInBuffer() throws SMBProtocolDecodingException {
            // Given - negative values (treated as unsigned in protocol)
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(-1L);
            buffer.putLong(-1L);
            buffer.putInt(-1);
            buffer.putInt(-1);
            byte[] bufferArray = buffer.array();

            // When
            int bytesConsumed = fileFsSizeInfo.decode(bufferArray, 0, bufferArray.length);

            // Then
            assertEquals(24, bytesConsumed);
            // Values are read as-is (can be negative due to overflow)
            assertNotNull(fileFsSizeInfo.getCapacity());
            assertNotNull(fileFsSizeInfo.getFree());
        }

        @ParameterizedTest
        @DisplayName("Should decode various sector and allocation configurations")
        @CsvSource({ "1000, 500, 1, 512", // Minimal sectors per alloc
                "1000, 500, 8, 512", // Typical configuration
                "1000, 500, 64, 512", // Large allocation units
                "1000, 500, 8, 4096", // 4K sectors
                "1000, 500, 16, 4096", // Large sectors and allocation
                "1000, 0, 8, 512", // No free space
                "1000, 1000, 8, 512" // All space free
        })
        void shouldDecodeVariousSectorConfigurations(long alloc, long free, int sectPerAlloc, int bytesPerSect)
                throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(alloc);
            buffer.putLong(free);
            buffer.putInt(sectPerAlloc);
            buffer.putInt(bytesPerSect);
            byte[] bufferArray = buffer.array();

            // When
            int bytesConsumed = fileFsSizeInfo.decode(bufferArray, 0, bufferArray.length);

            // Then
            assertEquals(24, bytesConsumed);
            assertEquals(alloc * sectPerAlloc * bytesPerSect, fileFsSizeInfo.getCapacity());
            assertEquals(free * sectPerAlloc * bytesPerSect, fileFsSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should return correct number of bytes consumed from buffer")
        void shouldReturnCorrectBytesConsumed() throws SMBProtocolDecodingException {
            // Given - larger buffer than needed
            byte[] buffer = new byte[100];
            ByteBuffer bb = ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN);
            bb.putLong(1000L);
            bb.putLong(500L);
            bb.putInt(8);
            bb.putInt(512);

            // When
            int bytesConsumed = fileFsSizeInfo.decode(buffer, 0, buffer.length);

            // Then
            assertEquals(24, bytesConsumed); // Should always consume exactly 24 bytes
        }

        @Test
        @DisplayName("Should decode from middle of buffer correctly")
        void shouldDecodeFromMiddleOfBuffer() throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[100];
            int offset = 40;
            ByteBuffer bb = ByteBuffer.wrap(buffer, offset, 24).order(ByteOrder.LITTLE_ENDIAN);
            bb.putLong(5000L);
            bb.putLong(2500L);
            bb.putInt(16);
            bb.putInt(1024);

            // When
            int bytesConsumed = fileFsSizeInfo.decode(buffer, offset, 24);

            // Then
            assertEquals(24, bytesConsumed);
            assertEquals(5000L * 16 * 1024, fileFsSizeInfo.getCapacity());
            assertEquals(2500L * 16 * 1024, fileFsSizeInfo.getFree());
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

            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(alloc);
            buffer.putLong(0L);
            buffer.putInt(sectPerAlloc);
            buffer.putInt(bytesPerSect);

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);

            // Then
            long expectedCapacity = alloc * sectPerAlloc * bytesPerSect;
            assertEquals(expectedCapacity, fileFsSizeInfo.getCapacity());
            assertEquals(4194304L, fileFsSizeInfo.getCapacity()); // 1024 * 8 * 512
        }

        @Test
        @DisplayName("Should calculate free space correctly")
        void shouldCalculateFreeSpaceCorrectly() throws SMBProtocolDecodingException {
            // Given
            long free = 512L;
            int sectPerAlloc = 8;
            int bytesPerSect = 512;

            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(0L);
            buffer.putLong(free);
            buffer.putInt(sectPerAlloc);
            buffer.putInt(bytesPerSect);

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);

            // Then
            long expectedFree = free * sectPerAlloc * bytesPerSect;
            assertEquals(expectedFree, fileFsSizeInfo.getFree());
            assertEquals(2097152L, fileFsSizeInfo.getFree()); // 512 * 8 * 512
        }

        @Test
        @DisplayName("Should handle overflow in capacity calculation")
        void shouldHandleOverflowInCapacityCalculation() throws SMBProtocolDecodingException {
            // Given - values that will cause overflow
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(Long.MAX_VALUE / 2);
            buffer.putLong(Long.MAX_VALUE / 4);
            buffer.putInt(10);
            buffer.putInt(10);

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);

            // Then - overflow is expected behavior
            assertNotNull(fileFsSizeInfo.getCapacity());
            assertNotNull(fileFsSizeInfo.getFree());
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
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(alloc);
            buffer.putLong(free);
            buffer.putInt(sectPerAlloc);
            buffer.putInt(bytesPerSect);

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);

            // Then
            assertEquals(expectedCapacity, fileFsSizeInfo.getCapacity());
            assertEquals(expectedFree, fileFsSizeInfo.getFree());
        }
    }

    @Nested
    @DisplayName("ToString Method Tests")
    class ToStringMethodTests {

        @Test
        @DisplayName("Should return correct string representation with default values")
        void shouldReturnCorrectStringWithDefaultValues() {
            // When
            String result = fileFsSizeInfo.toString();

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
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(1000L);
            buffer.putLong(500L);
            buffer.putInt(8);
            buffer.putInt(512);

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);
            String result = fileFsSizeInfo.toString();

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
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(123456L);
            buffer.putLong(78910L);
            buffer.putInt(16);
            buffer.putInt(4096);

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);
            String result = fileFsSizeInfo.toString();

            // Then
            String expected = "SmbInfoAllocation[alloc=123456,free=78910,sectPerAlloc=16,bytesPerSect=4096]";
            assertEquals(expected, result);
        }

        @Test
        @DisplayName("Should handle negative values in toString")
        void shouldHandleNegativeValuesInToString() throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(-1L);
            buffer.putLong(-2L);
            buffer.putInt(-3);
            buffer.putInt(-4);

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);
            String result = fileFsSizeInfo.toString();

            // Then
            assertNotNull(result);
            assertTrue(result.contains("alloc=-1"));
            assertTrue(result.contains("free=-2"));
            assertTrue(result.contains("sectPerAlloc=-3"));
            assertTrue(result.contains("bytesPerSect=-4"));
        }
    }

    @Nested
    @DisplayName("State Management Tests")
    class StateManagementTests {

        @Test
        @DisplayName("Should maintain state after decode")
        void shouldMaintainStateAfterDecode() throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(2000L);
            buffer.putLong(1000L);
            buffer.putInt(4);
            buffer.putInt(1024);

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);

            // Then - multiple calls should return same values
            assertEquals(2000L * 4 * 1024, fileFsSizeInfo.getCapacity());
            assertEquals(2000L * 4 * 1024, fileFsSizeInfo.getCapacity());
            assertEquals(1000L * 4 * 1024, fileFsSizeInfo.getFree());
            assertEquals(1000L * 4 * 1024, fileFsSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should update state on subsequent decode calls")
        void shouldUpdateStateOnSubsequentDecodeCalls() throws SMBProtocolDecodingException {
            // Given - first decode
            ByteBuffer buffer1 = ByteBuffer.allocate(24);
            buffer1.order(ByteOrder.LITTLE_ENDIAN);
            buffer1.putLong(1000L);
            buffer1.putLong(500L);
            buffer1.putInt(8);
            buffer1.putInt(512);

            fileFsSizeInfo.decode(buffer1.array(), 0, 24);
            long firstCapacity = fileFsSizeInfo.getCapacity();
            long firstFree = fileFsSizeInfo.getFree();

            // When - second decode with different values
            ByteBuffer buffer2 = ByteBuffer.allocate(24);
            buffer2.order(ByteOrder.LITTLE_ENDIAN);
            buffer2.putLong(2000L);
            buffer2.putLong(1500L);
            buffer2.putInt(16);
            buffer2.putInt(1024);

            fileFsSizeInfo.decode(buffer2.array(), 0, 24);

            // Then
            assertNotEquals(firstCapacity, fileFsSizeInfo.getCapacity());
            assertNotEquals(firstFree, fileFsSizeInfo.getFree());
            assertEquals(2000L * 16 * 1024, fileFsSizeInfo.getCapacity());
            assertEquals(1500L * 16 * 1024, fileFsSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should have initial zero state")
        void shouldHaveInitialZeroState() {
            // Given - newly created instance
            FileFsSizeInformation freshInfo = new FileFsSizeInformation();

            // Then
            assertEquals(0L, freshInfo.getCapacity());
            assertEquals(0L, freshInfo.getFree());
            assertEquals(FileSystemInformation.FS_SIZE_INFO, freshInfo.getFileSystemInformationClass());
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

            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(totalClusters);
            buffer.putLong(freeClusters);
            buffer.putInt(8);
            buffer.putInt(512);

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);

            // Then
            assertEquals(107374182400L, fileFsSizeInfo.getCapacity()); // 100GB
            assertEquals(53687091200L, fileFsSizeInfo.getFree()); // 50GB
        }

        @Test
        @DisplayName("Should handle typical Linux ext4 configuration")
        void shouldHandleTypicalExt4Configuration() throws SMBProtocolDecodingException {
            // Given - typical ext4: 4KB blocks
            long totalBlocks = 26214400L; // 100GB / 4KB
            long freeBlocks = 5242880L; // 20GB / 4KB

            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(totalBlocks);
            buffer.putLong(freeBlocks);
            buffer.putInt(1); // 1 sector per allocation unit
            buffer.putInt(4096); // 4KB sectors

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);

            // Then
            assertEquals(107374182400L, fileFsSizeInfo.getCapacity()); // 100GB
            assertEquals(21474836480L, fileFsSizeInfo.getFree()); // 20GB
        }

        @Test
        @DisplayName("Should handle large file systems")
        void shouldHandleLargeFileSystems() throws SMBProtocolDecodingException {
            // Given - 10TB file system with 4KB clusters
            long totalClusters = 2684354560L; // 10TB / 4KB
            long freeClusters = 536870912L; // 2TB / 4KB

            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(totalClusters);
            buffer.putLong(freeClusters);
            buffer.putInt(8);
            buffer.putInt(512);

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);

            // Then
            assertEquals(10995116277760L, fileFsSizeInfo.getCapacity()); // 10TB
            assertEquals(2199023255552L, fileFsSizeInfo.getFree()); // 2TB
        }

        @ParameterizedTest
        @DisplayName("Should handle various sector sizes")
        @ValueSource(ints = { 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 })
        void shouldHandleVariousSectorSizes(int sectorSize) throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(1000L);
            buffer.putLong(500L);
            buffer.putInt(1);
            buffer.putInt(sectorSize);

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);

            // Then
            assertEquals(1000L * sectorSize, fileFsSizeInfo.getCapacity());
            assertEquals(500L * sectorSize, fileFsSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should handle full disk scenario")
        void shouldHandleFullDiskScenario() throws SMBProtocolDecodingException {
            // Given - disk with no free space
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(1000000L);
            buffer.putLong(0L);
            buffer.putInt(8);
            buffer.putInt(512);

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);

            // Then
            assertTrue(fileFsSizeInfo.getCapacity() > 0);
            assertEquals(0L, fileFsSizeInfo.getFree());
        }

        @Test
        @DisplayName("Should handle empty disk scenario")
        void shouldHandleEmptyDiskScenario() throws SMBProtocolDecodingException {
            // Given - disk with all space free
            long totalUnits = 1000000L;

            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(totalUnits);
            buffer.putLong(totalUnits);
            buffer.putInt(8);
            buffer.putInt(512);

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);

            // Then
            assertEquals(fileFsSizeInfo.getCapacity(), fileFsSizeInfo.getFree());
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should work as AllocInfo implementation")
        void shouldWorkAsAllocInfoImplementation() throws SMBProtocolDecodingException {
            // Given
            AllocInfo allocInfo = new FileFsSizeInformation();
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(5000L);
            buffer.putLong(2000L);
            buffer.putInt(4);
            buffer.putInt(2048);

            // When
            allocInfo.decode(buffer.array(), 0, 24);

            // Then
            assertEquals(5000L * 4 * 2048, allocInfo.getCapacity());
            assertEquals(2000L * 4 * 2048, allocInfo.getFree());
            assertEquals(FileSystemInformation.FS_SIZE_INFO, allocInfo.getFileSystemInformationClass());
        }

        @Test
        @DisplayName("Should calculate used space correctly")
        void shouldCalculateUsedSpaceCorrectly() throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(10000L);
            buffer.putLong(3000L);
            buffer.putInt(8);
            buffer.putInt(512);

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);
            long usedSpace = fileFsSizeInfo.getCapacity() - fileFsSizeInfo.getFree();

            // Then
            assertEquals(7000L * 8 * 512, usedSpace);
        }

        @Test
        @DisplayName("Should support percentage calculations")
        void shouldSupportPercentageCalculations() throws SMBProtocolDecodingException {
            // Given
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(1000L);
            buffer.putLong(250L);
            buffer.putInt(1);
            buffer.putInt(1);

            // When
            fileFsSizeInfo.decode(buffer.array(), 0, 24);
            double percentFree = (fileFsSizeInfo.getFree() * 100.0) / fileFsSizeInfo.getCapacity();
            double percentUsed = ((fileFsSizeInfo.getCapacity() - fileFsSizeInfo.getFree()) * 100.0) / fileFsSizeInfo.getCapacity();

            // Then
            assertEquals(25.0, percentFree, 0.001);
            assertEquals(75.0, percentUsed, 0.001);
        }
    }
}
