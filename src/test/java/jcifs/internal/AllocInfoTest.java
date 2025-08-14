package jcifs.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.internal.fscc.FileSystemInformation;

/**
 * Test suite for AllocInfo interface
 */
class AllocInfoTest {

    @Mock
    private AllocInfo mockAllocInfo;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    /**
     * Test implementation class for AllocInfo interface
     */
    static class TestAllocInfo implements AllocInfo {
        private final long capacity;
        private final long free;
        private byte fileSystemInformationClass = FS_SIZE_INFO;

        TestAllocInfo(long capacity, long free) {
            this.capacity = capacity;
            this.free = free;
        }

        TestAllocInfo(long capacity, long free, byte fileSystemInformationClass) {
            this.capacity = capacity;
            this.free = free;
            this.fileSystemInformationClass = fileSystemInformationClass;
        }

        @Override
        public long getCapacity() {
            return capacity;
        }

        @Override
        public long getFree() {
            return free;
        }

        @Override
        public byte getFileSystemInformationClass() {
            return fileSystemInformationClass;
        }

        @Override
        public int decode(byte[] buffer, int bufferIndex, int len) throws jcifs.internal.SMBProtocolDecodingException {
            // Simple test implementation - not used in these tests
            return 0;
        }
    }

    @Nested
    @DisplayName("Interface Contract Tests")
    class InterfaceContractTests {

        @Test
        @DisplayName("Should implement FileSystemInformation interface")
        void shouldImplementFileSystemInformation() {
            // Verify that AllocInfo extends FileSystemInformation
            assertTrue(FileSystemInformation.class.isAssignableFrom(AllocInfo.class));
        }

        @Test
        @DisplayName("Should implement Decodable interface through FileSystemInformation")
        void shouldImplementDecodableInterface() {
            // Verify that AllocInfo indirectly implements Decodable
            assertTrue(jcifs.Decodable.class.isAssignableFrom(AllocInfo.class));
        }

        @Test
        @DisplayName("Should define getCapacity method")
        void shouldDefineGetCapacityMethod() throws NoSuchMethodException {
            // Verify method exists with correct signature
            assertNotNull(AllocInfo.class.getMethod("getCapacity"));
            assertEquals(long.class, AllocInfo.class.getMethod("getCapacity").getReturnType());
        }

        @Test
        @DisplayName("Should define getFree method")
        void shouldDefineGetFreeMethod() throws NoSuchMethodException {
            // Verify method exists with correct signature
            assertNotNull(AllocInfo.class.getMethod("getFree"));
            assertEquals(long.class, AllocInfo.class.getMethod("getFree").getReturnType());
        }

        @Test
        @DisplayName("Should inherit getFileSystemInformationClass from FileSystemInformation")
        void shouldInheritGetFileSystemInformationClass() throws NoSuchMethodException {
            // Verify method is inherited
            assertNotNull(AllocInfo.class.getMethod("getFileSystemInformationClass"));
            assertEquals(byte.class, AllocInfo.class.getMethod("getFileSystemInformationClass").getReturnType());
        }

        @Test
        @DisplayName("Should inherit decode from Decodable")
        void shouldInheritDecodeMethod() throws NoSuchMethodException {
            // Verify method is inherited
            assertNotNull(AllocInfo.class.getMethod("decode", byte[].class, int.class, int.class));
            assertEquals(int.class, AllocInfo.class.getMethod("decode", byte[].class, int.class, int.class).getReturnType());
        }

        @Test
        @DisplayName("Should have FileSystemInformation constants accessible")
        void shouldHaveFileSystemInformationConstants() {
            // Verify constants are accessible through interface
            assertEquals(-1, FileSystemInformation.SMB_INFO_ALLOCATION);
            assertEquals(3, FileSystemInformation.FS_SIZE_INFO);
            assertEquals(7, FileSystemInformation.FS_FULL_SIZE_INFO);
        }
    }

    @Nested
    @DisplayName("Mock Behavior Tests")
    class MockBehaviorTests {

        @Test
        @DisplayName("Should return mocked capacity value")
        void shouldReturnMockedCapacity() {
            // Given
            long expectedCapacity = 1024L * 1024L * 1024L * 100L; // 100GB
            when(mockAllocInfo.getCapacity()).thenReturn(expectedCapacity);

            // When
            long actualCapacity = mockAllocInfo.getCapacity();

            // Then
            assertEquals(expectedCapacity, actualCapacity);
            verify(mockAllocInfo, times(1)).getCapacity();
        }

        @Test
        @DisplayName("Should return mocked free space value")
        void shouldReturnMockedFreeSpace() {
            // Given
            long expectedFree = 1024L * 1024L * 1024L * 50L; // 50GB
            when(mockAllocInfo.getFree()).thenReturn(expectedFree);

            // When
            long actualFree = mockAllocInfo.getFree();

            // Then
            assertEquals(expectedFree, actualFree);
            verify(mockAllocInfo, times(1)).getFree();
        }

        @Test
        @DisplayName("Should handle multiple invocations")
        void shouldHandleMultipleInvocations() {
            // Given
            when(mockAllocInfo.getCapacity()).thenReturn(1000L, 2000L, 3000L);
            when(mockAllocInfo.getFree()).thenReturn(500L, 1000L, 1500L);

            // When & Then
            assertEquals(1000L, mockAllocInfo.getCapacity());
            assertEquals(500L, mockAllocInfo.getFree());
            assertEquals(2000L, mockAllocInfo.getCapacity());
            assertEquals(1000L, mockAllocInfo.getFree());
            assertEquals(3000L, mockAllocInfo.getCapacity());
            assertEquals(1500L, mockAllocInfo.getFree());

            verify(mockAllocInfo, times(3)).getCapacity();
            verify(mockAllocInfo, times(3)).getFree();
        }

        @Test
        @DisplayName("Should return mocked file system information class")
        void shouldReturnMockedFileSystemInformationClass() {
            // Given
            when(mockAllocInfo.getFileSystemInformationClass()).thenReturn(FileSystemInformation.FS_FULL_SIZE_INFO);

            // When
            byte fsClass = mockAllocInfo.getFileSystemInformationClass();

            // Then
            assertEquals(FileSystemInformation.FS_FULL_SIZE_INFO, fsClass);
            verify(mockAllocInfo, times(1)).getFileSystemInformationClass();
        }

        @Test
        @DisplayName("Should handle mocked decode method")
        void shouldHandleMockedDecodeMethod() throws jcifs.internal.SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[100];
            when(mockAllocInfo.decode(any(byte[].class), anyInt(), anyInt())).thenReturn(42);

            // When
            int result = mockAllocInfo.decode(buffer, 10, 50);

            // Then
            assertEquals(42, result);
            verify(mockAllocInfo, times(1)).decode(buffer, 10, 50);
        }

        @Test
        @DisplayName("Should handle decode method throwing exception")
        void shouldHandleDecodeMethodThrowingException() throws jcifs.internal.SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[100];
            when(mockAllocInfo.decode(any(byte[].class), anyInt(), anyInt()))
                    .thenThrow(new jcifs.internal.SMBProtocolDecodingException("Test error"));

            // When & Then
            assertThrows(jcifs.internal.SMBProtocolDecodingException.class, () -> mockAllocInfo.decode(buffer, 0, buffer.length));
            verify(mockAllocInfo, times(1)).decode(buffer, 0, buffer.length);
        }
    }

    @Nested
    @DisplayName("Test Implementation Tests")
    class TestImplementationTests {

        @Test
        @DisplayName("Should correctly store and return capacity")
        void shouldCorrectlyStoreAndReturnCapacity() {
            // Given
            long expectedCapacity = 1024L * 1024L * 1024L * 500L; // 500GB
            TestAllocInfo allocInfo = new TestAllocInfo(expectedCapacity, 0);

            // When
            long actualCapacity = allocInfo.getCapacity();

            // Then
            assertEquals(expectedCapacity, actualCapacity);
        }

        @Test
        @DisplayName("Should correctly store and return free space")
        void shouldCorrectlyStoreAndReturnFreeSpace() {
            // Given
            long expectedFree = 1024L * 1024L * 1024L * 250L; // 250GB
            TestAllocInfo allocInfo = new TestAllocInfo(0, expectedFree);

            // When
            long actualFree = allocInfo.getFree();

            // Then
            assertEquals(expectedFree, actualFree);
        }

        @ParameterizedTest
        @DisplayName("Should handle various capacity and free space values")
        @CsvSource({ "0, 0", "1024, 512", "1048576, 524288", "1073741824, 536870912", "9223372036854775807, 4611686018427387903", // Long.MAX_VALUE and half
                "-1, -1", // Negative values (edge case)
                "100, 200" // Free space greater than capacity (edge case)
        })
        void shouldHandleVariousValues(long capacity, long free) {
            // Given
            TestAllocInfo allocInfo = new TestAllocInfo(capacity, free);

            // When & Then
            assertEquals(capacity, allocInfo.getCapacity());
            assertEquals(free, allocInfo.getFree());
        }

        @Test
        @DisplayName("Should handle zero values")
        void shouldHandleZeroValues() {
            // Given
            TestAllocInfo allocInfo = new TestAllocInfo(0L, 0L);

            // When & Then
            assertEquals(0L, allocInfo.getCapacity());
            assertEquals(0L, allocInfo.getFree());
        }

        @Test
        @DisplayName("Should handle maximum long values")
        void shouldHandleMaximumLongValues() {
            // Given
            TestAllocInfo allocInfo = new TestAllocInfo(Long.MAX_VALUE, Long.MAX_VALUE);

            // When & Then
            assertEquals(Long.MAX_VALUE, allocInfo.getCapacity());
            assertEquals(Long.MAX_VALUE, allocInfo.getFree());
        }

        @Test
        @DisplayName("Should handle minimum long values")
        void shouldHandleMinimumLongValues() {
            // Given
            TestAllocInfo allocInfo = new TestAllocInfo(Long.MIN_VALUE, Long.MIN_VALUE);

            // When & Then
            assertEquals(Long.MIN_VALUE, allocInfo.getCapacity());
            assertEquals(Long.MIN_VALUE, allocInfo.getFree());
        }

        @Test
        @DisplayName("Should calculate used space correctly")
        void shouldCalculateUsedSpaceCorrectly() {
            // Given
            long capacity = 1024L * 1024L * 1024L * 100L; // 100GB
            long free = 1024L * 1024L * 1024L * 40L; // 40GB
            TestAllocInfo allocInfo = new TestAllocInfo(capacity, free);

            // When
            long used = allocInfo.getCapacity() - allocInfo.getFree();

            // Then
            assertEquals(1024L * 1024L * 1024L * 60L, used); // 60GB used
        }

        @Test
        @DisplayName("Should maintain immutability")
        void shouldMaintainImmutability() {
            // Given
            long capacity = 1000L;
            long free = 500L;
            TestAllocInfo allocInfo = new TestAllocInfo(capacity, free);

            // When - multiple calls should return same values
            long firstCapacityCall = allocInfo.getCapacity();
            long secondCapacityCall = allocInfo.getCapacity();
            long firstFreeCall = allocInfo.getFree();
            long secondFreeCall = allocInfo.getFree();

            // Then
            assertEquals(firstCapacityCall, secondCapacityCall);
            assertEquals(firstFreeCall, secondFreeCall);
            assertEquals(capacity, firstCapacityCall);
            assertEquals(free, firstFreeCall);
        }

        @Test
        @DisplayName("Should return correct file system information class")
        void shouldReturnCorrectFileSystemInformationClass() {
            // Test with default FS_SIZE_INFO
            TestAllocInfo defaultInfo = new TestAllocInfo(1000L, 500L);
            assertEquals(FileSystemInformation.FS_SIZE_INFO, defaultInfo.getFileSystemInformationClass());

            // Test with SMB_INFO_ALLOCATION
            TestAllocInfo smbInfo = new TestAllocInfo(1000L, 500L, FileSystemInformation.SMB_INFO_ALLOCATION);
            assertEquals(FileSystemInformation.SMB_INFO_ALLOCATION, smbInfo.getFileSystemInformationClass());

            // Test with FS_FULL_SIZE_INFO
            TestAllocInfo fullInfo = new TestAllocInfo(1000L, 500L, FileSystemInformation.FS_FULL_SIZE_INFO);
            assertEquals(FileSystemInformation.FS_FULL_SIZE_INFO, fullInfo.getFileSystemInformationClass());
        }

        @Test
        @DisplayName("Should handle decode method call")
        void shouldHandleDecodeMethodCall() throws jcifs.internal.SMBProtocolDecodingException {
            // Given
            TestAllocInfo allocInfo = new TestAllocInfo(1000L, 500L);
            byte[] buffer = new byte[100];

            // When
            int result = allocInfo.decode(buffer, 0, buffer.length);

            // Then
            assertEquals(0, result); // Test implementation returns 0
        }

        @Test
        @DisplayName("Should support different file system information classes")
        void shouldSupportDifferentFileSystemInformationClasses() {
            // Test all known constants
            byte[] classes = { FileSystemInformation.SMB_INFO_ALLOCATION, FileSystemInformation.FS_SIZE_INFO,
                    FileSystemInformation.FS_FULL_SIZE_INFO, (byte) 0, (byte) 1, (byte) 127, (byte) -128 };

            for (byte fsClass : classes) {
                TestAllocInfo allocInfo = new TestAllocInfo(1024L, 512L, fsClass);
                assertEquals(fsClass, allocInfo.getFileSystemInformationClass());
            }
        }
    }

    @Nested
    @DisplayName("Edge Cases and Boundary Tests")
    class EdgeCasesTests {

        @ParameterizedTest
        @DisplayName("Should handle boundary values for capacity")
        @ValueSource(longs = { 0L, 1L, -1L, 1024L, 1048576L, 1073741824L, Long.MAX_VALUE, Long.MIN_VALUE, Long.MAX_VALUE - 1,
                Long.MIN_VALUE + 1 })
        void shouldHandleBoundaryValuesForCapacity(long capacity) {
            // Given
            TestAllocInfo allocInfo = new TestAllocInfo(capacity, 0);

            // When & Then
            assertEquals(capacity, allocInfo.getCapacity());
        }

        @ParameterizedTest
        @DisplayName("Should handle boundary values for free space")
        @ValueSource(longs = { 0L, 1L, -1L, 1024L, 1048576L, 1073741824L, Long.MAX_VALUE, Long.MIN_VALUE, Long.MAX_VALUE - 1,
                Long.MIN_VALUE + 1 })
        void shouldHandleBoundaryValuesForFreeSpace(long free) {
            // Given
            TestAllocInfo allocInfo = new TestAllocInfo(0, free);

            // When & Then
            assertEquals(free, allocInfo.getFree());
        }

        @Test
        @DisplayName("Should handle overflow scenarios")
        void shouldHandleOverflowScenarios() {
            // Given - capacity at max, free space at max
            TestAllocInfo allocInfo = new TestAllocInfo(Long.MAX_VALUE, Long.MAX_VALUE);

            // When
            long capacity = allocInfo.getCapacity();
            long free = allocInfo.getFree();

            // Then - values should be preserved even at boundaries
            assertEquals(Long.MAX_VALUE, capacity);
            assertEquals(Long.MAX_VALUE, free);

            // Note: In real implementation, free > capacity might be invalid,
            // but interface doesn't enforce this constraint
        }

        @Test
        @DisplayName("Should handle typical file system sizes")
        void shouldHandleTypicalFileSystemSizes() {
            // Test common file system sizes
            long[] typicalSizes = { 1024L * 1024L * 1024L, // 1 GB
                    1024L * 1024L * 1024L * 10L, // 10 GB
                    1024L * 1024L * 1024L * 100L, // 100 GB
                    1024L * 1024L * 1024L * 1024L, // 1 TB
                    1024L * 1024L * 1024L * 1024L * 10L // 10 TB
            };

            for (long size : typicalSizes) {
                TestAllocInfo allocInfo = new TestAllocInfo(size, size / 2);
                assertEquals(size, allocInfo.getCapacity());
                assertEquals(size / 2, allocInfo.getFree());
            }
        }
    }

    @Nested
    @DisplayName("Usage Pattern Tests")
    class UsagePatternTests {

        @Test
        @DisplayName("Should support percentage calculation pattern")
        void shouldSupportPercentageCalculationPattern() {
            // Given
            TestAllocInfo allocInfo = new TestAllocInfo(1000L, 250L);

            // When - calculate percentage free
            double percentFree = (allocInfo.getFree() * 100.0) / allocInfo.getCapacity();

            // Then
            assertEquals(25.0, percentFree, 0.001);
        }

        @Test
        @DisplayName("Should support available space check pattern")
        void shouldSupportAvailableSpaceCheckPattern() {
            // Given
            TestAllocInfo allocInfo = new TestAllocInfo(1024L * 1024L, 512L * 1024L);
            long requiredSpace = 256L * 1024L;

            // When - check if enough space available
            boolean hasEnoughSpace = allocInfo.getFree() >= requiredSpace;

            // Then
            assertTrue(hasEnoughSpace);
        }

        @Test
        @DisplayName("Should support full disk detection pattern")
        void shouldSupportFullDiskDetectionPattern() {
            // Given
            TestAllocInfo fullDisk = new TestAllocInfo(1024L, 0L);
            TestAllocInfo partialDisk = new TestAllocInfo(1024L, 512L);

            // When & Then
            assertTrue(fullDisk.getFree() == 0);
            assertFalse(partialDisk.getFree() == 0);
        }
    }
}
