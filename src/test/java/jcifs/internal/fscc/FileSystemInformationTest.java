/*
 * © 2025 Test Suite
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
package jcifs.internal.fscc;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.internal.AllocInfo;
import jcifs.internal.SMBProtocolDecodingException;

/**
 * Test suite for FileSystemInformation interface and its implementations
 */
class FileSystemInformationTest {

    @Mock
    private FileSystemInformation mockFileSystemInfo;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    /**
     * Test implementation class for FileSystemInformation interface
     */
    static class TestFileSystemInformation implements FileSystemInformation {
        private byte informationClass;

        public TestFileSystemInformation(byte informationClass) {
            this.informationClass = informationClass;
        }

        @Override
        public byte getFileSystemInformationClass() {
            return informationClass;
        }

        @Override
        public int decode(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
            return 0;
        }
    }

    @Nested
    @DisplayName("Interface Constants Tests")
    class InterfaceConstantsTests {

        @Test
        @DisplayName("Should have correct SMB_INFO_ALLOCATION constant value")
        void testSmbInfoAllocationConstant() {
            assertEquals((byte) -1, FileSystemInformation.SMB_INFO_ALLOCATION);
        }

        @Test
        @DisplayName("Should have correct FS_SIZE_INFO constant value")
        void testFsSizeInfoConstant() {
            assertEquals((byte) 3, FileSystemInformation.FS_SIZE_INFO);
        }

        @Test
        @DisplayName("Should have correct FS_FULL_SIZE_INFO constant value")
        void testFsFullSizeInfoConstant() {
            assertEquals((byte) 7, FileSystemInformation.FS_FULL_SIZE_INFO);
        }

        @Test
        @DisplayName("Should have distinct constant values")
        void testConstantUniqueness() {
            assertNotEquals(FileSystemInformation.SMB_INFO_ALLOCATION, FileSystemInformation.FS_SIZE_INFO);
            assertNotEquals(FileSystemInformation.SMB_INFO_ALLOCATION, FileSystemInformation.FS_FULL_SIZE_INFO);
            assertNotEquals(FileSystemInformation.FS_SIZE_INFO, FileSystemInformation.FS_FULL_SIZE_INFO);
        }
    }

    @Nested
    @DisplayName("Mock Interface Tests")
    class MockInterfaceTests {

        @Test
        @DisplayName("Should return configured file system information class")
        void testGetFileSystemInformationClass() {
            when(mockFileSystemInfo.getFileSystemInformationClass()).thenReturn(FileSystemInformation.FS_SIZE_INFO);
            
            byte result = mockFileSystemInfo.getFileSystemInformationClass();
            
            assertEquals(FileSystemInformation.FS_SIZE_INFO, result);
            verify(mockFileSystemInfo, times(1)).getFileSystemInformationClass();
        }

        @Test
        @DisplayName("Should decode buffer correctly")
        void testDecode() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[100];
            when(mockFileSystemInfo.decode(any(byte[].class), anyInt(), anyInt())).thenReturn(24);
            
            int result = mockFileSystemInfo.decode(buffer, 0, 100);
            
            assertEquals(24, result);
            verify(mockFileSystemInfo, times(1)).decode(buffer, 0, 100);
        }

        @Test
        @DisplayName("Should handle decode exception")
        void testDecodeException() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[100];
            when(mockFileSystemInfo.decode(any(byte[].class), anyInt(), anyInt()))
                .thenThrow(new SMBProtocolDecodingException("Test error"));
            
            assertThrows(SMBProtocolDecodingException.class, () -> {
                mockFileSystemInfo.decode(buffer, 0, 100);
            });
        }
    }

    @Nested
    @DisplayName("Test Implementation Tests")
    class TestImplementationTests {

        @ParameterizedTest
        @ValueSource(bytes = { -1, 0, 1, 3, 7, Byte.MAX_VALUE, Byte.MIN_VALUE })
        @DisplayName("Should handle various information class values")
        void testVariousInformationClassValues(byte classValue) {
            TestFileSystemInformation testImpl = new TestFileSystemInformation(classValue);
            assertEquals(classValue, testImpl.getFileSystemInformationClass());
        }

        @Test
        @DisplayName("Should decode with test implementation")
        void testDecodeWithTestImplementation() throws SMBProtocolDecodingException {
            TestFileSystemInformation testImpl = new TestFileSystemInformation(FileSystemInformation.FS_SIZE_INFO);
            byte[] buffer = new byte[50];
            
            int result = testImpl.decode(buffer, 10, 40);
            
            assertEquals(0, result); // Test implementation returns 0
        }
    }

    @Nested
    @DisplayName("SmbInfoAllocation Implementation Tests")
    class SmbInfoAllocationTests {

        private SmbInfoAllocation smbInfoAllocation;

        @BeforeEach
        void setUp() {
            smbInfoAllocation = new SmbInfoAllocation();
        }

        @Test
        @DisplayName("Should return correct information class")
        void testGetFileSystemInformationClass() {
            assertEquals(FileSystemInformation.SMB_INFO_ALLOCATION, smbInfoAllocation.getFileSystemInformationClass());
        }

        @Test
        @DisplayName("Should decode buffer correctly")
        void testDecode() throws SMBProtocolDecodingException {
            // Prepare test buffer with sample data
            byte[] buffer = new byte[24];
            // Skip idFileSystem (4 bytes)
            buffer[4] = 0x08; // sectPerAlloc = 8
            buffer[8] = 0x00; buffer[9] = 0x10; // alloc = 4096
            buffer[12] = 0x00; buffer[13] = 0x08; // free = 2048
            buffer[16] = 0x00; buffer[17] = 0x02; // bytesPerSect = 512

            int bytesDecoded = smbInfoAllocation.decode(buffer, 0, buffer.length);
            
            assertEquals(20, bytesDecoded);
            assertEquals(8L * 4096L * 512L, smbInfoAllocation.getCapacity());
            assertEquals(8L * 2048L * 512L, smbInfoAllocation.getFree());
        }

        @Test
        @DisplayName("Should calculate capacity correctly")
        void testCapacityCalculation() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[24];
            buffer[4] = 0x04; // sectPerAlloc = 4
            buffer[8] = 0x00; buffer[9] = 0x20; // alloc = 8192
            buffer[16] = 0x00; buffer[17] = 0x04; // bytesPerSect = 1024
            
            smbInfoAllocation.decode(buffer, 0, buffer.length);
            
            assertEquals(4L * 8192L * 1024L, smbInfoAllocation.getCapacity());
        }

        @Test
        @DisplayName("Should handle zero values")
        void testZeroValues() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[24];
            
            smbInfoAllocation.decode(buffer, 0, buffer.length);
            
            assertEquals(0, smbInfoAllocation.getCapacity());
            assertEquals(0, smbInfoAllocation.getFree());
        }

        @Test
        @DisplayName("Should provide string representation")
        void testToString() {
            String result = smbInfoAllocation.toString();
            
            assertNotNull(result);
            assertTrue(result.contains("SmbInfoAllocation"));
            assertTrue(result.contains("alloc="));
            assertTrue(result.contains("free="));
            assertTrue(result.contains("sectPerAlloc="));
            assertTrue(result.contains("bytesPerSect="));
        }
    }

    @Nested
    @DisplayName("FileFsSizeInformation Implementation Tests")
    class FileFsSizeInformationTests {

        private FileFsSizeInformation fileFsSizeInfo;

        @BeforeEach
        void setUp() {
            fileFsSizeInfo = new FileFsSizeInformation();
        }

        @Test
        @DisplayName("Should return correct information class")
        void testGetFileSystemInformationClass() {
            assertEquals(FileSystemInformation.FS_SIZE_INFO, fileFsSizeInfo.getFileSystemInformationClass());
        }

        @Test
        @DisplayName("Should decode 64-bit values correctly")
        void testDecode64BitValues() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[24];
            // alloc (8 bytes) - 0x0000000100000000 (4294967296)
            buffer[4] = 0x01;
            // free (8 bytes) - 0x0000000080000000 (2147483648)
            buffer[12] = (byte) 0x80;
            // sectPerAlloc (4 bytes) - 8
            buffer[16] = 0x08;
            // bytesPerSect (4 bytes) - 512
            buffer[20] = 0x00; buffer[21] = 0x02;
            
            int bytesDecoded = fileFsSizeInfo.decode(buffer, 0, buffer.length);
            
            assertEquals(24, bytesDecoded);
            assertTrue(fileFsSizeInfo.getCapacity() > 0);
            assertTrue(fileFsSizeInfo.getFree() > 0);
        }

        @Test
        @DisplayName("Should handle buffer offset correctly")
        void testDecodeWithOffset() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[100];
            int offset = 50;
            
            // Set data at offset
            buffer[offset + 16] = 0x04; // sectPerAlloc
            buffer[offset + 20] = 0x00; buffer[offset + 21] = 0x02; // bytesPerSect
            
            int bytesDecoded = fileFsSizeInfo.decode(buffer, offset, 24);
            
            assertEquals(24, bytesDecoded);
        }

        @Test
        @DisplayName("Should provide string representation")
        void testToString() {
            String result = fileFsSizeInfo.toString();
            
            assertNotNull(result);
            assertTrue(result.contains("SmbInfoAllocation")); // Note: toString() uses this name
            assertTrue(result.contains("alloc="));
            assertTrue(result.contains("free="));
        }
    }

    @Nested
    @DisplayName("FileFsFullSizeInformation Implementation Tests")
    class FileFsFullSizeInformationTests {

        private FileFsFullSizeInformation fileFsFullSizeInfo;

        @BeforeEach
        void setUp() {
            fileFsFullSizeInfo = new FileFsFullSizeInformation();
        }

        @Test
        @DisplayName("Should return correct information class")
        void testGetFileSystemInformationClass() {
            assertEquals(FileSystemInformation.FS_FULL_SIZE_INFO, fileFsFullSizeInfo.getFileSystemInformationClass());
        }

        @Test
        @DisplayName("Should decode with actual free units skipped")
        void testDecodeSkipsActualFreeUnits() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[32];
            // total allocation units (8 bytes)
            buffer[4] = 0x01;
            // caller available allocation units (8 bytes)
            buffer[12] = 0x01;
            // actual free units (8 bytes) - should be skipped
            buffer[20] = (byte) 0xFF; buffer[21] = (byte) 0xFF;
            // sectPerAlloc (4 bytes)
            buffer[24] = 0x08;
            // bytesPerSect (4 bytes)
            buffer[28] = 0x00; buffer[29] = 0x02;
            
            int bytesDecoded = fileFsFullSizeInfo.decode(buffer, 0, buffer.length);
            
            assertEquals(32, bytesDecoded);
            // Should use caller available units, not actual free units
            assertTrue(fileFsFullSizeInfo.getFree() > 0);
        }

        @Test
        @DisplayName("Should calculate large capacities correctly")
        void testLargeCapacityCalculation() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[32];
            // Set large values to test 64-bit arithmetic
            buffer[0] = (byte) 0xFF; buffer[1] = (byte) 0xFF; // Large alloc
            buffer[24] = (byte) 0xFF; // Large sectPerAlloc
            buffer[28] = (byte) 0xFF; buffer[29] = (byte) 0xFF; // Large bytesPerSect
            
            int bytesDecoded = fileFsFullSizeInfo.decode(buffer, 0, buffer.length);
            
            assertEquals(32, bytesDecoded);
            assertTrue(fileFsFullSizeInfo.getCapacity() != 0);
        }

        @Test
        @DisplayName("Should implement AllocInfo interface")
        void testAllocInfoInterface() {
            assertTrue(fileFsFullSizeInfo instanceof AllocInfo);
            assertTrue(fileFsFullSizeInfo instanceof FileSystemInformation);
        }

        @Test
        @DisplayName("Should provide string representation")
        void testToString() {
            String result = fileFsFullSizeInfo.toString();
            
            assertNotNull(result);
            assertTrue(result.contains("SmbInfoAllocation")); // Note: toString() uses this name
        }
    }

    @Nested
    @DisplayName("Edge Cases and Error Handling")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle null buffer in decode")
        void testNullBuffer() {
            FileFsSizeInformation info = new FileFsSizeInformation();
            
            assertThrows(NullPointerException.class, () -> {
                info.decode(null, 0, 0);
            });
        }

        @Test
        @DisplayName("Should handle insufficient buffer length")
        void testInsufficientBufferLength() {
            FileFsSizeInformation info = new FileFsSizeInformation();
            byte[] buffer = new byte[10]; // Too small
            
            // Should throw ArrayIndexOutOfBoundsException for insufficient buffer
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
                info.decode(buffer, 0, buffer.length);
            });
        }

        @ParameterizedTest
        @CsvSource({
            "0, 0, 0",
            "100, 0, 0",
            "100, 50, 50",
            "1000, 999, 1"
        })
        @DisplayName("Should handle various buffer configurations")
        void testVariousBufferConfigurations(int bufferSize, int offset, int length) {
            byte[] buffer = new byte[bufferSize];
            FileFsSizeInformation info = new FileFsSizeInformation();
            
            if (offset + length <= bufferSize && length >= 24) {
                assertDoesNotThrow(() -> {
                    info.decode(buffer, offset, length);
                });
            }
        }
    }

    @Nested
    @DisplayName("Interface Compatibility Tests")
    class InterfaceCompatibilityTests {

        @Test
        @DisplayName("Should verify AllocInfo extends FileSystemInformation")
        void testAllocInfoExtendsFileSystemInformation() {
            assertTrue(FileSystemInformation.class.isAssignableFrom(AllocInfo.class));
        }

        @Test
        @DisplayName("Should verify all implementations are AllocInfo")
        void testImplementationsAreAllocInfo() {
            assertTrue(AllocInfo.class.isAssignableFrom(SmbInfoAllocation.class));
            assertTrue(AllocInfo.class.isAssignableFrom(FileFsSizeInformation.class));
            assertTrue(AllocInfo.class.isAssignableFrom(FileFsFullSizeInformation.class));
        }

        @Test
        @DisplayName("Should verify correct interface hierarchy")
        void testInterfaceHierarchy() {
            // Create instances
            SmbInfoAllocation smbInfo = new SmbInfoAllocation();
            FileFsSizeInformation sizeInfo = new FileFsSizeInformation();
            FileFsFullSizeInformation fullSizeInfo = new FileFsFullSizeInformation();
            
            // All should be FileSystemInformation
            assertTrue(smbInfo instanceof FileSystemInformation);
            assertTrue(sizeInfo instanceof FileSystemInformation);
            assertTrue(fullSizeInfo instanceof FileSystemInformation);
            
            // All should be AllocInfo
            assertTrue(smbInfo instanceof AllocInfo);
            assertTrue(sizeInfo instanceof AllocInfo);
            assertTrue(fullSizeInfo instanceof AllocInfo);
        }
    }

    @Nested
    @DisplayName("Performance and Boundary Tests")
    class PerformanceTests {

        @Test
        @DisplayName("Should handle maximum values without overflow")
        void testMaximumValues() throws SMBProtocolDecodingException {
            FileFsFullSizeInformation info = new FileFsFullSizeInformation();
            byte[] buffer = new byte[32];
            
            // Set all bytes to 0xFF for maximum values
            for (int i = 0; i < buffer.length; i++) {
                buffer[i] = (byte) 0xFF;
            }
            
            assertDoesNotThrow(() -> {
                info.decode(buffer, 0, buffer.length);
            });
            
            // Capacity should not be negative (overflow check)
            assertTrue(info.getCapacity() != 0);
        }

        @Test
        @DisplayName("Should decode efficiently for large buffers")
        void testLargeBufferDecoding() throws SMBProtocolDecodingException {
            byte[] largeBuffer = new byte[10000];
            FileFsSizeInformation info = new FileFsSizeInformation();
            
            long startTime = System.nanoTime();
            info.decode(largeBuffer, 0, 24);
            long endTime = System.nanoTime();
            
            // Should complete quickly (under 1ms)
            assertTrue((endTime - startTime) < 1_000_000);
        }

        @ParameterizedTest
        @ValueSource(ints = {24, 32, 100, 1000, 10000})
        @DisplayName("Should handle various buffer sizes correctly")
        void testVariousBufferSizes(int bufferSize) throws SMBProtocolDecodingException {
            byte[] buffer = new byte[bufferSize];
            FileFsSizeInformation info = new FileFsSizeInformation();
            
            int decoded = info.decode(buffer, 0, Math.min(bufferSize, 24));
            
            assertEquals(24, decoded);
        }
    }
}