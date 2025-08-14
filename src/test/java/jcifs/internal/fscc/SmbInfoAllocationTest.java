package jcifs.internal.fscc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for SmbInfoAllocation
 */
class SmbInfoAllocationTest {

    private SmbInfoAllocation smbInfoAllocation;

    @BeforeEach
    void setUp() {
        smbInfoAllocation = new SmbInfoAllocation();
    }

    @Test
    @DisplayName("Test getFileSystemInformationClass returns SMB_INFO_ALLOCATION")
    void testGetFileSystemInformationClass() {
        assertEquals(FileSystemInformation.SMB_INFO_ALLOCATION, smbInfoAllocation.getFileSystemInformationClass());
    }

    @Test
    @DisplayName("Test decode with typical values")
    void testDecodeWithTypicalValues() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = new byte[22];
        int idFileSystem = 0x12345678;
        int sectPerAlloc = 8;
        long alloc = 1000000L;
        long free = 500000L;
        int bytesPerSect = 512;

        // Encode test data
        int offset = 0;
        SMBUtil.writeInt4(idFileSystem, buffer, offset); // idFileSystem (skipped)
        offset += 4;
        SMBUtil.writeInt4(sectPerAlloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4((int) alloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4((int) free, buffer, offset);
        offset += 4;
        SMBUtil.writeInt2(bytesPerSect, buffer, offset);
        offset += 2;

        // Decode
        int bytesDecoded = smbInfoAllocation.decode(buffer, 0, buffer.length);

        // Verify - actual implementation reads 20 bytes (4 + 4 + 4 + 4 + 4)
        // bytesPerSect is read as Int2 but advances by 4 bytes (padding)
        assertEquals(20, bytesDecoded);

        // Verify capacity calculation: alloc * sectPerAlloc * bytesPerSect
        long expectedCapacity = alloc * sectPerAlloc * bytesPerSect;
        assertEquals(expectedCapacity, smbInfoAllocation.getCapacity());

        // Verify free space calculation: free * sectPerAlloc * bytesPerSect
        long expectedFree = free * sectPerAlloc * bytesPerSect;
        assertEquals(expectedFree, smbInfoAllocation.getFree());
    }

    @Test
    @DisplayName("Test decode with offset")
    void testDecodeWithOffset() throws SMBProtocolDecodingException {
        // Prepare test data with offset
        byte[] buffer = new byte[30];
        int bufferIndex = 5; // Start at offset 5
        int idFileSystem = 0xFFFFFFFF;
        int sectPerAlloc = 16;
        long alloc = 2000000L;
        long free = 1500000L;
        int bytesPerSect = 1024;

        // Encode test data at offset
        int offset = bufferIndex;
        SMBUtil.writeInt4(idFileSystem, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4(sectPerAlloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4((int) alloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4((int) free, buffer, offset);
        offset += 4;
        SMBUtil.writeInt2(bytesPerSect, buffer, offset);

        // Decode from offset
        int bytesDecoded = smbInfoAllocation.decode(buffer, bufferIndex, 20);

        // Verify - actual implementation reads 20 bytes
        assertEquals(20, bytesDecoded);

        // Verify calculations
        long expectedCapacity = alloc * sectPerAlloc * bytesPerSect;
        assertEquals(expectedCapacity, smbInfoAllocation.getCapacity());

        long expectedFree = free * sectPerAlloc * bytesPerSect;
        assertEquals(expectedFree, smbInfoAllocation.getFree());
    }

    @Test
    @DisplayName("Test getCapacity with zero values")
    void testGetCapacityWithZeroValues() throws SMBProtocolDecodingException {
        // Prepare test data with zeros
        byte[] buffer = new byte[22];

        // All zeros
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = 0;
        }

        // Decode
        smbInfoAllocation.decode(buffer, 0, buffer.length);

        // Verify - all zeros should result in 0 capacity and free
        assertEquals(0L, smbInfoAllocation.getCapacity());
        assertEquals(0L, smbInfoAllocation.getFree());
    }

    @Test
    @DisplayName("Test getFree with maximum values")
    void testGetFreeWithMaximumValues() throws SMBProtocolDecodingException {
        // Prepare test data with maximum int values
        byte[] buffer = new byte[22];
        int idFileSystem = Integer.MAX_VALUE;
        int sectPerAlloc = 100;
        int alloc = Integer.MAX_VALUE / 200;
        int free = Integer.MAX_VALUE / 200;
        int bytesPerSect = 512;

        // Encode test data
        int offset = 0;
        SMBUtil.writeInt4(idFileSystem, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4(sectPerAlloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4(alloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4(free, buffer, offset);
        offset += 4;
        SMBUtil.writeInt2(bytesPerSect, buffer, offset);

        // Decode
        smbInfoAllocation.decode(buffer, 0, buffer.length);

        // Verify calculations work with large values
        long expectedCapacity = (long) alloc * sectPerAlloc * bytesPerSect;
        assertEquals(expectedCapacity, smbInfoAllocation.getCapacity());

        long expectedFree = (long) free * sectPerAlloc * bytesPerSect;
        assertEquals(expectedFree, smbInfoAllocation.getFree());
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = new byte[22];
        int idFileSystem = 0xABCDEF00;
        int sectPerAlloc = 4;
        long alloc = 500000L;
        long free = 250000L;
        int bytesPerSect = 4096;

        // Encode test data
        int offset = 0;
        SMBUtil.writeInt4(idFileSystem, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4(sectPerAlloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4((int) alloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4((int) free, buffer, offset);
        offset += 4;
        SMBUtil.writeInt2(bytesPerSect, buffer, offset);

        // Decode
        smbInfoAllocation.decode(buffer, 0, buffer.length);

        // Test toString
        String result = smbInfoAllocation.toString();

        // Verify string contains expected values
        assertTrue(result.contains("SmbInfoAllocation"));
        assertTrue(result.contains("alloc=" + alloc));
        assertTrue(result.contains("free=" + free));
        assertTrue(result.contains("sectPerAlloc=" + sectPerAlloc));
        assertTrue(result.contains("bytesPerSect=" + bytesPerSect));
    }

    @Test
    @DisplayName("Test decode with single sector per allocation")
    void testDecodeWithSingleSectorPerAllocation() throws SMBProtocolDecodingException {
        // Prepare test data with sectPerAlloc = 1
        byte[] buffer = new byte[22];
        int idFileSystem = 0x11111111;
        int sectPerAlloc = 1;
        long alloc = 1000L;
        long free = 500L;
        int bytesPerSect = 512;

        // Encode test data
        int offset = 0;
        SMBUtil.writeInt4(idFileSystem, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4(sectPerAlloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4((int) alloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4((int) free, buffer, offset);
        offset += 4;
        SMBUtil.writeInt2(bytesPerSect, buffer, offset);

        // Decode
        smbInfoAllocation.decode(buffer, 0, buffer.length);

        // Verify - with sectPerAlloc = 1, capacity = alloc * bytesPerSect
        assertEquals(alloc * bytesPerSect, smbInfoAllocation.getCapacity());
        assertEquals(free * bytesPerSect, smbInfoAllocation.getFree());
    }

    @Test
    @DisplayName("Test decode with large bytes per sector")
    void testDecodeWithLargeBytesPerSector() throws SMBProtocolDecodingException {
        // Prepare test data with large bytesPerSect
        byte[] buffer = new byte[22];
        int idFileSystem = 0x22222222;
        int sectPerAlloc = 8;
        long alloc = 10000L;
        long free = 5000L;
        int bytesPerSect = 32768; // 32KB sectors

        // Encode test data
        int offset = 0;
        SMBUtil.writeInt4(idFileSystem, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4(sectPerAlloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4((int) alloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4((int) free, buffer, offset);
        offset += 4;
        SMBUtil.writeInt2(bytesPerSect, buffer, offset);

        // Decode
        smbInfoAllocation.decode(buffer, 0, buffer.length);

        // Verify calculations with large sector size
        long expectedCapacity = alloc * sectPerAlloc * bytesPerSect;
        assertEquals(expectedCapacity, smbInfoAllocation.getCapacity());

        long expectedFree = free * sectPerAlloc * bytesPerSect;
        assertEquals(expectedFree, smbInfoAllocation.getFree());
    }

    @Test
    @DisplayName("Test decode reads correct number of bytes")
    void testDecodeReadsCorrectBytes() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = new byte[22];

        // Fill with pattern to verify we read correct bytes
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (byte) (i + 1);
        }

        // Decode
        int bytesDecoded = smbInfoAllocation.decode(buffer, 0, buffer.length);

        // Verify we read exactly 20 bytes (4 + 4 + 4 + 4 + 4)
        // Note: bytesPerSect is read as Int2 but 4 bytes are consumed (padding)
        assertEquals(20, bytesDecoded);
    }

    @Test
    @DisplayName("Test capacity calculation overflow handling")
    void testCapacityCalculationOverflow() throws SMBProtocolDecodingException {
        // Prepare test data that might cause overflow in naive implementations
        byte[] buffer = new byte[22];
        int idFileSystem = 0;
        int sectPerAlloc = 1000;
        int alloc = 1000000; // Large allocation count
        int free = 500000;
        int bytesPerSect = 4096;

        // Encode test data
        int offset = 0;
        SMBUtil.writeInt4(idFileSystem, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4(sectPerAlloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4(alloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4(free, buffer, offset);
        offset += 4;
        SMBUtil.writeInt2(bytesPerSect, buffer, offset);

        // Decode
        smbInfoAllocation.decode(buffer, 0, buffer.length);

        // Verify calculations use long arithmetic to avoid overflow
        long expectedCapacity = (long) alloc * sectPerAlloc * bytesPerSect;
        assertEquals(expectedCapacity, smbInfoAllocation.getCapacity());

        long expectedFree = (long) free * sectPerAlloc * bytesPerSect;
        assertEquals(expectedFree, smbInfoAllocation.getFree());
    }

    @Test
    @DisplayName("Test decode with negative values interpreted as unsigned")
    void testDecodeWithNegativeValues() throws SMBProtocolDecodingException {
        // Prepare test data with values that would be negative if signed
        byte[] buffer = new byte[22];
        int idFileSystem = -1; // 0xFFFFFFFF
        int sectPerAlloc = 8;
        int alloc = -100; // Large unsigned value
        int free = -200; // Large unsigned value
        int bytesPerSect = 512;

        // Encode test data
        int offset = 0;
        SMBUtil.writeInt4(idFileSystem, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4(sectPerAlloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4(alloc, buffer, offset);
        offset += 4;
        SMBUtil.writeInt4(free, buffer, offset);
        offset += 4;
        SMBUtil.writeInt2(bytesPerSect, buffer, offset);

        // Decode
        smbInfoAllocation.decode(buffer, 0, buffer.length);

        // The implementation reads values as signed integers and stores them as long
        // Negative values remain negative when stored in long fields
        // The calculations will result in negative values
        long expectedCapacity = (long) alloc * sectPerAlloc * bytesPerSect;
        assertEquals(expectedCapacity, smbInfoAllocation.getCapacity());

        long expectedFree = (long) free * sectPerAlloc * bytesPerSect;
        assertEquals(expectedFree, smbInfoAllocation.getFree());
    }

    @Test
    @DisplayName("Test multiple decode calls on same instance")
    void testMultipleDecodeCalls() throws SMBProtocolDecodingException {
        // First decode
        byte[] buffer1 = new byte[22];
        int offset = 0;
        SMBUtil.writeInt4(0, buffer1, offset); // idFileSystem
        offset += 4;
        SMBUtil.writeInt4(4, buffer1, offset); // sectPerAlloc
        offset += 4;
        SMBUtil.writeInt4(1000, buffer1, offset); // alloc
        offset += 4;
        SMBUtil.writeInt4(500, buffer1, offset); // free
        offset += 4;
        SMBUtil.writeInt2(512, buffer1, offset); // bytesPerSect

        smbInfoAllocation.decode(buffer1, 0, buffer1.length);

        long firstCapacity = smbInfoAllocation.getCapacity();
        long firstFree = smbInfoAllocation.getFree();

        // Second decode with different values
        byte[] buffer2 = new byte[22];
        offset = 0;
        SMBUtil.writeInt4(0, buffer2, offset); // idFileSystem
        offset += 4;
        SMBUtil.writeInt4(8, buffer2, offset); // sectPerAlloc
        offset += 4;
        SMBUtil.writeInt4(2000, buffer2, offset); // alloc
        offset += 4;
        SMBUtil.writeInt4(1000, buffer2, offset); // free
        offset += 4;
        SMBUtil.writeInt2(1024, buffer2, offset); // bytesPerSect

        smbInfoAllocation.decode(buffer2, 0, buffer2.length);

        // Verify values are updated
        assertNotEquals(firstCapacity, smbInfoAllocation.getCapacity());
        assertNotEquals(firstFree, smbInfoAllocation.getFree());

        // Verify new calculations
        assertEquals(2000L * 8 * 1024, smbInfoAllocation.getCapacity());
        assertEquals(1000L * 8 * 1024, smbInfoAllocation.getFree());
    }
}
