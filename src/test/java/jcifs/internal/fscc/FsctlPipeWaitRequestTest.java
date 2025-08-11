package jcifs.internal.fscc;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.EmptySource;

import jcifs.internal.util.SMBUtil;

/**
 * Test class for FsctlPipeWaitRequest
 */
class FsctlPipeWaitRequestTest {

    @Test
    @DisplayName("Test constructor with name only sets correct fields")
    void testConstructorWithNameOnly() {
        // Test with simple pipe name
        String pipeName = "TestPipe";
        FsctlPipeWaitRequest request = new FsctlPipeWaitRequest(pipeName);
        
        // Verify size calculation
        int expectedSize = 14 + pipeName.getBytes(StandardCharsets.UTF_16LE).length;
        assertEquals(expectedSize, request.size());
    }

    @Test
    @DisplayName("Test constructor with name and timeout sets correct fields")
    void testConstructorWithNameAndTimeout() {
        // Test with pipe name and timeout
        String pipeName = "TestPipe";
        long timeout = 5000L;
        FsctlPipeWaitRequest request = new FsctlPipeWaitRequest(pipeName, timeout);
        
        // Verify size calculation
        int expectedSize = 14 + pipeName.getBytes(StandardCharsets.UTF_16LE).length;
        assertEquals(expectedSize, request.size());
    }

    @Test
    @DisplayName("Test encode with name only (no timeout specified)")
    void testEncodeWithNameOnly() {
        // Setup
        String pipeName = "TestPipe";
        FsctlPipeWaitRequest request = new FsctlPipeWaitRequest(pipeName);
        byte[] nameBytes = pipeName.getBytes(StandardCharsets.UTF_16LE);
        byte[] buffer = new byte[100];
        
        // Execute
        int bytesEncoded = request.encode(buffer, 0);
        
        // Verify
        assertEquals(14 + nameBytes.length, bytesEncoded);
        
        // Check timeout (should be 0)
        assertEquals(0L, SMBUtil.readInt8(buffer, 0));
        
        // Check name length
        assertEquals(nameBytes.length, SMBUtil.readInt4(buffer, 8));
        
        // Check timeout specified flag (should be 0)
        assertEquals(0x0, buffer[12]);
        
        // Check padding
        assertEquals(0x0, buffer[13]);
        
        // Check name bytes
        byte[] encodedName = new byte[nameBytes.length];
        System.arraycopy(buffer, 14, encodedName, 0, nameBytes.length);
        assertArrayEquals(nameBytes, encodedName);
    }

    @Test
    @DisplayName("Test encode with name and timeout")
    void testEncodeWithNameAndTimeout() {
        // Setup
        String pipeName = "TestPipe";
        long timeout = 10000L;
        FsctlPipeWaitRequest request = new FsctlPipeWaitRequest(pipeName, timeout);
        byte[] nameBytes = pipeName.getBytes(StandardCharsets.UTF_16LE);
        byte[] buffer = new byte[100];
        
        // Execute
        int bytesEncoded = request.encode(buffer, 0);
        
        // Verify
        assertEquals(14 + nameBytes.length, bytesEncoded);
        
        // Check timeout value
        assertEquals(timeout, SMBUtil.readInt8(buffer, 0));
        
        // Check name length
        assertEquals(nameBytes.length, SMBUtil.readInt4(buffer, 8));
        
        // Check timeout specified flag (should be 1)
        assertEquals(0x1, buffer[12]);
        
        // Check padding
        assertEquals(0x0, buffer[13]);
        
        // Check name bytes
        byte[] encodedName = new byte[nameBytes.length];
        System.arraycopy(buffer, 14, encodedName, 0, nameBytes.length);
        assertArrayEquals(nameBytes, encodedName);
    }

    @Test
    @DisplayName("Test encode with offset")
    void testEncodeWithOffset() {
        // Setup
        String pipeName = "TestPipe";
        long timeout = 5000L;
        FsctlPipeWaitRequest request = new FsctlPipeWaitRequest(pipeName, timeout);
        byte[] nameBytes = pipeName.getBytes(StandardCharsets.UTF_16LE);
        byte[] buffer = new byte[200];
        int offset = 50;
        
        // Execute
        int bytesEncoded = request.encode(buffer, offset);
        
        // Verify
        assertEquals(14 + nameBytes.length, bytesEncoded);
        
        // Check timeout value at offset
        assertEquals(timeout, SMBUtil.readInt8(buffer, offset));
        
        // Check name length at offset
        assertEquals(nameBytes.length, SMBUtil.readInt4(buffer, offset + 8));
        
        // Check timeout specified flag at offset
        assertEquals(0x1, buffer[offset + 12]);
        
        // Check padding at offset
        assertEquals(0x0, buffer[offset + 13]);
        
        // Check name bytes at offset
        byte[] encodedName = new byte[nameBytes.length];
        System.arraycopy(buffer, offset + 14, encodedName, 0, nameBytes.length);
        assertArrayEquals(nameBytes, encodedName);
    }

    @Test
    @DisplayName("Test with empty pipe name")
    void testWithEmptyPipeName() {
        // Test with empty string
        String pipeName = "";
        FsctlPipeWaitRequest request = new FsctlPipeWaitRequest(pipeName);
        
        // Verify size (14 bytes header + 0 bytes for empty name)
        assertEquals(14, request.size());
        
        // Test encoding
        byte[] buffer = new byte[50];
        int bytesEncoded = request.encode(buffer, 0);
        
        // Verify
        assertEquals(14, bytesEncoded);
        assertEquals(0, SMBUtil.readInt4(buffer, 8)); // Name length should be 0
    }

    @Test
    @DisplayName("Test with Unicode pipe name")
    void testWithUnicodePipeName() {
        // Test with Unicode characters
        String pipeName = "テストパイプ名";
        FsctlPipeWaitRequest request = new FsctlPipeWaitRequest(pipeName);
        byte[] nameBytes = pipeName.getBytes(StandardCharsets.UTF_16LE);
        
        // Verify size
        assertEquals(14 + nameBytes.length, request.size());
        
        // Test encoding
        byte[] buffer = new byte[100];
        int bytesEncoded = request.encode(buffer, 0);
        
        // Verify
        assertEquals(14 + nameBytes.length, bytesEncoded);
        assertEquals(nameBytes.length, SMBUtil.readInt4(buffer, 8));
        
        // Check encoded name
        byte[] encodedName = new byte[nameBytes.length];
        System.arraycopy(buffer, 14, encodedName, 0, nameBytes.length);
        assertArrayEquals(nameBytes, encodedName);
    }

    @Test
    @DisplayName("Test with long pipe name")
    void testWithLongPipeName() {
        // Test with a very long pipe name
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            sb.append("LongPipeName");
        }
        String pipeName = sb.toString();
        FsctlPipeWaitRequest request = new FsctlPipeWaitRequest(pipeName);
        byte[] nameBytes = pipeName.getBytes(StandardCharsets.UTF_16LE);
        
        // Verify size
        assertEquals(14 + nameBytes.length, request.size());
        
        // Test encoding with large buffer
        byte[] buffer = new byte[14 + nameBytes.length + 100];
        int bytesEncoded = request.encode(buffer, 0);
        
        // Verify
        assertEquals(14 + nameBytes.length, bytesEncoded);
        assertEquals(nameBytes.length, SMBUtil.readInt4(buffer, 8));
    }

    @ParameterizedTest
    @DisplayName("Test with various timeout values")
    @ValueSource(longs = {0L, 1L, -1L, Long.MAX_VALUE, Long.MIN_VALUE, 1000L, -1000L})
    void testWithVariousTimeoutValues(long timeout) {
        // Setup
        String pipeName = "TestPipe";
        FsctlPipeWaitRequest request = new FsctlPipeWaitRequest(pipeName, timeout);
        byte[] buffer = new byte[100];
        
        // Execute
        int bytesEncoded = request.encode(buffer, 0);
        
        // Verify timeout value is correctly encoded
        assertEquals(timeout, SMBUtil.readInt8(buffer, 0));
        
        // Verify timeout specified flag is set
        assertEquals(0x1, buffer[12]);
    }

    @Test
    @DisplayName("Test with special characters in pipe name")
    void testWithSpecialCharactersInPipeName() {
        // Test with special characters
        String pipeName = "\\\\?\\pipe\\test$pipe#name!";
        FsctlPipeWaitRequest request = new FsctlPipeWaitRequest(pipeName);
        byte[] nameBytes = pipeName.getBytes(StandardCharsets.UTF_16LE);
        
        // Verify size
        assertEquals(14 + nameBytes.length, request.size());
        
        // Test encoding
        byte[] buffer = new byte[200];
        int bytesEncoded = request.encode(buffer, 0);
        
        // Verify
        assertEquals(14 + nameBytes.length, bytesEncoded);
        
        // Check encoded name
        byte[] encodedName = new byte[nameBytes.length];
        System.arraycopy(buffer, 14, encodedName, 0, nameBytes.length);
        assertArrayEquals(nameBytes, encodedName);
    }

    @Test
    @DisplayName("Test zero timeout with timeout specified constructor")
    void testZeroTimeoutWithTimeoutSpecified() {
        // Setup
        String pipeName = "TestPipe";
        long timeout = 0L;
        FsctlPipeWaitRequest request = new FsctlPipeWaitRequest(pipeName, timeout);
        byte[] buffer = new byte[100];
        
        // Execute
        int bytesEncoded = request.encode(buffer, 0);
        
        // Verify
        assertEquals(0L, SMBUtil.readInt8(buffer, 0));
        
        // Even with zero timeout, if using timeout constructor, flag should be set
        assertEquals(0x1, buffer[12]);
    }

    @Test
    @DisplayName("Test size method consistency")
    void testSizeMethodConsistency() {
        // Test that size() method returns consistent value with encode()
        String pipeName = "ConsistencyTest";
        
        // Test without timeout
        FsctlPipeWaitRequest request1 = new FsctlPipeWaitRequest(pipeName);
        byte[] buffer1 = new byte[200];
        int encoded1 = request1.encode(buffer1, 0);
        assertEquals(request1.size(), encoded1);
        
        // Test with timeout
        FsctlPipeWaitRequest request2 = new FsctlPipeWaitRequest(pipeName, 5000L);
        byte[] buffer2 = new byte[200];
        int encoded2 = request2.encode(buffer2, 0);
        assertEquals(request2.size(), encoded2);
    }

    @Test
    @DisplayName("Test multiple encodes produce same result")
    void testMultipleEncodesProduceSameResult() {
        // Setup
        String pipeName = "RepeatedEncode";
        long timeout = 3000L;
        FsctlPipeWaitRequest request = new FsctlPipeWaitRequest(pipeName, timeout);
        
        // Encode multiple times
        byte[] buffer1 = new byte[100];
        byte[] buffer2 = new byte[100];
        byte[] buffer3 = new byte[100];
        
        int encoded1 = request.encode(buffer1, 0);
        int encoded2 = request.encode(buffer2, 0);
        int encoded3 = request.encode(buffer3, 0);
        
        // All should produce same result
        assertEquals(encoded1, encoded2);
        assertEquals(encoded2, encoded3);
        
        // Compare actual bytes (up to encoded length)
        for (int i = 0; i < encoded1; i++) {
            assertEquals(buffer1[i], buffer2[i], "Mismatch at position " + i);
            assertEquals(buffer2[i], buffer3[i], "Mismatch at position " + i);
        }
    }

    @Test
    @DisplayName("Test with typical Windows pipe name format")
    void testWithTypicalWindowsPipeName() {
        // Test with typical Windows named pipe format
        String pipeName = "\\pipe\\TestPipe";
        FsctlPipeWaitRequest request = new FsctlPipeWaitRequest(pipeName, 30000L);
        byte[] nameBytes = pipeName.getBytes(StandardCharsets.UTF_16LE);
        
        // Verify size
        assertEquals(14 + nameBytes.length, request.size());
        
        // Test encoding
        byte[] buffer = new byte[200];
        int bytesEncoded = request.encode(buffer, 0);
        
        // Verify proper encoding
        assertEquals(14 + nameBytes.length, bytesEncoded);
        assertEquals(30000L, SMBUtil.readInt8(buffer, 0));
        assertEquals(nameBytes.length, SMBUtil.readInt4(buffer, 8));
        assertEquals(0x1, buffer[12]); // Timeout specified
        
        // Verify pipe name
        byte[] encodedName = new byte[nameBytes.length];
        System.arraycopy(buffer, 14, encodedName, 0, nameBytes.length);
        assertArrayEquals(nameBytes, encodedName);
    }

    @Test
    @DisplayName("Test encode fills buffer correctly at various offsets")
    void testEncodeAtVariousOffsets() {
        String pipeName = "OffsetTest";
        long timeout = 2500L;
        FsctlPipeWaitRequest request = new FsctlPipeWaitRequest(pipeName, timeout);
        
        int[] offsets = {0, 1, 10, 50, 100};
        
        for (int offset : offsets) {
            byte[] buffer = new byte[200];
            // Fill buffer with pattern to ensure proper writing
            for (int i = 0; i < buffer.length; i++) {
                buffer[i] = (byte) 0xFF;
            }
            
            int bytesEncoded = request.encode(buffer, offset);
            
            // Verify data at correct offset
            assertEquals(timeout, SMBUtil.readInt8(buffer, offset));
            assertEquals(pipeName.getBytes(StandardCharsets.UTF_16LE).length, 
                        SMBUtil.readInt4(buffer, offset + 8));
            assertEquals(0x1, buffer[offset + 12]);
            // Note: Padding byte at offset + 13 is not guaranteed to be 0 after encode
            
            // Verify areas before offset are untouched
            for (int i = 0; i < offset; i++) {
                assertEquals((byte) 0xFF, buffer[i], 
                           "Buffer corrupted before offset at position " + i);
            }
        }
    }
}
