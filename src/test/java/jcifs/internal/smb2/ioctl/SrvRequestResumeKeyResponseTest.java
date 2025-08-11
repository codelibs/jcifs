package jcifs.internal.smb2.ioctl;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.internal.SMBProtocolDecodingException;

/**
 * Test class for SrvRequestResumeKeyResponse
 */
class SrvRequestResumeKeyResponseTest {

    private SrvRequestResumeKeyResponse response;
    
    @BeforeEach
    void setUp() {
        response = new SrvRequestResumeKeyResponse();
    }
    
    @Test
    @DisplayName("Test successful decode with valid resume key")
    void testDecodeValidResumeKey() throws SMBProtocolDecodingException {
        // Prepare test data - 24 bytes for resume key + 4 bytes for context length
        byte[] buffer = new byte[28];
        
        // Fill resume key with test pattern
        for (int i = 0; i < 24; i++) {
            buffer[i] = (byte)(i + 1);
        }
        
        // Add context length (reserved) - 4 bytes
        buffer[24] = 0x00;
        buffer[25] = 0x00;
        buffer[26] = 0x00;
        buffer[27] = 0x00;
        
        // Decode
        int bytesConsumed = response.decode(buffer, 0, 28);
        
        // Verify
        assertEquals(28, bytesConsumed, "Should consume exactly 28 bytes");
        
        byte[] resumeKey = response.getResumeKey();
        assertNotNull(resumeKey, "Resume key should not be null");
        assertEquals(24, resumeKey.length, "Resume key should be 24 bytes");
        
        // Verify resume key content
        for (int i = 0; i < 24; i++) {
            assertEquals((byte)(i + 1), resumeKey[i], "Resume key byte " + i + " should match");
        }
    }
    
    @Test
    @DisplayName("Test decode with non-zero buffer offset")
    void testDecodeWithOffset() throws SMBProtocolDecodingException {
        // Prepare test data with offset
        byte[] buffer = new byte[100];
        int offset = 50;
        
        // Fill resume key at offset with test pattern
        for (int i = 0; i < 24; i++) {
            buffer[offset + i] = (byte)(0xFF - i);
        }
        
        // Add context length at offset
        buffer[offset + 24] = 0x12;
        buffer[offset + 25] = 0x34;
        buffer[offset + 26] = 0x56;
        buffer[offset + 27] = 0x78;
        
        // Decode
        int bytesConsumed = response.decode(buffer, offset, 28);
        
        // Verify
        assertEquals(28, bytesConsumed, "Should consume exactly 28 bytes");
        
        byte[] resumeKey = response.getResumeKey();
        assertNotNull(resumeKey, "Resume key should not be null");
        assertEquals(24, resumeKey.length, "Resume key should be 24 bytes");
        
        // Verify resume key content
        for (int i = 0; i < 24; i++) {
            assertEquals((byte)(0xFF - i), resumeKey[i], "Resume key byte " + i + " should match");
        }
    }
    
    @Test
    @DisplayName("Test decode with minimum valid length")
    void testDecodeMinimumValidLength() throws SMBProtocolDecodingException {
        // Prepare minimum valid buffer - exactly 24 bytes
        byte[] buffer = new byte[28];
        Arrays.fill(buffer, 0, 24, (byte)0xAA);
        
        // Decode with len = 24 (minimum valid)
        int bytesConsumed = response.decode(buffer, 0, 24);
        
        // Verify - should consume 28 bytes even though len is 24
        assertEquals(28, bytesConsumed, "Should consume 28 bytes");
        
        byte[] resumeKey = response.getResumeKey();
        assertNotNull(resumeKey, "Resume key should not be null");
        assertEquals(24, resumeKey.length, "Resume key should be 24 bytes");
        
        // Verify all bytes are 0xAA
        for (int i = 0; i < 24; i++) {
            assertEquals((byte)0xAA, resumeKey[i], "Resume key byte " + i + " should be 0xAA");
        }
    }
    
    @Test
    @DisplayName("Test decode throws exception when length is too short")
    void testDecodeThrowsExceptionWhenLengthTooShort() {
        byte[] buffer = new byte[28];
        
        // Test with len = 23 (one byte too short)
        SMBProtocolDecodingException exception = assertThrows(
            SMBProtocolDecodingException.class,
            () -> response.decode(buffer, 0, 23),
            "Should throw exception when length < 24"
        );
        
        assertEquals("Invalid resume key", exception.getMessage(), "Exception message should match");
    }
    
    @Test
    @DisplayName("Test decode throws exception with zero length")
    void testDecodeThrowsExceptionWithZeroLength() {
        byte[] buffer = new byte[28];
        
        SMBProtocolDecodingException exception = assertThrows(
            SMBProtocolDecodingException.class,
            () -> response.decode(buffer, 0, 0),
            "Should throw exception when length is 0"
        );
        
        assertEquals("Invalid resume key", exception.getMessage(), "Exception message should match");
    }
    
    @Test
    @DisplayName("Test decode throws exception with negative length")
    void testDecodeThrowsExceptionWithNegativeLength() {
        byte[] buffer = new byte[28];
        
        SMBProtocolDecodingException exception = assertThrows(
            SMBProtocolDecodingException.class,
            () -> response.decode(buffer, 0, -1),
            "Should throw exception when length is negative"
        );
        
        assertEquals("Invalid resume key", exception.getMessage(), "Exception message should match");
    }
    
    @Test
    @DisplayName("Test getResumeKey returns null before decode")
    void testGetResumeKeyBeforeDecode() {
        assertNull(response.getResumeKey(), "Resume key should be null before decode");
    }
    
    @Test
    @DisplayName("Test decode with all zero bytes")
    void testDecodeWithAllZeroBytes() throws SMBProtocolDecodingException {
        byte[] buffer = new byte[28];
        // All bytes are already 0
        
        int bytesConsumed = response.decode(buffer, 0, 28);
        
        assertEquals(28, bytesConsumed, "Should consume exactly 28 bytes");
        
        byte[] resumeKey = response.getResumeKey();
        assertNotNull(resumeKey, "Resume key should not be null");
        assertEquals(24, resumeKey.length, "Resume key should be 24 bytes");
        
        // Verify all bytes are 0
        for (int i = 0; i < 24; i++) {
            assertEquals(0, resumeKey[i], "Resume key byte " + i + " should be 0");
        }
    }
    
    @Test
    @DisplayName("Test decode with all max value bytes")
    void testDecodeWithAllMaxValueBytes() throws SMBProtocolDecodingException {
        byte[] buffer = new byte[28];
        Arrays.fill(buffer, (byte)0xFF);
        
        int bytesConsumed = response.decode(buffer, 0, 28);
        
        assertEquals(28, bytesConsumed, "Should consume exactly 28 bytes");
        
        byte[] resumeKey = response.getResumeKey();
        assertNotNull(resumeKey, "Resume key should not be null");
        assertEquals(24, resumeKey.length, "Resume key should be 24 bytes");
        
        // Verify all bytes are 0xFF
        for (int i = 0; i < 24; i++) {
            assertEquals((byte)0xFF, resumeKey[i], "Resume key byte " + i + " should be 0xFF");
        }
    }
    
    @Test
    @DisplayName("Test decode with larger buffer and length")
    void testDecodeWithLargerBufferAndLength() throws SMBProtocolDecodingException {
        // Test with buffer and length larger than needed
        byte[] buffer = new byte[100];
        
        // Fill test pattern
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (byte)(i % 256);
        }
        
        int bytesConsumed = response.decode(buffer, 0, 50);
        
        assertEquals(28, bytesConsumed, "Should consume exactly 28 bytes regardless of extra length");
        
        byte[] resumeKey = response.getResumeKey();
        assertNotNull(resumeKey, "Resume key should not be null");
        assertEquals(24, resumeKey.length, "Resume key should be 24 bytes");
        
        // Verify first 24 bytes were copied
        for (int i = 0; i < 24; i++) {
            assertEquals((byte)(i % 256), resumeKey[i], "Resume key byte " + i + " should match buffer");
        }
    }
    
    @Test
    @DisplayName("Test multiple decode calls on same instance")
    void testMultipleDecodeCalls() throws SMBProtocolDecodingException {
        // First decode
        byte[] buffer1 = new byte[28];
        Arrays.fill(buffer1, 0, 24, (byte)0x11);
        
        int bytesConsumed1 = response.decode(buffer1, 0, 28);
        assertEquals(28, bytesConsumed1);
        
        byte[] resumeKey1 = response.getResumeKey();
        assertNotNull(resumeKey1);
        assertEquals((byte)0x11, resumeKey1[0]);
        
        // Second decode - should overwrite
        byte[] buffer2 = new byte[28];
        Arrays.fill(buffer2, 0, 24, (byte)0x22);
        
        int bytesConsumed2 = response.decode(buffer2, 0, 28);
        assertEquals(28, bytesConsumed2);
        
        byte[] resumeKey2 = response.getResumeKey();
        assertNotNull(resumeKey2);
        assertEquals((byte)0x22, resumeKey2[0]);
        
        // Verify it's a different array
        assertNotSame(resumeKey1, resumeKey2, "Should create new array on each decode");
    }
}
