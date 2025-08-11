package jcifs.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.Configuration;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.util.SMBUtil;

public class SmbComQueryInformationResponseTest {

    private Configuration mockConfig;
    private SmbComQueryInformationResponse response;
    
    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
    }
    
    @Test
    void testConstructor() {
        // Test constructor with positive timezone offset
        long serverTimeZoneOffset = 3600000L; // 1 hour in milliseconds
        response = new SmbComQueryInformationResponse(mockConfig, serverTimeZoneOffset);
        
        assertNotNull(response);
        assertEquals(ServerMessageBlock.SMB_COM_QUERY_INFORMATION, getCommand(response));
    }
    
    @Test
    void testConstructorWithNegativeTimezone() {
        // Test constructor with negative timezone offset
        long serverTimeZoneOffset = -7200000L; // -2 hours in milliseconds
        response = new SmbComQueryInformationResponse(mockConfig, serverTimeZoneOffset);
        
        assertNotNull(response);
        assertEquals(ServerMessageBlock.SMB_COM_QUERY_INFORMATION, getCommand(response));
    }
    
    @Test
    void testGetAttributesDefault() {
        // Test default attributes value
        response = new SmbComQueryInformationResponse(mockConfig, 0L);
        assertEquals(0x0000, response.getAttributes());
    }
    
    @Test
    void testGetSizeDefault() {
        // Test default file size value
        response = new SmbComQueryInformationResponse(mockConfig, 0L);
        assertEquals(0, response.getSize());
    }
    
    @Test
    void testTimeConversionMethods() {
        // Test time conversion methods with timezone offset
        long serverTimeZoneOffset = 3600000L; // 1 hour
        response = new SmbComQueryInformationResponse(mockConfig, serverTimeZoneOffset);
        
        // Set a test time using reflection
        long testTime = System.currentTimeMillis();
        setFieldValue(response, "lastWriteTime", testTime);
        
        // All time methods should return the same converted time
        long expectedTime = testTime + serverTimeZoneOffset;
        assertEquals(expectedTime, response.getCreateTime());
        assertEquals(expectedTime, response.getLastWriteTime());
        assertEquals(expectedTime, response.getLastAccessTime());
    }
    
    @Test
    void testReadParameterWordsWireFormatWithData() {
        // Test reading parameter words from wire format
        response = new SmbComQueryInformationResponse(mockConfig, 0L);
        
        // Prepare test data
        byte[] buffer = new byte[256];
        int bufferIndex = 0;
        
        // Set wordCount to non-zero
        setFieldValue(response, "wordCount", 10);
        
        // Write test data to buffer
        int fileAttributes = 0x0021; // FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE
        long lastWriteTime = System.currentTimeMillis();
        int fileSize = 12345678;
        
        SMBUtil.writeInt2(fileAttributes, buffer, bufferIndex);
        SMBUtil.writeUTime(lastWriteTime, buffer, bufferIndex + 2);
        SMBUtil.writeInt4(fileSize, buffer, bufferIndex + 6);
        
        // Read the data
        int bytesRead = response.readParameterWordsWireFormat(buffer, bufferIndex);
        
        // Verify results
        assertEquals(20, bytesRead);
        assertEquals(fileAttributes, response.getAttributes());
        assertEquals(fileSize, response.getSize());
        
        // Verify time was read correctly (accounting for UTime conversion)
        long readTime = (Long) getFieldValue(response, "lastWriteTime");
        // UTime is seconds since 1970, so we need to compare at second precision
        assertEquals(lastWriteTime / 1000, readTime / 1000);
    }
    
    @Test
    void testReadParameterWordsWireFormatWithZeroWordCount() {
        // Test reading when wordCount is 0
        response = new SmbComQueryInformationResponse(mockConfig, 0L);
        
        // Set wordCount to 0
        setFieldValue(response, "wordCount", 0);
        
        byte[] buffer = new byte[256];
        int bytesRead = response.readParameterWordsWireFormat(buffer, 0);
        
        // Should return 0 and not read any data
        assertEquals(0, bytesRead);
        assertEquals(0, response.getAttributes());
        assertEquals(0, response.getSize());
    }
    
    @ParameterizedTest
    @ValueSource(ints = {0x0001, 0x0002, 0x0004, 0x0010, 0x0020, 0x0080, 0x0100})
    void testDifferentFileAttributes(int fileAttribute) {
        // Test various file attribute values
        response = new SmbComQueryInformationResponse(mockConfig, 0L);
        setFieldValue(response, "wordCount", 10);
        
        byte[] buffer = new byte[256];
        SMBUtil.writeInt2(fileAttribute, buffer, 0);
        SMBUtil.writeUTime(0, buffer, 2);
        SMBUtil.writeInt4(0, buffer, 6);
        
        response.readParameterWordsWireFormat(buffer, 0);
        
        assertEquals(fileAttribute, response.getAttributes());
    }
    
    @ParameterizedTest
    @ValueSource(longs = {0L, 1024L, 1048576L, 2147483647L})
    void testDifferentFileSizes(long fileSize) {
        // Test various file size values (excluding values that would overflow signed int)
        response = new SmbComQueryInformationResponse(mockConfig, 0L);
        setFieldValue(response, "wordCount", 10);
        
        byte[] buffer = new byte[256];
        SMBUtil.writeInt2(0, buffer, 0);
        SMBUtil.writeUTime(0, buffer, 2);
        SMBUtil.writeInt4(fileSize, buffer, 6);
        
        response.readParameterWordsWireFormat(buffer, 0);
        
        // File size is stored as signed int
        long expectedSize = (int) fileSize;
        assertEquals(expectedSize, response.getSize());
    }
    
    @Test
    void testFileSizeOverflow() {
        // Test file size that overflows signed int
        response = new SmbComQueryInformationResponse(mockConfig, 0L);
        setFieldValue(response, "wordCount", 10);
        
        byte[] buffer = new byte[256];
        long overflowSize = 0xFFFFFFFFL; // This will become -1 as signed int
        
        SMBUtil.writeInt2(0, buffer, 0);
        SMBUtil.writeUTime(0, buffer, 2);
        SMBUtil.writeInt4(overflowSize, buffer, 6);
        
        response.readParameterWordsWireFormat(buffer, 0);
        
        // 0xFFFFFFFF becomes -1 when interpreted as signed int
        assertEquals(-1L, response.getSize());
    }
    
    @Test
    void testReadBytesWireFormat() {
        // Test readBytesWireFormat - should always return 0
        response = new SmbComQueryInformationResponse(mockConfig, 0L);
        
        byte[] buffer = new byte[256];
        int bytesRead = response.readBytesWireFormat(buffer, 0);
        
        assertEquals(0, bytesRead);
    }
    
    @Test
    void testWriteParameterWordsWireFormat() {
        // Test writeParameterWordsWireFormat - should always return 0
        response = new SmbComQueryInformationResponse(mockConfig, 0L);
        
        byte[] buffer = new byte[256];
        int bytesWritten = response.writeParameterWordsWireFormat(buffer, 0);
        
        assertEquals(0, bytesWritten);
    }
    
    @Test
    void testWriteBytesWireFormat() {
        // Test writeBytesWireFormat - should always return 0
        response = new SmbComQueryInformationResponse(mockConfig, 0L);
        
        byte[] buffer = new byte[256];
        int bytesWritten = response.writeBytesWireFormat(buffer, 0);
        
        assertEquals(0, bytesWritten);
    }
    
    @Test
    void testToString() {
        // Test toString method
        response = new SmbComQueryInformationResponse(mockConfig, 0L);
        
        // Set test values
        setFieldValue(response, "fileAttributes", 0x0021);
        setFieldValue(response, "lastWriteTime", System.currentTimeMillis());
        setFieldValue(response, "fileSize", 12345);
        
        String result = response.toString();
        
        assertNotNull(result);
        assertTrue(result.contains("SmbComQueryInformationResponse"));
        assertTrue(result.contains("fileAttributes=0x"));
        assertTrue(result.contains("lastWriteTime="));
        assertTrue(result.contains("fileSize=12345"));
    }
    
    @Test
    void testToStringWithZeroValues() {
        // Test toString with all zero values
        response = new SmbComQueryInformationResponse(mockConfig, 0L);
        
        String result = response.toString();
        
        assertNotNull(result);
        assertTrue(result.contains("fileAttributes=0x0000"));
        assertTrue(result.contains("fileSize=0"));
    }
    
    @Test
    void testLargeTimezoneOffset() {
        // Test with maximum timezone offset
        long maxOffset = 12L * 3600000L; // +12 hours
        response = new SmbComQueryInformationResponse(mockConfig, maxOffset);
        
        long testTime = 1000000000L;
        setFieldValue(response, "lastWriteTime", testTime);
        
        assertEquals(testTime + maxOffset, response.getCreateTime());
        assertEquals(testTime + maxOffset, response.getLastWriteTime());
        assertEquals(testTime + maxOffset, response.getLastAccessTime());
    }
    
    @Test
    void testNegativeTimezoneOffset() {
        // Test with negative timezone offset
        long negativeOffset = -11L * 3600000L; // -11 hours
        response = new SmbComQueryInformationResponse(mockConfig, negativeOffset);
        
        long testTime = 2000000000L;
        setFieldValue(response, "lastWriteTime", testTime);
        
        assertEquals(testTime + negativeOffset, response.getCreateTime());
        assertEquals(testTime + negativeOffset, response.getLastWriteTime());
        assertEquals(testTime + negativeOffset, response.getLastAccessTime());
    }
    
    @Test
    void testMaximumFileSize() {
        // Test with maximum unsigned 32-bit file size
        // Note: fileSize is stored as signed int in SmbComQueryInformationResponse
        // 0xFFFFFFFF becomes -1 when interpreted as signed int
        response = new SmbComQueryInformationResponse(mockConfig, 0L);
        setFieldValue(response, "wordCount", 10);
        
        byte[] buffer = new byte[256];
        long maxFileSize = 0xFFFFFFFFL;
        
        SMBUtil.writeInt2(0, buffer, 0);
        SMBUtil.writeUTime(0, buffer, 2);
        SMBUtil.writeInt4(maxFileSize, buffer, 6);
        
        response.readParameterWordsWireFormat(buffer, 0);
        
        // When 0xFFFFFFFF is read as signed int, it becomes -1
        assertEquals(-1L, response.getSize());
    }
    
    // Helper methods for reflection
    private void setFieldValue(Object obj, String fieldName, Object value) {
        try {
            Field field = findField(obj.getClass(), fieldName);
            field.setAccessible(true);
            field.set(obj, value);
        } catch (Exception e) {
            throw new RuntimeException("Failed to set field " + fieldName, e);
        }
    }
    
    private Object getFieldValue(Object obj, String fieldName) {
        try {
            Field field = findField(obj.getClass(), fieldName);
            field.setAccessible(true);
            return field.get(obj);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get field " + fieldName, e);
        }
    }
    
    private Field findField(Class<?> clazz, String fieldName) throws NoSuchFieldException {
        Class<?> current = clazz;
        while (current != null) {
            try {
                return current.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                current = current.getSuperclass();
            }
        }
        throw new NoSuchFieldException(fieldName);
    }
    
    private byte getCommand(ServerMessageBlock smb) {
        try {
            Field field = findField(ServerMessageBlock.class, "command");
            field.setAccessible(true);
            return (byte) field.get(smb);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get command field", e);
        }
    }
}
