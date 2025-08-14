package jcifs.smb1.smb1;

import static jcifs.smb1.smb1.ServerMessageBlock.SMB_COM_WRITE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;

import org.junit.jupiter.api.Test;

/**
 * Tests for SmbComWrite command - SMB write operations
 */
public class SmbComWriteTest {

    /**
     * Helper method to get private field value using reflection
     */
    private Object getFieldValue(Object obj, String fieldName) {
        try {
            Field field = SmbComWrite.class.getDeclaredField(fieldName);
            field.setAccessible(true);
            return field.get(obj);
        } catch (Exception e) {
            throw new RuntimeException("Failed to access field " + fieldName, e);
        }
    }

    /**
     * Test that the constructor initializes all fields correctly
     */
    @Test
    public void testConstructor() {
        // Arrange
        int fid = 0x1234;
        int offset = 100;
        int remaining = 50;
        byte[] buffer = new byte[100];
        int off = 10;
        int len = 40;

        // Act
        SmbComWrite write = new SmbComWrite(fid, offset, remaining, buffer, off, len);

        // Assert
        assertEquals(fid, getFieldValue(write, "fid"), "FID should match constructor arg");
        assertEquals(offset, getFieldValue(write, "offset"), "Offset should match constructor arg");
        assertEquals(remaining, getFieldValue(write, "remaining"), "Remaining should match constructor arg");
        assertEquals(buffer, getFieldValue(write, "b"), "Buffer reference should be set");
        assertEquals(off, getFieldValue(write, "off"), "Off should match constructor arg");
        assertEquals(len, getFieldValue(write, "count"), "Count should equal len");
    }

    /**
     * Test setParam method updates the write parameters
     */
    @Test
    public void testSetParam() {
        // Arrange
        SmbComWrite write = new SmbComWrite();
        int fid = 0x5678;
        long offset = 200L;
        int remaining = 75;
        byte[] buffer = new byte[50];
        int off = 5;
        int len = 25;

        // Act
        write.setParam(fid, offset, remaining, buffer, off, len);

        // Assert
        assertEquals(fid, getFieldValue(write, "fid"), "FID should be updated");
        assertEquals((int) offset, getFieldValue(write, "offset"), "Offset should be updated");
        assertEquals(remaining, getFieldValue(write, "remaining"), "Remaining should be updated");
        assertEquals(buffer, getFieldValue(write, "b"), "Buffer should be updated");
        assertEquals(off, getFieldValue(write, "off"), "Off should be updated");
        assertEquals(len, getFieldValue(write, "count"), "Count should be updated");
        assertEquals(SMB_COM_WRITE, write.command, "Command should be SMB_COM_WRITE");
    }

    /**
     * Test writeParameterWordsWireFormat writes correct bytes
     */
    @Test
    public void testWriteParameterWordsWireFormat() {
        // Arrange
        SmbComWrite write = new SmbComWrite();
        write.setParam(0x1234, 0x5678L, 100, new byte[10], 0, 10);
        byte[] dst = new byte[20];

        // Act
        int bytesWritten = write.writeParameterWordsWireFormat(dst, 0);

        // Assert
        assertEquals(10, bytesWritten, "Should write 10 bytes");
        // Check FID (little-endian)
        assertEquals(0x34, dst[0] & 0xFF);
        assertEquals(0x12, dst[1] & 0xFF);
        // Check count
        assertEquals(10, dst[2] & 0xFF);
        assertEquals(0, dst[3] & 0xFF);
        // Check offset
        assertEquals(0x78, dst[4] & 0xFF);
        assertEquals(0x56, dst[5] & 0xFF);
    }

    /**
     * Test writeBytesWireFormat writes data correctly
     */
    @Test
    public void testWriteBytesWireFormat() {
        // Arrange
        byte[] data = { 1, 2, 3, 4, 5 };
        SmbComWrite write = new SmbComWrite();
        write.setParam(0, 0L, 0, data, 1, 3); // Write bytes 2,3,4
        byte[] dst = new byte[10];

        // Act
        int bytesWritten = write.writeBytesWireFormat(dst, 0);

        // Assert
        assertEquals(6, bytesWritten, "Should write 6 bytes (1 type + 2 length + 3 data)");
        assertEquals(0x01, dst[0], "Data block type");
        assertEquals(3, dst[1] & 0xFF, "Data length low byte");
        assertEquals(0, dst[2] & 0xFF, "Data length high byte");
        assertEquals(2, dst[3], "First data byte");
        assertEquals(3, dst[4], "Second data byte");
        assertEquals(4, dst[5], "Third data byte");
    }

    /**
     * Test readParameterWordsWireFormat always returns 0
     */
    @Test
    public void testReadParameterWordsWireFormat() {
        SmbComWrite write = new SmbComWrite();
        byte[] buffer = new byte[10];
        int result = write.readParameterWordsWireFormat(buffer, 0);
        assertEquals(0, result, "readParameterWordsWireFormat should always return 0");
    }

    /**
     * Test readBytesWireFormat always returns 0
     */
    @Test
    public void testReadBytesWireFormat() {
        SmbComWrite write = new SmbComWrite();
        byte[] buffer = new byte[10];
        int result = write.readBytesWireFormat(buffer, 0);
        assertEquals(0, result, "readBytesWireFormat should always return 0");
    }

    /**
     * Test toString contains relevant information
     */
    @Test
    public void testToString() {
        SmbComWrite write = new SmbComWrite();
        write.setParam(0x1234, 100L, 50, new byte[10], 0, 10);

        String str = write.toString();
        assertNotNull(str);
        assertTrue(str.contains("SmbComWrite"), "Should contain class name");
        assertTrue(str.contains("fid="), "Should contain fid");
        assertTrue(str.contains("count="), "Should contain count");
        assertTrue(str.contains("offset="), "Should contain offset");
    }
}