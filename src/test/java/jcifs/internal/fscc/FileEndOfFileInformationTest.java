/*
 * © 2017 AgNO3 Gmbh & Co. KG
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for FileEndOfFileInformation
 * 
 * @author test
 */
class FileEndOfFileInformationTest {

    private FileEndOfFileInformation fileInfo;

    @BeforeEach
    void setUp() {
        fileInfo = new FileEndOfFileInformation();
    }

    @Test
    @DisplayName("Test default constructor creates valid instance")
    void testDefaultConstructor() {
        // Verify instance is created
        assertNotNull(fileInfo);
        assertEquals(FileInformation.FILE_ENDOFFILE_INFO, fileInfo.getFileInformationLevel());
    }

    @Test
    @DisplayName("Test parameterized constructor with end of file value")
    void testParameterizedConstructor() {
        // Test with specific end of file value
        long endOfFile = 1024L;
        FileEndOfFileInformation info = new FileEndOfFileInformation(endOfFile);
        
        assertNotNull(info);
        assertEquals(FileInformation.FILE_ENDOFFILE_INFO, info.getFileInformationLevel());
        
        // Verify through toString that value is set
        assertTrue(info.toString().contains("endOfFile=" + endOfFile));
    }

    @ParameterizedTest
    @ValueSource(longs = {0L, 1L, 100L, 1024L, Long.MAX_VALUE, -1L, Long.MIN_VALUE})
    @DisplayName("Test constructor with various end of file values")
    void testConstructorWithVariousValues(long endOfFile) {
        FileEndOfFileInformation info = new FileEndOfFileInformation(endOfFile);
        
        assertNotNull(info);
        assertTrue(info.toString().contains("endOfFile=" + endOfFile));
    }

    @Test
    @DisplayName("Test getFileInformationLevel returns correct value")
    void testGetFileInformationLevel() {
        assertEquals(FileInformation.FILE_ENDOFFILE_INFO, fileInfo.getFileInformationLevel());
        
        // Test with parameterized constructor
        FileEndOfFileInformation info = new FileEndOfFileInformation(5000L);
        assertEquals(FileInformation.FILE_ENDOFFILE_INFO, info.getFileInformationLevel());
    }

    @Test
    @DisplayName("Test size method returns 8")
    void testSize() {
        assertEquals(8, fileInfo.size());
        
        // Test with different instance
        FileEndOfFileInformation info = new FileEndOfFileInformation(999L);
        assertEquals(8, info.size());
    }

    @Test
    @DisplayName("Test encode method with valid buffer")
    void testEncode() {
        // Create instance with known value
        long endOfFile = 0x123456789ABCDEFL;
        FileEndOfFileInformation info = new FileEndOfFileInformation(endOfFile);
        
        // Create buffer for encoding
        byte[] buffer = new byte[16];
        int bytesWritten = info.encode(buffer, 0);
        
        // Verify bytes written
        assertEquals(8, bytesWritten);
        
        // Verify encoded value
        long decodedValue = SMBUtil.readInt8(buffer, 0);
        assertEquals(endOfFile, decodedValue);
    }

    @Test
    @DisplayName("Test encode with offset")
    void testEncodeWithOffset() {
        long endOfFile = 0xFEDCBA9876543210L;
        FileEndOfFileInformation info = new FileEndOfFileInformation(endOfFile);
        
        // Create buffer with offset
        byte[] buffer = new byte[20];
        int offset = 5;
        int bytesWritten = info.encode(buffer, offset);
        
        assertEquals(8, bytesWritten);
        
        // Verify encoded value at offset
        long decodedValue = SMBUtil.readInt8(buffer, offset);
        assertEquals(endOfFile, decodedValue);
    }

    @Test
    @DisplayName("Test decode method with valid buffer")
    void testDecode() throws SMBProtocolDecodingException {
        // Prepare buffer with known value
        long expectedValue = 0x0123456789ABCDEFL;
        byte[] buffer = new byte[16];
        SMBUtil.writeInt8(expectedValue, buffer, 0);
        
        // Decode
        int bytesRead = fileInfo.decode(buffer, 0, buffer.length);
        
        // Verify bytes read
        assertEquals(8, bytesRead);
        
        // Verify decoded value through toString
        assertTrue(fileInfo.toString().contains("endOfFile=" + expectedValue));
    }

    @Test
    @DisplayName("Test decode with offset")
    void testDecodeWithOffset() throws SMBProtocolDecodingException {
        // Prepare buffer with offset
        long expectedValue = 0xAAAABBBBCCCCDDDDL;
        byte[] buffer = new byte[20];
        int offset = 7;
        SMBUtil.writeInt8(expectedValue, buffer, offset);
        
        // Decode from offset
        int bytesRead = fileInfo.decode(buffer, offset, buffer.length - offset);
        
        assertEquals(8, bytesRead);
        assertTrue(fileInfo.toString().contains("endOfFile=" + expectedValue));
    }

    @Test
    @DisplayName("Test encode and decode round trip")
    void testEncodeDecodeRoundTrip() throws SMBProtocolDecodingException {
        // Test various values
        long[] testValues = {0L, 1L, -1L, Long.MAX_VALUE, Long.MIN_VALUE, 0x123456789ABCDEFL};
        
        for (long testValue : testValues) {
            // Create and encode
            FileEndOfFileInformation original = new FileEndOfFileInformation(testValue);
            byte[] buffer = new byte[8];
            int encoded = original.encode(buffer, 0);
            
            assertEquals(8, encoded);
            
            // Decode into new instance
            FileEndOfFileInformation decoded = new FileEndOfFileInformation();
            int decodedBytes = decoded.decode(buffer, 0, buffer.length);
            
            assertEquals(8, decodedBytes);
            
            // Verify values match
            assertEquals(original.toString(), decoded.toString());
        }
    }

    @Test
    @DisplayName("Test decode with minimum buffer size")
    void testDecodeWithMinimumBuffer() throws SMBProtocolDecodingException {
        // Create buffer with exact size needed
        byte[] buffer = new byte[8];
        long value = 42L;
        SMBUtil.writeInt8(value, buffer, 0);
        
        // Decode with minimum length
        int bytesRead = fileInfo.decode(buffer, 0, 8);
        
        assertEquals(8, bytesRead);
        assertTrue(fileInfo.toString().contains("endOfFile=" + value));
    }

    @Test
    @DisplayName("Test decode ignores extra buffer length")
    void testDecodeIgnoresExtraLength() throws SMBProtocolDecodingException {
        // Create larger buffer
        byte[] buffer = new byte[100];
        long value = 999L;
        SMBUtil.writeInt8(value, buffer, 0);
        
        // Decode with extra length - should only read 8 bytes
        int bytesRead = fileInfo.decode(buffer, 0, 100);
        
        assertEquals(8, bytesRead);
        assertTrue(fileInfo.toString().contains("endOfFile=" + value));
    }

    @Test
    @DisplayName("Test toString format")
    void testToString() {
        // Test default constructor
        String str1 = fileInfo.toString();
        assertNotNull(str1);
        assertTrue(str1.startsWith("EndOfFileInformation["));
        assertTrue(str1.contains("endOfFile="));
        assertTrue(str1.endsWith("]"));
        
        // Test with specific value
        FileEndOfFileInformation info = new FileEndOfFileInformation(12345L);
        String str2 = info.toString();
        assertEquals("EndOfFileInformation[endOfFile=12345]", str2);
    }

    @Test
    @DisplayName("Test toString with various values")
    void testToStringWithVariousValues() {
        // Test negative value
        FileEndOfFileInformation info1 = new FileEndOfFileInformation(-100L);
        assertEquals("EndOfFileInformation[endOfFile=-100]", info1.toString());
        
        // Test zero
        FileEndOfFileInformation info2 = new FileEndOfFileInformation(0L);
        assertEquals("EndOfFileInformation[endOfFile=0]", info2.toString());
        
        // Test max value
        FileEndOfFileInformation info3 = new FileEndOfFileInformation(Long.MAX_VALUE);
        assertEquals("EndOfFileInformation[endOfFile=" + Long.MAX_VALUE + "]", info3.toString());
    }

    @Test
    @DisplayName("Test multiple encode operations")
    void testMultipleEncodeOperations() {
        long endOfFile = 0x1234567890ABCDEFL;
        FileEndOfFileInformation info = new FileEndOfFileInformation(endOfFile);
        
        // Encode multiple times to verify consistency
        byte[] buffer1 = new byte[8];
        byte[] buffer2 = new byte[8];
        
        int bytes1 = info.encode(buffer1, 0);
        int bytes2 = info.encode(buffer2, 0);
        
        assertEquals(8, bytes1);
        assertEquals(8, bytes2);
        assertArrayEquals(buffer1, buffer2);
    }

    @Test
    @DisplayName("Test multiple decode operations")
    void testMultipleDecodeOperations() throws SMBProtocolDecodingException {
        // Prepare buffer
        long value = 0x987654321L;
        byte[] buffer = new byte[8];
        SMBUtil.writeInt8(value, buffer, 0);
        
        // Decode multiple times
        FileEndOfFileInformation info1 = new FileEndOfFileInformation();
        FileEndOfFileInformation info2 = new FileEndOfFileInformation();
        
        int bytes1 = info1.decode(buffer, 0, 8);
        int bytes2 = info2.decode(buffer, 0, 8);
        
        assertEquals(8, bytes1);
        assertEquals(8, bytes2);
        assertEquals(info1.toString(), info2.toString());
    }

    @Test
    @DisplayName("Test encode does not modify source object")
    void testEncodeImmutability() {
        long originalValue = 1000L;
        FileEndOfFileInformation info = new FileEndOfFileInformation(originalValue);
        
        // Get original toString
        String originalString = info.toString();
        
        // Encode
        byte[] buffer = new byte[8];
        info.encode(buffer, 0);
        
        // Verify object unchanged
        assertEquals(originalString, info.toString());
    }
}