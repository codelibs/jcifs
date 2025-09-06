package org.codelibs.jcifs.smb.internal.fscc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

/**
 * Test class for FileInformation interface and its implementations
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FileInformationTest {

    /**
     * Test that interface constants are correctly defined
     */
    @Test
    @DisplayName("Test FileInformation constants are correctly defined")
    void testInterfaceConstants() {
        // Verify all constants have expected values
        assertEquals((byte) 20, FileInformation.FILE_ENDOFFILE_INFO);
        assertEquals((byte) 0x4, FileInformation.FILE_BASIC_INFO);
        assertEquals((byte) 0x5, FileInformation.FILE_STANDARD_INFO);
        assertEquals((byte) 0x6, FileInformation.FILE_INTERNAL_INFO);
        assertEquals((byte) 10, FileInformation.FILE_RENAME_INFO);
    }

    /**
     * Test that constants are unique
     */
    @Test
    @DisplayName("Test FileInformation constants are unique")
    void testConstantsAreUnique() {
        byte[] constants = { FileInformation.FILE_ENDOFFILE_INFO, FileInformation.FILE_BASIC_INFO, FileInformation.FILE_STANDARD_INFO,
                FileInformation.FILE_INTERNAL_INFO, FileInformation.FILE_RENAME_INFO };

        // Check all constants are unique
        for (int i = 0; i < constants.length; i++) {
            for (int j = i + 1; j < constants.length; j++) {
                assertTrue(constants[i] != constants[j], "Constants at index " + i + " and " + j + " should be unique");
            }
        }
    }

    /**
     * Test mock implementation of FileInformation interface
     */
    @Test
    @DisplayName("Test FileInformation interface mock implementation")
    void testFileInformationMockImplementation() {
        // Create mock
        FileInformation mockFileInfo = mock(FileInformation.class);

        // Define behavior
        when(mockFileInfo.getFileInformationLevel()).thenReturn(FileInformation.FILE_BASIC_INFO);

        // Test interface method
        byte level = mockFileInfo.getFileInformationLevel();
        assertEquals(FileInformation.FILE_BASIC_INFO, level);

        // Verify interaction
        verify(mockFileInfo).getFileInformationLevel();
    }

    /**
     * Test FileInformation as Decodable
     */
    @Test
    @DisplayName("Test FileInformation decode method")
    void testFileInformationDecode() throws SMBProtocolDecodingException {
        // Create mock
        FileInformation mockFileInfo = mock(FileInformation.class);
        byte[] buffer = new byte[100];

        // Define behavior
        when(mockFileInfo.decode(buffer, 0, 100)).thenReturn(8);

        // Test decode
        int decoded = mockFileInfo.decode(buffer, 0, 100);
        assertEquals(8, decoded);

        // Verify interaction
        verify(mockFileInfo).decode(buffer, 0, 100);
    }

    /**
     * Test FileInformation as Encodable
     */
    @Test
    @DisplayName("Test FileInformation encode method")
    void testFileInformationEncode() {
        // Create mock
        FileInformation mockFileInfo = mock(FileInformation.class);
        byte[] dst = new byte[100];

        // Define behavior
        when(mockFileInfo.encode(dst, 0)).thenReturn(8);
        when(mockFileInfo.size()).thenReturn(8);

        // Test encode
        int encoded = mockFileInfo.encode(dst, 0);
        assertEquals(8, encoded);

        // Test size
        int size = mockFileInfo.size();
        assertEquals(8, size);

        // Verify interactions
        verify(mockFileInfo).encode(dst, 0);
        verify(mockFileInfo).size();
    }

    /**
     * Test concrete implementation with FileEndOfFileInformation
     */
    @Test
    @DisplayName("Test FileEndOfFileInformation implementation")
    void testFileEndOfFileInformationImplementation() {
        // Test default constructor
        FileEndOfFileInformation fileInfo = new FileEndOfFileInformation();
        assertNotNull(fileInfo);
        assertEquals(FileInformation.FILE_ENDOFFILE_INFO, fileInfo.getFileInformationLevel());
        assertEquals(8, fileInfo.size());

        // Test parameterized constructor
        long endOfFile = 1024L;
        FileEndOfFileInformation fileInfoWithEof = new FileEndOfFileInformation(endOfFile);
        assertEquals(FileInformation.FILE_ENDOFFILE_INFO, fileInfoWithEof.getFileInformationLevel());

        // Test toString
        String str = fileInfoWithEof.toString();
        assertNotNull(str);
        assertTrue(str.contains("EndOfFileInformation"));
        assertTrue(str.contains("1024"));
    }

    /**
     * Test FileEndOfFileInformation encode/decode round trip
     */
    @Test
    @DisplayName("Test FileEndOfFileInformation encode/decode round trip")
    void testFileEndOfFileInformationEncodeDecodeRoundTrip() throws SMBProtocolDecodingException {
        long originalValue = 0x123456789ABCDEFL;
        FileEndOfFileInformation original = new FileEndOfFileInformation(originalValue);

        // Encode
        byte[] buffer = new byte[8];
        int encoded = original.encode(buffer, 0);
        assertEquals(8, encoded);

        // Decode
        FileEndOfFileInformation decoded = new FileEndOfFileInformation();
        int decodedBytes = decoded.decode(buffer, 0, 8);
        assertEquals(8, decodedBytes);

        // Verify the round trip preserves the value
        // Note: We can't directly access endOfFile field, but toString contains it
        assertEquals(original.toString(), decoded.toString());
    }

    /**
     * Test FileEndOfFileInformation with various end of file values
     */
    @ParameterizedTest
    @ValueSource(longs = { 0L, 1L, -1L, Long.MAX_VALUE, Long.MIN_VALUE, 1024L, 1048576L })
    @DisplayName("Test FileEndOfFileInformation with various values")
    void testFileEndOfFileInformationWithVariousValues(long endOfFile) throws SMBProtocolDecodingException {
        FileEndOfFileInformation fileInfo = new FileEndOfFileInformation(endOfFile);

        // Test encoding
        byte[] buffer = new byte[8];
        int encoded = fileInfo.encode(buffer, 0);
        assertEquals(8, encoded);

        // Test decoding
        FileEndOfFileInformation decoded = new FileEndOfFileInformation();
        int decodedBytes = decoded.decode(buffer, 0, 8);
        assertEquals(8, decodedBytes);

        // Verify toString contains the value
        assertTrue(decoded.toString().contains(String.valueOf(endOfFile)));
    }

    /**
     * Test FileEndOfFileInformation decode with offset
     */
    @Test
    @DisplayName("Test FileEndOfFileInformation decode with offset")
    void testFileEndOfFileInformationDecodeWithOffset() throws SMBProtocolDecodingException {
        long originalValue = 0xFEDCBA9876543210L;
        FileEndOfFileInformation original = new FileEndOfFileInformation(originalValue);

        // Create buffer with offset
        byte[] buffer = new byte[20];
        int offset = 5;
        original.encode(buffer, offset);

        // Decode from offset
        FileEndOfFileInformation decoded = new FileEndOfFileInformation();
        int decodedBytes = decoded.decode(buffer, offset, 8);
        assertEquals(8, decodedBytes);

        // Verify the values match
        assertEquals(original.toString(), decoded.toString());
    }

    /**
     * Test multiple FileInformation implementations can coexist
     */
    @Test
    @DisplayName("Test multiple FileInformation implementations")
    void testMultipleFileInformationImplementations() {
        // Create different mock implementations
        FileInformation basicInfo = mock(FileInformation.class);
        FileInformation standardInfo = mock(FileInformation.class);
        FileInformation internalInfo = mock(FileInformation.class);

        // Set different levels
        when(basicInfo.getFileInformationLevel()).thenReturn(FileInformation.FILE_BASIC_INFO);
        when(standardInfo.getFileInformationLevel()).thenReturn(FileInformation.FILE_STANDARD_INFO);
        when(internalInfo.getFileInformationLevel()).thenReturn(FileInformation.FILE_INTERNAL_INFO);

        // Verify each has correct level
        assertEquals(FileInformation.FILE_BASIC_INFO, basicInfo.getFileInformationLevel());
        assertEquals(FileInformation.FILE_STANDARD_INFO, standardInfo.getFileInformationLevel());
        assertEquals(FileInformation.FILE_INTERNAL_INFO, internalInfo.getFileInformationLevel());
    }

    /**
     * Test that FileInformation can be used as both Decodable and Encodable
     */
    @Test
    @DisplayName("Test FileInformation as both Decodable and Encodable")
    void testFileInformationAsDecodableAndEncodable() throws SMBProtocolDecodingException {
        FileInformation fileInfo = new FileEndOfFileInformation(2048L);

        // Test as Encodable
        assertTrue(fileInfo instanceof org.codelibs.jcifs.smb.Encodable);
        int size = fileInfo.size();
        assertTrue(size > 0);

        byte[] encodeBuffer = new byte[size];
        int encoded = fileInfo.encode(encodeBuffer, 0);
        assertEquals(size, encoded);

        // Test as Decodable
        assertTrue(fileInfo instanceof org.codelibs.jcifs.smb.Decodable);
        FileInformation newFileInfo = new FileEndOfFileInformation();
        int decoded = newFileInfo.decode(encodeBuffer, 0, size);
        assertEquals(size, decoded);
    }

    /**
     * Test FileInformation implementation with spy to verify method calls
     */
    @Test
    @DisplayName("Test FileInformation implementation with spy")
    void testFileInformationWithSpy() throws SMBProtocolDecodingException {
        // Create spy on real object
        FileEndOfFileInformation realObject = new FileEndOfFileInformation(4096L);
        FileEndOfFileInformation spy = Mockito.spy(realObject);

        // Call methods
        byte level = spy.getFileInformationLevel();
        int size = spy.size();
        byte[] buffer = new byte[8];
        int encoded = spy.encode(buffer, 0);
        int decoded = spy.decode(buffer, 0, 8);
        String str = spy.toString();

        // Verify all methods were called except toString (Mockito limitation)
        verify(spy).getFileInformationLevel();
        verify(spy).size();
        verify(spy).encode(buffer, 0);
        verify(spy).decode(buffer, 0, 8);
        // Note: Cannot verify toString() with Mockito - it's a special method

        // Verify return values
        assertEquals(FileInformation.FILE_ENDOFFILE_INFO, level);
        assertEquals(8, size);
        assertEquals(8, encoded);
        assertEquals(8, decoded);
        assertNotNull(str);
        assertTrue(str.contains("4096"));
    }

    /**
     * Test FileInformation constants match expected protocol values
     */
    @Test
    @DisplayName("Test FileInformation constants match SMB protocol values")
    void testFileInformationConstantsMatchProtocol() {
        // These values are defined in MS-FSCC specification
        assertEquals(0x04, FileInformation.FILE_BASIC_INFO);
        assertEquals(0x05, FileInformation.FILE_STANDARD_INFO);
        assertEquals(0x06, FileInformation.FILE_INTERNAL_INFO);
        assertEquals(10, FileInformation.FILE_RENAME_INFO);
        assertEquals(20, FileInformation.FILE_ENDOFFILE_INFO);
    }
}
