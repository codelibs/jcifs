/*
 * © 2025 Test Class for Smb2CloseResponse
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
package jcifs.internal.smb2.create;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for Smb2CloseResponse functionality
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Smb2CloseResponse Tests")
class Smb2CloseResponseTest {

    @Mock
    private Configuration mockConfig;

    private Smb2CloseResponse response;
    private byte[] testFileId;
    private String testFileName;

    @BeforeEach
    void setUp() {
        
        // Create a test file ID (16 bytes)
        testFileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            testFileId[i] = (byte)(i + 1);
        }
        
        testFileName = "test-file.txt";
        response = new Smb2CloseResponse(mockConfig, testFileId, testFileName);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {
        
        @Test
        @DisplayName("Constructor should initialize with config, fileId and fileName")
        void testConstructorWithAllParameters() {
            // When
            Smb2CloseResponse closeResponse = new Smb2CloseResponse(mockConfig, testFileId, testFileName);
            
            // Then
            assertNotNull(closeResponse);
            assertArrayEquals(testFileId, closeResponse.getFileId());
            assertEquals(testFileName, closeResponse.getFileName());
        }

        @Test
        @DisplayName("Constructor should accept null fileId")
        void testConstructorWithNullFileId() {
            // When
            Smb2CloseResponse closeResponse = new Smb2CloseResponse(mockConfig, null, testFileName);
            
            // Then
            assertNotNull(closeResponse);
            assertNull(closeResponse.getFileId());
            assertEquals(testFileName, closeResponse.getFileName());
        }

        @Test
        @DisplayName("Constructor should accept null fileName")
        void testConstructorWithNullFileName() {
            // When
            Smb2CloseResponse closeResponse = new Smb2CloseResponse(mockConfig, testFileId, null);
            
            // Then
            assertNotNull(closeResponse);
            assertArrayEquals(testFileId, closeResponse.getFileId());
            assertNull(closeResponse.getFileName());
        }

        @Test
        @DisplayName("Constructor should accept both null parameters")
        void testConstructorWithBothNull() {
            // When
            Smb2CloseResponse closeResponse = new Smb2CloseResponse(mockConfig, null, null);
            
            // Then
            assertNotNull(closeResponse);
            assertNull(closeResponse.getFileId());
            assertNull(closeResponse.getFileName());
        }
    }

    @Nested
    @DisplayName("Getter Methods Tests")
    class GetterMethodsTests {
        
        @Test
        @DisplayName("getCloseFlags should return initial value of 0")
        void testGetCloseFlags() {
            assertEquals(0, response.getCloseFlags());
        }

        @Test
        @DisplayName("getCreationTime should return initial value of 0")
        void testGetCreationTime() {
            assertEquals(0, response.getCreationTime());
        }

        @Test
        @DisplayName("getCreateTime should return same as getCreationTime")
        void testGetCreateTime() {
            assertEquals(response.getCreationTime(), response.getCreateTime());
        }

        @Test
        @DisplayName("getLastAccessTime should return initial value of 0")
        void testGetLastAccessTime() {
            assertEquals(0, response.getLastAccessTime());
        }

        @Test
        @DisplayName("getLastWriteTime should return initial value of 0")
        void testGetLastWriteTime() {
            assertEquals(0, response.getLastWriteTime());
        }

        @Test
        @DisplayName("getChangeTime should return initial value of 0")
        void testGetChangeTime() {
            assertEquals(0, response.getChangeTime());
        }

        @Test
        @DisplayName("getAllocationSize should return initial value of 0")
        void testGetAllocationSize() {
            assertEquals(0, response.getAllocationSize());
        }

        @Test
        @DisplayName("getEndOfFile should return initial value of 0")
        void testGetEndOfFile() {
            assertEquals(0, response.getEndOfFile());
        }

        @Test
        @DisplayName("getSize should return same as getEndOfFile")
        void testGetSize() {
            assertEquals(response.getEndOfFile(), response.getSize());
        }

        @Test
        @DisplayName("getFileAttributes should return initial value of 0")
        void testGetFileAttributes() {
            assertEquals(0, response.getFileAttributes());
        }

        @Test
        @DisplayName("getAttributes should return same as getFileAttributes")
        void testGetAttributes() {
            assertEquals(response.getFileAttributes(), response.getAttributes());
        }

        @Test
        @DisplayName("getFileId should return the file ID passed in constructor")
        void testGetFileId() {
            assertArrayEquals(testFileId, response.getFileId());
        }

        @Test
        @DisplayName("getFileName should return the file name passed in constructor")
        void testGetFileName() {
            assertEquals(testFileName, response.getFileName());
        }
    }

    @Nested
    @DisplayName("writeBytesWireFormat Tests")
    class WriteBytesWireFormatTests {
        
        @Test
        @DisplayName("Should always return 0")
        void testWriteBytesWireFormat() {
            // Given
            byte[] dst = new byte[100];
            int dstIndex = 0;
            
            // When
            int result = response.writeBytesWireFormat(dst, dstIndex);
            
            // Then
            assertEquals(0, result);
        }

        @ParameterizedTest
        @ValueSource(ints = {0, 10, 50, 99})
        @DisplayName("Should return 0 regardless of destination index")
        void testWriteBytesWireFormatWithDifferentIndices(int index) {
            // Given
            byte[] dst = new byte[100];
            
            // When
            int result = response.writeBytesWireFormat(dst, index);
            
            // Then
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should not modify destination buffer")
        void testWriteBytesWireFormatDoesNotModifyBuffer() {
            // Given
            byte[] dst = new byte[100];
            Arrays.fill(dst, (byte)0xFF);
            byte[] originalDst = dst.clone();
            
            // When
            response.writeBytesWireFormat(dst, 0);
            
            // Then
            assertArrayEquals(originalDst, dst);
        }
    }

    @Nested
    @DisplayName("readBytesWireFormat Tests")
    class ReadBytesWireFormatTests {
        
        @Test
        @DisplayName("Should correctly parse valid SMB2 Close response")
        void testReadBytesWireFormatWithValidData() throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[60];
            int bufferIndex = 0;
            
            // Structure Size (2 bytes) - must be 60
            SMBUtil.writeInt2(60, buffer, bufferIndex);
            // Flags (2 bytes)
            SMBUtil.writeInt2(SMB2_CLOSE_FLAG_POSTQUERY_ATTIB, buffer, bufferIndex + 2);
            // Reserved (4 bytes)
            SMBUtil.writeInt4(0, buffer, bufferIndex + 4);
            // Creation Time (8 bytes)
            long creationTime = System.currentTimeMillis() * 10000L + 116444736000000000L;
            SMBUtil.writeInt8(creationTime, buffer, bufferIndex + 8);
            // Last Access Time (8 bytes)
            long lastAccessTime = creationTime + 1000000L;
            SMBUtil.writeInt8(lastAccessTime, buffer, bufferIndex + 16);
            // Last Write Time (8 bytes)
            long lastWriteTime = creationTime + 2000000L;
            SMBUtil.writeInt8(lastWriteTime, buffer, bufferIndex + 24);
            // Change Time (8 bytes)
            long changeTime = creationTime + 3000000L;
            SMBUtil.writeInt8(changeTime, buffer, bufferIndex + 32);
            // Allocation Size (8 bytes)
            SMBUtil.writeInt8(4096, buffer, bufferIndex + 40);
            // End of File (8 bytes)
            SMBUtil.writeInt8(1024, buffer, bufferIndex + 48);
            // File Attributes (4 bytes)
            SMBUtil.writeInt4(0x20, buffer, bufferIndex + 56); // FILE_ATTRIBUTE_ARCHIVE
            
            // When
            int bytesRead = response.readBytesWireFormat(buffer, bufferIndex);
            
            // Then
            assertEquals(60, bytesRead);
            assertEquals(SMB2_CLOSE_FLAG_POSTQUERY_ATTIB, response.getCloseFlags());
            assertEquals(SMBUtil.readTime(buffer, bufferIndex + 8), response.getCreationTime());
            assertEquals(SMBUtil.readTime(buffer, bufferIndex + 16), response.getLastAccessTime());
            assertEquals(SMBUtil.readTime(buffer, bufferIndex + 24), response.getLastWriteTime());
            assertEquals(SMBUtil.readTime(buffer, bufferIndex + 32), response.getChangeTime());
            assertEquals(4096, response.getAllocationSize());
            assertEquals(1024, response.getEndOfFile());
            assertEquals(0x20, response.getFileAttributes());
        }

        @Test
        @DisplayName("Should throw exception for invalid structure size")
        void testReadBytesWireFormatWithInvalidStructureSize() {
            // Given
            byte[] buffer = new byte[60];
            SMBUtil.writeInt2(59, buffer, 0); // Invalid structure size (should be 60)
            
            // When & Then
            assertThrows(SMBProtocolDecodingException.class, () -> {
                response.readBytesWireFormat(buffer, 0);
            });
        }

        @Test
        @DisplayName("Should throw exception with correct message for invalid structure size")
        void testReadBytesWireFormatExceptionMessage() {
            // Given
            byte[] buffer = new byte[60];
            SMBUtil.writeInt2(100, buffer, 0); // Invalid structure size
            
            // When & Then
            SMBProtocolDecodingException exception = assertThrows(
                SMBProtocolDecodingException.class,
                () -> response.readBytesWireFormat(buffer, 0)
            );
            assertEquals("Expected structureSize = 60", exception.getMessage());
        }

        @ParameterizedTest
        @ValueSource(ints = {0, 10, 20, 30})
        @DisplayName("Should correctly read from different buffer offsets")
        void testReadBytesWireFormatWithDifferentOffsets(int offset) throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[100];
            
            // Write valid structure at offset
            SMBUtil.writeInt2(60, buffer, offset);
            SMBUtil.writeInt2(0, buffer, offset + 2);
            SMBUtil.writeInt4(0, buffer, offset + 4);
            
            // Write test values
            long testTime = System.currentTimeMillis() * 10000L + 116444736000000000L;
            SMBUtil.writeInt8(testTime, buffer, offset + 8);
            SMBUtil.writeInt8(testTime + 1000, buffer, offset + 16);
            SMBUtil.writeInt8(testTime + 2000, buffer, offset + 24);
            SMBUtil.writeInt8(testTime + 3000, buffer, offset + 32);
            SMBUtil.writeInt8(8192, buffer, offset + 40);
            SMBUtil.writeInt8(2048, buffer, offset + 48);
            SMBUtil.writeInt4(0x10, buffer, offset + 56);
            
            // When
            int bytesRead = response.readBytesWireFormat(buffer, offset);
            
            // Then
            assertEquals(60, bytesRead);
            assertEquals(8192, response.getAllocationSize());
            assertEquals(2048, response.getEndOfFile());
            assertEquals(0x10, response.getFileAttributes());
        }

        @Test
        @DisplayName("Should handle all zero values correctly")
        void testReadBytesWireFormatWithZeroValues() throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[60];
            SMBUtil.writeInt2(60, buffer, 0); // Structure size
            // All other values remain zero
            
            // When
            int bytesRead = response.readBytesWireFormat(buffer, 0);
            
            // Then
            assertEquals(60, bytesRead);
            assertEquals(0, response.getCloseFlags());
            // Zero Windows FileTime converts to negative Unix time
            long expectedTime = -SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601;
            assertEquals(expectedTime, response.getCreationTime());
            assertEquals(expectedTime, response.getLastAccessTime());
            assertEquals(expectedTime, response.getLastWriteTime());
            assertEquals(expectedTime, response.getChangeTime());
            assertEquals(0, response.getAllocationSize());
            assertEquals(0, response.getEndOfFile());
            assertEquals(0, response.getFileAttributes());
        }

        @Test
        @DisplayName("Should handle maximum values correctly")
        void testReadBytesWireFormatWithMaxValues() throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[60];
            SMBUtil.writeInt2(60, buffer, 0);
            SMBUtil.writeInt2(0xFFFF, buffer, 2); // Max flags
            SMBUtil.writeInt4(0xFFFFFFFF, buffer, 4); // Max reserved (ignored)
            SMBUtil.writeInt8(Long.MAX_VALUE, buffer, 8); // Max times
            SMBUtil.writeInt8(Long.MAX_VALUE, buffer, 16);
            SMBUtil.writeInt8(Long.MAX_VALUE, buffer, 24);
            SMBUtil.writeInt8(Long.MAX_VALUE, buffer, 32);
            SMBUtil.writeInt8(Long.MAX_VALUE, buffer, 40); // Max allocation size
            SMBUtil.writeInt8(Long.MAX_VALUE, buffer, 48); // Max end of file
            SMBUtil.writeInt4(0xFFFFFFFF, buffer, 56); // Max attributes
            
            // When
            int bytesRead = response.readBytesWireFormat(buffer, 0);
            
            // Then
            assertEquals(60, bytesRead);
            assertEquals(0xFFFF, response.getCloseFlags());
            assertEquals(Long.MAX_VALUE, response.getAllocationSize());
            assertEquals(Long.MAX_VALUE, response.getEndOfFile());
            assertEquals(0xFFFFFFFF, response.getFileAttributes());
        }

        @Test
        @DisplayName("Should throw exception for buffer underrun")
        void testReadBytesWireFormatWithBufferUnderrun() {
            // Given
            byte[] buffer = new byte[59]; // One byte too small
            SMBUtil.writeInt2(60, buffer, 0);
            
            // When & Then
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
                response.readBytesWireFormat(buffer, 0);
            });
        }
    }

    @Nested
    @DisplayName("SmbBasicFileInfo Interface Tests")
    class SmbBasicFileInfoTests {
        
        @Test
        @DisplayName("Should correctly implement SmbBasicFileInfo interface")
        void testSmbBasicFileInfoInterface() throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[60];
            SMBUtil.writeInt2(60, buffer, 0);
            
            // Use proper millisecond times that will be converted correctly
            long creationTimeMs = System.currentTimeMillis();
            long lastAccessTimeMs = creationTimeMs + 100;
            long lastWriteTimeMs = creationTimeMs + 200;
            
            // Write as Windows FileTime format
            SMBUtil.writeTime(creationTimeMs, buffer, 8);
            SMBUtil.writeTime(lastAccessTimeMs, buffer, 16);
            SMBUtil.writeTime(lastWriteTimeMs, buffer, 24);
            SMBUtil.writeTime(creationTimeMs + 300, buffer, 32);
            SMBUtil.writeInt8(4096, buffer, 40);
            SMBUtil.writeInt8(2048, buffer, 48);
            SMBUtil.writeInt4(0x20, buffer, 56);
            
            // When
            response.readBytesWireFormat(buffer, 0);
            
            // Then - verify interface methods
            assertEquals(response.getCreationTime(), response.getCreateTime());
            assertEquals(lastAccessTimeMs, response.getLastAccessTime());
            assertEquals(lastWriteTimeMs, response.getLastWriteTime());
            assertEquals(2048, response.getSize());
            assertEquals(0x20, response.getAttributes());
        }
    }

    @Nested
    @DisplayName("Field Access Tests")
    class FieldAccessTests {
        
        @Test
        @DisplayName("Should update internal fields correctly during read")
        void testInternalFieldsUpdate() throws Exception {
            // Given
            byte[] buffer = new byte[60];
            SMBUtil.writeInt2(60, buffer, 0);
            SMBUtil.writeInt2(1, buffer, 2);
            
            long testTime = 116444736000000000L;
            SMBUtil.writeInt8(testTime, buffer, 8);
            SMBUtil.writeInt8(testTime + 1000, buffer, 16);
            SMBUtil.writeInt8(testTime + 2000, buffer, 24);
            SMBUtil.writeInt8(testTime + 3000, buffer, 32);
            SMBUtil.writeInt8(1024, buffer, 40);
            SMBUtil.writeInt8(512, buffer, 48);
            SMBUtil.writeInt4(0x01, buffer, 56);
            
            // When
            response.readBytesWireFormat(buffer, 0);
            
            // Then - use reflection to verify private fields
            Field closeFlagsField = Smb2CloseResponse.class.getDeclaredField("closeFlags");
            closeFlagsField.setAccessible(true);
            assertEquals(1, closeFlagsField.get(response));
            
            Field creationTimeField = Smb2CloseResponse.class.getDeclaredField("creationTime");
            creationTimeField.setAccessible(true);
            assertEquals(SMBUtil.readTime(buffer, 8), creationTimeField.get(response));
            
            Field allocationSizeField = Smb2CloseResponse.class.getDeclaredField("allocationSize");
            allocationSizeField.setAccessible(true);
            assertEquals(1024L, allocationSizeField.get(response));
            
            Field endOfFileField = Smb2CloseResponse.class.getDeclaredField("endOfFile");
            endOfFileField.setAccessible(true);
            assertEquals(512L, endOfFileField.get(response));
            
            Field fileAttributesField = Smb2CloseResponse.class.getDeclaredField("fileAttributes");
            fileAttributesField.setAccessible(true);
            assertEquals(0x01, fileAttributesField.get(response));
        }
    }

    @Nested
    @DisplayName("Edge Cases and Boundary Tests")
    class EdgeCasesTests {
        
        @Test
        @DisplayName("Should handle negative time values")
        void testNegativeTimeValues() throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[60];
            SMBUtil.writeInt2(60, buffer, 0);
            
            // Write negative times (as they would appear in the buffer)
            SMBUtil.writeInt8(-1L, buffer, 8);
            SMBUtil.writeInt8(-1000L, buffer, 16);
            SMBUtil.writeInt8(-2000L, buffer, 24);
            SMBUtil.writeInt8(-3000L, buffer, 32);
            
            // When
            int bytesRead = response.readBytesWireFormat(buffer, 0);
            
            // Then
            assertEquals(60, bytesRead);
            // SMBUtil.readTime will handle the conversion
            assertEquals(SMBUtil.readTime(buffer, 8), response.getCreationTime());
            assertEquals(SMBUtil.readTime(buffer, 16), response.getLastAccessTime());
            assertEquals(SMBUtil.readTime(buffer, 24), response.getLastWriteTime());
            assertEquals(SMBUtil.readTime(buffer, 32), response.getChangeTime());
        }

        @Test
        @DisplayName("Should handle file attributes with multiple flags set")
        void testMultipleFileAttributeFlags() throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[60];
            SMBUtil.writeInt2(60, buffer, 0);
            
            // Set multiple attribute flags
            int attributes = 0x01 | 0x02 | 0x04 | 0x10 | 0x20; // Multiple attributes
            SMBUtil.writeInt4(attributes, buffer, 56);
            
            // When
            response.readBytesWireFormat(buffer, 0);
            
            // Then
            assertEquals(attributes, response.getFileAttributes());
            assertEquals(attributes, response.getAttributes());
        }

        @ParameterizedTest
        @CsvSource({
            "0, 0",
            "1, 1",
            "1024, 1024",
            "1048576, 1048576",
            "9223372036854775807, 9223372036854775807" // Long.MAX_VALUE
        })
        @DisplayName("Should handle various file sizes correctly")
        void testVariousFileSizes(long size, long expectedSize) throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[60];
            SMBUtil.writeInt2(60, buffer, 0);
            SMBUtil.writeInt8(size * 2, buffer, 40); // Allocation size
            SMBUtil.writeInt8(size, buffer, 48); // End of file
            
            // When
            response.readBytesWireFormat(buffer, 0);
            
            // Then
            assertEquals(size * 2, response.getAllocationSize());
            assertEquals(expectedSize, response.getEndOfFile());
            assertEquals(expectedSize, response.getSize());
        }

        @Test
        @DisplayName("Should handle response with different fileId and fileName combinations")
        void testDifferentFileIdAndFileNameCombinations() throws SMBProtocolDecodingException {
            // Test with empty fileName
            Smb2CloseResponse emptyNameResponse = new Smb2CloseResponse(mockConfig, testFileId, "");
            assertEquals("", emptyNameResponse.getFileName());
            assertArrayEquals(testFileId, emptyNameResponse.getFileId());
            
            // Test with long fileName
            String longFileName = "a".repeat(255); // Maximum typical filename length
            Smb2CloseResponse longNameResponse = new Smb2CloseResponse(mockConfig, testFileId, longFileName);
            assertEquals(longFileName, longNameResponse.getFileName());
            
            // Test with special characters in fileName
            String specialFileName = "file!@#$%^&*()_+-=[]{}|;':\",./<>?.txt";
            Smb2CloseResponse specialNameResponse = new Smb2CloseResponse(mockConfig, testFileId, specialFileName);
            assertEquals(specialFileName, specialNameResponse.getFileName());
            
            // Test with different fileId patterns
            byte[] zeroFileId = new byte[16];
            Smb2CloseResponse zeroIdResponse = new Smb2CloseResponse(mockConfig, zeroFileId, testFileName);
            assertArrayEquals(zeroFileId, zeroIdResponse.getFileId());
            
            byte[] maxFileId = new byte[16];
            Arrays.fill(maxFileId, (byte)0xFF);
            Smb2CloseResponse maxIdResponse = new Smb2CloseResponse(mockConfig, maxFileId, testFileName);
            assertArrayEquals(maxFileId, maxIdResponse.getFileId());
        }
    }

    @Nested
    @DisplayName("Time Conversion Tests")
    class TimeConversionTests {
        
        @Test
        @DisplayName("Should correctly handle SMB time format conversion")
        void testSmbTimeFormatConversion() throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[60];
            SMBUtil.writeInt2(60, buffer, 0);
            
            // SMB times are in 100-nanosecond intervals since 1601
            // Java times are in milliseconds since 1970
            long currentJavaTime = System.currentTimeMillis();
            long smbTime = currentJavaTime * 10000L + 116444736000000000L;
            
            SMBUtil.writeInt8(smbTime, buffer, 8);
            SMBUtil.writeInt8(smbTime, buffer, 16);
            SMBUtil.writeInt8(smbTime, buffer, 24);
            SMBUtil.writeInt8(smbTime, buffer, 32);
            
            // When
            response.readBytesWireFormat(buffer, 0);
            
            // Then
            // SMBUtil.readTime should convert back to Java time
            long readTime = response.getCreationTime();
            assertEquals(currentJavaTime, readTime);
            assertEquals(readTime, response.getCreateTime());
            assertEquals(currentJavaTime, response.getLastAccessTime());
            assertEquals(currentJavaTime, response.getLastWriteTime());
            assertEquals(currentJavaTime, response.getChangeTime());
        }

        @Test
        @DisplayName("Should handle zero times correctly")
        void testZeroTimes() throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[60];
            SMBUtil.writeInt2(60, buffer, 0);
            // All times remain zero in buffer
            
            // When
            response.readBytesWireFormat(buffer, 0);
            
            // Then - zero Windows FileTime converts to negative Unix time
            // (0 / 10000L - MILLISECONDS_BETWEEN_1970_AND_1601)
            long expectedTime = -SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601;
            assertEquals(expectedTime, response.getCreationTime());
            assertEquals(expectedTime, response.getLastAccessTime());
            assertEquals(expectedTime, response.getLastWriteTime());
            assertEquals(expectedTime, response.getChangeTime());
        }
    }

    @Nested
    @DisplayName("Multiple Read Operations Tests")
    class MultipleReadOperationsTests {
        
        @Test
        @DisplayName("Should update fields correctly on subsequent reads")
        void testMultipleReads() throws SMBProtocolDecodingException {
            // First read
            byte[] buffer1 = new byte[60];
            SMBUtil.writeInt2(60, buffer1, 0);
            SMBUtil.writeInt2(1, buffer1, 2);
            SMBUtil.writeInt8(1000, buffer1, 40);
            SMBUtil.writeInt8(500, buffer1, 48);
            SMBUtil.writeInt4(0x01, buffer1, 56);
            
            response.readBytesWireFormat(buffer1, 0);
            
            assertEquals(1, response.getCloseFlags());
            assertEquals(1000, response.getAllocationSize());
            assertEquals(500, response.getEndOfFile());
            assertEquals(0x01, response.getFileAttributes());
            
            // Second read with different values
            byte[] buffer2 = new byte[60];
            SMBUtil.writeInt2(60, buffer2, 0);
            SMBUtil.writeInt2(2, buffer2, 2);
            SMBUtil.writeInt8(2000, buffer2, 40);
            SMBUtil.writeInt8(1500, buffer2, 48);
            SMBUtil.writeInt4(0x02, buffer2, 56);
            
            response.readBytesWireFormat(buffer2, 0);
            
            // Values should be updated
            assertEquals(2, response.getCloseFlags());
            assertEquals(2000, response.getAllocationSize());
            assertEquals(1500, response.getEndOfFile());
            assertEquals(0x02, response.getFileAttributes());
        }
    }

    // Constants from the main class
    private static final int SMB2_CLOSE_FLAG_POSTQUERY_ATTIB = 0x1;
}