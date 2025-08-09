/*
 * © 2025 jcifs Project Contributors
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
package jcifs.internal.smb1.trans.nt;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.DialectVersion;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for SmbComNtTransactionResponse
 */
@DisplayName("SmbComNtTransactionResponse Tests")
class SmbComNtTransactionResponseTest {

    @Mock
    private Configuration mockConfig;

    private TestSmbComNtTransactionResponse response;

    // Concrete implementation for testing
    private static class TestSmbComNtTransactionResponse extends SmbComNtTransactionResponse {
        
        public TestSmbComNtTransactionResponse(Configuration config) {
            super(config);
        }

        @Override
        protected int writeSetupWireFormat(byte[] dst, int dstIndex) {
            return 0;
        }

        @Override
        protected int writeParametersWireFormat(byte[] dst, int dstIndex) {
            return 0;
        }

        @Override
        protected int writeDataWireFormat(byte[] dst, int dstIndex) {
            return 0;
        }

        @Override
        protected int readSetupWireFormat(byte[] buffer, int bufferIndex, int len) {
            return len;
        }

        @Override
        protected int readParametersWireFormat(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
            return len;
        }

        @Override
        protected int readDataWireFormat(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
            return len;
        }
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockConfig.getMaximumBufferSize()).thenReturn(65535);
        when(mockConfig.getMinimumVersion()).thenReturn(DialectVersion.SMB1);
        when(mockConfig.getMaximumVersion()).thenReturn(DialectVersion.SMB311);
        response = new TestSmbComNtTransactionResponse(mockConfig);
    }

    @Test
    @DisplayName("Test constructor with Configuration")
    void testConstructor() {
        assertNotNull(response);
        // Verify configuration is set through parent constructor
        verify(mockConfig, atLeastOnce()).getMaximumBufferSize();
    }

    @Test
    @DisplayName("Test readParameterWordsWireFormat with zero setup count")
    void testReadParameterWordsWireFormatZeroSetupCount() throws Exception {
        byte[] buffer = new byte[100];
        int bufferIndex = 10;
        
        // Prepare buffer with test data
        // Reserved bytes (3 bytes)
        buffer[bufferIndex] = 0x00;
        buffer[bufferIndex + 1] = 0x00;
        buffer[bufferIndex + 2] = 0x00;
        
        // totalParameterCount (4 bytes)
        SMBUtil.writeInt4(1000, buffer, bufferIndex + 3);
        
        // totalDataCount (4 bytes)
        SMBUtil.writeInt4(2000, buffer, bufferIndex + 7);
        
        // parameterCount (4 bytes)
        SMBUtil.writeInt4(100, buffer, bufferIndex + 11);
        
        // parameterOffset (4 bytes)
        SMBUtil.writeInt4(64, buffer, bufferIndex + 15);
        
        // parameterDisplacement (4 bytes)
        SMBUtil.writeInt4(0, buffer, bufferIndex + 19);
        
        // dataCount (4 bytes)
        SMBUtil.writeInt4(200, buffer, bufferIndex + 23);
        
        // dataOffset (4 bytes)
        SMBUtil.writeInt4(128, buffer, bufferIndex + 27);
        
        // dataDisplacement (4 bytes)
        SMBUtil.writeInt4(0, buffer, bufferIndex + 31);
        
        // setupCount (1 byte) + 1 reserved byte
        buffer[bufferIndex + 35] = 0x00; // setupCount = 0
        buffer[bufferIndex + 36] = 0x00; // reserved
        
        int bytesRead = response.readParameterWordsWireFormat(buffer, bufferIndex);
        
        // Verify the correct number of bytes were read (37 bytes total)
        assertEquals(37, bytesRead);
        
        // Verify values through reflection
        Field totalParamField = response.getClass().getSuperclass().getSuperclass().getDeclaredField("totalParameterCount");
        totalParamField.setAccessible(true);
        assertEquals(1000, totalParamField.get(response));
        
        Field totalDataField = response.getClass().getSuperclass().getSuperclass().getDeclaredField("totalDataCount");
        totalDataField.setAccessible(true);
        assertEquals(2000, totalDataField.get(response));
        
        Field paramCountField = response.getClass().getSuperclass().getSuperclass().getDeclaredField("parameterCount");
        paramCountField.setAccessible(true);
        assertEquals(100, paramCountField.get(response));
        
        Field dataCountField = response.getClass().getSuperclass().getSuperclass().getDeclaredField("dataCount");
        dataCountField.setAccessible(true);
        assertEquals(200, dataCountField.get(response));
        
        Field setupCountField = response.getClass().getSuperclass().getSuperclass().getDeclaredField("setupCount");
        setupCountField.setAccessible(true);
        assertEquals(0, setupCountField.get(response));
    }

    @Test
    @DisplayName("Test readParameterWordsWireFormat with non-zero setup count")
    void testReadParameterWordsWireFormatNonZeroSetupCount() throws Exception {
        byte[] buffer = new byte[100];
        int bufferIndex = 10;
        
        // Prepare buffer with test data
        // Reserved bytes (3 bytes)
        buffer[bufferIndex] = 0x00;
        buffer[bufferIndex + 1] = 0x00;
        buffer[bufferIndex + 2] = 0x00;
        
        // totalParameterCount (4 bytes)
        SMBUtil.writeInt4(500, buffer, bufferIndex + 3);
        
        // totalDataCount (4 bytes)
        SMBUtil.writeInt4(1500, buffer, bufferIndex + 7);
        
        // parameterCount (4 bytes)
        SMBUtil.writeInt4(50, buffer, bufferIndex + 11);
        
        // parameterOffset (4 bytes)
        SMBUtil.writeInt4(80, buffer, bufferIndex + 15);
        
        // parameterDisplacement (4 bytes)
        SMBUtil.writeInt4(10, buffer, bufferIndex + 19);
        
        // dataCount (4 bytes)
        SMBUtil.writeInt4(150, buffer, bufferIndex + 23);
        
        // dataOffset (4 bytes)
        SMBUtil.writeInt4(160, buffer, bufferIndex + 27);
        
        // dataDisplacement (4 bytes)
        SMBUtil.writeInt4(20, buffer, bufferIndex + 31);
        
        // setupCount (1 byte) + 1 reserved byte
        buffer[bufferIndex + 35] = 0x05; // setupCount = 5
        buffer[bufferIndex + 36] = 0x00; // reserved
        
        int bytesRead = response.readParameterWordsWireFormat(buffer, bufferIndex);
        
        // Verify the correct number of bytes were read
        assertEquals(37, bytesRead);
        
        // Verify setupCount through reflection
        Field setupCountField = response.getClass().getSuperclass().getSuperclass().getDeclaredField("setupCount");
        setupCountField.setAccessible(true);
        assertEquals(5, setupCountField.get(response));
    }

    @ParameterizedTest
    @DisplayName("Test readParameterWordsWireFormat with various parameter values")
    @CsvSource({
        "0, 0, 0, 0, 0, 0, 0, 0, 0",
        "100, 200, 10, 64, 0, 20, 128, 0, 1",
        "65535, 65535, 1024, 256, 512, 2048, 512, 1024, 10",
        "1, 1, 1, 1, 0, 1, 1, 0, 255"
    })
    void testReadParameterWordsWireFormatWithVariousValues(
            int totalParams, int totalData, int paramCount, int paramOffset,
            int paramDisp, int dataCount, int dataOffset, int dataDisp, int setupCount) throws Exception {
        
        byte[] buffer = new byte[100];
        int bufferIndex = 5;
        
        // Reserved bytes
        buffer[bufferIndex] = 0x00;
        buffer[bufferIndex + 1] = 0x00;
        buffer[bufferIndex + 2] = 0x00;
        
        SMBUtil.writeInt4(totalParams, buffer, bufferIndex + 3);
        SMBUtil.writeInt4(totalData, buffer, bufferIndex + 7);
        SMBUtil.writeInt4(paramCount, buffer, bufferIndex + 11);
        SMBUtil.writeInt4(paramOffset, buffer, bufferIndex + 15);
        SMBUtil.writeInt4(paramDisp, buffer, bufferIndex + 19);
        SMBUtil.writeInt4(dataCount, buffer, bufferIndex + 23);
        SMBUtil.writeInt4(dataOffset, buffer, bufferIndex + 27);
        SMBUtil.writeInt4(dataDisp, buffer, bufferIndex + 31);
        buffer[bufferIndex + 35] = (byte)(setupCount & 0xFF);
        buffer[bufferIndex + 36] = 0x00;
        
        int bytesRead = response.readParameterWordsWireFormat(buffer, bufferIndex);
        
        assertEquals(37, bytesRead);
        
        // Verify all fields through reflection
        Field field = response.getClass().getSuperclass().getSuperclass().getDeclaredField("totalParameterCount");
        field.setAccessible(true);
        assertEquals(totalParams, field.get(response));
        
        field = response.getClass().getSuperclass().getSuperclass().getDeclaredField("totalDataCount");
        field.setAccessible(true);
        assertEquals(totalData, field.get(response));
        
        field = response.getClass().getSuperclass().getSuperclass().getDeclaredField("setupCount");
        field.setAccessible(true);
        assertEquals(setupCount, field.get(response));
    }

    @Test
    @DisplayName("Test bufDataStart initialization when zero")
    void testBufDataStartInitialization() throws Exception {
        byte[] buffer = new byte[100];
        int bufferIndex = 0;
        
        // Set bufDataStart to 0 initially
        Field bufDataStartField = response.getClass().getSuperclass().getSuperclass().getDeclaredField("bufDataStart");
        bufDataStartField.setAccessible(true);
        bufDataStartField.set(response, 0);
        
        // Prepare buffer with totalParameterCount = 1500
        buffer[bufferIndex] = 0x00;
        buffer[bufferIndex + 1] = 0x00;
        buffer[bufferIndex + 2] = 0x00;
        SMBUtil.writeInt4(1500, buffer, bufferIndex + 3);
        
        // Fill rest of required fields
        for (int i = 7; i < 37; i++) {
            buffer[bufferIndex + i] = 0x00;
        }
        
        response.readParameterWordsWireFormat(buffer, bufferIndex);
        
        // Verify bufDataStart was set to totalParameterCount
        assertEquals(1500, bufDataStartField.get(response));
    }

    @Test
    @DisplayName("Test bufDataStart not changed when non-zero")
    void testBufDataStartNotChangedWhenNonZero() throws Exception {
        byte[] buffer = new byte[100];
        int bufferIndex = 0;
        
        // Set bufDataStart to a non-zero value
        Field bufDataStartField = response.getClass().getSuperclass().getSuperclass().getDeclaredField("bufDataStart");
        bufDataStartField.setAccessible(true);
        bufDataStartField.set(response, 999);
        
        // Prepare buffer with totalParameterCount = 1500
        buffer[bufferIndex] = 0x00;
        buffer[bufferIndex + 1] = 0x00;
        buffer[bufferIndex + 2] = 0x00;
        SMBUtil.writeInt4(1500, buffer, bufferIndex + 3);
        
        // Fill rest of required fields
        for (int i = 7; i < 37; i++) {
            buffer[bufferIndex + i] = 0x00;
        }
        
        response.readParameterWordsWireFormat(buffer, bufferIndex);
        
        // Verify bufDataStart was not changed
        assertEquals(999, bufDataStartField.get(response));
    }

    @ParameterizedTest
    @DisplayName("Test reserved bytes are properly skipped")
    @ValueSource(bytes = {0x00, 0x01, (byte)0xFF, 0x7F, (byte)0x80})
    void testReservedBytesSkipped(byte reservedValue) throws Exception {
        byte[] buffer = new byte[100];
        int bufferIndex = 0;
        
        // Set reserved bytes to non-zero values (should be ignored)
        buffer[bufferIndex] = reservedValue;
        buffer[bufferIndex + 1] = reservedValue;
        buffer[bufferIndex + 2] = reservedValue;
        
        // Set valid data for other fields
        SMBUtil.writeInt4(100, buffer, bufferIndex + 3);
        for (int i = 7; i < 35; i++) {
            buffer[bufferIndex + i] = 0x00;
        }
        buffer[bufferIndex + 35] = 0x00;
        buffer[bufferIndex + 36] = reservedValue; // Reserved byte after setupCount
        
        int bytesRead = response.readParameterWordsWireFormat(buffer, bufferIndex);
        
        // Should still read 37 bytes regardless of reserved byte values
        assertEquals(37, bytesRead);
    }

    @Test
    @DisplayName("Test handling of maximum values")
    void testMaximumValues() throws Exception {
        byte[] buffer = new byte[100];
        int bufferIndex = 0;
        
        // Reserved bytes
        buffer[bufferIndex] = 0x00;
        buffer[bufferIndex + 1] = 0x00;
        buffer[bufferIndex + 2] = 0x00;
        
        // Set all fields to maximum 32-bit values
        SMBUtil.writeInt4(Integer.MAX_VALUE, buffer, bufferIndex + 3);
        SMBUtil.writeInt4(Integer.MAX_VALUE, buffer, bufferIndex + 7);
        SMBUtil.writeInt4(Integer.MAX_VALUE, buffer, bufferIndex + 11);
        SMBUtil.writeInt4(Integer.MAX_VALUE, buffer, bufferIndex + 15);
        SMBUtil.writeInt4(Integer.MAX_VALUE, buffer, bufferIndex + 19);
        SMBUtil.writeInt4(Integer.MAX_VALUE, buffer, bufferIndex + 23);
        SMBUtil.writeInt4(Integer.MAX_VALUE, buffer, bufferIndex + 27);
        SMBUtil.writeInt4(Integer.MAX_VALUE, buffer, bufferIndex + 31);
        buffer[bufferIndex + 35] = (byte)0xFF; // Maximum setup count (255)
        buffer[bufferIndex + 36] = 0x00;
        
        int bytesRead = response.readParameterWordsWireFormat(buffer, bufferIndex);
        
        assertEquals(37, bytesRead);
        
        // Verify maximum values are correctly handled
        Field setupCountField = response.getClass().getSuperclass().getSuperclass().getDeclaredField("setupCount");
        setupCountField.setAccessible(true);
        assertEquals(255, setupCountField.get(response));
    }

    @Test
    @DisplayName("Test negative values handling (as unsigned)")
    void testNegativeValuesAsUnsigned() throws Exception {
        byte[] buffer = new byte[100];
        int bufferIndex = 0;
        
        // Reserved bytes
        buffer[bufferIndex] = (byte)0xFF;
        buffer[bufferIndex + 1] = (byte)0xFF;
        buffer[bufferIndex + 2] = (byte)0xFF;
        
        // Set fields with negative values (should be treated as unsigned)
        SMBUtil.writeInt4(-1, buffer, bufferIndex + 3);  // Should be read as 0xFFFFFFFF
        SMBUtil.writeInt4(-100, buffer, bufferIndex + 7);
        SMBUtil.writeInt4(-1000, buffer, bufferIndex + 11);
        SMBUtil.writeInt4(0, buffer, bufferIndex + 15);
        SMBUtil.writeInt4(0, buffer, bufferIndex + 19);
        SMBUtil.writeInt4(-5000, buffer, bufferIndex + 23);
        SMBUtil.writeInt4(0, buffer, bufferIndex + 27);
        SMBUtil.writeInt4(0, buffer, bufferIndex + 31);
        buffer[bufferIndex + 35] = (byte)0x80; // 128 as unsigned
        buffer[bufferIndex + 36] = (byte)0xFF;
        
        int bytesRead = response.readParameterWordsWireFormat(buffer, bufferIndex);
        
        assertEquals(37, bytesRead);
        
        // Verify setupCount treats byte as unsigned
        Field setupCountField = response.getClass().getSuperclass().getSuperclass().getDeclaredField("setupCount");
        setupCountField.setAccessible(true);
        assertEquals(128, setupCountField.get(response));
    }

    @Test
    @DisplayName("Test reading from different buffer positions")
    void testReadFromDifferentPositions() throws Exception {
        byte[] buffer = new byte[200];
        
        // Test at various positions in the buffer
        int[] positions = {0, 10, 50, 100, 150};
        
        for (int pos : positions) {
            response = new TestSmbComNtTransactionResponse(mockConfig); // Reset response
            
            // Fill buffer at position
            for (int i = 0; i < 37; i++) {
                buffer[pos + i] = 0x00;
            }
            SMBUtil.writeInt4(pos * 10, buffer, pos + 3); // Unique value per position
            
            int bytesRead = response.readParameterWordsWireFormat(buffer, pos);
            
            assertEquals(37, bytesRead, "Failed at position " + pos);
            
            // Verify unique value was read correctly
            Field totalParamField = response.getClass().getSuperclass().getSuperclass().getDeclaredField("totalParameterCount");
            totalParamField.setAccessible(true);
            assertEquals(pos * 10, totalParamField.get(response), "Value mismatch at position " + pos);
        }
    }
}