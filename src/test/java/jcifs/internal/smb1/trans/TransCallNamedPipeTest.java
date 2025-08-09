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
package jcifs.internal.smb1.trans;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.internal.smb1.trans.SmbComTransaction;

/**
 * Test class for TransCallNamedPipe
 */
class TransCallNamedPipeTest {

    @Mock
    private Configuration mockConfig;

    private TransCallNamedPipe transCallNamedPipe;
    private static final String TEST_PIPE_NAME = "\\\\PIPE\\\\testpipe";
    private static final byte[] TEST_DATA = "Test pipe data".getBytes();

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    @DisplayName("Test constructor initializes fields correctly")
    void testConstructorInitialization() {
        // Given
        int offset = 0;
        int length = TEST_DATA.length;

        // When
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_DATA, offset, length);

        // Then
        assertNotNull(transCallNamedPipe);
        assertEquals(SmbComTransaction.SMB_COM_TRANSACTION, transCallNamedPipe.getCommand());
        assertEquals(SmbComTransaction.TRANS_CALL_NAMED_PIPE, transCallNamedPipe.getSubCommand());
        assertEquals(0xFFFFFFFF, transCallNamedPipe.timeout);
        assertEquals(0, transCallNamedPipe.maxParameterCount);
        assertEquals(0xFFFF, transCallNamedPipe.maxDataCount);
        assertEquals((byte) 0x00, transCallNamedPipe.maxSetupCount);
        assertEquals(2, transCallNamedPipe.setupCount);
    }

    @Test
    @DisplayName("Test constructor with partial data")
    void testConstructorWithPartialData() {
        // Given
        int offset = 5;
        int length = 5;

        // When
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_DATA, offset, length);

        // Then
        assertNotNull(transCallNamedPipe);
        assertEquals(TEST_PIPE_NAME, transCallNamedPipe.name);
    }

    @Test
    @DisplayName("Test writeSetupWireFormat writes correct bytes")
    void testWriteSetupWireFormat() {
        // Given
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_DATA, 0, TEST_DATA.length);
        byte[] dst = new byte[10];

        // When
        int bytesWritten = transCallNamedPipe.writeSetupWireFormat(dst, 0);

        // Then
        assertEquals(4, bytesWritten);
        assertEquals(SmbComTransaction.TRANS_CALL_NAMED_PIPE, dst[0]);
        assertEquals((byte) 0x00, dst[1]);
        assertEquals((byte) 0x00, dst[2]);
        assertEquals((byte) 0x00, dst[3]);
    }

    @Test
    @DisplayName("Test writeSetupWireFormat with offset")
    void testWriteSetupWireFormatWithOffset() {
        // Given
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_DATA, 0, TEST_DATA.length);
        byte[] dst = new byte[20];
        int offset = 5;

        // When
        int bytesWritten = transCallNamedPipe.writeSetupWireFormat(dst, offset);

        // Then
        assertEquals(4, bytesWritten);
        assertEquals(SmbComTransaction.TRANS_CALL_NAMED_PIPE, dst[offset]);
        assertEquals((byte) 0x00, dst[offset + 1]);
        assertEquals((byte) 0x00, dst[offset + 2]);
        assertEquals((byte) 0x00, dst[offset + 3]);
    }

    @Test
    @DisplayName("Test readSetupWireFormat returns 0")
    void testReadSetupWireFormat() {
        // Given
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_DATA, 0, TEST_DATA.length);
        byte[] buffer = new byte[10];

        // When
        int bytesRead = transCallNamedPipe.readSetupWireFormat(buffer, 0, buffer.length);

        // Then
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat returns 0")
    void testWriteParametersWireFormat() {
        // Given
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_DATA, 0, TEST_DATA.length);
        byte[] dst = new byte[10];

        // When
        int bytesWritten = transCallNamedPipe.writeParametersWireFormat(dst, 0);

        // Then
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("Test writeDataWireFormat copies data correctly")
    void testWriteDataWireFormat() {
        // Given
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_DATA, 0, TEST_DATA.length);
        byte[] dst = new byte[100];

        // When
        int bytesWritten = transCallNamedPipe.writeDataWireFormat(dst, 0);

        // Then
        assertEquals(TEST_DATA.length, bytesWritten);
        byte[] writtenData = Arrays.copyOfRange(dst, 0, TEST_DATA.length);
        assertArrayEquals(TEST_DATA, writtenData);
    }

    @Test
    @DisplayName("Test writeDataWireFormat with offset and length")
    void testWriteDataWireFormatWithOffsetAndLength() {
        // Given
        int dataOffset = 2;
        int dataLength = 5;
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_DATA, dataOffset, dataLength);
        byte[] dst = new byte[100];
        int dstIndex = 10;

        // When
        int bytesWritten = transCallNamedPipe.writeDataWireFormat(dst, dstIndex);

        // Then
        assertEquals(dataLength, bytesWritten);
        byte[] expectedData = Arrays.copyOfRange(TEST_DATA, dataOffset, dataOffset + dataLength);
        byte[] writtenData = Arrays.copyOfRange(dst, dstIndex, dstIndex + dataLength);
        assertArrayEquals(expectedData, writtenData);
    }

    @Test
    @DisplayName("Test writeDataWireFormat with insufficient buffer space")
    void testWriteDataWireFormatInsufficientBuffer() {
        // Given
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_DATA, 0, TEST_DATA.length);
        byte[] dst = new byte[5]; // Buffer too small for TEST_DATA

        // When
        int bytesWritten = transCallNamedPipe.writeDataWireFormat(dst, 0);

        // Then
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("Test writeDataWireFormat with exactly fitting buffer")
    void testWriteDataWireFormatExactBuffer() {
        // Given
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_DATA, 0, TEST_DATA.length);
        byte[] dst = new byte[TEST_DATA.length];

        // When
        int bytesWritten = transCallNamedPipe.writeDataWireFormat(dst, 0);

        // Then
        assertEquals(TEST_DATA.length, bytesWritten);
        assertArrayEquals(TEST_DATA, dst);
    }

    @Test
    @DisplayName("Test writeDataWireFormat boundary check with offset")
    void testWriteDataWireFormatBoundaryWithOffset() {
        // Given
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_DATA, 0, TEST_DATA.length);
        byte[] dst = new byte[20];
        int dstIndex = 15; // Not enough space after offset

        // When
        int bytesWritten = transCallNamedPipe.writeDataWireFormat(dst, dstIndex);

        // Then
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("Test readParametersWireFormat returns 0")
    void testReadParametersWireFormat() {
        // Given
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_DATA, 0, TEST_DATA.length);
        byte[] buffer = new byte[10];

        // When
        int bytesRead = transCallNamedPipe.readParametersWireFormat(buffer, 0, buffer.length);

        // Then
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("Test readDataWireFormat returns 0")
    void testReadDataWireFormat() {
        // Given
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_DATA, 0, TEST_DATA.length);
        byte[] buffer = new byte[10];

        // When
        int bytesRead = transCallNamedPipe.readDataWireFormat(buffer, 0, buffer.length);

        // Then
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() {
        // Given
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_DATA, 0, TEST_DATA.length);

        // When
        String result = transCallNamedPipe.toString();

        // Then
        assertNotNull(result);
        assertTrue(result.contains("TransCallNamedPipe"));
        assertTrue(result.contains("pipeName=" + TEST_PIPE_NAME));
    }

    @Test
    @DisplayName("Test with empty data")
    void testWithEmptyData() {
        // Given
        byte[] emptyData = new byte[0];
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, emptyData, 0, 0);
        byte[] dst = new byte[10];

        // When
        int bytesWritten = transCallNamedPipe.writeDataWireFormat(dst, 0);

        // Then
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("Test with null pipe name")
    void testWithNullPipeName() {
        // Given
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, null, TEST_DATA, 0, TEST_DATA.length);

        // When
        String result = transCallNamedPipe.toString();

        // Then
        assertNotNull(result);
        assertTrue(result.contains("pipeName=null"));
    }

    @Test
    @DisplayName("Test with large data")
    void testWithLargeData() {
        // Given
        byte[] largeData = new byte[1000];
        Arrays.fill(largeData, (byte) 0x42);
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, largeData, 0, largeData.length);
        byte[] dst = new byte[2000];

        // When
        int bytesWritten = transCallNamedPipe.writeDataWireFormat(dst, 0);

        // Then
        assertEquals(largeData.length, bytesWritten);
        byte[] writtenData = Arrays.copyOfRange(dst, 0, largeData.length);
        assertArrayEquals(largeData, writtenData);
    }

    @Test
    @DisplayName("Test with maximum data size")
    void testWithMaxDataSize() {
        // Given
        byte[] maxData = new byte[0xFFFF];
        Arrays.fill(maxData, (byte) 0x55);
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, maxData, 0, maxData.length);
        byte[] dst = new byte[0x10000];

        // When
        int bytesWritten = transCallNamedPipe.writeDataWireFormat(dst, 0);

        // Then
        assertEquals(maxData.length, bytesWritten);
    }

    @Test
    @DisplayName("Test zero-length write with valid data array")
    void testZeroLengthWrite() {
        // Given
        transCallNamedPipe = new TransCallNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_DATA, 0, 0);
        byte[] dst = new byte[100];

        // When
        int bytesWritten = transCallNamedPipe.writeDataWireFormat(dst, 0);

        // Then
        assertEquals(0, bytesWritten);
    }
}