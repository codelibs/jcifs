/*
 * jcifs smb client library in Java
 * Copyright (C) 2025  "Test Authors"
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

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.internal.util.SMBUtil;

/**
 * Unit tests for TransTransactNamedPipe class
 */
@DisplayName("TransTransactNamedPipe Tests")
class TransTransactNamedPipeTest {

    @Mock
    private Configuration mockConfig;

    private static final int TEST_FID = 0x1234;
    private static final byte[] TEST_DATA = "Test pipe data".getBytes(StandardCharsets.UTF_8);
    private static final int TEST_OFFSET = 0;
    private static final int TEST_LENGTH = TEST_DATA.length;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    @DisplayName("Test constructor initializes fields correctly")
    void testConstructor() {
        // Act
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, TEST_FID, TEST_DATA, TEST_OFFSET, TEST_LENGTH
        );

        // Assert
        assertNotNull(trans);
        assertEquals(0, trans.maxParameterCount);
        assertEquals(0xFFFF, trans.maxDataCount);
        assertEquals(0x00, trans.maxSetupCount);
        assertEquals(2, trans.setupCount);
        assertEquals("\\PIPE\\", trans.name);
    }

    @Test
    @DisplayName("Test writeSetupWireFormat writes correct data")
    void testWriteSetupWireFormat() {
        // Arrange
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, TEST_FID, TEST_DATA, TEST_OFFSET, TEST_LENGTH
        );
        byte[] dst = new byte[10];
        int dstIndex = 0;

        // Act
        int bytesWritten = trans.writeSetupWireFormat(dst, dstIndex);

        // Assert
        assertEquals(4, bytesWritten);
        assertEquals(SmbComTransaction.TRANS_TRANSACT_NAMED_PIPE, dst[0]);
        assertEquals(0x00, dst[1]);
        
        // Verify FID is written correctly (little-endian)
        int writtenFid = SMBUtil.readInt2(dst, 2);
        assertEquals(TEST_FID, writtenFid);
    }

    @Test
    @DisplayName("Test writeDataWireFormat with sufficient buffer")
    void testWriteDataWireFormatSufficientBuffer() {
        // Arrange
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, TEST_FID, TEST_DATA, TEST_OFFSET, TEST_LENGTH
        );
        byte[] dst = new byte[100];
        int dstIndex = 10;

        // Act
        int bytesWritten = trans.writeDataWireFormat(dst, dstIndex);

        // Assert
        assertEquals(TEST_LENGTH, bytesWritten);
        
        // Verify data is copied correctly
        byte[] copiedData = new byte[TEST_LENGTH];
        System.arraycopy(dst, dstIndex, copiedData, 0, TEST_LENGTH);
        assertArrayEquals(TEST_DATA, copiedData);
    }

    @Test
    @DisplayName("Test writeDataWireFormat with insufficient buffer")
    void testWriteDataWireFormatInsufficientBuffer() {
        // Arrange
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, TEST_FID, TEST_DATA, TEST_OFFSET, TEST_LENGTH
        );
        byte[] dst = new byte[5]; // Buffer too small
        int dstIndex = 0;

        // Act
        int bytesWritten = trans.writeDataWireFormat(dst, dstIndex);

        // Assert
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("Test writeDataWireFormat with exact buffer size")
    void testWriteDataWireFormatExactBuffer() {
        // Arrange
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, TEST_FID, TEST_DATA, TEST_OFFSET, TEST_LENGTH
        );
        byte[] dst = new byte[TEST_LENGTH];
        int dstIndex = 0;

        // Act
        int bytesWritten = trans.writeDataWireFormat(dst, dstIndex);

        // Assert
        assertEquals(TEST_LENGTH, bytesWritten);
        assertArrayEquals(TEST_DATA, dst);
    }

    @Test
    @DisplayName("Test writeDataWireFormat with partial data")
    void testWriteDataWireFormatPartialData() {
        // Arrange
        int partialOffset = 5;
        int partialLength = 8;
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, TEST_FID, TEST_DATA, partialOffset, partialLength
        );
        byte[] dst = new byte[100];
        int dstIndex = 0;

        // Act
        int bytesWritten = trans.writeDataWireFormat(dst, dstIndex);

        // Assert
        assertEquals(partialLength, bytesWritten);
        
        // Verify correct portion of data is copied
        byte[] expectedData = new byte[partialLength];
        System.arraycopy(TEST_DATA, partialOffset, expectedData, 0, partialLength);
        byte[] copiedData = new byte[partialLength];
        System.arraycopy(dst, dstIndex, copiedData, 0, partialLength);
        assertArrayEquals(expectedData, copiedData);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat returns 0")
    void testWriteParametersWireFormat() {
        // Arrange
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, TEST_FID, TEST_DATA, TEST_OFFSET, TEST_LENGTH
        );
        byte[] dst = new byte[10];

        // Act
        int bytesWritten = trans.writeParametersWireFormat(dst, 0);

        // Assert
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("Test readSetupWireFormat returns 0")
    void testReadSetupWireFormat() {
        // Arrange
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, TEST_FID, TEST_DATA, TEST_OFFSET, TEST_LENGTH
        );
        byte[] buffer = new byte[10];

        // Act
        int bytesRead = trans.readSetupWireFormat(buffer, 0, 10);

        // Assert
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("Test readParametersWireFormat returns 0")
    void testReadParametersWireFormat() {
        // Arrange
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, TEST_FID, TEST_DATA, TEST_OFFSET, TEST_LENGTH
        );
        byte[] buffer = new byte[10];

        // Act
        int bytesRead = trans.readParametersWireFormat(buffer, 0, 10);

        // Assert
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("Test readDataWireFormat returns 0")
    void testReadDataWireFormat() {
        // Arrange
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, TEST_FID, TEST_DATA, TEST_OFFSET, TEST_LENGTH
        );
        byte[] buffer = new byte[10];

        // Act
        int bytesRead = trans.readDataWireFormat(buffer, 0, 10);

        // Assert
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() {
        // Arrange
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, TEST_FID, TEST_DATA, TEST_OFFSET, TEST_LENGTH
        );

        // Act
        String result = trans.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("TransTransactNamedPipe"));
        assertTrue(result.contains("pipeFid=" + TEST_FID));
    }

    @Test
    @DisplayName("Test with null data array")
    void testWithNullData() {
        // Arrange & Act
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, TEST_FID, null, 0, 0
        );

        // Assert
        assertNotNull(trans);
        assertEquals(0, trans.maxParameterCount);
        assertEquals(0xFFFF, trans.maxDataCount);
    }

    @Test
    @DisplayName("Test with zero length data")
    void testWithZeroLengthData() {
        // Arrange
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, TEST_FID, TEST_DATA, TEST_OFFSET, 0
        );
        byte[] dst = new byte[10];

        // Act
        int bytesWritten = trans.writeDataWireFormat(dst, 0);

        // Assert
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("Test with large FID value")
    void testWithLargeFid() {
        // Arrange
        int largeFid = 0xFFFF;
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, largeFid, TEST_DATA, TEST_OFFSET, TEST_LENGTH
        );
        byte[] dst = new byte[10];

        // Act
        int bytesWritten = trans.writeSetupWireFormat(dst, 0);

        // Assert
        assertEquals(4, bytesWritten);
        int writtenFid = SMBUtil.readInt2(dst, 2);
        assertEquals(largeFid, writtenFid);
    }

    @Test
    @DisplayName("Test boundary condition with buffer size equal to data length minus one")
    void testBoundaryBufferSize() {
        // Arrange
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, TEST_FID, TEST_DATA, TEST_OFFSET, TEST_LENGTH
        );
        byte[] dst = new byte[TEST_LENGTH - 1]; // One byte short
        int dstIndex = 0;

        // Act
        int bytesWritten = trans.writeDataWireFormat(dst, dstIndex);

        // Assert
        assertEquals(0, bytesWritten); // Should return 0 as buffer is insufficient
    }

    @Test
    @DisplayName("Test with maximum offset boundary")
    void testMaxOffsetBoundary() {
        // Arrange
        byte[] largeData = new byte[1000];
        for (int i = 0; i < largeData.length; i++) {
            largeData[i] = (byte)(i % 256);
        }
        int offset = 990;
        int length = 10;
        
        TransTransactNamedPipe trans = new TransTransactNamedPipe(
            mockConfig, TEST_FID, largeData, offset, length
        );
        byte[] dst = new byte[100];

        // Act
        int bytesWritten = trans.writeDataWireFormat(dst, 0);

        // Assert
        assertEquals(length, bytesWritten);
        
        // Verify correct data portion
        for (int i = 0; i < length; i++) {
            assertEquals(largeData[offset + i], dst[i]);
        }
    }
}