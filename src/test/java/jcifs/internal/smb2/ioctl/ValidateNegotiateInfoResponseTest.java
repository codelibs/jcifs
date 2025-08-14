package jcifs.internal.smb2.ioctl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for ValidateNegotiateInfoResponse
 */
class ValidateNegotiateInfoResponseTest {

    private ValidateNegotiateInfoResponse response;

    @BeforeEach
    void setUp() {
        response = new ValidateNegotiateInfoResponse();
    }

    @Test
    @DisplayName("Test decode with valid buffer")
    void testDecodeValidBuffer() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = new byte[64];
        int bufferIndex = 10;

        // Set capabilities (4 bytes)
        int testCapabilities = 0x12345678;
        SMBUtil.writeInt4(testCapabilities, buffer, bufferIndex);

        // Set server GUID (16 bytes)
        byte[] testGuid = new byte[16];
        for (int i = 0; i < 16; i++) {
            testGuid[i] = (byte) (i + 1);
        }
        System.arraycopy(testGuid, 0, buffer, bufferIndex + 4, 16);

        // Set security mode (2 bytes)
        int testSecurityMode = 0x0003;
        SMBUtil.writeInt2(testSecurityMode, buffer, bufferIndex + 20);

        // Set dialect (2 bytes)
        int testDialect = 0x0311;
        SMBUtil.writeInt2(testDialect, buffer, bufferIndex + 22);

        // Execute decode
        int bytesDecoded = response.decode(buffer, bufferIndex, 24);

        // Verify results
        assertEquals(24, bytesDecoded, "Should decode exactly 24 bytes");
        assertEquals(testCapabilities, response.getCapabilities(), "Capabilities should match");
        assertArrayEquals(testGuid, response.getServerGuid(), "Server GUID should match");
        assertEquals(testSecurityMode, response.getSecurityMode(), "Security mode should match");
        assertEquals(testDialect, response.getDialect(), "Dialect should match");
    }

    @Test
    @DisplayName("Test decode with different buffer offset")
    void testDecodeWithDifferentOffset() throws SMBProtocolDecodingException {
        // Prepare test data with different offset
        byte[] buffer = new byte[100];
        int bufferIndex = 50;

        // Set test values
        int testCapabilities = 0xABCDEF00;
        byte[] testGuid = new byte[16];
        Arrays.fill(testGuid, (byte) 0xFF);
        int testSecurityMode = 0x0001;
        int testDialect = 0x0202;

        // Write to buffer
        SMBUtil.writeInt4(testCapabilities, buffer, bufferIndex);
        System.arraycopy(testGuid, 0, buffer, bufferIndex + 4, 16);
        SMBUtil.writeInt2(testSecurityMode, buffer, bufferIndex + 20);
        SMBUtil.writeInt2(testDialect, buffer, bufferIndex + 22);

        // Execute decode
        int bytesDecoded = response.decode(buffer, bufferIndex, 24);

        // Verify results
        assertEquals(24, bytesDecoded, "Should decode exactly 24 bytes");
        assertEquals(testCapabilities, response.getCapabilities(), "Capabilities should match");
        assertArrayEquals(testGuid, response.getServerGuid(), "Server GUID should match");
        assertEquals(testSecurityMode, response.getSecurityMode(), "Security mode should match");
        assertEquals(testDialect, response.getDialect(), "Dialect should match");
    }

    @Test
    @DisplayName("Test decode with zero values")
    void testDecodeWithZeroValues() throws SMBProtocolDecodingException {
        // Prepare buffer with all zeros
        byte[] buffer = new byte[50];
        int bufferIndex = 5;

        // Execute decode
        int bytesDecoded = response.decode(buffer, bufferIndex, 24);

        // Verify results
        assertEquals(24, bytesDecoded, "Should decode exactly 24 bytes");
        assertEquals(0, response.getCapabilities(), "Capabilities should be zero");
        assertArrayEquals(new byte[16], response.getServerGuid(), "Server GUID should be all zeros");
        assertEquals(0, response.getSecurityMode(), "Security mode should be zero");
        assertEquals(0, response.getDialect(), "Dialect should be zero");
    }

    @Test
    @DisplayName("Test decode with maximum values")
    void testDecodeWithMaxValues() throws SMBProtocolDecodingException {
        // Prepare test data with maximum values
        byte[] buffer = new byte[50];
        int bufferIndex = 0;

        // Set maximum values
        int testCapabilities = 0xFFFFFFFF;
        byte[] testGuid = new byte[16];
        Arrays.fill(testGuid, (byte) 0xFF);
        int testSecurityMode = 0xFFFF;
        int testDialect = 0xFFFF;

        // Write to buffer
        SMBUtil.writeInt4(testCapabilities, buffer, bufferIndex);
        System.arraycopy(testGuid, 0, buffer, bufferIndex + 4, 16);
        SMBUtil.writeInt2(testSecurityMode, buffer, bufferIndex + 20);
        SMBUtil.writeInt2(testDialect, buffer, bufferIndex + 22);

        // Execute decode
        int bytesDecoded = response.decode(buffer, bufferIndex, 24);

        // Verify results
        assertEquals(24, bytesDecoded, "Should decode exactly 24 bytes");
        assertEquals(testCapabilities, response.getCapabilities(), "Capabilities should match");
        assertArrayEquals(testGuid, response.getServerGuid(), "Server GUID should match");
        assertEquals(testSecurityMode, response.getSecurityMode(), "Security mode should match");
        assertEquals(testDialect, response.getDialect(), "Dialect should match");
    }

    @Test
    @DisplayName("Test initial state of response object")
    void testInitialState() {
        // Verify initial state
        assertEquals(0, response.getCapabilities(), "Initial capabilities should be 0");
        assertNotNull(response.getServerGuid(), "Server GUID should not be null");
        assertEquals(16, response.getServerGuid().length, "Server GUID should be 16 bytes");
        assertArrayEquals(new byte[16], response.getServerGuid(), "Initial server GUID should be all zeros");
        assertEquals(0, response.getSecurityMode(), "Initial security mode should be 0");
        assertEquals(0, response.getDialect(), "Initial dialect should be 0");
    }

    @Test
    @DisplayName("Test decode with real-world SMB3 values")
    void testDecodeWithRealWorldValues() throws SMBProtocolDecodingException {
        // Prepare test data with realistic SMB3 values
        byte[] buffer = new byte[50];
        int bufferIndex = 0;

        // SMB3 capabilities
        int testCapabilities = 0x0000002F; // DFS, LEASING, LARGE_MTU, MULTI_CHANNEL, PERSISTENT_HANDLES, DIRECTORY_LEASING

        // Random but realistic GUID
        byte[] testGuid = { (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
                (byte) 0xFE, (byte) 0xDC, (byte) 0xBA, (byte) 0x98, (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10 };

        // Security mode with signing required
        int testSecurityMode = 0x0003; // SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED

        // SMB 3.1.1 dialect
        int testDialect = 0x0311;

        // Write to buffer
        SMBUtil.writeInt4(testCapabilities, buffer, bufferIndex);
        System.arraycopy(testGuid, 0, buffer, bufferIndex + 4, 16);
        SMBUtil.writeInt2(testSecurityMode, buffer, bufferIndex + 20);
        SMBUtil.writeInt2(testDialect, buffer, bufferIndex + 22);

        // Execute decode
        int bytesDecoded = response.decode(buffer, bufferIndex, 24);

        // Verify results
        assertEquals(24, bytesDecoded, "Should decode exactly 24 bytes");
        assertEquals(testCapabilities, response.getCapabilities(), "Capabilities should match");
        assertArrayEquals(testGuid, response.getServerGuid(), "Server GUID should match");
        assertEquals(testSecurityMode, response.getSecurityMode(), "Security mode should match");
        assertEquals(testDialect, response.getDialect(), "Dialect should match");
    }

    @Test
    @DisplayName("Test decode returns correct bytes consumed")
    void testDecodeBytesConsumed() throws SMBProtocolDecodingException {
        // Prepare minimal buffer
        byte[] buffer = new byte[24];

        // Test with offset 0
        int bytesDecoded = response.decode(buffer, 0, 24);
        assertEquals(24, bytesDecoded, "Should return 24 bytes consumed from offset 0");

        // Test with different offset
        response = new ValidateNegotiateInfoResponse();
        buffer = new byte[50];
        bytesDecoded = response.decode(buffer, 10, 24);
        assertEquals(24, bytesDecoded, "Should return 24 bytes consumed regardless of offset");
    }

    @Test
    @DisplayName("Test server GUID reference")
    void testServerGuidReference() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = new byte[50];
        byte[] originalGuid = new byte[16];
        for (int i = 0; i < 16; i++) {
            originalGuid[i] = (byte) i;
        }
        System.arraycopy(originalGuid, 0, buffer, 4, 16);

        // Decode
        response.decode(buffer, 0, 24);

        // Get the server GUID
        byte[] returnedGuid = response.getServerGuid();

        // Verify it matches original
        assertArrayEquals(originalGuid, returnedGuid, "Returned GUID should match original");

        // Test that the same reference is returned (implementation detail)
        byte[] secondGuid = response.getServerGuid();
        assertSame(returnedGuid, secondGuid, "getServerGuid() returns the same array reference");
    }

    @Test
    @DisplayName("Test multiple decode calls on same instance")
    void testMultipleDecodeCalls() throws SMBProtocolDecodingException {
        // First decode
        byte[] buffer1 = new byte[50];
        SMBUtil.writeInt4(0x11111111, buffer1, 0);
        SMBUtil.writeInt2(0x1111, buffer1, 20);
        SMBUtil.writeInt2(0x0210, buffer1, 22);

        response.decode(buffer1, 0, 24);
        assertEquals(0x11111111, response.getCapabilities(), "First decode capabilities");
        assertEquals(0x1111, response.getSecurityMode(), "First decode security mode");
        assertEquals(0x0210, response.getDialect(), "First decode dialect");

        // Second decode - should overwrite values
        byte[] buffer2 = new byte[50];
        SMBUtil.writeInt4(0x22222222, buffer2, 0);
        SMBUtil.writeInt2(0x2222, buffer2, 20);
        SMBUtil.writeInt2(0x0311, buffer2, 22);

        response.decode(buffer2, 0, 24);
        assertEquals(0x22222222, response.getCapabilities(), "Second decode capabilities");
        assertEquals(0x2222, response.getSecurityMode(), "Second decode security mode");
        assertEquals(0x0311, response.getDialect(), "Second decode dialect");
    }
}
