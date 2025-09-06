package org.codelibs.jcifs.smb.internal.smb1.trans2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransaction;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransactionResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class Trans2SetFileInformationResponseTest {

    private Trans2SetFileInformationResponse response;
    private Configuration config;

    @Mock
    private Configuration mockConfig;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        Properties props = new Properties();
        config = new PropertyConfiguration(props);
        response = new Trans2SetFileInformationResponse(config);
    }

    @Test
    @DisplayName("Test constructor initializes object correctly")
    void testConstructor() {
        // Test that the constructor properly initializes the object
        assertNotNull(response);
        // The command is not set in the constructor, defaults to 0
        assertEquals(0, response.getCommand());
        // The subcommand should be TRANS2_SET_FILE_INFORMATION (0x08)
        assertEquals(SmbComTransaction.TRANS2_SET_FILE_INFORMATION, response.getSubCommand());
    }

    @Test
    @DisplayName("Test constructor with mock configuration")
    void testConstructorWithMockConfig() {
        // Test constructor with mock configuration
        Trans2SetFileInformationResponse mockResponse = new Trans2SetFileInformationResponse(mockConfig);
        assertNotNull(mockResponse);
        assertEquals(SmbComTransaction.TRANS2_SET_FILE_INFORMATION, mockResponse.getSubCommand());
    }

    @Test
    @DisplayName("Test writeSetupWireFormat returns 0")
    void testWriteSetupWireFormat() {
        // Test that writeSetupWireFormat always returns 0
        byte[] buffer = new byte[100];
        int result = response.writeSetupWireFormat(buffer, 0);
        assertEquals(0, result);

        // Test with different offset
        result = response.writeSetupWireFormat(buffer, 50);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat returns 0")
    void testWriteParametersWireFormat() {
        // Test that writeParametersWireFormat always returns 0
        byte[] buffer = new byte[100];
        int result = response.writeParametersWireFormat(buffer, 0);
        assertEquals(0, result);

        // Test with different offset
        result = response.writeParametersWireFormat(buffer, 25);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeDataWireFormat returns 0")
    void testWriteDataWireFormat() {
        // Test that writeDataWireFormat always returns 0
        byte[] buffer = new byte[100];
        int result = response.writeDataWireFormat(buffer, 0);
        assertEquals(0, result);

        // Test with different offset
        result = response.writeDataWireFormat(buffer, 75);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readSetupWireFormat returns 0")
    void testReadSetupWireFormat() {
        // Test that readSetupWireFormat always returns 0
        byte[] buffer = new byte[100];
        int result = response.readSetupWireFormat(buffer, 0, 100);
        assertEquals(0, result);

        // Test with different parameters
        result = response.readSetupWireFormat(buffer, 10, 50);
        assertEquals(0, result);

        // Test with zero length
        result = response.readSetupWireFormat(buffer, 0, 0);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readParametersWireFormat returns 0")
    void testReadParametersWireFormat() {
        // Test that readParametersWireFormat always returns 0
        byte[] buffer = new byte[100];
        int result = response.readParametersWireFormat(buffer, 0, 100);
        assertEquals(0, result);

        // Test with different parameters
        result = response.readParametersWireFormat(buffer, 20, 30);
        assertEquals(0, result);

        // Test with zero length
        result = response.readParametersWireFormat(buffer, 0, 0);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readDataWireFormat returns 0")
    void testReadDataWireFormat() {
        // Test that readDataWireFormat always returns 0
        byte[] buffer = new byte[100];
        int result = response.readDataWireFormat(buffer, 0, 100);
        assertEquals(0, result);

        // Test with different parameters
        result = response.readDataWireFormat(buffer, 15, 85);
        assertEquals(0, result);

        // Test with zero length
        result = response.readDataWireFormat(buffer, 0, 0);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() {
        // Test the toString method
        String result = response.toString();
        assertNotNull(result);
        assertTrue(result.contains("Trans2SetFileInformationResponse"));
        assertTrue(result.contains("["));
        assertTrue(result.contains("]"));
    }

    @Test
    @DisplayName("Test inherited properties from SmbComTransactionResponse")
    void testInheritedProperties() {
        // Test that inherited properties are accessible

        // Test dataCount property - using public method
        response.setDataCount(100);
        // Note: getDataCount() is protected, so we can't test it directly

        // Test subCommand property
        assertEquals(SmbComTransaction.TRANS2_SET_FILE_INFORMATION, response.getSubCommand());

        // Test status property - getStatus() is public
        assertEquals(0, response.getStatus());

        // Test numEntries property - getNumEntries() is public
        assertEquals(0, response.getNumEntries());

        // Test results property (should be null initially) - getResults() is public
        assertNull(response.getResults());
    }

    @Test
    @DisplayName("Test buffer management")
    void testBufferManagement() {
        // Test buffer setting and releasing
        byte[] testBuffer = new byte[1024];
        response.setBuffer(testBuffer);

        byte[] releasedBuffer = response.releaseBuffer();
        assertSame(testBuffer, releasedBuffer);

        // After release, the buffer should be null
        assertNull(response.releaseBuffer());
    }

    @Test
    @DisplayName("Test hasMoreElements inherited behavior")
    void testHasMoreElements() {
        // Initially should have more elements if error code is 0
        assertTrue(response.hasMoreElements());

        // After calling nextElement once, isPrimary becomes false but hasMore is still true initially
        response.nextElement();

        // Can still have more elements
        assertTrue(response.hasMoreElements());
    }

    @Test
    @DisplayName("Test reset method")
    void testReset() {
        // Set some values
        response.setDataCount(50);

        // Call reset
        response.reset();

        // After reset, hasMore should be true
        assertTrue(response.hasMoreElements());
    }

    @Test
    @DisplayName("Test all write methods with null buffer")
    void testWriteMethodsWithNullBuffer() {
        // Even with null buffer, methods should return 0 without throwing exception
        int result = response.writeSetupWireFormat(null, 0);
        assertEquals(0, result);

        result = response.writeParametersWireFormat(null, 0);
        assertEquals(0, result);

        result = response.writeDataWireFormat(null, 0);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test all read methods with null buffer")
    void testReadMethodsWithNullBuffer() {
        // Even with null buffer, methods should return 0 without throwing exception
        int result = response.readSetupWireFormat(null, 0, 0);
        assertEquals(0, result);

        result = response.readParametersWireFormat(null, 0, 0);
        assertEquals(0, result);

        result = response.readDataWireFormat(null, 0, 0);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test boundary conditions for buffer offsets")
    void testBoundaryConditions() {
        byte[] smallBuffer = new byte[10];

        // Test with maximum offset
        int result = response.writeSetupWireFormat(smallBuffer, Integer.MAX_VALUE);
        assertEquals(0, result);

        result = response.readSetupWireFormat(smallBuffer, Integer.MAX_VALUE, 0);
        assertEquals(0, result);

        // Test with negative length (should still return 0)
        result = response.readParametersWireFormat(smallBuffer, 0, -1);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test command type is correct")
    void testCommandType() {
        // Verify that the command is not set in constructor (defaults to 0)
        assertEquals(0, response.getCommand());

        // Verify we can change the subcommand
        response.setSubCommand((byte) 0xFF);
        assertEquals((byte) 0xFF, response.getSubCommand());

        // But creating a new instance should have the correct subcommand
        Trans2SetFileInformationResponse newResponse = new Trans2SetFileInformationResponse(config);
        assertEquals(SmbComTransaction.TRANS2_SET_FILE_INFORMATION, newResponse.getSubCommand());
    }

    @Test
    @DisplayName("Test multiple sequential calls to read/write methods")
    void testMultipleSequentialCalls() {
        byte[] buffer = new byte[200];

        // Multiple calls should each return 0
        for (int i = 0; i < 10; i++) {
            assertEquals(0, response.writeSetupWireFormat(buffer, i * 10));
            assertEquals(0, response.writeParametersWireFormat(buffer, i * 10));
            assertEquals(0, response.writeDataWireFormat(buffer, i * 10));
            assertEquals(0, response.readSetupWireFormat(buffer, i * 10, 10));
            assertEquals(0, response.readParametersWireFormat(buffer, i * 10, 10));
            assertEquals(0, response.readDataWireFormat(buffer, i * 10, 10));
        }
    }

    @Test
    @DisplayName("Test toString contains proper class name")
    void testToStringFormat() {
        String str = response.toString();

        // Should start with the class name
        assertTrue(str.startsWith("Trans2SetFileInformationResponse["));

        // Should end with closing bracket
        assertTrue(str.endsWith("]"));

        // Should contain parent toString content
        // Note: The parent toString might include various fields
        assertNotNull(str);
        assertTrue(str.length() > "Trans2SetFileInformationResponse[]".length());
    }

    @Test
    @DisplayName("Test decode method")
    void testDecode() throws Exception {
        // Test the decode method which is inherited from ServerMessageBlock
        byte[] buffer = new byte[256];

        // Set up a minimal SMB header (size 32 bytes)
        // SMB signature
        buffer[0] = (byte) 0xFF;
        buffer[1] = 'S';
        buffer[2] = 'M';
        buffer[3] = 'B';

        // Command - SMB_COM_TRANSACTION2
        buffer[4] = ServerMessageBlock.SMB_COM_TRANSACTION2;

        // Status (4 bytes) - success
        buffer[5] = 0x00;
        buffer[6] = 0x00;
        buffer[7] = 0x00;
        buffer[8] = 0x00;

        // Flags
        buffer[9] = 0x00;

        // Flags2 (2 bytes)
        buffer[10] = 0x00;
        buffer[11] = 0x00;

        // Process ID High (2 bytes)
        buffer[12] = 0x00;
        buffer[13] = 0x00;

        // Signature (8 bytes)
        for (int i = 14; i < 22; i++) {
            buffer[i] = 0x00;
        }

        // Reserved (2 bytes)
        buffer[22] = 0x00;
        buffer[23] = 0x00;

        // TID (2 bytes)
        buffer[24] = 0x01;
        buffer[25] = 0x00;

        // PID (2 bytes)
        buffer[26] = 0x02;
        buffer[27] = 0x00;

        // UID (2 bytes)
        buffer[28] = 0x03;
        buffer[29] = 0x00;

        // MID (2 bytes)
        buffer[30] = 0x04;
        buffer[31] = 0x00;

        // Word count
        buffer[32] = 10; // 10 words = 20 bytes

        // Parameter words for transaction response
        // Total parameter count (2 bytes)
        buffer[33] = 0x00;
        buffer[34] = 0x00;

        // Total data count (2 bytes)
        buffer[35] = 0x00;
        buffer[36] = 0x00;

        // Reserved (2 bytes)
        buffer[37] = 0x00;
        buffer[38] = 0x00;

        // Parameter count (2 bytes)
        buffer[39] = 0x00;
        buffer[40] = 0x00;

        // Parameter offset (2 bytes)
        buffer[41] = 0x00;
        buffer[42] = 0x00;

        // Parameter displacement (2 bytes)
        buffer[43] = 0x00;
        buffer[44] = 0x00;

        // Data count (2 bytes)
        buffer[45] = 0x00;
        buffer[46] = 0x00;

        // Data offset (2 bytes)
        buffer[47] = 0x00;
        buffer[48] = 0x00;

        // Data displacement (2 bytes)
        buffer[49] = 0x00;
        buffer[50] = 0x00;

        // Setup count (1 byte)
        buffer[51] = 0x00;

        // Reserved (1 byte)
        buffer[52] = 0x00;

        // Byte count (2 bytes)
        buffer[53] = 0x00;
        buffer[54] = 0x00;

        // Test decode
        int bytesDecoded = response.decode(buffer, 0);

        // Should decode at least the header
        assertTrue(bytesDecoded > 0);

        // Verify the command was decoded correctly
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION2, response.getCommand());
    }

    @Test
    @DisplayName("Test nextElement method")
    void testNextElement() {
        // Test the nextElement method from Enumeration interface
        SmbComTransactionResponse element = response.nextElement();

        // Should return itself
        assertSame(response, element);

        // Can be called multiple times
        element = response.nextElement();
        assertSame(response, element);
    }

    @Test
    @DisplayName("Test with various Configuration implementations")
    void testWithDifferentConfigurations() throws Exception {
        // Test with different configuration settings
        Properties props = new Properties();
        props.setProperty("jcifs.client.maxVersion", "SMB302");
        Configuration customConfig = new PropertyConfiguration(props);

        Trans2SetFileInformationResponse customResponse = new Trans2SetFileInformationResponse(customConfig);
        assertNotNull(customResponse);
        assertEquals(SmbComTransaction.TRANS2_SET_FILE_INFORMATION, customResponse.getSubCommand());
    }

    @Test
    @DisplayName("Test concurrent access")
    void testConcurrentAccess() throws InterruptedException {
        // Test thread safety - multiple threads accessing the same response
        final int THREAD_COUNT = 10;
        Thread[] threads = new Thread[THREAD_COUNT];
        final boolean[] success = new boolean[THREAD_COUNT];

        for (int i = 0; i < THREAD_COUNT; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                try {
                    // Each thread performs operations on the response
                    byte[] buffer = new byte[100];
                    response.writeSetupWireFormat(buffer, 0);
                    response.readParametersWireFormat(buffer, 0, 100);
                    response.toString();
                    success[index] = true;
                } catch (Exception e) {
                    success[index] = false;
                }
            });
            threads[i].start();
        }

        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }

        // All threads should complete successfully
        for (boolean s : success) {
            assertTrue(s);
        }
    }
}
