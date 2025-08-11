package jcifs.internal.smb1.trans;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;

/**
 * Test class for TransWaitNamedPipe
 */
class TransWaitNamedPipeTest {

    @Mock
    private Configuration mockConfig;

    private TransWaitNamedPipe transWaitNamedPipe;
    private String testPipeName = "\\PIPE\\testpipe";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    @DisplayName("Constructor should initialize with correct values")
    void testConstructor() {
        // Act
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, testPipeName);

        // Assert
        assertNotNull(transWaitNamedPipe);
        assertEquals(testPipeName, transWaitNamedPipe.name);
        assertEquals(0xFFFFFFFF, transWaitNamedPipe.timeout);
        assertEquals(0, transWaitNamedPipe.maxParameterCount);
        assertEquals(0, transWaitNamedPipe.maxDataCount);
        assertEquals((byte) 0x00, transWaitNamedPipe.maxSetupCount);
        assertEquals(2, transWaitNamedPipe.setupCount);
    }

    @Test
    @DisplayName("Constructor with null pipe name should handle gracefully")
    void testConstructorWithNullPipeName() {
        // Act
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, null);

        // Assert
        assertNotNull(transWaitNamedPipe);
        assertNull(transWaitNamedPipe.name);
    }

    @Test
    @DisplayName("Constructor with empty pipe name should handle gracefully")
    void testConstructorWithEmptyPipeName() {
        // Act
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, "");

        // Assert
        assertNotNull(transWaitNamedPipe);
        assertEquals("", transWaitNamedPipe.name);
    }

    @Test
    @DisplayName("writeSetupWireFormat should write correct bytes")
    void testWriteSetupWireFormat() {
        // Arrange
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, testPipeName);
        byte[] dst = new byte[10];
        int dstIndex = 0;

        // Act
        int bytesWritten = transWaitNamedPipe.writeSetupWireFormat(dst, dstIndex);

        // Assert
        assertEquals(4, bytesWritten);
        assertEquals(SmbComTransaction.TRANS_WAIT_NAMED_PIPE, dst[0]);
        assertEquals((byte) 0x00, dst[1]);
        assertEquals((byte) 0x00, dst[2]); // no FID
        assertEquals((byte) 0x00, dst[3]);
    }

    @Test
    @DisplayName("writeSetupWireFormat with offset should write at correct position")
    void testWriteSetupWireFormatWithOffset() {
        // Arrange
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, testPipeName);
        byte[] dst = new byte[20];
        int dstIndex = 5;

        // Act
        int bytesWritten = transWaitNamedPipe.writeSetupWireFormat(dst, dstIndex);

        // Assert
        assertEquals(4, bytesWritten);
        assertEquals(SmbComTransaction.TRANS_WAIT_NAMED_PIPE, dst[5]);
        assertEquals((byte) 0x00, dst[6]);
        assertEquals((byte) 0x00, dst[7]);
        assertEquals((byte) 0x00, dst[8]);
    }

    @Test
    @DisplayName("readSetupWireFormat should return 0")
    void testReadSetupWireFormat() {
        // Arrange
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, testPipeName);
        byte[] buffer = new byte[10];

        // Act
        int result = transWaitNamedPipe.readSetupWireFormat(buffer, 0, 10);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("writeParametersWireFormat should return 0")
    void testWriteParametersWireFormat() {
        // Arrange
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, testPipeName);
        byte[] dst = new byte[10];

        // Act
        int result = transWaitNamedPipe.writeParametersWireFormat(dst, 0);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("writeDataWireFormat should return 0")
    void testWriteDataWireFormat() {
        // Arrange
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, testPipeName);
        byte[] dst = new byte[10];

        // Act
        int result = transWaitNamedPipe.writeDataWireFormat(dst, 0);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("readParametersWireFormat should return 0")
    void testReadParametersWireFormat() {
        // Arrange
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, testPipeName);
        byte[] buffer = new byte[10];

        // Act
        int result = transWaitNamedPipe.readParametersWireFormat(buffer, 0, 10);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("readDataWireFormat should return 0")
    void testReadDataWireFormat() {
        // Arrange
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, testPipeName);
        byte[] buffer = new byte[10];

        // Act
        int result = transWaitNamedPipe.readDataWireFormat(buffer, 0, 10);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("toString should return formatted string with pipe name")
    void testToString() {
        // Arrange
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, testPipeName);

        // Act
        String result = transWaitNamedPipe.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("TransWaitNamedPipe"));
        assertTrue(result.contains("pipeName=" + testPipeName));
    }

    @Test
    @DisplayName("toString with null pipe name should handle gracefully")
    void testToStringWithNullPipeName() {
        // Arrange
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, null);

        // Act
        String result = transWaitNamedPipe.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("TransWaitNamedPipe"));
        assertTrue(result.contains("pipeName=null"));
    }

    @Test
    @DisplayName("toString with special characters in pipe name")
    void testToStringWithSpecialCharacters() {
        // Arrange
        String specialPipeName = "\\PIPE\\test$pipe#123";
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, specialPipeName);

        // Act
        String result = transWaitNamedPipe.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("pipeName=" + specialPipeName));
    }

    @Test
    @DisplayName("Verify parent class command types")
    void testParentClassCommandTypes() {
        // Arrange
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, testPipeName);

        // Assert
        assertEquals(SmbComTransaction.SMB_COM_TRANSACTION, transWaitNamedPipe.getCommand());
        assertEquals(SmbComTransaction.TRANS_WAIT_NAMED_PIPE, transWaitNamedPipe.getSubCommand());
    }

    @Test
    @DisplayName("Multiple wire format operations should be consistent")
    void testMultipleWireFormatOperations() {
        // Arrange
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, testPipeName);
        byte[] dst1 = new byte[10];
        byte[] dst2 = new byte[10];

        // Act
        int result1 = transWaitNamedPipe.writeSetupWireFormat(dst1, 0);
        int result2 = transWaitNamedPipe.writeSetupWireFormat(dst2, 0);

        // Assert
        assertEquals(result1, result2);
        assertArrayEquals(dst1, dst2);
    }

    @Test
    @DisplayName("Boundary test for writeSetupWireFormat with minimum buffer")
    void testWriteSetupWireFormatMinimumBuffer() {
        // Arrange
        transWaitNamedPipe = new TransWaitNamedPipe(mockConfig, testPipeName);
        byte[] dst = new byte[4]; // Minimum required size

        // Act
        int bytesWritten = transWaitNamedPipe.writeSetupWireFormat(dst, 0);

        // Assert
        assertEquals(4, bytesWritten);
        assertEquals(SmbComTransaction.TRANS_WAIT_NAMED_PIPE, dst[0]);
    }

    @Test
    @DisplayName("Test with various pipe name formats")
    void testVariousPipeNameFormats() {
        // Test various pipe name formats
        String[] pipeNames = {
            "\\\\server\\PIPE\\testpipe",
            "\\PIPE\\LANMAN",
            "\\PIPE\\srvsvc",
            "\\PIPE\\wkssvc",
            "PIPE\\test",
            "testpipe"
        };

        for (String pipeName : pipeNames) {
            // Act
            TransWaitNamedPipe trans = new TransWaitNamedPipe(mockConfig, pipeName);

            // Assert
            assertEquals(pipeName, trans.name);
            assertEquals(0xFFFFFFFF, trans.timeout);
        }
    }
}
