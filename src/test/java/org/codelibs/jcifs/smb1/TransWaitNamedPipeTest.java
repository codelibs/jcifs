package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;

/**
 * Unit tests for the {@link TransWaitNamedPipe} transaction.
 * The transaction is package private, so the test class lives in the
 * same package to access its fields.
 */
public class TransWaitNamedPipeTest {

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    @DisplayName("Constructor should initialize fields correctly")
    public void constructorShouldInitializeFields() {
        // Test constructor initialization with proper expectations
        String pipeName = "\\\\pipe\\testPipe";
        TransWaitNamedPipe pipe = new TransWaitNamedPipe(pipeName);

        // Verify the name is set correctly
        assertEquals(pipeName, pipe.name);

        // Command should be SMB_COM_TRANSACTION
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION, pipe.command);

        // SubCommand should be TRANS_WAIT_NAMED_PIPE (0x53)
        assertEquals(SmbComTransaction.TRANS_WAIT_NAMED_PIPE, pipe.subCommand);

        // Timeout is set to 0xFFFFFFFF (-1 when cast to int)
        assertEquals(0xFFFFFFFF, pipe.timeout);

        // Max parameter and data counts should be 0
        assertEquals(0, pipe.maxParameterCount);
        assertEquals(0, pipe.maxDataCount);

        // Max setup count should be 0
        assertEquals(0, pipe.maxSetupCount);

        // Setup count should be 2 (as per actual implementation)
        assertEquals(2, pipe.setupCount);
    }

    @Test
    @DisplayName("writeSetupWireFormat should write 4 bytes with subCommand")
    public void writeSetupWireFormatShouldWriteCorrectBytes() {
        // Test the writeSetupWireFormat method
        TransWaitNamedPipe pipe = new TransWaitNamedPipe("\\\\pipe\\testPipe");
        byte[] dst = new byte[10];

        // writeSetupWireFormat writes 4 bytes:
        // - subCommand byte
        // - 3 zero bytes (padding and no FID)
        int written = pipe.writeSetupWireFormat(dst, 0);

        assertEquals(4, written, "Setup should write 4 bytes");
        assertEquals(SmbComTransaction.TRANS_WAIT_NAMED_PIPE, dst[0], "First byte should be subCommand");
        assertEquals(0, dst[1], "Second byte should be 0");
        assertEquals(0, dst[2], "Third byte should be 0 (no FID)");
        assertEquals(0, dst[3], "Fourth byte should be 0 (no FID)");
    }

    @Test
    @DisplayName("readSetupWireFormat should always return 0")
    public void readSetupWireFormatShouldReturnZero() {
        // Test the readSetupWireFormat method
        TransWaitNamedPipe pipe = new TransWaitNamedPipe("\\\\pipe\\testPipe");
        byte[] buffer = new byte[10];

        // The implementation always returns 0
        int consumed = pipe.readSetupWireFormat(buffer, 0, 4);
        assertEquals(0, consumed, "readSetupWireFormat should always return 0");
    }

    @Test
    @DisplayName("writeParametersWireFormat should return 0")
    public void writeParametersWireFormatShouldReturnZero() {
        // Test that writeParametersWireFormat returns 0
        TransWaitNamedPipe pipe = new TransWaitNamedPipe("\\\\pipe\\testPipe");
        byte[] dst = new byte[100];

        int written = pipe.writeParametersWireFormat(dst, 0);
        assertEquals(0, written, "writeParametersWireFormat should return 0");
    }

    @Test
    @DisplayName("writeDataWireFormat should return 0")
    public void writeDataWireFormatShouldReturnZero() {
        // Test that writeDataWireFormat returns 0
        TransWaitNamedPipe pipe = new TransWaitNamedPipe("\\\\pipe\\testPipe");
        byte[] dst = new byte[100];

        int written = pipe.writeDataWireFormat(dst, 0);
        assertEquals(0, written, "writeDataWireFormat should return 0");
    }

    @Test
    @DisplayName("readParametersWireFormat should return 0")
    public void readParametersWireFormatShouldReturnZero() {
        // Test that readParametersWireFormat returns 0
        TransWaitNamedPipe pipe = new TransWaitNamedPipe("\\\\pipe\\testPipe");
        byte[] buffer = new byte[100];

        int consumed = pipe.readParametersWireFormat(buffer, 0, 10);
        assertEquals(0, consumed, "readParametersWireFormat should return 0");
    }

    @Test
    @DisplayName("readDataWireFormat should return 0")
    public void readDataWireFormatShouldReturnZero() {
        // Test that readDataWireFormat returns 0
        TransWaitNamedPipe pipe = new TransWaitNamedPipe("\\\\pipe\\testPipe");
        byte[] buffer = new byte[100];

        int consumed = pipe.readDataWireFormat(buffer, 0, 10);
        assertEquals(0, consumed, "readDataWireFormat should return 0");
    }

    @Test
    @DisplayName("toString should contain class name and pipe name")
    public void toStringShouldContainClassAndPipeName() {
        // Test the toString method
        String pipeName = "\\\\pipe\\testPipe";
        TransWaitNamedPipe pipe = new TransWaitNamedPipe(pipeName);

        String result = pipe.toString();
        assertNotNull(result);
        assertTrue(result.contains("TransWaitNamedPipe"), "toString should contain class name");
        assertTrue(result.contains(pipeName), "toString should contain pipe name");
    }

    @Test
    @DisplayName("Constructor should work with various pipe names")
    public void constructorShouldWorkWithVariousPipeNames() {
        // Test with various pipe names
        String[] pipeNames = { "\\\\pipe\\test", "\\\\pipe\\PIPE\\sql\\query", "\\\\pipe\\spoolss", "\\\\pipe\\winreg" };

        for (String pipeName : pipeNames) {
            TransWaitNamedPipe pipe = new TransWaitNamedPipe(pipeName);
            assertEquals(pipeName, pipe.name, "Pipe name should be preserved: " + pipeName);
            assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION, pipe.command);
            assertEquals(SmbComTransaction.TRANS_WAIT_NAMED_PIPE, pipe.subCommand);
        }
    }
}