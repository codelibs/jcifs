package jcifs.internal.smb1.trans;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.internal.util.SMBUtil;

class TransPeekNamedPipeTest {

    @Mock
    private Configuration mockConfig;

    private TransPeekNamedPipe transPeekNamedPipe;
    private static final String TEST_PIPE_NAME = "\\PIPE\\testpipe";
    private static final int TEST_FID = 0x1234;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    @DisplayName("Constructor should initialize with correct values")
    void testConstructor() {
        // Act
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_FID);

        // Assert
        assertNotNull(transPeekNamedPipe);
        assertEquals(TEST_PIPE_NAME, transPeekNamedPipe.name);
        assertEquals(0xFFFFFFFF, transPeekNamedPipe.timeout);
        assertEquals(6, transPeekNamedPipe.maxParameterCount);
        assertEquals(1, transPeekNamedPipe.maxDataCount);
        assertEquals((byte) 0x00, transPeekNamedPipe.maxSetupCount);
        assertEquals(2, transPeekNamedPipe.setupCount);
    }

    @Test
    @DisplayName("Constructor should work with null pipe name")
    void testConstructorWithNullPipeName() {
        // Act
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, null, TEST_FID);

        // Assert
        assertNotNull(transPeekNamedPipe);
        assertNull(transPeekNamedPipe.name);
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, -1, Integer.MAX_VALUE, Integer.MIN_VALUE, 0xFFFF })
    @DisplayName("Constructor should handle various FID values")
    void testConstructorWithVariousFids(int fid) {
        // Act
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, fid);

        // Assert
        assertNotNull(transPeekNamedPipe);
        // FID is written in writeSetupWireFormat, verify it there
    }

    @Test
    @DisplayName("writeSetupWireFormat should write correct bytes")
    void testWriteSetupWireFormat() {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_FID);
        byte[] buffer = new byte[10];
        int offset = 2;

        // Act
        int bytesWritten = transPeekNamedPipe.writeSetupWireFormat(buffer, offset);

        // Assert
        assertEquals(4, bytesWritten);
        assertEquals(SmbComTransaction.TRANS_PEEK_NAMED_PIPE, buffer[offset]);
        assertEquals((byte) 0x00, buffer[offset + 1]);

        // Verify FID is written correctly (little-endian)
        int writtenFid = SMBUtil.readInt2(buffer, offset + 2);
        assertEquals(TEST_FID, writtenFid);
    }

    @Test
    @DisplayName("writeSetupWireFormat should handle buffer boundary")
    void testWriteSetupWireFormatAtBufferEnd() {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_FID);
        byte[] buffer = new byte[4];
        int offset = 0;

        // Act
        int bytesWritten = transPeekNamedPipe.writeSetupWireFormat(buffer, offset);

        // Assert
        assertEquals(4, bytesWritten);
        assertEquals(SmbComTransaction.TRANS_PEEK_NAMED_PIPE, buffer[0]);
        assertEquals((byte) 0x00, buffer[1]);
    }

    @ParameterizedTest
    @MethodSource("provideFidTestCases")
    @DisplayName("writeSetupWireFormat should correctly encode various FID values")
    void testWriteSetupWireFormatWithVariousFids(int fid, byte expectedLow, byte expectedHigh) {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, fid);
        byte[] buffer = new byte[10];
        int offset = 0;

        // Act
        int bytesWritten = transPeekNamedPipe.writeSetupWireFormat(buffer, offset);

        // Assert
        assertEquals(4, bytesWritten);
        assertEquals(expectedLow, buffer[offset + 2]);
        assertEquals(expectedHigh, buffer[offset + 3]);
    }

    private static Stream<Arguments> provideFidTestCases() {
        return Stream.of(Arguments.of(0x0000, (byte) 0x00, (byte) 0x00), Arguments.of(0x00FF, (byte) 0xFF, (byte) 0x00),
                Arguments.of(0xFF00, (byte) 0x00, (byte) 0xFF), Arguments.of(0xFFFF, (byte) 0xFF, (byte) 0xFF),
                Arguments.of(0x1234, (byte) 0x34, (byte) 0x12));
    }

    @Test
    @DisplayName("readSetupWireFormat should return 0")
    void testReadSetupWireFormat() {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_FID);
        byte[] buffer = new byte[10];

        // Act
        int result = transPeekNamedPipe.readSetupWireFormat(buffer, 0, buffer.length);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("writeParametersWireFormat should return 0")
    void testWriteParametersWireFormat() {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_FID);
        byte[] buffer = new byte[10];

        // Act
        int result = transPeekNamedPipe.writeParametersWireFormat(buffer, 0);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("writeDataWireFormat should return 0")
    void testWriteDataWireFormat() {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_FID);
        byte[] buffer = new byte[10];

        // Act
        int result = transPeekNamedPipe.writeDataWireFormat(buffer, 0);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("readParametersWireFormat should return 0")
    void testReadParametersWireFormat() {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_FID);
        byte[] buffer = new byte[10];

        // Act
        int result = transPeekNamedPipe.readParametersWireFormat(buffer, 0, buffer.length);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("readDataWireFormat should return 0")
    void testReadDataWireFormat() {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_FID);
        byte[] buffer = new byte[10];

        // Act
        int result = transPeekNamedPipe.readDataWireFormat(buffer, 0, buffer.length);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("toString should return correct format with pipe name")
    void testToString() {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_FID);

        // Act
        String result = transPeekNamedPipe.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("TransPeekNamedPipe"));
        assertTrue(result.contains("pipeName=" + TEST_PIPE_NAME));
    }

    @Test
    @DisplayName("toString should handle null pipe name")
    void testToStringWithNullPipeName() {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, null, TEST_FID);

        // Act
        String result = transPeekNamedPipe.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("TransPeekNamedPipe"));
        assertTrue(result.contains("pipeName=null"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { "\\PIPE\\test", "testpipe", "\\\\server\\pipe\\test", " ", "pipe with spaces" })
    @DisplayName("toString should handle various pipe names")
    void testToStringWithVariousPipeNames(String pipeName) {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, pipeName, TEST_FID);

        // Act
        String result = transPeekNamedPipe.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("TransPeekNamedPipe"));
        if (pipeName != null) {
            assertTrue(result.contains("pipeName=" + pipeName));
        } else {
            assertTrue(result.contains("pipeName=null"));
        }
    }

    @Test
    @DisplayName("Should verify command and subcommand are set correctly")
    void testCommandAndSubCommand() {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_FID);

        // Assert
        assertEquals(SmbComTransaction.SMB_COM_TRANSACTION, transPeekNamedPipe.getCommand());
        assertEquals(SmbComTransaction.TRANS_PEEK_NAMED_PIPE, transPeekNamedPipe.getSubCommand());
    }

    @Test
    @DisplayName("Should handle edge case with zero FID")
    void testZeroFid() {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, 0);
        byte[] buffer = new byte[10];

        // Act
        int bytesWritten = transPeekNamedPipe.writeSetupWireFormat(buffer, 0);

        // Assert
        assertEquals(4, bytesWritten);
        assertEquals(SmbComTransaction.TRANS_PEEK_NAMED_PIPE, buffer[0]);
        assertEquals((byte) 0x00, buffer[1]);
        assertEquals((byte) 0x00, buffer[2]);
        assertEquals((byte) 0x00, buffer[3]);
    }

    @Test
    @DisplayName("Should handle negative FID values")
    void testNegativeFid() {
        // Arrange
        int negativeFid = -1;
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, negativeFid);
        byte[] buffer = new byte[10];

        // Act
        int bytesWritten = transPeekNamedPipe.writeSetupWireFormat(buffer, 0);

        // Assert
        assertEquals(4, bytesWritten);
        // -1 in 16-bit is 0xFFFF
        assertEquals((byte) 0xFF, buffer[2]);
        assertEquals((byte) 0xFF, buffer[3]);
    }

    @Test
    @DisplayName("Should verify all read methods return 0 with various parameters")
    void testAllReadMethodsReturnZero() {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_FID);
        byte[] smallBuffer = new byte[1];
        byte[] largeBuffer = new byte[1000];

        // Act & Assert
        assertEquals(0, transPeekNamedPipe.readSetupWireFormat(smallBuffer, 0, 1));
        assertEquals(0, transPeekNamedPipe.readSetupWireFormat(largeBuffer, 500, 500));
        assertEquals(0, transPeekNamedPipe.readParametersWireFormat(smallBuffer, 0, 1));
        assertEquals(0, transPeekNamedPipe.readParametersWireFormat(largeBuffer, 999, 1));
        assertEquals(0, transPeekNamedPipe.readDataWireFormat(smallBuffer, 0, 1));
        assertEquals(0, transPeekNamedPipe.readDataWireFormat(largeBuffer, 0, 1000));
    }

    @Test
    @DisplayName("Should verify all write methods except setup return 0")
    void testWriteMethodsReturnCorrectValues() {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_FID);
        byte[] buffer = new byte[100];

        // Act & Assert
        assertEquals(4, transPeekNamedPipe.writeSetupWireFormat(buffer, 0));
        assertEquals(0, transPeekNamedPipe.writeParametersWireFormat(buffer, 10));
        assertEquals(0, transPeekNamedPipe.writeDataWireFormat(buffer, 20));
    }

    @Test
    @DisplayName("Should handle concurrent access to toString")
    void testToStringConcurrency() throws InterruptedException {
        // Arrange
        transPeekNamedPipe = new TransPeekNamedPipe(mockConfig, TEST_PIPE_NAME, TEST_FID);
        String[] results = new String[10];
        Thread[] threads = new Thread[10];

        // Act
        for (int i = 0; i < threads.length; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                results[index] = transPeekNamedPipe.toString();
            });
            threads[i].start();
        }

        for (Thread thread : threads) {
            thread.join();
        }

        // Assert
        for (String result : results) {
            assertNotNull(result);
            assertTrue(result.contains("TransPeekNamedPipe"));
            assertTrue(result.contains("pipeName=" + TEST_PIPE_NAME));
        }
    }
}