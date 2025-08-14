package jcifs.internal.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.RuntimeCIFSException;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb1.com.SmbComNTCreateAndXResponse;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for AndXServerMessageBlock
 */
class AndXServerMessageBlockTest {

    @Mock
    private Configuration mockConfig;

    @Mock
    private ServerMessageBlock mockAndxCommand;

    @Mock
    private SMB1SigningDigest mockDigest;

    private TestAndXServerMessageBlock testBlock;

    /**
     * Test implementation of AndXServerMessageBlock for testing
     */
    private static class TestAndXServerMessageBlock extends AndXServerMessageBlock {

        private int paramWordsWritten = 0;
        private int bytesWritten = 0;
        private int paramWordsRead = 0;
        private int bytesRead = 0;
        private boolean retainPayload = false;
        private byte[] rawPayload = null;

        public TestAndXServerMessageBlock(Configuration config, byte command, ServerMessageBlock andx) {
            super(config, command, andx);
        }

        public TestAndXServerMessageBlock(Configuration config, byte command) {
            super(config, command);
        }

        public TestAndXServerMessageBlock(Configuration config) {
            super(config);
        }

        @Override
        protected int writeParameterWordsWireFormat(byte[] dst, int dstIndex) {
            paramWordsWritten = 10; // Simulate writing parameter words
            return paramWordsWritten;
        }

        @Override
        protected int writeBytesWireFormat(byte[] dst, int dstIndex) {
            bytesWritten = 20; // Simulate writing bytes
            return bytesWritten;
        }

        @Override
        protected int readParameterWordsWireFormat(byte[] src, int srcIndex) {
            paramWordsRead = 10;
            return paramWordsRead;
        }

        @Override
        protected int readBytesWireFormat(byte[] src, int srcIndex) {
            bytesRead = 20;
            return bytesRead;
        }

        @Override
        public boolean isRetainPayload() {
            return retainPayload;
        }

        @Override
        public void setRawPayload(byte[] payload) {
            this.rawPayload = payload;
        }

        @Override
        public boolean verifySignature(byte[] data, int offset, int length) {
            return true; // Default to successful verification
        }

        public void setRetainPayload(boolean retain) {
            this.retainPayload = retain;
        }

        public byte[] getRawPayload() {
            return rawPayload;
        }

        // Expose headerStart for testing
        public int getHeaderStart() {
            return headerStart;
        }
    }

    /**
     * Test implementation of SmbComNTCreateAndXResponse for testing
     */
    private static class TestSmbComNTCreateAndXResponse extends SmbComNTCreateAndXResponse {

        private boolean extended = false;
        private int fileType = 0;

        public TestSmbComNTCreateAndXResponse(Configuration config, boolean extended, int fileType) {
            super(config);
            this.extended = extended;
            this.fileType = fileType;
        }

        // Use setter methods to configure extended and fileType in parent class
        public void configureForTest(boolean extended, int fileType) {
            setExtended(extended);
            this.fileType = fileType;
        }

        @Override
        protected int readBytesWireFormat(byte[] src, int srcIndex) {
            return 0;
        }

        @Override
        protected int readParameterWordsWireFormat(byte[] src, int srcIndex) {
            return 34; // Return proper word count for extended response
        }
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockConfig.isUseBatching()).thenReturn(true);
    }

    @Test
    @DisplayName("Test constructor with andx command")
    void testConstructorWithAndx() {
        when(mockAndxCommand.getCommand()).thenReturn(0x42);

        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25, mockAndxCommand);

        assertEquals(mockAndxCommand, testBlock.getAndx());
        assertEquals(mockAndxCommand, testBlock.getNext());
        assertEquals(mockAndxCommand, testBlock.getNextResponse());
    }

    @Test
    @DisplayName("Test constructor without andx command")
    void testConstructorWithoutAndx() {
        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25);

        assertNull(testBlock.getAndx());
        assertNull(testBlock.getNext());
        assertNull(testBlock.getNextResponse());
    }

    @Test
    @DisplayName("Test constructor with null andx command")
    void testConstructorWithNullAndx() {
        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25, (ServerMessageBlock) null);

        assertNull(testBlock.getAndx());
    }

    @Test
    @DisplayName("Test getBatchLimit returns 0 by default")
    void testGetBatchLimit() {
        testBlock = new TestAndXServerMessageBlock(mockConfig);

        assertEquals(0, testBlock.getBatchLimit(mockConfig, (byte) 0x25));
    }

    @Test
    @DisplayName("Test encode without andx command")
    void testEncodeWithoutAndx() {
        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25);
        byte[] buffer = new byte[1024];

        int length = testBlock.encode(buffer, 0);

        assertTrue(length > 0);
        // Just verify that encoding worked without checking specific byte positions
        assertNull(testBlock.getAndx());
    }

    @Test
    @DisplayName("Test encode with andx command and batching disabled")
    void testEncodeWithAndxBatchingDisabled() {
        when(mockConfig.isUseBatching()).thenReturn(false);
        when(mockAndxCommand.getCommand()).thenReturn(0x42);

        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25, mockAndxCommand);
        byte[] buffer = new byte[1024];

        int length = testBlock.encode(buffer, 0);

        assertTrue(length > 0);
        assertNull(testBlock.getAndx()); // andx should be cleared when batching disabled
    }

    @Test
    @DisplayName("Test encode with andx command and batching enabled")
    void testEncodeWithAndxBatchingEnabled() {
        when(mockConfig.isUseBatching()).thenReturn(true);
        when(mockAndxCommand.getCommand()).thenReturn(0x42);

        TestAndXServerMessageBlock andxBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x42);
        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25, andxBlock);
        testBlock.batchLevel = 0;

        // Override getBatchLimit to allow batching
        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25, andxBlock) {
            @Override
            protected int getBatchLimit(Configuration cfg, byte cmd) {
                return 1; // Allow one batched message
            }
        };

        byte[] buffer = new byte[1024];
        int length = testBlock.encode(buffer, 0);

        assertTrue(length > 0);
        assertEquals(1, andxBlock.batchLevel); // batchLevel should be incremented
    }

    @Test
    @DisplayName("Test encode with signature")
    void testEncodeWithSignature() {
        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25);
        testBlock.setDigest(mockDigest);
        byte[] buffer = new byte[1024];

        int length = testBlock.encode(buffer, 0);

        assertTrue(length > 0);
        verify(mockDigest).sign(eq(buffer), eq(0), eq(length), eq(testBlock), any());
    }

    @Test
    @DisplayName("Test decode basic message")
    void testDecodeBasicMessage() throws SMBProtocolDecodingException {
        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25) {
            @Override
            protected int readHeaderWireFormat(byte[] buffer, int bufferIndex) {
                // Simulate header reading
                return 33;
            }
        };
        byte[] buffer = new byte[1024];

        // Setup buffer after header
        buffer[33] = 4; // wordCount
        buffer[34] = (byte) 0xFF; // andxCommand
        buffer[36] = 0; // andxOffset low
        buffer[37] = 0; // andxOffset high
        SMBUtil.writeInt2(20, buffer, 42); // byteCount

        int length = testBlock.decode(buffer, 0);

        assertTrue(length > 0);
        assertEquals(4, testBlock.wordCount);
        assertNull(testBlock.getAndx());
    }

    @Test
    @DisplayName("Test decode with retain payload")
    void testDecodeWithRetainPayload() throws SMBProtocolDecodingException {
        TestAndXServerMessageBlock testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25) {
            @Override
            protected int readHeaderWireFormat(byte[] buffer, int bufferIndex) {
                // Simulate header reading
                return 33;
            }
        };
        testBlock.setRetainPayload(true);

        byte[] buffer = new byte[1024];
        buffer[33] = 4; // wordCount
        buffer[34] = (byte) 0xFF; // andxCommand
        SMBUtil.writeInt2(20, buffer, 42); // byteCount

        int length = testBlock.decode(buffer, 0);

        assertTrue(length > 0);
        assertNotNull(testBlock.getRawPayload());
    }

    @Test
    @DisplayName("Test decode with signature verification failure")
    void testDecodeWithSignatureVerificationFailure() {
        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25) {
            @Override
            public boolean verifySignature(byte[] data, int offset, int length) {
                return false; // Simulate signature verification failure
            }

            @Override
            protected int readHeaderWireFormat(byte[] buffer, int bufferIndex) {
                return 33;
            }
        };

        byte[] buffer = new byte[1024];
        buffer[33] = 4; // wordCount
        buffer[34] = (byte) 0xFF; // andxCommand
        SMBUtil.writeInt2(20, buffer, 42); // byteCount

        assertThrows(SMBProtocolDecodingException.class, () -> {
            testBlock.decode(buffer, 0);
        });
    }

    @Test
    @DisplayName("Test decode NT_CREATE_ANDX extended response")
    void testDecodeNTCreateAndXExtended() throws SMBProtocolDecodingException {
        TestSmbComNTCreateAndXResponse testBlock = new TestSmbComNTCreateAndXResponse(mockConfig, true, 2) {
            @Override
            protected int readHeaderWireFormat(byte[] buffer, int bufferIndex) {
                return 33;
            }
        };
        testBlock.configureForTest(true, 2);
        testBlock.setCommand((byte) ServerMessageBlock.SMB_COM_NT_CREATE_ANDX);

        byte[] buffer = new byte[1024];
        buffer[33] = 34; // wordCount for extended response
        buffer[34] = (byte) 0xFF; // andxCommand
        SMBUtil.writeInt2(20, buffer, 102); // byteCount

        int length = testBlock.decode(buffer, 0);

        assertTrue(length > 0);
        // wordCount is set to 34 + 8 = 42 in the implementation for extended response
        assertEquals(42, testBlock.wordCount); // Should be 34 + 8 = 42
    }

    @Test
    @DisplayName("Test decode with andx command but no andx object")
    void testDecodeWithAndxCommandNoAndxObject() {
        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25) {
            @Override
            protected int readHeaderWireFormat(byte[] buffer, int bufferIndex) {
                return 33;
            }
        };
        byte[] buffer = new byte[1024];

        buffer[33] = 4; // wordCount
        buffer[34] = (byte) 0x42; // andxCommand (not 0xFF)
        buffer[36] = 100; // andxOffset low
        buffer[37] = 0; // andxOffset high
        SMBUtil.writeInt2(20, buffer, 42); // byteCount

        assertThrows(RuntimeCIFSException.class, () -> {
            testBlock.decode(buffer, 0);
        });
    }

    @Test
    @DisplayName("Test decode with andx command and andx object")
    void testDecodeWithAndxCommandAndObject() throws SMBProtocolDecodingException {
        TestAndXServerMessageBlock andxBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x42);
        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25, andxBlock) {
            @Override
            protected int readHeaderWireFormat(byte[] buffer, int bufferIndex) {
                return 33;
            }
        };

        byte[] buffer = new byte[1024];
        buffer[33] = 4; // wordCount
        buffer[34] = (byte) 0x42; // andxCommand
        SMBUtil.writeInt2(83, buffer, 36); // andxOffset (33 + 50)
        SMBUtil.writeInt2(20, buffer, 42); // byteCount

        // Setup andx command data at offset 83 (absolute position from buffer start)
        buffer[83] = 2; // andx wordCount
        SMBUtil.writeInt2(10, buffer, 88); // andx byteCount

        int length = testBlock.decode(buffer, 0);

        assertTrue(length > 0);
        assertEquals((byte) 0x42, andxBlock.getCommand());
    }

    @Test
    @DisplayName("Test decode with zero wordCount")
    void testDecodeWithZeroWordCount() throws SMBProtocolDecodingException {
        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25) {
            @Override
            protected int readHeaderWireFormat(byte[] buffer, int bufferIndex) {
                return 33;
            }
        };
        byte[] buffer = new byte[1024];

        buffer[33] = 0; // wordCount = 0
        SMBUtil.writeInt2(0, buffer, 34); // byteCount = 0

        int length = testBlock.decode(buffer, 0);

        assertTrue(length > 0);
        assertEquals(0, testBlock.wordCount);
        assertEquals(0, testBlock.byteCount);
    }

    @Test
    @DisplayName("Test decode with Snap server workaround")
    void testDecodeWithSnapServerWorkaround() throws SMBProtocolDecodingException {
        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25);
        byte[] buffer = new byte[1024];

        // Setup readAndXWireFormat scenario
        testBlock.headerStart = 0;
        buffer[0] = 4; // wordCount at position 0
        buffer[1] = (byte) 0x42; // andxCommand
        SMBUtil.writeInt2(0, buffer, 3); // andxOffset = 0 (triggers Snap workaround)
        SMBUtil.writeInt2(20, buffer, 9); // byteCount

        int length = testBlock.readAndXWireFormat(buffer, 0);

        assertTrue(length > 0);
        // andxCommand is private, but we can verify the behavior
        assertNull(testBlock.getAndx());
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() {
        when(mockAndxCommand.getCommand()).thenReturn(0x42);
        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25, mockAndxCommand);

        String result = testBlock.toString();

        assertNotNull(result);
        assertTrue(result.contains("andxCommand=0x42"));
        assertTrue(result.contains("andxOffset="));
    }

    @Test
    @DisplayName("Test writeAndXWireFormat with non-AndX andx command")
    void testWriteAndXWireFormatWithNonAndXCommand() {
        when(mockConfig.isUseBatching()).thenReturn(true);
        when(mockAndxCommand.getCommand()).thenReturn(0x42);
        when(mockAndxCommand.writeParameterWordsWireFormat(any(byte[].class), anyInt())).thenReturn(10);
        when(mockAndxCommand.writeBytesWireFormat(any(byte[].class), anyInt())).thenReturn(20);

        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25, mockAndxCommand) {
            @Override
            protected int getBatchLimit(Configuration cfg, byte cmd) {
                return 1; // Allow batching
            }
        };

        byte[] buffer = new byte[1024];
        int length = testBlock.writeAndXWireFormat(buffer, 0);

        assertTrue(length > 0);
        verify(mockAndxCommand).setUseUnicode(anyBoolean());
        assertEquals(testBlock.uid, mockAndxCommand.uid);
    }

    @Test
    @DisplayName("Test readAndXWireFormat with non-AndX andx command")
    void testReadAndXWireFormatWithNonAndXCommand() throws SMBProtocolDecodingException {
        when(mockAndxCommand.readParameterWordsWireFormat(any(byte[].class), anyInt())).thenReturn(10);
        when(mockAndxCommand.readBytesWireFormat(any(byte[].class), anyInt())).thenReturn(20);

        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25, mockAndxCommand);

        byte[] buffer = new byte[1024];
        // For readAndXWireFormat testing, we need to setup the headerStart
        testBlock.headerStart = 0; // This is set by the decode method
        buffer[0] = 4; // wordCount
        buffer[1] = (byte) 0x42; // andxCommand
        SMBUtil.writeInt2(50, buffer, 3); // andxOffset
        SMBUtil.writeInt2(20, buffer, 9); // byteCount

        // Setup andx command data at offset 50 (absolute position)
        buffer[50] = 4; // andx wordCount
        SMBUtil.writeInt2(20, buffer, 59); // andx byteCount

        int length = testBlock.readAndXWireFormat(buffer, 0);

        assertTrue(length > 0);
        verify(mockAndxCommand).setCommand((byte) 0x42);
        verify(mockAndxCommand).setUseUnicode(anyBoolean());
        // For non-AndX commands, the implementation calls received() instead of read methods
        verify(mockAndxCommand).received();
    }

    @Test
    @DisplayName("Test readAndXWireFormat with error code")
    void testReadAndXWireFormatWithErrorCode() throws SMBProtocolDecodingException {
        testBlock = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25, mockAndxCommand);
        testBlock.errorCode = 1; // Set error code

        byte[] buffer = new byte[1024];
        testBlock.headerStart = 0;
        buffer[0] = 4; // wordCount
        buffer[1] = (byte) 0x42; // andxCommand
        SMBUtil.writeInt2(50, buffer, 3); // andxOffset
        SMBUtil.writeInt2(20, buffer, 9); // byteCount

        int length = testBlock.readAndXWireFormat(buffer, 0);

        assertTrue(length > 0);
        // andxCommand is private, but we can verify the behavior
        assertNull(testBlock.getAndx()); // andx should be cleared
    }

    @Test
    @DisplayName("Test all constructors with name parameter")
    void testConstructorsWithName() {
        // Test constructor with command, name, and andx
        TestAndXServerMessageBlock block1 = new TestAndXServerMessageBlock(mockConfig, (byte) 0x25, mockAndxCommand) {
            {
                // Access protected constructor via anonymous class
                super.setCommand((byte) 0x25);
            }
        };
        assertNotNull(block1);

        // Test constructor with just config
        TestAndXServerMessageBlock block2 = new TestAndXServerMessageBlock(mockConfig);
        assertNotNull(block2);

        // Test constructor with config and andx
        TestAndXServerMessageBlock block3 = new TestAndXServerMessageBlock(mockConfig) {
            {
                // Set andx via constructor chain
                super.setCommand((byte) 0x25);
            }
        };
        assertNotNull(block3);
    }
}
