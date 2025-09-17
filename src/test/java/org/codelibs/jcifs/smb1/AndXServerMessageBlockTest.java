package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * JUnit 5 tests for AndXServerMessageBlock in legacy smb1 package.
 *
 * The tests use small stub subclasses to drive encode/decode paths and
 * validate batching, chaining, signing, and NT_CREATE_ANDX extended handling.
 */
class AndXServerMessageBlockTest {

    /**
     * Test stub for AndXServerMessageBlock to control read/write logic.
     */
    static class DummyAndXBlock extends AndXServerMessageBlock {
        int paramWordsWritten = 0;
        int bytesWritten = 0;
        int paramWordsRead = 0;
        int bytesRead = 0;
        Integer customBatchLimit = null;

        DummyAndXBlock() {
            super();
        }

        DummyAndXBlock(ServerMessageBlock andx) {
            super(andx);
        }

        @Override
        int writeParameterWordsWireFormat(byte[] dst, int dstIndex) {
            paramWordsWritten = 10; // simulate write of 10 bytes of parameter words
            return paramWordsWritten;
        }

        @Override
        int writeBytesWireFormat(byte[] dst, int dstIndex) {
            bytesWritten = 20; // simulate 20 bytes of data
            return bytesWritten;
        }

        @Override
        int readParameterWordsWireFormat(byte[] buffer, int bufferIndex) {
            paramWordsRead = 10;
            return paramWordsRead;
        }

        @Override
        int readBytesWireFormat(byte[] buffer, int bufferIndex) {
            bytesRead = 20;
            return bytesRead;
        }

        // Allow tests to control batching limit
        @Override
        int getBatchLimit(byte command) {
            return customBatchLimit != null ? customBatchLimit : 0;
        }
    }

    /**
     * Test stub for a plain ServerMessageBlock used as the chained andx command.
     */
    static class DummyPlainSMB extends ServerMessageBlock {
        int writeParamCalls = 0;
        int writeBytesCalls = 0;
        int readParamCalls = 0;
        int readBytesCalls = 0;

        @Override
        int writeParameterWordsWireFormat(byte[] dst, int dstIndex) {
            writeParamCalls++;
            return 10;
        }

        @Override
        int writeBytesWireFormat(byte[] dst, int dstIndex) {
            writeBytesCalls++;
            return 20;
        }

        @Override
        int readParameterWordsWireFormat(byte[] buffer, int bufferIndex) {
            readParamCalls++;
            return 10;
        }

        @Override
        int readBytesWireFormat(byte[] buffer, int bufferIndex) {
            readBytesCalls++;
            return 20;
        }
    }

    /**
     * SigningDigest spy that records whether sign() was invoked.
     */
    static class TestSigningDigest extends SigningDigest {
        boolean called;
        int lastLength;

        TestSigningDigest() throws SmbException {
            super(new byte[16], false);
        }

        @Override
        void sign(byte[] data, int offset, int length, ServerMessageBlock request, ServerMessageBlock response) {
            called = true;
            lastLength = length;
        }
    }

    @Test
    @DisplayName("Constructor with andx sets next command")
    void testConstructorWithAndx() {
        DummyPlainSMB next = new DummyPlainSMB();
        DummyAndXBlock block = new DummyAndXBlock(next);

        assertNotNull(block);
        assertSame(next, block.andx, "andx should reference provided SMB");
    }

    @Test
    @DisplayName("getBatchLimit defaults to 0")
    void testGetBatchLimitDefault() {
        DummyAndXBlock block = new DummyAndXBlock();
        assertEquals(0, block.getBatchLimit((byte) 0x25));
    }

    @Test
    @DisplayName("encode without andx succeeds and signs when digest present")
    void testEncodeNoAndxWithSigning() throws Exception {
        DummyAndXBlock block = new DummyAndXBlock();
        TestSigningDigest digest = new TestSigningDigest();
        block.digest = digest;

        byte[] buf = new byte[256];
        int len = block.encode(buf, 0);

        assertTrue(len > 0);
        assertTrue(digest.called, "sign() should be called during encode");
        assertEquals(len, digest.lastLength);
    }

    @Test
    @DisplayName("writeAndXWireFormat without andx writes 0xFF and sentinel offset")
    void testWriteAndXWireFormatWithoutAndx() {
        DummyAndXBlock block = new DummyAndXBlock();
        byte[] buf = new byte[128];
        int n = block.writeAndXWireFormat(buf, 0);

        assertTrue(n > 0);
        // Common AndX header: command at +1, reserved at +2, offset at +3/+4
        assertEquals((byte) 0xFF, buf[1], "AndX command should be 0xFF when no chaining");
        assertEquals((byte) 0x00, buf[2], "Reserved byte must be 0");
        assertEquals((byte) 0xDE, buf[3], "Sentinel low offset when no chaining");
        assertEquals((byte) 0xDE, buf[4], "Sentinel high offset when no chaining");
        assertNull(block.andx, "andx should be cleared when not chaining");
    }

    @Test
    @DisplayName("writeAndXWireFormat with andx but batching prevented by limit")
    void testWriteAndXWireFormatBatchingPrevented() {
        DummyPlainSMB next = new DummyPlainSMB();
        DummyAndXBlock block = new DummyAndXBlock(next);
        block.customBatchLimit = 1; // allow 1, but we'll set batchLevel to meet limit
        block.batchLevel = 1; // batchLevel >= limit prevents chaining

        byte[] buf = new byte[128];
        int n = block.writeAndXWireFormat(buf, 0);

        assertTrue(n > 0);
        assertEquals((byte) 0xFF, buf[1]);
        assertNull(block.andx, "andx should be cleared when batching prevented");
    }

    @Test
    @DisplayName("writeAndXWireFormat chains non-AndX SMB and propagates header fields")
    void testWriteAndXWireFormatChainsPlainSMB() {
        DummyPlainSMB next = new DummyPlainSMB();
        DummyAndXBlock block = new DummyAndXBlock(next);
        block.customBatchLimit = 2; // batchLevel (0) < limit (2) so chaining allowed
        block.uid = 0x1234;
        block.useUnicode = true;

        byte[] buf = new byte[256];
        int n = block.writeAndXWireFormat(buf, 0);

        assertTrue(n > 0);
        // Note: In actual implementation, uid is NOT propagated for non-AndX SMBs
        // uid is only set for AndXServerMessageBlock instances (line 167 in AndXServerMessageBlock.java)
        // Only useUnicode is set before the instanceof check (line 149)
        assertEquals(block.useUnicode, next.useUnicode, "useUnicode must be propagated");
        assertTrue(next.writeParamCalls > 0, "chained SMB parameter words should be written");
        assertTrue(next.writeBytesCalls > 0, "chained SMB bytes should be written");
    }

    @Test
    @DisplayName("decode basic AndX block with no chaining")
    void testDecodeBasicNoAndx() {
        DummyAndXBlock block = new DummyAndXBlock() {
            @Override
            int readHeaderWireFormat(byte[] buffer, int bufferIndex) {
                // Simulate fixed-size header parsing
                return 33;
            }
        };

        byte[] buf = new byte[128];
        // After header at 0..32
        buf[33] = 4; // wordCount
        buf[34] = (byte) 0xFF; // andxCommand
        // andxOffset (ignored when 0xFF)
        buf[36] = 0;
        buf[37] = 0;
        // byteCount at index start + 1 + wordCount*2 = 33 + 1 + 8 = 42
        ServerMessageBlock.writeInt2(20, buf, 42);

        int len = block.decode(buf, 0);
        assertTrue(len > 0);
        assertEquals(4, block.wordCount);
        assertNull(block.andx);
    }

    @Test
    @DisplayName("readAndXWireFormat applies Snap server workaround (offset 0)")
    void testReadAndXWireFormatSnapWorkaround() {
        DummyAndXBlock block = new DummyAndXBlock();
        block.headerStart = 0;

        byte[] buf = new byte[64];
        buf[0] = 4; // wordCount
        buf[1] = 0x42; // andxCommand
        // andxOffset = 0 triggers workaround -> treat as no andx
        ServerMessageBlock.writeInt2(0, buf, 3);
        ServerMessageBlock.writeInt2(10, buf, 9); // byteCount

        int n = block.readAndXWireFormat(buf, 0);
        assertTrue(n > 0);
        assertNull(block.andx, "andx should be cleared when offset is 0");
    }

    @Test
    @DisplayName("decode throws when andx command present but no andx object supplied")
    void testDecodeWithAndxCommandButNoObject() {
        DummyAndXBlock block = new DummyAndXBlock() {
            @Override
            int readHeaderWireFormat(byte[] buffer, int bufferIndex) {
                return 33;
            }
        };
        byte[] buf = new byte[128];
        buf[33] = 4; // wordCount
        buf[34] = 0x55; // andxCommand != 0xFF
        // andxOffset arbitrarily > 0
        ServerMessageBlock.writeInt2(80, buf, 36);
        // byteCount position: 33 + 1 + 8 = 42
        ServerMessageBlock.writeInt2(0, buf, 42);

        assertThrows(RuntimeException.class, () -> block.decode(buf, 0));
    }

    @Test
    @DisplayName("readAndXWireFormat reads chained plain SMB and marks received")
    void testReadAndXWireFormatWithPlainSMB() {
        DummyPlainSMB next = new DummyPlainSMB();
        // The implementation uses andx.wordCount, which starts at 0 by default
        // We need to test the actual behavior where wordCount is 0
        // This means readParameterWordsWireFormat won't be called (line 282-284)

        DummyAndXBlock block = new DummyAndXBlock(next);
        block.headerStart = 0;

        byte[] buf = new byte[256];
        buf[0] = 4; // wordCount for main block
        buf[1] = 0x66; // andxCommand
        ServerMessageBlock.writeInt2(50, buf, 3); // andxOffset
        ServerMessageBlock.writeInt2(20, buf, 9); // byteCount for main block

        // At offset 50, the implementation writes andx.wordCount (0) to buffer
        // Then reads byteCount at offset 51
        ServerMessageBlock.writeInt2(20, buf, 51);

        int n = block.readAndXWireFormat(buf, 0);
        assertTrue(n > 0);
        assertTrue(next.received, "Chained SMB should be marked received");
        // Since wordCount is 0, readParameterWordsWireFormat is not called
        assertEquals(0, next.readParamCalls);
        assertEquals(1, next.readBytesCalls);
    }

    @Test
    @DisplayName("readAndXWireFormat clears chaining when errorCode set")
    void testReadAndXWireFormatWithErrorCode() {
        DummyPlainSMB next = new DummyPlainSMB();
        DummyAndXBlock block = new DummyAndXBlock(next);
        block.errorCode = 1; // any non-zero error code should inhibit chaining
        block.headerStart = 0;

        byte[] buf = new byte[64];
        buf[0] = 4; // wordCount
        buf[1] = 0x42; // andxCommand present
        ServerMessageBlock.writeInt2(50, buf, 3);
        ServerMessageBlock.writeInt2(10, buf, 9);

        int n = block.readAndXWireFormat(buf, 0);
        assertTrue(n > 0);
        assertNull(block.andx, "andx should be cleared when errorCode != 0");
    }

    @Test
    @DisplayName("NT_CREATE_ANDX extended response adjusts wordCount by +8")
    void testNtCreateAndxExtendedAdjustsWordCount() {
        SmbComNTCreateAndXResponse resp = new SmbComNTCreateAndXResponse() {
            @Override
            int readHeaderWireFormat(byte[] buffer, int bufferIndex) {
                return 33;
            }
        };
        // Set command to NT_CREATE_ANDX and mark extended
        resp.command = ServerMessageBlock.SMB_COM_NT_CREATE_ANDX;
        resp.isExtended = true;

        byte[] buf = new byte[256];
        buf[33] = 34; // baseline wordCount reported by server
        buf[34] = (byte) 0xFF; // no further andx
        // byteCount at 33 + 1 + 34*2 = 102
        ServerMessageBlock.writeInt2(0, buf, 102);

        int n = resp.decode(buf, 0);
        assertTrue(n > 0);
        // Implementation adds +8 words (16 bytes) to account for CSC extra
        assertEquals(42, resp.wordCount);
    }

    @Test
    @DisplayName("toString includes andxCommand and andxOffset")
    void testToStringContainsFields() {
        DummyPlainSMB next = new DummyPlainSMB();
        DummyAndXBlock block = new DummyAndXBlock(next);

        byte[] buf = new byte[128];
        block.writeAndXWireFormat(buf, 0);

        String s = block.toString();
        assertNotNull(s);
        assertTrue(s.contains("andxCommand=0x"));
        assertTrue(s.contains("andxOffset="));
    }
}
