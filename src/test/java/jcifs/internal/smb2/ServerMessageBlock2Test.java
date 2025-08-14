package jcifs.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlockResponse;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

class ServerMessageBlock2Test {

    @Mock
    private Configuration mockConfig;

    @Mock
    private Smb2SigningDigest mockDigest;

    @Mock
    private ServerMessageBlock2Response mockResponse;

    private TestServerMessageBlock2 testMessage;

    // Test implementation of abstract class
    private static class TestServerMessageBlock2 extends ServerMessageBlock2 {
        private int bytesWritten = 0;
        private int bytesRead = 0;
        private boolean throwOnRead = false;

        public TestServerMessageBlock2(Configuration config) {
            super(config);
        }

        public TestServerMessageBlock2(Configuration config, int command) {
            super(config, command);
        }

        @Override
        protected int writeBytesWireFormat(byte[] dst, int dstIndex) {
            return bytesWritten;
        }

        @Override
        protected int readBytesWireFormat(byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
            if (throwOnRead) {
                throw new SMBProtocolDecodingException("Test exception");
            }
            return bytesRead;
        }

        public void setBytesWritten(int bytes) {
            this.bytesWritten = bytes;
        }

        public void setBytesRead(int bytes) {
            this.bytesRead = bytes;
        }

        public void setThrowOnRead(boolean throwOnRead) {
            this.throwOnRead = throwOnRead;
        }
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testMessage = new TestServerMessageBlock2(mockConfig);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create with configuration only")
        void testConstructorWithConfig() {
            ServerMessageBlock2 msg = new TestServerMessageBlock2(mockConfig);
            assertNotNull(msg);
            assertEquals(mockConfig, msg.getConfig());
            assertEquals(0, msg.getCommand());
        }

        @Test
        @DisplayName("Should create with configuration and command")
        void testConstructorWithConfigAndCommand() {
            int command = ServerMessageBlock2.SMB2_NEGOTIATE;
            ServerMessageBlock2 msg = new TestServerMessageBlock2(mockConfig, command);
            assertNotNull(msg);
            assertEquals(mockConfig, msg.getConfig());
            assertEquals(command, msg.getCommand());
        }
    }

    @Nested
    @DisplayName("Command Constants Tests")
    class CommandConstantsTests {

        @Test
        @DisplayName("Should have correct command constants")
        void testCommandConstants() {
            assertEquals(0x00, ServerMessageBlock2.SMB2_NEGOTIATE);
            assertEquals(0x01, ServerMessageBlock2.SMB2_SESSION_SETUP);
            assertEquals(0x02, ServerMessageBlock2.SMB2_LOGOFF);
            assertEquals(0x03, ServerMessageBlock2.SMB2_TREE_CONNECT);
            assertEquals(0x04, ServerMessageBlock2.SMB2_TREE_DISCONNECT);
            assertEquals(0x05, ServerMessageBlock2.SMB2_CREATE);
            assertEquals(0x06, ServerMessageBlock2.SMB2_CLOSE);
            assertEquals(0x07, ServerMessageBlock2.SMB2_FLUSH);
            assertEquals(0x08, ServerMessageBlock2.SMB2_READ);
            assertEquals(0x09, ServerMessageBlock2.SMB2_WRITE);
            assertEquals(0x0A, ServerMessageBlock2.SMB2_LOCK);
            assertEquals(0x0B, ServerMessageBlock2.SMB2_IOCTL);
            assertEquals(0x0C, ServerMessageBlock2.SMB2_CANCEL);
            assertEquals(0x0D, ServerMessageBlock2.SMB2_ECHO);
            assertEquals(0x0E, ServerMessageBlock2.SMB2_QUERY_DIRECTORY);
            assertEquals(0x0F, ServerMessageBlock2.SMB2_CHANGE_NOTIFY);
            assertEquals(0x10, ServerMessageBlock2.SMB2_QUERY_INFO);
            assertEquals(0x11, ServerMessageBlock2.SMB2_SET_INFO);
            assertEquals(0x12, ServerMessageBlock2.SMB2_OPLOCK_BREAK);
        }

        @Test
        @DisplayName("Should have correct flag constants")
        void testFlagConstants() {
            assertEquals(0x00000001, ServerMessageBlock2.SMB2_FLAGS_SERVER_TO_REDIR);
            assertEquals(0x00000002, ServerMessageBlock2.SMB2_FLAGS_ASYNC_COMMAND);
            assertEquals(0x00000004, ServerMessageBlock2.SMB2_FLAGS_RELATED_OPERATIONS);
            assertEquals(0x00000008, ServerMessageBlock2.SMB2_FLAGS_SIGNED);
            assertEquals(0x00000070, ServerMessageBlock2.SMB2_FLAGS_PRIORITY_MASK);
            assertEquals(0x10000000, ServerMessageBlock2.SMB2_FLAGS_DFS_OPERATIONS);
            assertEquals(0x20000000, ServerMessageBlock2.SMB2_FLAGS_REPLAY_OPERATION);
        }
    }

    @Nested
    @DisplayName("Basic Property Tests")
    class BasicPropertyTests {

        @Test
        @DisplayName("Should get and set command")
        void testCommandProperty() {
            assertEquals(0, testMessage.getCommand());
            testMessage.setCommand(ServerMessageBlock2.SMB2_CREATE);
            assertEquals(ServerMessageBlock2.SMB2_CREATE, testMessage.getCommand());
        }

        @Test
        @DisplayName("Should get and set tree ID")
        void testTreeIdProperty() {
            assertEquals(0, testMessage.getTreeId());
            testMessage.setTreeId(123);
            assertEquals(123, testMessage.getTreeId());
        }

        @Test
        @DisplayName("Should propagate tree ID to chained message")
        void testTreeIdPropagation() {
            TestServerMessageBlock2 nextMessage = new TestServerMessageBlock2(mockConfig);
            testMessage.chain(nextMessage);
            testMessage.setTreeId(456);
            assertEquals(456, nextMessage.getTreeId());
        }

        @Test
        @DisplayName("Should get and set session ID")
        void testSessionIdProperty() {
            assertEquals(0, testMessage.getSessionId());
            testMessage.setSessionId(789L);
            assertEquals(789L, testMessage.getSessionId());
        }

        @Test
        @DisplayName("Should propagate session ID to chained message")
        void testSessionIdPropagation() {
            TestServerMessageBlock2 nextMessage = new TestServerMessageBlock2(mockConfig);
            testMessage.chain(nextMessage);
            testMessage.setSessionId(999L);
            assertEquals(999L, nextMessage.getSessionId());
        }

        @Test
        @DisplayName("Should get and set MID")
        void testMidProperty() {
            assertEquals(0, testMessage.getMid());
            testMessage.setMid(12345L);
            assertEquals(12345L, testMessage.getMid());
        }

        @Test
        @DisplayName("Should get and set async ID")
        void testAsyncIdProperty() {
            assertEquals(0, testMessage.getAsyncId());
            testMessage.setAsyncId(67890L);
            assertEquals(67890L, testMessage.getAsyncId());
        }

        @Test
        @DisplayName("Should get and set credit")
        void testCreditProperty() {
            assertEquals(0, testMessage.getCredit());
            testMessage.setCredit(100);
            assertEquals(100, testMessage.getCredit());
        }

        @Test
        @DisplayName("Should get credit charge")
        void testCreditChargeProperty() {
            assertEquals(0, testMessage.getCreditCharge());
        }

        @Test
        @DisplayName("Should get and set read size")
        void testReadSizeProperty() {
            testMessage.setReadSize(1024);
            // No getter for readSize, but it's used internally in decode
        }

        @Test
        @DisplayName("Should check if async")
        void testAsyncProperty() {
            assertFalse(testMessage.isAsync());
        }
    }

    @Nested
    @DisplayName("Flag Operations Tests")
    class FlagOperationsTests {

        @Test
        @DisplayName("Should add flags correctly")
        void testAddFlags() {
            assertEquals(0, testMessage.getFlags());
            testMessage.addFlags(ServerMessageBlock2.SMB2_FLAGS_SIGNED);
            assertEquals(ServerMessageBlock2.SMB2_FLAGS_SIGNED, testMessage.getFlags());
            testMessage.addFlags(ServerMessageBlock2.SMB2_FLAGS_DFS_OPERATIONS);
            assertEquals(ServerMessageBlock2.SMB2_FLAGS_SIGNED | ServerMessageBlock2.SMB2_FLAGS_DFS_OPERATIONS, testMessage.getFlags());
        }

        @Test
        @DisplayName("Should clear flags correctly")
        void testClearFlags() {
            testMessage.addFlags(ServerMessageBlock2.SMB2_FLAGS_SIGNED | ServerMessageBlock2.SMB2_FLAGS_DFS_OPERATIONS);
            testMessage.clearFlags(ServerMessageBlock2.SMB2_FLAGS_SIGNED);
            assertEquals(ServerMessageBlock2.SMB2_FLAGS_DFS_OPERATIONS, testMessage.getFlags());
        }

        @Test
        @DisplayName("Should detect response flag")
        void testIsResponse() {
            assertFalse(testMessage.isResponse());
            testMessage.addFlags(ServerMessageBlock2.SMB2_FLAGS_SERVER_TO_REDIR);
            assertTrue(testMessage.isResponse());
        }
    }

    @Nested
    @DisplayName("Digest Tests")
    class DigestTests {

        @Test
        @DisplayName("Should get and set digest")
        void testDigestProperty() {
            assertNull(testMessage.getDigest());
            testMessage.setDigest(mockDigest);
            assertEquals(mockDigest, testMessage.getDigest());
        }

        @Test
        @DisplayName("Should propagate digest to chained message")
        void testDigestPropagation() {
            TestServerMessageBlock2 nextMessage = new TestServerMessageBlock2(mockConfig);
            testMessage.chain(nextMessage);
            testMessage.setDigest(mockDigest);
            assertEquals(mockDigest, nextMessage.getDigest());
        }
    }

    @Nested
    @DisplayName("Payload Tests")
    class PayloadTests {

        @Test
        @DisplayName("Should retain payload when requested")
        void testRetainPayload() {
            assertFalse(testMessage.isRetainPayload());
            testMessage.retainPayload();
            assertTrue(testMessage.isRetainPayload());
        }

        @Test
        @DisplayName("Should get and set raw payload")
        void testRawPayload() {
            assertNull(testMessage.getRawPayload());
            byte[] payload = new byte[] { 1, 2, 3, 4, 5 };
            testMessage.setRawPayload(payload);
            assertArrayEquals(payload, testMessage.getRawPayload());
        }
    }

    @Nested
    @DisplayName("Error Data Tests")
    class ErrorDataTests {

        @Test
        @DisplayName("Should get error data")
        void testErrorData() {
            assertNull(testMessage.getErrorData());
        }

        @Test
        @DisplayName("Should get error context count")
        void testErrorContextCount() {
            assertEquals(0, testMessage.getErrorContextCount());
        }

        @Test
        @DisplayName("Should detect error response status")
        void testIsErrorResponseStatus() {
            assertFalse(testMessage.isErrorResponseStatus());
        }
    }

    @Nested
    @DisplayName("Chain Tests")
    class ChainTests {

        @Test
        @DisplayName("Should chain messages successfully")
        void testChain() {
            TestServerMessageBlock2 nextMessage = new TestServerMessageBlock2(mockConfig);
            assertTrue(testMessage.chain(nextMessage));
            assertEquals(nextMessage, testMessage.getNext());
            assertTrue((nextMessage.getFlags() & ServerMessageBlock2.SMB2_FLAGS_RELATED_OPERATIONS) != 0);
        }

        @Test
        @DisplayName("Should chain multiple messages")
        void testMultipleChain() {
            TestServerMessageBlock2 second = new TestServerMessageBlock2(mockConfig);
            TestServerMessageBlock2 third = new TestServerMessageBlock2(mockConfig);

            assertTrue(testMessage.chain(second));
            assertTrue(testMessage.chain(third));

            assertEquals(second, testMessage.getNext());
            assertEquals(third, second.getNext());
        }

        @Test
        @DisplayName("Should set next message")
        void testSetNext() {
            TestServerMessageBlock2 nextMessage = new TestServerMessageBlock2(mockConfig);
            testMessage.setNext(nextMessage);
            assertEquals(nextMessage, testMessage.getNext());
        }
    }

    @Nested
    @DisplayName("Reset Tests")
    class ResetTests {

        @Test
        @DisplayName("Should reset message state")
        void testReset() {
            testMessage.addFlags(ServerMessageBlock2.SMB2_FLAGS_SIGNED);
            testMessage.setDigest(mockDigest);
            testMessage.setSessionId(123L);
            testMessage.setTreeId(456);

            testMessage.reset();

            assertEquals(0, testMessage.getFlags());
            assertNull(testMessage.getDigest());
            assertEquals(0, testMessage.getSessionId());
            assertEquals(0, testMessage.getTreeId());
        }
    }

    @Nested
    @DisplayName("Size Calculation Tests")
    class SizeCalculationTests {

        @Test
        @DisplayName("Should calculate size8 without alignment")
        void testSize8NoAlignment() {
            assertEquals(8, ServerMessageBlock2.size8(8));
            assertEquals(16, ServerMessageBlock2.size8(9));
            assertEquals(16, ServerMessageBlock2.size8(15));
            assertEquals(16, ServerMessageBlock2.size8(16));
            assertEquals(24, ServerMessageBlock2.size8(17));
        }

        @Test
        @DisplayName("Should calculate size8 with alignment")
        void testSize8WithAlignment() {
            assertEquals(8, ServerMessageBlock2.size8(8, 0));
            // size8(10, 2): rem = 10%8 - 2 = 2 - 2 = 0, returns 10
            assertEquals(10, ServerMessageBlock2.size8(10, 2));
            // size8(18, 2): rem = 18%8 - 2 = 2 - 2 = 0, returns 18
            assertEquals(18, ServerMessageBlock2.size8(18, 2));
            // size8(17, 2): rem = 17%8 - 2 = 1 - 2 = -1, rem = 8 + (-1) = 7, returns 17 + 8 - 7 = 18
            assertEquals(18, ServerMessageBlock2.size8(17, 2));
            // size8(15, 2): rem = 15%8 - 2 = 7 - 2 = 5, returns 15 + 8 - 5 = 18
            assertEquals(18, ServerMessageBlock2.size8(15, 2));
        }

        @Test
        @DisplayName("Should calculate padding")
        void testPad8() {
            testMessage.encode(new byte[1024], 0);
            // After header is written, padding depends on position
            int headerStart = testMessage.getHeaderStart();
            assertEquals(0, headerStart); // Should start at 0
        }
    }

    @Nested
    @DisplayName("Encode/Decode Tests")
    class EncodeDecodeTests {

        @Test
        @DisplayName("Should encode message correctly")
        void testEncode() {
            byte[] buffer = new byte[1024];
            testMessage.setBytesWritten(10);
            testMessage.setMid(12345L);
            testMessage.setSessionId(67890L);
            testMessage.setTreeId(789);
            testMessage.setCommand(ServerMessageBlock2.SMB2_CREATE);
            testMessage.setCredit(100);

            int len = testMessage.encode(buffer, 0);

            assertTrue(len > 0);
            assertEquals(0, testMessage.getHeaderStart());
            assertTrue(testMessage.getLength() > 0);

            // Verify SMB2 header
            assertEquals((byte) 0xFE, buffer[0]);
            assertEquals((byte) 'S', buffer[1]);
            assertEquals((byte) 'M', buffer[2]);
            assertEquals((byte) 'B', buffer[3]);
        }

        @Test
        @DisplayName("Should encode with signature when digest is set")
        void testEncodeWithSignature() {
            byte[] buffer = new byte[1024];
            testMessage.setBytesWritten(10);
            testMessage.setDigest(mockDigest);

            int len = testMessage.encode(buffer, 0);

            verify(mockDigest).sign(eq(buffer), eq(0), anyInt(), eq(testMessage), isNull());
        }

        @Test
        @DisplayName("Should retain payload when requested")
        void testEncodeRetainPayload() {
            byte[] buffer = new byte[1024];
            testMessage.setBytesWritten(10);
            testMessage.retainPayload();

            int len = testMessage.encode(buffer, 0);

            assertNotNull(testMessage.getRawPayload());
            assertEquals(len, testMessage.getRawPayload().length);
        }

        @Test
        @DisplayName("Should decode sync message correctly")
        void testDecodeSync() throws SMBProtocolDecodingException {
            byte[] buffer = createValidSyncMessage();
            testMessage.setBytesRead(10);

            int len = testMessage.decode(buffer, 0);

            assertTrue(len > 0);
            assertFalse(testMessage.isAsync());
            assertEquals(123, testMessage.getTreeId());
            assertEquals(456L, testMessage.getSessionId());
        }

        @Test
        @DisplayName("Should decode async message correctly")
        void testDecodeAsync() throws SMBProtocolDecodingException {
            byte[] buffer = createValidAsyncMessage();
            testMessage.setBytesRead(10);

            int len = testMessage.decode(buffer, 0);

            assertTrue(len > 0);
            assertTrue(testMessage.isAsync());
            assertEquals(789L, testMessage.getAsyncId());
            assertEquals(456L, testMessage.getSessionId());
        }

        @Test
        @DisplayName("Should decode error response")
        void testDecodeErrorResponse() throws SMBProtocolDecodingException {
            byte[] buffer = createErrorResponseMessage();
            testMessage.setBytesRead(0);

            int len = testMessage.decode(buffer, 0);

            assertTrue(len > 0);
            assertNotNull(testMessage.getErrorData());
            assertEquals(5, testMessage.getErrorData().length);
        }

        @Test
        @DisplayName("Should handle compound messages")
        void testDecodeCompound() throws SMBProtocolDecodingException {
            byte[] buffer = createCompoundMessage();
            testMessage.setBytesRead(10);
            testMessage.setReadSize(100);

            int len = testMessage.decode(buffer, 0, true);

            assertTrue(len > 0);
        }

        @Test
        @DisplayName("Should throw exception for misaligned compound")
        void testDecodeMisalignedCompound() {
            byte[] buffer = createMisalignedCompoundMessage();
            TestServerMessageBlock2 next = new TestServerMessageBlock2(mockConfig);
            testMessage.setNext(next);
            testMessage.setBytesRead(10);

            assertThrows(SMBProtocolDecodingException.class, () -> {
                testMessage.decode(buffer, 0);
            });
        }

        @Test
        @DisplayName("Should handle decode exception")
        void testDecodeException() {
            byte[] buffer = createValidSyncMessage();
            testMessage.setThrowOnRead(true);

            assertThrows(SMBProtocolDecodingException.class, () -> {
                testMessage.decode(buffer, 0);
            });
        }

        private byte[] createValidSyncMessage() {
            byte[] buffer = new byte[256];
            System.arraycopy(SMBUtil.SMB2_HEADER, 0, buffer, 0, 4);
            // Set up sync message fields
            SMBUtil.writeInt4(0, buffer, 16); // flags (no async flag)
            SMBUtil.writeInt4(123, buffer, 36); // tree ID
            SMBUtil.writeInt8(456L, buffer, 40); // session ID
            return buffer;
        }

        private byte[] createValidAsyncMessage() {
            byte[] buffer = new byte[256];
            System.arraycopy(SMBUtil.SMB2_HEADER, 0, buffer, 0, 4);
            // Set up async message fields
            SMBUtil.writeInt4(ServerMessageBlock2.SMB2_FLAGS_ASYNC_COMMAND, buffer, 16); // flags with async
            SMBUtil.writeInt8(789L, buffer, 32); // async ID
            SMBUtil.writeInt8(456L, buffer, 40); // session ID
            return buffer;
        }

        private byte[] createErrorResponseMessage() {
            byte[] buffer = new byte[256];
            System.arraycopy(SMBUtil.SMB2_HEADER, 0, buffer, 0, 4);
            SMBUtil.writeInt4(0x80000005, buffer, 8); // status (error)

            // Error response structure
            int errorStart = 64;
            SMBUtil.writeInt2(9, buffer, errorStart); // structure size
            buffer[errorStart + 2] = 1; // error context count
            SMBUtil.writeInt4(5, buffer, errorStart + 4); // byte count

            // Error data
            buffer[errorStart + 8] = 1;
            buffer[errorStart + 9] = 2;
            buffer[errorStart + 10] = 3;
            buffer[errorStart + 11] = 4;
            buffer[errorStart + 12] = 5;

            return buffer;
        }

        private byte[] createCompoundMessage() {
            byte[] buffer = new byte[256];
            System.arraycopy(SMBUtil.SMB2_HEADER, 0, buffer, 0, 4);
            SMBUtil.writeInt4(128, buffer, 20); // next command offset
            return buffer;
        }

        private byte[] createMisalignedCompoundMessage() {
            byte[] buffer = new byte[256];
            System.arraycopy(SMBUtil.SMB2_HEADER, 0, buffer, 0, 4);
            SMBUtil.writeInt4(127, buffer, 20); // misaligned next command offset
            return buffer;
        }
    }

    @Nested
    @DisplayName("Response Tests")
    class ResponseTests {

        @Test
        @DisplayName("Should return null response by default")
        void testGetResponse() {
            assertNull(testMessage.getResponse());
        }

        @Test
        @DisplayName("Should accept response setting")
        void testSetResponse() {
            CommonServerMessageBlockResponse response = mock(CommonServerMessageBlockResponse.class);
            testMessage.setResponse(response);
            // Method is empty by default, just ensure no exception
        }
    }

    @Nested
    @DisplayName("Legacy Method Tests")
    class LegacyMethodTests {

        @Test
        @DisplayName("Should ignore extended security setting")
        void testSetExtendedSecurity() {
            testMessage.setExtendedSecurity(true);
            testMessage.setExtendedSecurity(false);
            // Method is empty, just ensure no exception
        }

        @Test
        @DisplayName("Should ignore UID setting")
        void testSetUid() {
            testMessage.setUid(123);
            // Method is empty, just ensure no exception
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsHashCodeTests {

        @Test
        @DisplayName("Should calculate hashCode from MID")
        void testHashCode() {
            testMessage.setMid(12345L);
            assertEquals(12345, testMessage.hashCode());
        }

        @Test
        @DisplayName("Should be equal when MIDs match")
        void testEquals() {
            TestServerMessageBlock2 other = new TestServerMessageBlock2(mockConfig);
            testMessage.setMid(12345L);
            other.setMid(12345L);

            assertTrue(testMessage.equals(other));
        }

        @Test
        @DisplayName("Should not be equal when MIDs differ")
        void testNotEqualsDifferentMid() {
            TestServerMessageBlock2 other = new TestServerMessageBlock2(mockConfig);
            testMessage.setMid(12345L);
            other.setMid(67890L);

            assertFalse(testMessage.equals(other));
        }

        @Test
        @DisplayName("Should not be equal to null")
        void testNotEqualsNull() {
            assertFalse(testMessage.equals(null));
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void testNotEqualsDifferentType() {
            assertFalse(testMessage.equals("not a message"));
        }

        @Test
        @DisplayName("Should be equal to itself")
        void testEqualsSelf() {
            testMessage.setMid(12345L);
            assertTrue(testMessage.equals(testMessage));
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @ParameterizedTest
        @DisplayName("Should format command name correctly")
        @ValueSource(shorts = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
                0x12 })
        void testToStringCommandNames(short command) {
            testMessage.setCommand(command);
            String result = testMessage.toString();

            assertNotNull(result);
            assertTrue(result.contains("command="));
            assertFalse(result.contains("command=UNKNOWN"));
        }

        @Test
        @DisplayName("Should format unknown command")
        void testToStringUnknownCommand() {
            testMessage.setCommand(0xFF);
            String result = testMessage.toString();

            assertTrue(result.contains("command=UNKNOWN"));
        }

        @Test
        @DisplayName("Should include all fields in toString")
        void testToStringFields() {
            testMessage.setCommand(ServerMessageBlock2.SMB2_CREATE);
            testMessage.setMid(12345L);
            testMessage.addFlags(0x1234);

            String result = testMessage.toString();

            assertTrue(result.contains("command=SMB2_CREATE"));
            assertTrue(result.contains("status=0"));
            assertTrue(result.contains("flags=0x1234"));
            assertTrue(result.contains("mid=12345"));
            assertTrue(result.contains("wordCount=0"));
            assertTrue(result.contains("byteCount=0"));
        }
    }

    @Nested
    @DisplayName("Property Access Tests")
    class PropertyAccessTests {

        @Test
        @DisplayName("Should get header start")
        void testGetHeaderStart() {
            assertEquals(0, testMessage.getHeaderStart());
            byte[] buffer = new byte[1024];
            testMessage.encode(buffer, 100);
            assertEquals(100, testMessage.getHeaderStart());
        }

        @Test
        @DisplayName("Should get length")
        void testGetLength() {
            assertEquals(0, testMessage.getLength());
            byte[] buffer = new byte[1024];
            testMessage.setBytesWritten(20);
            testMessage.encode(buffer, 0);
            assertTrue(testMessage.getLength() > 0);
        }

        @Test
        @DisplayName("Should get status")
        void testGetStatus() {
            assertEquals(0, testMessage.getStatus());
        }

        @Test
        @DisplayName("Should get next command offset")
        void testGetNextCommandOffset() {
            assertEquals(0, testMessage.getNextCommandOffset());
        }
    }

    @Nested
    @DisplayName("Error Response Decoding Tests")
    class ErrorResponseDecodingTests {

        @Test
        @DisplayName("Should decode error response with correct structure size")
        void testReadErrorResponseValid() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[256];
            int bufferIndex = 0;

            // Write error response structure
            SMBUtil.writeInt2(9, buffer, bufferIndex); // structure size
            buffer[bufferIndex + 2] = 2; // error context count
            SMBUtil.writeInt4(10, buffer, bufferIndex + 4); // byte count

            // Write error data
            for (int i = 0; i < 10; i++) {
                buffer[bufferIndex + 8 + i] = (byte) i;
            }

            int bytesRead = testMessage.readErrorResponse(buffer, bufferIndex);

            assertEquals(18, bytesRead); // 8 header + 10 data
            assertEquals(2, testMessage.getErrorContextCount());
            assertNotNull(testMessage.getErrorData());
            assertEquals(10, testMessage.getErrorData().length);
        }

        @Test
        @DisplayName("Should throw exception for invalid structure size")
        void testReadErrorResponseInvalidStructureSize() {
            byte[] buffer = new byte[256];
            SMBUtil.writeInt2(8, buffer, 0); // wrong structure size

            assertThrows(SMBProtocolDecodingException.class, () -> {
                testMessage.readErrorResponse(buffer, 0);
            });
        }

        @Test
        @DisplayName("Should handle zero byte count")
        void testReadErrorResponseZeroByteCount() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[256];
            int bufferIndex = 0;

            SMBUtil.writeInt2(9, buffer, bufferIndex); // structure size
            buffer[bufferIndex + 2] = 0; // error context count
            SMBUtil.writeInt4(0, buffer, bufferIndex + 4); // zero byte count

            int bytesRead = testMessage.readErrorResponse(buffer, bufferIndex);

            assertEquals(8, bytesRead);
            assertEquals(0, testMessage.getErrorContextCount());
            assertNull(testMessage.getErrorData());
        }
    }

    @Nested
    @DisplayName("Chained Encode Tests")
    class ChainedEncodeTests {

        @Test
        @DisplayName("Should encode chained messages")
        void testEncodeChained() {
            TestServerMessageBlock2 second = new TestServerMessageBlock2(mockConfig);
            second.setBytesWritten(15);

            testMessage.setBytesWritten(10);
            testMessage.chain(second);

            byte[] buffer = new byte[1024];
            int totalLen = testMessage.encode(buffer, 0);

            assertTrue(totalLen > testMessage.getLength());

            // Check next command offset was written
            int nextOffset = SMBUtil.readInt4(buffer, 20);
            assertTrue(nextOffset > 0);
        }

        @Test
        @DisplayName("Should sign chained messages with digest")
        void testEncodeChainedWithDigest() {
            TestServerMessageBlock2 second = new TestServerMessageBlock2(mockConfig);
            second.setBytesWritten(15);

            testMessage.setBytesWritten(10);
            testMessage.chain(second);
            testMessage.setDigest(mockDigest);

            byte[] buffer = new byte[1024];
            testMessage.encode(buffer, 0);

            // Both messages should be signed
            verify(mockDigest, times(2)).sign(any(), anyInt(), anyInt(), any(), any());
        }
    }

    @Nested
    @DisplayName("Protected Method Tests")
    class ProtectedMethodTests {

        @Test
        @DisplayName("Should call haveResponse on decode")
        void testHaveResponseCalled() throws SMBProtocolDecodingException {
            TestServerMessageBlock2 customMessage = new TestServerMessageBlock2(mockConfig) {
                boolean haveResponseCalled = false;

                @Override
                protected void haveResponse(byte[] buffer, int start, int len) throws SMBProtocolDecodingException {
                    haveResponseCalled = true;
                    super.haveResponse(buffer, start, len);
                }
            };

            byte[] buffer = new byte[256];
            System.arraycopy(SMBUtil.SMB2_HEADER, 0, buffer, 0, 4);
            // Set up sync message fields
            SMBUtil.writeInt4(0, buffer, 16); // flags (no async flag)
            SMBUtil.writeInt4(123, buffer, 36); // tree ID
            SMBUtil.writeInt8(456L, buffer, 40); // session ID

            customMessage.setBytesRead(10);
            customMessage.decode(buffer, 0);

            // Can't directly test protected method, but decode should work without exception
            assertTrue(customMessage.getLength() > 0);
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle empty buffer encoding")
        void testEmptyBufferEncoding() {
            byte[] buffer = new byte[256];
            testMessage.setBytesWritten(0);
            int len = testMessage.encode(buffer, 0);
            assertTrue(len >= Smb2Constants.SMB2_HEADER_LENGTH);
        }

        @Test
        @DisplayName("Should handle large MID values")
        void testLargeMidValue() {
            long largeMid = Long.MAX_VALUE;
            testMessage.setMid(largeMid);
            assertEquals(largeMid, testMessage.getMid());

            // HashCode should handle overflow correctly
            int hash = testMessage.hashCode();
            assertEquals((int) largeMid, hash);
        }

        @Test
        @DisplayName("Should handle negative status codes")
        void testNegativeStatusCode() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[256];
            System.arraycopy(SMBUtil.SMB2_HEADER, 0, buffer, 0, 4);
            SMBUtil.writeInt4(-1, buffer, 8); // negative status

            // Write error response structure at offset 64
            int errorStart = 64;
            SMBUtil.writeInt2(9, buffer, errorStart); // structure size
            buffer[errorStart + 2] = 1; // error context count
            SMBUtil.writeInt4(4, buffer, errorStart + 4); // byte count

            // Write some error data
            buffer[errorStart + 8] = (byte) 0xFF;
            buffer[errorStart + 9] = (byte) 0xFE;
            buffer[errorStart + 10] = (byte) 0xFD;
            buffer[errorStart + 11] = (byte) 0xFC;

            testMessage.setBytesRead(0);
            testMessage.decode(buffer, 0);

            assertEquals(-1, testMessage.getStatus());
            assertTrue(testMessage.isErrorResponseStatus());
            assertNotNull(testMessage.getErrorData());
            assertEquals(4, testMessage.getErrorData().length);
        }

        @Test
        @DisplayName("Should handle maximum tree ID")
        void testMaxTreeId() {
            int maxTreeId = Integer.MAX_VALUE;
            testMessage.setTreeId(maxTreeId);
            assertEquals(maxTreeId, testMessage.getTreeId());
        }

        @Test
        @DisplayName("Should handle maximum session ID")
        void testMaxSessionId() {
            long maxSessionId = Long.MAX_VALUE;
            testMessage.setSessionId(maxSessionId);
            assertEquals(maxSessionId, testMessage.getSessionId());
        }

        @Test
        @DisplayName("Should handle all flags set")
        void testAllFlagsSet() {
            int allFlags = 0xFFFFFFFF;
            testMessage.addFlags(allFlags);
            assertEquals(allFlags, testMessage.getFlags());

            // Should still be able to clear specific flags
            testMessage.clearFlags(ServerMessageBlock2.SMB2_FLAGS_SIGNED);
            assertEquals(allFlags & ~ServerMessageBlock2.SMB2_FLAGS_SIGNED, testMessage.getFlags());
        }

        @Test
        @DisplayName("Should handle encoding at non-zero offset")
        void testEncodeAtNonZeroOffset() {
            byte[] buffer = new byte[1024];
            int offset = 100;
            testMessage.setBytesWritten(20);

            int len = testMessage.encode(buffer, offset);

            assertTrue(len > 0);
            assertEquals(offset, testMessage.getHeaderStart());

            // Verify SMB2 header at correct offset
            assertEquals((byte) 0xFE, buffer[offset]);
            assertEquals((byte) 'S', buffer[offset + 1]);
            assertEquals((byte) 'M', buffer[offset + 2]);
            assertEquals((byte) 'B', buffer[offset + 3]);
        }

        @Test
        @DisplayName("Should handle deep message chaining")
        void testDeepMessageChaining() {
            TestServerMessageBlock2[] messages = new TestServerMessageBlock2[10];
            for (int i = 0; i < messages.length; i++) {
                messages[i] = new TestServerMessageBlock2(mockConfig);
                if (i > 0) {
                    assertTrue(messages[0].chain(messages[i]));
                }
            }

            // Verify chain is properly linked
            ServerMessageBlock2 current = messages[0];
            for (int i = 1; i < messages.length; i++) {
                current = current.getNext();
                assertEquals(messages[i], current);
            }
        }

        @Test
        @DisplayName("Should handle zero-length error data")
        void testZeroLengthErrorData() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[256];
            System.arraycopy(SMBUtil.SMB2_HEADER, 0, buffer, 0, 4);
            SMBUtil.writeInt4(0x80000001, buffer, 8); // error status

            // Error response with zero data
            int errorStart = 64;
            SMBUtil.writeInt2(9, buffer, errorStart); // structure size
            buffer[errorStart + 2] = 0; // no error context
            SMBUtil.writeInt4(0, buffer, errorStart + 4); // zero byte count

            testMessage.setBytesRead(0);
            int len = testMessage.decode(buffer, 0);

            assertTrue(len > 0);
            assertTrue(testMessage.isErrorResponseStatus());
            assertNull(testMessage.getErrorData());
        }

        @Test
        @DisplayName("Should preserve signature bytes during decode")
        void testPreserveSignatureDuringDecode() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[256];
            System.arraycopy(SMBUtil.SMB2_HEADER, 0, buffer, 0, 4);

            // Create signature pattern
            byte[] testSignature = new byte[16];
            for (int i = 0; i < 16; i++) {
                testSignature[i] = (byte) (i + 1);
            }

            // Write signature to buffer (at offset 48 for sync messages)
            System.arraycopy(testSignature, 0, buffer, 48, 16);

            testMessage.setBytesRead(10);
            testMessage.decode(buffer, 0);

            // Signature is stored internally but not directly accessible
            // Verify decode completes successfully
            assertTrue(testMessage.getLength() > 0);
        }
    }

    @Nested
    @DisplayName("Compound Response Tests")
    class CompoundResponseTests {

        @Test
        @DisplayName("Should handle compound with final response")
        void testCompoundFinalResponse() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[512];
            System.arraycopy(SMBUtil.SMB2_HEADER, 0, buffer, 0, 4);
            SMBUtil.writeInt4(0, buffer, 20); // nextCommand = 0 (final)

            testMessage.setBytesRead(10);
            testMessage.setReadSize(200); // Total read size

            int len = testMessage.decode(buffer, 0, true);

            // Should include remaining bytes for final response
            assertTrue(len > Smb2Constants.SMB2_HEADER_LENGTH);
        }

        @Test
        @DisplayName("Should add padding for non-final compound response")
        void testCompoundNonFinalResponse() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[512];
            System.arraycopy(SMBUtil.SMB2_HEADER, 0, buffer, 0, 4);
            SMBUtil.writeInt4(128, buffer, 20); // nextCommand = 128 (not final)

            testMessage.setBytesRead(10);

            int len = testMessage.decode(buffer, 0, false);

            // Length should include padding for alignment
            assertTrue(len >= testMessage.getLength());
        }
    }
}
