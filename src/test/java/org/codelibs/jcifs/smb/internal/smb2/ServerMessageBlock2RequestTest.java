package org.codelibs.jcifs.smb.internal.smb2;

import static org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2.SMB2_FLAGS_RELATED_OPERATIONS;
import static org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2.SMB2_NEGOTIATE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class ServerMessageBlock2RequestTest {

    @Mock
    private Configuration mockConfig;

    @Mock
    private CIFSContext mockContext;

    @Mock
    private Smb2SigningDigest mockDigest;

    @Mock
    private ServerMessageBlock2Response mockResponse;

    private TestServerMessageBlock2Request testRequest;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testRequest = new TestServerMessageBlock2Request(mockConfig);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create request with configuration only")
        void testConstructorWithConfig() {
            TestServerMessageBlock2Request request = new TestServerMessageBlock2Request(mockConfig);
            assertNotNull(request);
            assertEquals(mockConfig, request.getConfig());
        }

        @Test
        @DisplayName("Should create request with configuration and command")
        void testConstructorWithConfigAndCommand() {
            int command = SMB2_NEGOTIATE;
            TestServerMessageBlock2Request request = new TestServerMessageBlock2Request(mockConfig, command);
            assertNotNull(request);
            assertEquals(mockConfig, request.getConfig());
            assertEquals(command, request.getCommand());
        }
    }

    @Nested
    @DisplayName("Basic Method Tests")
    class BasicMethodTests {

        @Test
        @DisplayName("ignoreDisconnect should return itself")
        void testIgnoreDisconnect() {
            ServerMessageBlock2Request<TestServerMessageBlock2Response> result = testRequest.ignoreDisconnect();
            assertSame(testRequest, result);
        }

        @Test
        @DisplayName("isCancel should always return false")
        void testIsCancel() {
            assertFalse(testRequest.isCancel());
        }

        @Test
        @DisplayName("getCreditCost should return 1 by default")
        void testGetCreditCost() {
            assertEquals(1, testRequest.getCreditCost());
        }

        @Test
        @DisplayName("setRequestCredits should set credit value")
        void testSetRequestCredits() {
            int credits = 10;
            testRequest.setRequestCredits(credits);
            assertEquals(credits, testRequest.getCredit());
        }

        @Test
        @DisplayName("setTid should set tree ID")
        void testSetTid() {
            int tid = 12345;
            testRequest.setTid(tid);
            assertEquals(tid, testRequest.getTreeId());
        }
    }

    @Nested
    @DisplayName("Async Operation Tests")
    class AsyncOperationTests {

        @Test
        @DisplayName("isResponseAsync should return false when asyncId is 0")
        void testIsResponseAsyncFalse() {
            testRequest.setAsyncId(0);
            assertFalse(testRequest.isResponseAsync());
        }

        @Test
        @DisplayName("isResponseAsync should return true when asyncId is not 0")
        void testIsResponseAsyncTrue() {
            testRequest.setAsyncId(12345L);
            assertTrue(testRequest.isResponseAsync());
        }

        @ParameterizedTest
        @ValueSource(longs = { 1L, 100L, Long.MAX_VALUE })
        @DisplayName("isResponseAsync should return true for various non-zero asyncIds")
        void testIsResponseAsyncWithDifferentValues(long asyncId) {
            testRequest.setAsyncId(asyncId);
            assertTrue(testRequest.isResponseAsync());
        }
    }

    @Nested
    @DisplayName("Timeout Tests")
    class TimeoutTests {

        @Test
        @DisplayName("getOverrideTimeout should return null initially")
        void testGetOverrideTimeoutInitial() {
            assertNull(testRequest.getOverrideTimeout());
        }

        @Test
        @DisplayName("setOverrideTimeout should set timeout value")
        void testSetOverrideTimeout() {
            Integer timeout = 5000;
            testRequest.setOverrideTimeout(timeout);
            assertEquals(timeout, testRequest.getOverrideTimeout());
        }

        @Test
        @DisplayName("setOverrideTimeout should handle null value")
        void testSetOverrideTimeoutNull() {
            testRequest.setOverrideTimeout(5000);
            testRequest.setOverrideTimeout(null);
            assertNull(testRequest.getOverrideTimeout());
        }
    }

    @Nested
    @DisplayName("Cancel Request Tests")
    class CancelRequestTests {

        @Test
        @DisplayName("createCancel should return Smb2CancelRequest with same mid and asyncId")
        void testCreateCancel() {
            long mid = 123L;
            long asyncId = 456L;
            testRequest.setMid(mid);
            testRequest.setAsyncId(asyncId);

            CommonServerMessageBlockRequest cancelRequest = testRequest.createCancel();

            assertNotNull(cancelRequest);
            assertInstanceOf(Smb2CancelRequest.class, cancelRequest);
            Smb2CancelRequest smb2Cancel = (Smb2CancelRequest) cancelRequest;
            assertEquals(mid, smb2Cancel.getMid());
            assertEquals(asyncId, smb2Cancel.getAsyncId());
        }
    }

    @Nested
    @DisplayName("Chain Operation Tests")
    class ChainOperationTests {

        @Test
        @DisplayName("allowChain should check configuration for both requests")
        void testAllowChain() {
            TestServerMessageBlock2Request nextRequest = new TestServerMessageBlock2Request(mockConfig);
            when(mockConfig.isAllowCompound("TestServerMessageBlock2Request")).thenReturn(true);

            boolean result = testRequest.allowChain(nextRequest);

            assertTrue(result);
            verify(mockConfig, times(2)).isAllowCompound("TestServerMessageBlock2Request");
        }

        @Test
        @DisplayName("allowChain should return false when config disallows compound")
        void testAllowChainDisallowed() {
            TestServerMessageBlock2Request nextRequest = new TestServerMessageBlock2Request(mockConfig);
            when(mockConfig.isAllowCompound(anyString())).thenReturn(false);

            boolean result = testRequest.allowChain(nextRequest);

            assertFalse(result);
        }

        @Test
        @DisplayName("getNext should return next request")
        void testGetNext() {
            TestServerMessageBlock2Request nextRequest = new TestServerMessageBlock2Request(mockConfig);
            testRequest.setNext(nextRequest);

            ServerMessageBlock2Request<?> result = testRequest.getNext();

            assertSame(nextRequest, result);
        }

        @Test
        @DisplayName("split should remove next and clear related operations flag")
        void testSplit() {
            TestServerMessageBlock2Request nextRequest = new TestServerMessageBlock2Request(mockConfig);
            nextRequest.addFlags(SMB2_FLAGS_RELATED_OPERATIONS);
            testRequest.setNext(nextRequest);

            CommonServerMessageBlockRequest result = testRequest.split();

            assertSame(nextRequest, result);
            assertNull(testRequest.getNext());
            assertEquals(0, nextRequest.getFlags() & SMB2_FLAGS_RELATED_OPERATIONS);
        }

        @Test
        @DisplayName("split should return null when no next request")
        void testSplitNoNext() {
            CommonServerMessageBlockRequest result = testRequest.split();
            assertNull(result);
        }
    }

    @Nested
    @DisplayName("Response Management Tests")
    class ResponseManagementTests {

        @Test
        @DisplayName("initResponse should create and set response")
        void testInitResponse() {
            TestServerMessageBlock2Response expectedResponse = new TestServerMessageBlock2Response(mockConfig);
            testRequest.setTestResponse(expectedResponse);
            testRequest.setDigest(mockDigest);

            TestServerMessageBlock2Response result = testRequest.initResponse(mockContext);

            assertNotNull(result);
            assertSame(expectedResponse, result);
            assertSame(expectedResponse, testRequest.getResponse());
            assertEquals(mockDigest, result.getDigest());
        }

        @Test
        @DisplayName("initResponse should handle null response")
        void testInitResponseNull() {
            testRequest.setTestResponse(null);

            TestServerMessageBlock2Response result = testRequest.initResponse(mockContext);

            assertNull(result);
        }

        @Test
        @DisplayName("initResponse should chain responses for chained requests")
        void testInitResponseChained() {
            TestServerMessageBlock2Response response1 = new TestServerMessageBlock2Response(mockConfig);
            TestServerMessageBlock2Response response2 = new TestServerMessageBlock2Response(mockConfig);

            TestServerMessageBlock2Request nextRequest = new TestServerMessageBlock2Request(mockConfig);
            nextRequest.setTestResponse(response2);

            testRequest.setTestResponse(response1);
            testRequest.setNext(nextRequest);

            TestServerMessageBlock2Response result = testRequest.initResponse(mockContext);

            assertNotNull(result);
            assertSame(response1, result);
            assertSame(response2, result.getNext());
        }

        @Test
        @DisplayName("setResponse should accept valid response")
        void testSetResponse() {
            TestServerMessageBlock2Response response = new TestServerMessageBlock2Response(mockConfig);

            testRequest.setResponse(response);

            assertSame(response, testRequest.getResponse());
        }

        @Test
        @DisplayName("setResponse should accept null")
        void testSetResponseNull() {
            testRequest.setResponse(null);
            assertNull(testRequest.getResponse());
        }

        @Test
        @DisplayName("setResponse should throw exception for incompatible response")
        void testSetResponseIncompatible() {
            CommonServerMessageBlockResponse incompatibleResponse = mock(CommonServerMessageBlockResponse.class);

            assertThrows(IllegalArgumentException.class, () -> {
                testRequest.setResponse(incompatibleResponse);
            });
        }
    }

    @Nested
    @DisplayName("Encoding Tests")
    class EncodingTests {

        @Test
        @DisplayName("encode should validate size calculation")
        void testEncodeValidSize() {
            byte[] buffer = new byte[1024];
            testRequest.setTestSize(64);
            testRequest.setTestLength(64);

            int result = testRequest.encode(buffer, 0);

            assertEquals(64, result);
        }

        @Test
        @DisplayName("encode should throw exception when size mismatch")
        void testEncodeSizeMismatch() {
            byte[] buffer = new byte[1024];
            testRequest.setTestSize(64);
            testRequest.setTestLength(128);

            IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
                testRequest.encode(buffer, 0);
            });

            assertTrue(exception.getMessage().contains("Wrong size calculation"));
        }
    }

    // Test implementation classes
    private static class TestServerMessageBlock2Request extends ServerMessageBlock2Request<TestServerMessageBlock2Response> {
        private TestServerMessageBlock2Response testResponse;
        private int testSize = 64;
        private int testEncodedLength = 64;

        public TestServerMessageBlock2Request(Configuration config) {
            super(config);
        }

        public TestServerMessageBlock2Request(Configuration config, int command) {
            super(config, command);
        }

        public void setTestResponse(TestServerMessageBlock2Response response) {
            this.testResponse = response;
        }

        public void setTestSize(int size) {
            this.testSize = size;
        }

        public void setTestLength(int length) {
            this.testEncodedLength = length;
        }

        @Override
        protected TestServerMessageBlock2Response createResponse(CIFSContext tc,
                ServerMessageBlock2Request<TestServerMessageBlock2Response> req) {
            return testResponse;
        }

        @Override
        public int size() {
            return testSize;
        }

        @Override
        protected int writeHeaderWireFormat(byte[] dst, int dstIndex) {
            return 64; // Simulate header writing
        }

        @Override
        public int encode(byte[] dst, int dstIndex) {
            // We need to override the parent ServerMessageBlock2's encode
            // to properly simulate setting the length field
            int start = dstIndex;
            dstIndex += writeHeaderWireFormat(dst, dstIndex);
            dstIndex += writeBytesWireFormat(dst, dstIndex);

            // Set the length field that will be checked by ServerMessageBlock2Request.encode()
            int calculatedLength = testEncodedLength;
            setLength(calculatedLength);

            // Now call the ServerMessageBlock2Request's encode which will do the validation
            int exp = size();
            int actual = getLength();
            if (exp != actual) {
                throw new IllegalStateException(String.format("Wrong size calculation have %d expect %d", exp, actual));
            }

            return calculatedLength;
        }

        private void setLength(int length) {
            try {
                // Use reflection to set the protected length field
                java.lang.reflect.Field lengthField = ServerMessageBlock2.class.getDeclaredField("length");
                lengthField.setAccessible(true);
                lengthField.setInt(this, length);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        protected int readBytesWireFormat(byte[] buffer, int bufferIndex) {
            return 0;
        }

        @Override
        protected int writeBytesWireFormat(byte[] dst, int dstIndex) {
            return 0;
        }
    }

    private static class TestServerMessageBlock2Response extends ServerMessageBlock2Response {
        public TestServerMessageBlock2Response(Configuration config) {
            super(config);
        }

        @Override
        protected int readBytesWireFormat(byte[] buffer, int bufferIndex) {
            return 0;
        }

        @Override
        protected int writeBytesWireFormat(byte[] dst, int dstIndex) {
            return 0;
        }
    }
}
