package jcifs.internal;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.config.PropertyConfiguration;

/**
 * Test class for Request interface
 */
@ExtendWith(MockitoExtension.class)
class RequestTest {

    @Mock
    private Request<CommonServerMessageBlockResponse> request;
    
    @Mock
    private CommonServerMessageBlockResponse response;
    
    @Mock
    private CIFSContext context;
    
    @Mock
    private CommonServerMessageBlock disconnectRequest;
    
    @Mock
    private CommonServerMessageBlockRequest nextRequest;

    @BeforeEach
    void setUp() {
        // Reset mocks before each test
        reset(request, response, context, disconnectRequest, nextRequest);
    }

    @Test
    @DisplayName("Test initResponse returns initialized response")
    void testInitResponse() {
        // Given
        when(request.initResponse(context)).thenReturn(response);
        
        // When
        CommonServerMessageBlockResponse result = request.initResponse(context);
        
        // Then
        assertNotNull(result);
        assertEquals(response, result);
        verify(request, times(1)).initResponse(context);
    }

    @Test
    @DisplayName("Test initResponse with null context")
    void testInitResponseWithNullContext() {
        // Given
        when(request.initResponse(null)).thenReturn(response);
        
        // When
        CommonServerMessageBlockResponse result = request.initResponse(null);
        
        // Then
        assertNotNull(result);
        assertEquals(response, result);
        verify(request, times(1)).initResponse(null);
    }

    @Test
    @DisplayName("Test getResponse returns the response message")
    void testGetResponse() {
        // Given
        when(request.getResponse()).thenReturn(response);
        
        // When
        CommonServerMessageBlockResponse result = request.getResponse();
        
        // Then
        assertNotNull(result);
        assertEquals(response, result);
        verify(request, times(1)).getResponse();
    }

    @Test
    @DisplayName("Test getResponse returns null when no response set")
    void testGetResponseReturnsNull() {
        // Given
        when(request.getResponse()).thenReturn(null);
        
        // When
        CommonServerMessageBlockResponse result = request.getResponse();
        
        // Then
        assertNull(result);
        verify(request, times(1)).getResponse();
    }

    @Test
    @DisplayName("Test ignoreDisconnect returns request")
    void testIgnoreDisconnect() {
        // Given
        when(request.ignoreDisconnect()).thenReturn(disconnectRequest);
        
        // When
        CommonServerMessageBlock result = request.ignoreDisconnect();
        
        // Then
        assertNotNull(result);
        assertEquals(disconnectRequest, result);
        verify(request, times(1)).ignoreDisconnect();
    }

    @Test
    @DisplayName("Test ignoreDisconnect returns self")
    void testIgnoreDisconnectReturnsSelf() {
        // Given
        when(request.ignoreDisconnect()).thenReturn(request);
        
        // When
        CommonServerMessageBlock result = request.ignoreDisconnect();
        
        // Then
        assertNotNull(result);
        assertEquals(request, result);
        verify(request, times(1)).ignoreDisconnect();
    }

    @Test
    @DisplayName("Test Request interface extends CommonServerMessageBlockRequest")
    void testRequestExtendsCommonServerMessageBlockRequest() {
        // Then
        assertTrue(CommonServerMessageBlockRequest.class.isAssignableFrom(Request.class));
    }

    @Test
    @DisplayName("Test Request methods inherited from CommonServerMessageBlockRequest")
    void testInheritedMethods() {
        // Given
        when(request.isResponseAsync()).thenReturn(true);
        when(request.getNext()).thenReturn(nextRequest);
        when(request.split()).thenReturn(nextRequest);
        when(request.allowChain(nextRequest)).thenReturn(true);
        when(request.createCancel()).thenReturn(nextRequest);
        when(request.size()).thenReturn(1024);
        when(request.getOverrideTimeout()).thenReturn(5000);
        
        // When & Then
        assertTrue(request.isResponseAsync());
        assertEquals(nextRequest, request.getNext());
        assertEquals(nextRequest, request.split());
        assertTrue(request.allowChain(nextRequest));
        assertEquals(nextRequest, request.createCancel());
        assertEquals(1024, request.size());
        assertEquals(Integer.valueOf(5000), request.getOverrideTimeout());
        
        verify(request, times(1)).isResponseAsync();
        verify(request, times(1)).getNext();
        verify(request, times(1)).split();
        verify(request, times(1)).allowChain(nextRequest);
        verify(request, times(1)).createCancel();
        verify(request, times(1)).size();
        verify(request, times(1)).getOverrideTimeout();
    }

    @Test
    @DisplayName("Test Request with concrete implementation")
    void testConcreteImplementation() {
        // Create a concrete implementation for testing
        TestRequest testRequest = new TestRequest();
        
        // Test initResponse
        CommonServerMessageBlockResponse testResponse = testRequest.initResponse(context);
        assertNotNull(testResponse);
        assertTrue(testResponse instanceof TestResponse);
        
        // Test getResponse
        assertNotNull(testRequest.getResponse());
        assertEquals(testResponse, testRequest.getResponse());
        
        // Test ignoreDisconnect
        CommonServerMessageBlock ignored = testRequest.ignoreDisconnect();
        assertNotNull(ignored);
        assertEquals(testRequest, ignored);
    }

    /**
     * Test implementation of Request interface
     */
    private static class TestRequest implements Request<TestResponse> {
        private TestResponse response;
        private boolean ignoreDisconnect = false;
        private int tid = 0;
        private SMBSigningDigest digest;
        private long mid = 0;
        private int command = 0;
        private byte[] rawPayload;
        private boolean retainPayload = false;
        private int requestCredits = 1;

        @Override
        public TestResponse initResponse(CIFSContext tc) {
            this.response = new TestResponse();
            return this.response;
        }

        @Override
        public TestResponse getResponse() {
            return this.response;
        }

        @Override
        public CommonServerMessageBlock ignoreDisconnect() {
            this.ignoreDisconnect = true;
            return this;
        }

        @Override
        public boolean isResponseAsync() {
            return false;
        }

        @Override
        public CommonServerMessageBlockRequest getNext() {
            return null;
        }

        @Override
        public CommonServerMessageBlockRequest split() {
            return null;
        }

        @Override
        public boolean allowChain(CommonServerMessageBlockRequest next) {
            return true;
        }

        @Override
        public CommonServerMessageBlockRequest createCancel() {
            return null;
        }

        @Override
        public int size() {
            return 0;
        }

        @Override
        public void setTid(int t) {
            this.tid = t;
        }

        @Override
        public Integer getOverrideTimeout() {
            return null;
        }

        // Methods from CommonServerMessageBlock interface
        @Override
        public int decode(byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
            return 0;
        }

        @Override
        public int encode(byte[] dst, int dstIndex) {
            return 0;
        }

        @Override
        public void setDigest(SMBSigningDigest digest) {
            this.digest = digest;
        }

        @Override
        public SMBSigningDigest getDigest() {
            return digest;
        }

        @Override
        public void setResponse(CommonServerMessageBlockResponse msg) {
            this.response = (TestResponse) msg;
        }

        @Override
        public long getMid() {
            return mid;
        }

        @Override
        public void setMid(long mid) {
            this.mid = mid;
        }

        @Override
        public int getCommand() {
            return command;
        }

        @Override
        public void setCommand(int command) {
            this.command = command;
        }

        @Override
        public void setUid(int uid) {
            // No-op for test
        }

        @Override
        public void setExtendedSecurity(boolean extendedSecurity) {
            // No-op for test
        }

        @Override
        public void setSessionId(long sessionId) {
            // No-op for test
        }

        @Override
        public void reset() {
            this.response = null;
            this.ignoreDisconnect = false;
        }

        // Methods from jcifs.util.transport.Request interface
        @Override
        public int getCreditCost() {
            return 1;
        }

        @Override
        public void setRequestCredits(int credits) {
            this.requestCredits = credits;
        }

        @Override
        public boolean isCancel() {
            return false;
        }

        // Methods from Message interface
        @Override
        public void retainPayload() {
            this.retainPayload = true;
        }

        @Override
        public boolean isRetainPayload() {
            return retainPayload;
        }

        @Override
        public byte[] getRawPayload() {
            return rawPayload;
        }

        @Override
        public void setRawPayload(byte[] rawPayload) {
            this.rawPayload = rawPayload;
        }
    }

    /**
     * Test implementation of CommonServerMessageBlockResponse
     */
    private static class TestResponse implements CommonServerMessageBlockResponse {
        private boolean async = false;
        private CommonServerMessageBlockResponse nextResponse;
        private boolean received = false;
        private int errorCode = 0;
        private long mid = 0;
        private Long expiration = null;
        private Exception exception = null;
        private SMBSigningDigest digest;
        private CommonServerMessageBlockResponse response;
        private int command = 0;
        private byte[] rawPayload;
        private boolean retainPayload = false;
        
        @Override
        public boolean isAsync() {
            return async;
        }

        @Override
        public CommonServerMessageBlockResponse getNextResponse() {
            return nextResponse;
        }

        @Override
        public void prepare(CommonServerMessageBlockRequest next) {
            // No-op for test
        }

        // Methods from CommonServerMessageBlock interface
        @Override
        public int decode(byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
            return 0;
        }

        @Override
        public int encode(byte[] dst, int dstIndex) {
            return 0;
        }

        @Override
        public void setDigest(SMBSigningDigest digest) {
            this.digest = digest;
        }

        @Override
        public SMBSigningDigest getDigest() {
            return digest;
        }

        @Override
        public CommonServerMessageBlockResponse getResponse() {
            return response;
        }

        @Override
        public void setResponse(CommonServerMessageBlockResponse msg) {
            this.response = msg;
        }

        @Override
        public long getMid() {
            return mid;
        }

        @Override
        public void setMid(long mid) {
            this.mid = mid;
        }

        @Override
        public int getCommand() {
            return command;
        }

        @Override
        public void setCommand(int command) {
            this.command = command;
        }

        @Override
        public void setUid(int uid) {
            // No-op for test
        }

        @Override
        public void setExtendedSecurity(boolean extendedSecurity) {
            // No-op for test
        }

        @Override
        public void setSessionId(long sessionId) {
            // No-op for test
        }

        @Override
        public void reset() {
            this.received = false;
            this.errorCode = 0;
            this.exception = null;
        }

        // Methods from jcifs.util.transport.Response interface
        @Override
        public boolean isReceived() {
            return received;
        }

        @Override
        public void received() {
            this.received = true;
        }

        @Override
        public void clearReceived() {
            this.received = false;
        }

        @Override
        public int getGrantedCredits() {
            return 1;
        }

        @Override
        public int getErrorCode() {
            return errorCode;
        }

        @Override
        public boolean verifySignature(byte[] buffer, int i, int size) {
            return true;
        }

        @Override
        public boolean isVerifyFailed() {
            return false;
        }

        @Override
        public boolean isError() {
            return errorCode != 0;
        }

        @Override
        public void error() {
            this.errorCode = -1;
        }

        @Override
        public Long getExpiration() {
            return expiration;
        }

        @Override
        public void setExpiration(Long exp) {
            this.expiration = exp;
        }

        @Override
        public Exception getException() {
            return exception;
        }

        @Override
        public void exception(Exception e) {
            this.exception = e;
        }

        // Methods from Message interface
        @Override
        public void retainPayload() {
            this.retainPayload = true;
        }

        @Override
        public boolean isRetainPayload() {
            return retainPayload;
        }

        @Override
        public byte[] getRawPayload() {
            return rawPayload;
        }

        @Override
        public void setRawPayload(byte[] rawPayload) {
            this.rawPayload = rawPayload;
        }
    }
}