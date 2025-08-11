package jcifs.internal;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Test class for CommonServerMessageBlockResponse interface
 */
class CommonServerMessageBlockResponseTest {

    @Mock
    private CommonServerMessageBlockResponse response;
    
    @Mock
    private CommonServerMessageBlockResponse nextResponse;
    
    @Mock
    private CommonServerMessageBlockRequest request;
    
    @Mock
    private SMBSigningDigest digest;
    
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }
    
    @Test
    @DisplayName("Test isAsync method returning true")
    void testIsAsyncTrue() {
        // Given
        when(response.isAsync()).thenReturn(true);
        
        // When
        boolean isAsync = response.isAsync();
        
        // Then
        assertTrue(isAsync);
        verify(response).isAsync();
    }
    
    @Test
    @DisplayName("Test isAsync method returning false")
    void testIsAsyncFalse() {
        // Given
        when(response.isAsync()).thenReturn(false);
        
        // When
        boolean isAsync = response.isAsync();
        
        // Then
        assertFalse(isAsync);
        verify(response).isAsync();
    }
    
    @Test
    @DisplayName("Test getNextResponse method with valid next response")
    void testGetNextResponseWithValidResponse() {
        // Given
        when(response.getNextResponse()).thenReturn(nextResponse);
        
        // When
        CommonServerMessageBlockResponse actual = response.getNextResponse();
        
        // Then
        assertEquals(nextResponse, actual);
        verify(response).getNextResponse();
    }
    
    @Test
    @DisplayName("Test getNextResponse method returning null")
    void testGetNextResponseReturningNull() {
        // Given
        when(response.getNextResponse()).thenReturn(null);
        
        // When
        CommonServerMessageBlockResponse actual = response.getNextResponse();
        
        // Then
        assertNull(actual);
        verify(response).getNextResponse();
    }
    
    @Test
    @DisplayName("Test prepare method with valid request")
    void testPrepareWithValidRequest() {
        // Given
        doNothing().when(response).prepare(request);
        
        // When
        response.prepare(request);
        
        // Then
        verify(response).prepare(request);
    }
    
    @Test
    @DisplayName("Test prepare method with null request")
    void testPrepareWithNullRequest() {
        // Given
        doNothing().when(response).prepare(null);
        
        // When
        response.prepare(null);
        
        // Then
        verify(response).prepare(null);
    }
    
    @Test
    @DisplayName("Test chained response navigation")
    void testChainedResponseNavigation() {
        // Given
        CommonServerMessageBlockResponse thirdResponse = mock(CommonServerMessageBlockResponse.class);
        when(response.getNextResponse()).thenReturn(nextResponse);
        when(nextResponse.getNextResponse()).thenReturn(thirdResponse);
        when(thirdResponse.getNextResponse()).thenReturn(null);
        
        // When - navigate through chain
        CommonServerMessageBlockResponse second = response.getNextResponse();
        CommonServerMessageBlockResponse third = second.getNextResponse();
        CommonServerMessageBlockResponse end = third.getNextResponse();
        
        // Then
        assertEquals(nextResponse, second);
        assertEquals(thirdResponse, third);
        assertNull(end);
    }
    
    @Test
    @DisplayName("Test Response interface methods - isReceived")
    void testIsReceived() {
        // Given
        when(response.isReceived()).thenReturn(true);
        
        // When
        boolean received = response.isReceived();
        
        // Then
        assertTrue(received);
        verify(response).isReceived();
    }
    
    @Test
    @DisplayName("Test Response interface methods - received")
    void testReceived() {
        // Given
        doNothing().when(response).received();
        
        // When
        response.received();
        
        // Then
        verify(response).received();
    }
    
    @Test
    @DisplayName("Test Response interface methods - clearReceived")
    void testClearReceived() {
        // Given
        doNothing().when(response).clearReceived();
        
        // When
        response.clearReceived();
        
        // Then
        verify(response).clearReceived();
    }
    
    @Test
    @DisplayName("Test Response interface methods - getGrantedCredits")
    void testGetGrantedCredits() {
        // Given
        int expectedCredits = 64;
        when(response.getGrantedCredits()).thenReturn(expectedCredits);
        
        // When
        int actualCredits = response.getGrantedCredits();
        
        // Then
        assertEquals(expectedCredits, actualCredits);
        verify(response).getGrantedCredits();
    }
    
    @Test
    @DisplayName("Test Response interface methods - getErrorCode")
    void testGetErrorCode() {
        // Given
        int expectedErrorCode = 0xC0000001;
        when(response.getErrorCode()).thenReturn(expectedErrorCode);
        
        // When
        int actualErrorCode = response.getErrorCode();
        
        // Then
        assertEquals(expectedErrorCode, actualErrorCode);
        verify(response).getErrorCode();
    }
    
    @Test
    @DisplayName("Test Response interface methods - verifySignature")
    void testVerifySignature() {
        // Given
        byte[] buffer = new byte[256];
        int offset = 10;
        int size = 100;
        when(response.verifySignature(buffer, offset, size)).thenReturn(true);
        
        // When
        boolean verified = response.verifySignature(buffer, offset, size);
        
        // Then
        assertTrue(verified);
        verify(response).verifySignature(buffer, offset, size);
    }
    
    @Test
    @DisplayName("Test Response interface methods - isVerifyFailed")
    void testIsVerifyFailed() {
        // Given
        when(response.isVerifyFailed()).thenReturn(false);
        
        // When
        boolean verifyFailed = response.isVerifyFailed();
        
        // Then
        assertFalse(verifyFailed);
        verify(response).isVerifyFailed();
    }
    
    @Test
    @DisplayName("Test Response interface methods - isError")
    void testIsError() {
        // Given
        when(response.isError()).thenReturn(false);
        
        // When
        boolean isError = response.isError();
        
        // Then
        assertFalse(isError);
        verify(response).isError();
    }
    
    @Test
    @DisplayName("Test Response interface methods - error")
    void testError() {
        // Given
        doNothing().when(response).error();
        
        // When
        response.error();
        
        // Then
        verify(response).error();
    }
    
    @Test
    @DisplayName("Test Response interface methods - getExpiration")
    void testGetExpiration() {
        // Given
        Long expectedExpiration = System.currentTimeMillis() + 30000L;
        when(response.getExpiration()).thenReturn(expectedExpiration);
        
        // When
        Long actualExpiration = response.getExpiration();
        
        // Then
        assertEquals(expectedExpiration, actualExpiration);
        verify(response).getExpiration();
    }
    
    @Test
    @DisplayName("Test Response interface methods - setExpiration")
    void testSetExpiration() {
        // Given
        Long expiration = System.currentTimeMillis() + 60000L;
        doNothing().when(response).setExpiration(expiration);
        
        // When
        response.setExpiration(expiration);
        
        // Then
        verify(response).setExpiration(expiration);
    }
    
    @Test
    @DisplayName("Test Response interface methods - getException")
    void testGetException() {
        // Given
        Exception expectedException = new Exception("Test exception");
        when(response.getException()).thenReturn(expectedException);
        
        // When
        Exception actualException = response.getException();
        
        // Then
        assertEquals(expectedException, actualException);
        verify(response).getException();
    }
    
    @Test
    @DisplayName("Test Response interface methods - exception")
    void testException() {
        // Given
        Exception ex = new RuntimeException("Runtime error");
        doNothing().when(response).exception(ex);
        
        // When
        response.exception(ex);
        
        // Then
        verify(response).exception(ex);
    }
    
    @Test
    @DisplayName("Test CommonServerMessageBlock inherited methods")
    void testCommonServerMessageBlockMethods() throws SMBProtocolDecodingException {
        // Test decode method
        byte[] buffer = new byte[512];
        int bufferIndex = 0;
        int expectedDecodeLength = 128;
        when(response.decode(buffer, bufferIndex)).thenReturn(expectedDecodeLength);
        assertEquals(expectedDecodeLength, response.decode(buffer, bufferIndex));
        
        // Test encode method
        byte[] dst = new byte[512];
        int dstIndex = 0;
        int expectedEncodeLength = 64;
        when(response.encode(dst, dstIndex)).thenReturn(expectedEncodeLength);
        assertEquals(expectedEncodeLength, response.encode(dst, dstIndex));
        
        // Test digest methods
        doNothing().when(response).setDigest(digest);
        when(response.getDigest()).thenReturn(digest);
        response.setDigest(digest);
        assertEquals(digest, response.getDigest());
        
        // Test mid methods
        long mid = 123456L;
        doNothing().when(response).setMid(mid);
        when(response.getMid()).thenReturn(mid);
        response.setMid(mid);
        assertEquals(mid, response.getMid());
        
        // Test command methods
        int command = 0x25;
        doNothing().when(response).setCommand(command);
        when(response.getCommand()).thenReturn(command);
        response.setCommand(command);
        assertEquals(command, response.getCommand());
        
        // Test other setter methods
        doNothing().when(response).setUid(1000);
        response.setUid(1000);
        verify(response).setUid(1000);
        
        doNothing().when(response).setExtendedSecurity(true);
        response.setExtendedSecurity(true);
        verify(response).setExtendedSecurity(true);
        
        doNothing().when(response).setSessionId(999L);
        response.setSessionId(999L);
        verify(response).setSessionId(999L);
        
        // Test reset method
        doNothing().when(response).reset();
        response.reset();
        verify(response).reset();
    }
    
    @Test
    @DisplayName("Test concrete implementation with multiple scenarios")
    void testConcreteImplementation() throws SMBProtocolDecodingException {
        // Create a concrete implementation for comprehensive testing
        CommonServerMessageBlockResponse concreteResponse = new CommonServerMessageBlockResponse() {
            private boolean async = false;
            private CommonServerMessageBlockResponse next;
            private boolean received = false;
            private boolean error = false;
            private boolean verifyFailed = false;
            private Long expiration;
            private Exception exception;
            private long mid;
            private int command;
            private SMBSigningDigest digest;
            private CommonServerMessageBlockResponse response;
            
            @Override
            public boolean isAsync() {
                return async;
            }
            
            @Override
            public CommonServerMessageBlockResponse getNextResponse() {
                return next;
            }
            
            @Override
            public void prepare(CommonServerMessageBlockRequest next) {
                // Prepare logic
            }
            
            @Override
            public boolean isReceived() {
                return received;
            }
            
            @Override
            public void received() {
                received = true;
            }
            
            @Override
            public void clearReceived() {
                received = false;
            }
            
            @Override
            public int getGrantedCredits() {
                return 32;
            }
            
            @Override
            public int getErrorCode() {
                return error ? 0xC0000001 : 0;
            }
            
            @Override
            public boolean verifySignature(byte[] buffer, int i, int size) {
                return !verifyFailed;
            }
            
            @Override
            public boolean isVerifyFailed() {
                return verifyFailed;
            }
            
            @Override
            public boolean isError() {
                return error;
            }
            
            @Override
            public void error() {
                error = true;
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
            public void reset() {
                async = false;
                next = null;
                received = false;
                error = false;
                verifyFailed = false;
                expiration = null;
                exception = null;
                mid = 0;
                command = 0;
                digest = null;
                response = null;
            }
            
            @Override
            public Exception getException() {
                return exception;
            }
            
            @Override
            public void exception(Exception e) {
                this.exception = e;
            }
            
            @Override
            public int decode(byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
                if (buffer == null || buffer.length < bufferIndex + 4) {
                    throw new SMBProtocolDecodingException("Buffer too small");
                }
                return 4;
            }
            
            @Override
            public int encode(byte[] dst, int dstIndex) {
                return 4;
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
                // Implementation
            }
            
            @Override
            public void setExtendedSecurity(boolean extendedSecurity) {
                // Implementation
            }
            
            @Override
            public void setSessionId(long sessionId) {
                // Implementation
            }
            
            @Override
            public void setRawPayload(byte[] rawPayload) {
                // Implementation for raw payload
            }
            
            @Override
            public byte[] getRawPayload() {
                // Implementation for getting raw payload
                return null;
            }
            
            @Override
            public boolean isRetainPayload() {
                // Implementation for retain payload flag
                return false;
            }
            
            @Override
            public void retainPayload() {
                // Implementation for retaining payload
            }
        };
        
        // Test async functionality
        assertFalse(concreteResponse.isAsync());
        
        // Test received status
        assertFalse(concreteResponse.isReceived());
        concreteResponse.received();
        assertTrue(concreteResponse.isReceived());
        concreteResponse.clearReceived();
        assertFalse(concreteResponse.isReceived());
        
        // Test error handling
        assertFalse(concreteResponse.isError());
        assertEquals(0, concreteResponse.getErrorCode());
        concreteResponse.error();
        assertTrue(concreteResponse.isError());
        assertEquals(0xC0000001, concreteResponse.getErrorCode());
        
        // Test signature verification
        assertTrue(concreteResponse.verifySignature(new byte[100], 0, 50));
        assertFalse(concreteResponse.isVerifyFailed());
        
        // Test exception handling
        assertNull(concreteResponse.getException());
        Exception testEx = new RuntimeException("Test");
        concreteResponse.exception(testEx);
        assertEquals(testEx, concreteResponse.getException());
        
        // Test expiration
        assertNull(concreteResponse.getExpiration());
        Long exp = System.currentTimeMillis() + 10000L;
        concreteResponse.setExpiration(exp);
        assertEquals(exp, concreteResponse.getExpiration());
        
        // Test granted credits
        assertEquals(32, concreteResponse.getGrantedCredits());
        
        // Test prepare method
        concreteResponse.prepare(request);
        
        // Test next response chain
        assertNull(concreteResponse.getNextResponse());
        
        // Test reset functionality
        concreteResponse.setMid(789L);
        concreteResponse.setCommand(0x42);
        concreteResponse.setDigest(digest);
        concreteResponse.reset();
        assertEquals(0L, concreteResponse.getMid());
        assertEquals(0, concreteResponse.getCommand());
        assertNull(concreteResponse.getDigest());
        assertNull(concreteResponse.getException());
        assertNull(concreteResponse.getExpiration());
        assertFalse(concreteResponse.isError());
        assertFalse(concreteResponse.isReceived());
    }
    
    @Test
    @DisplayName("Test response chain with multiple responses")
    void testResponseChainWithMultipleResponses() {
        // Given
        CommonServerMessageBlockResponse response1 = mock(CommonServerMessageBlockResponse.class);
        CommonServerMessageBlockResponse response2 = mock(CommonServerMessageBlockResponse.class);
        CommonServerMessageBlockResponse response3 = mock(CommonServerMessageBlockResponse.class);
        
        when(response1.getNextResponse()).thenReturn(response2);
        when(response2.getNextResponse()).thenReturn(response3);
        when(response3.getNextResponse()).thenReturn(null);
        
        when(response1.isAsync()).thenReturn(false);
        when(response2.isAsync()).thenReturn(true);
        when(response3.isAsync()).thenReturn(false);
        
        // When - test chain navigation and properties
        CommonServerMessageBlockResponse current = response1;
        int count = 0;
        boolean hasAsync = false;
        
        while (current != null) {
            count++;
            if (current.isAsync()) {
                hasAsync = true;
            }
            current = current.getNextResponse();
        }
        
        // Then
        assertEquals(3, count);
        assertTrue(hasAsync);
    }
    
    @Test
    @DisplayName("Test prepare method with different request types")
    void testPrepareWithDifferentRequestTypes() {
        // Given
        CommonServerMessageBlockRequest regularRequest = mock(CommonServerMessageBlockRequest.class);
        CommonServerMessageBlockRequest asyncRequest = mock(CommonServerMessageBlockRequest.class);
        
        when(asyncRequest.isResponseAsync()).thenReturn(true);
        when(regularRequest.isResponseAsync()).thenReturn(false);
        
        doNothing().when(response).prepare(any());
        
        // When
        response.prepare(regularRequest);
        response.prepare(asyncRequest);
        response.prepare(null);
        
        // Then
        verify(response).prepare(regularRequest);
        verify(response).prepare(asyncRequest);
        verify(response).prepare(null);
    }
}
