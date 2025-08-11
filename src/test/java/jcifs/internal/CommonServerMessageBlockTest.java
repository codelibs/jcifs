package jcifs.internal;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Test class for CommonServerMessageBlock interface
 */
class CommonServerMessageBlockTest {

    @Mock
    private CommonServerMessageBlock messageBlock;
    
    @Mock
    private CommonServerMessageBlockResponse response;
    
    @Mock
    private SMBSigningDigest digest;
    
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }
    
    @Test
    @DisplayName("Test decode method with valid buffer")
    void testDecodeWithValidBuffer() throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[256];
        int bufferIndex = 0;
        int expectedLength = 100;
        
        when(messageBlock.decode(buffer, bufferIndex)).thenReturn(expectedLength);
        
        // When
        int actualLength = messageBlock.decode(buffer, bufferIndex);
        
        // Then
        assertEquals(expectedLength, actualLength);
        verify(messageBlock).decode(buffer, bufferIndex);
    }
    
    @Test
    @DisplayName("Test decode method throws SMBProtocolDecodingException")
    void testDecodeThrowsException() throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[10];
        int bufferIndex = 0;
        
        when(messageBlock.decode(buffer, bufferIndex))
            .thenThrow(new SMBProtocolDecodingException("Invalid buffer"));
        
        // When & Then
        assertThrows(SMBProtocolDecodingException.class, 
            () -> messageBlock.decode(buffer, bufferIndex));
    }
    
    @Test
    @DisplayName("Test encode method with valid destination")
    void testEncodeWithValidDestination() {
        // Given
        byte[] dst = new byte[256];
        int dstIndex = 0;
        int expectedLength = 50;
        
        when(messageBlock.encode(dst, dstIndex)).thenReturn(expectedLength);
        
        // When
        int actualLength = messageBlock.encode(dst, dstIndex);
        
        // Then
        assertEquals(expectedLength, actualLength);
        verify(messageBlock).encode(dst, dstIndex);
    }
    
    @Test
    @DisplayName("Test setDigest and getDigest methods")
    void testSetAndGetDigest() {
        // Given
        doNothing().when(messageBlock).setDigest(digest);
        when(messageBlock.getDigest()).thenReturn(digest);
        
        // When
        messageBlock.setDigest(digest);
        SMBSigningDigest retrievedDigest = messageBlock.getDigest();
        
        // Then
        assertEquals(digest, retrievedDigest);
        verify(messageBlock).setDigest(digest);
        verify(messageBlock).getDigest();
    }
    
    @Test
    @DisplayName("Test setDigest with null value")
    void testSetDigestWithNull() {
        // Given
        doNothing().when(messageBlock).setDigest(null);
        when(messageBlock.getDigest()).thenReturn(null);
        
        // When
        messageBlock.setDigest(null);
        SMBSigningDigest retrievedDigest = messageBlock.getDigest();
        
        // Then
        assertNull(retrievedDigest);
        verify(messageBlock).setDigest(null);
    }
    
    @Test
    @DisplayName("Test setResponse and getResponse methods")
    void testSetAndGetResponse() {
        // Given
        doNothing().when(messageBlock).setResponse(response);
        when(messageBlock.getResponse()).thenReturn(response);
        
        // When
        messageBlock.setResponse(response);
        CommonServerMessageBlockResponse retrievedResponse = messageBlock.getResponse();
        
        // Then
        assertEquals(response, retrievedResponse);
        verify(messageBlock).setResponse(response);
        verify(messageBlock).getResponse();
    }
    
    @Test
    @DisplayName("Test setResponse with null value")
    void testSetResponseWithNull() {
        // Given
        doNothing().when(messageBlock).setResponse(null);
        when(messageBlock.getResponse()).thenReturn(null);
        
        // When
        messageBlock.setResponse(null);
        CommonServerMessageBlockResponse retrievedResponse = messageBlock.getResponse();
        
        // Then
        assertNull(retrievedResponse);
        verify(messageBlock).setResponse(null);
    }
    
    @Test
    @DisplayName("Test setMid and getMid methods")
    void testSetAndGetMid() {
        // Given
        long expectedMid = 12345L;
        doNothing().when(messageBlock).setMid(expectedMid);
        when(messageBlock.getMid()).thenReturn(expectedMid);
        
        // When
        messageBlock.setMid(expectedMid);
        long actualMid = messageBlock.getMid();
        
        // Then
        assertEquals(expectedMid, actualMid);
        verify(messageBlock).setMid(expectedMid);
        verify(messageBlock).getMid();
    }
    
    @Test
    @DisplayName("Test setMid with boundary values")
    void testSetMidWithBoundaryValues() {
        // Test with MAX_VALUE
        long maxMid = Long.MAX_VALUE;
        doNothing().when(messageBlock).setMid(maxMid);
        when(messageBlock.getMid()).thenReturn(maxMid);
        
        messageBlock.setMid(maxMid);
        assertEquals(maxMid, messageBlock.getMid());
        
        // Test with MIN_VALUE
        long minMid = Long.MIN_VALUE;
        doNothing().when(messageBlock).setMid(minMid);
        when(messageBlock.getMid()).thenReturn(minMid);
        
        messageBlock.setMid(minMid);
        assertEquals(minMid, messageBlock.getMid());
        
        // Test with zero
        long zeroMid = 0L;
        doNothing().when(messageBlock).setMid(zeroMid);
        when(messageBlock.getMid()).thenReturn(zeroMid);
        
        messageBlock.setMid(zeroMid);
        assertEquals(zeroMid, messageBlock.getMid());
    }
    
    @Test
    @DisplayName("Test setCommand and getCommand methods")
    void testSetAndGetCommand() {
        // Given
        int expectedCommand = 0x73;
        doNothing().when(messageBlock).setCommand(expectedCommand);
        when(messageBlock.getCommand()).thenReturn(expectedCommand);
        
        // When
        messageBlock.setCommand(expectedCommand);
        int actualCommand = messageBlock.getCommand();
        
        // Then
        assertEquals(expectedCommand, actualCommand);
        verify(messageBlock).setCommand(expectedCommand);
        verify(messageBlock).getCommand();
    }
    
    @Test
    @DisplayName("Test setCommand with various SMB command codes")
    void testSetCommandWithVariousCodes() {
        // Test common SMB command codes
        int[] commandCodes = {0x00, 0x72, 0x73, 0x74, 0x75, 0xFF};
        
        for (int command : commandCodes) {
            doNothing().when(messageBlock).setCommand(command);
            when(messageBlock.getCommand()).thenReturn(command);
            
            messageBlock.setCommand(command);
            assertEquals(command, messageBlock.getCommand());
        }
    }
    
    @Test
    @DisplayName("Test setUid method")
    void testSetUid() {
        // Given
        int uid = 1000;
        doNothing().when(messageBlock).setUid(uid);
        
        // When
        messageBlock.setUid(uid);
        
        // Then
        verify(messageBlock).setUid(uid);
    }
    
    @Test
    @DisplayName("Test setUid with boundary values")
    void testSetUidWithBoundaryValues() {
        // Test with various uid values
        int[] uids = {0, 1, Integer.MAX_VALUE, Integer.MIN_VALUE};
        
        for (int uid : uids) {
            doNothing().when(messageBlock).setUid(uid);
            messageBlock.setUid(uid);
            verify(messageBlock).setUid(uid);
        }
    }
    
    @Test
    @DisplayName("Test setExtendedSecurity method with true")
    void testSetExtendedSecurityTrue() {
        // Given
        boolean extendedSecurity = true;
        doNothing().when(messageBlock).setExtendedSecurity(extendedSecurity);
        
        // When
        messageBlock.setExtendedSecurity(extendedSecurity);
        
        // Then
        verify(messageBlock).setExtendedSecurity(true);
    }
    
    @Test
    @DisplayName("Test setExtendedSecurity method with false")
    void testSetExtendedSecurityFalse() {
        // Given
        boolean extendedSecurity = false;
        doNothing().when(messageBlock).setExtendedSecurity(extendedSecurity);
        
        // When
        messageBlock.setExtendedSecurity(extendedSecurity);
        
        // Then
        verify(messageBlock).setExtendedSecurity(false);
    }
    
    @Test
    @DisplayName("Test setSessionId method")
    void testSetSessionId() {
        // Given
        long sessionId = 987654321L;
        doNothing().when(messageBlock).setSessionId(sessionId);
        
        // When
        messageBlock.setSessionId(sessionId);
        
        // Then
        verify(messageBlock).setSessionId(sessionId);
    }
    
    @Test
    @DisplayName("Test setSessionId with boundary values")
    void testSetSessionIdWithBoundaryValues() {
        // Test with various session ID values
        long[] sessionIds = {0L, 1L, Long.MAX_VALUE, Long.MIN_VALUE, -1L};
        
        for (long sessionId : sessionIds) {
            doNothing().when(messageBlock).setSessionId(sessionId);
            messageBlock.setSessionId(sessionId);
            verify(messageBlock).setSessionId(sessionId);
        }
    }
    
    @Test
    @DisplayName("Test reset method")
    void testReset() {
        // Given
        doNothing().when(messageBlock).reset();
        
        // When
        messageBlock.reset();
        
        // Then
        verify(messageBlock).reset();
    }
    
    @Test
    @DisplayName("Test multiple operations in sequence")
    void testMultipleOperationsInSequence() {
        // Given
        long mid = 123L;
        int command = 0x73;
        int uid = 500;
        long sessionId = 999L;
        
        doNothing().when(messageBlock).setMid(mid);
        doNothing().when(messageBlock).setCommand(command);
        doNothing().when(messageBlock).setUid(uid);
        doNothing().when(messageBlock).setSessionId(sessionId);
        doNothing().when(messageBlock).setExtendedSecurity(true);
        doNothing().when(messageBlock).setDigest(digest);
        doNothing().when(messageBlock).setResponse(response);
        doNothing().when(messageBlock).reset();
        
        when(messageBlock.getMid()).thenReturn(mid);
        when(messageBlock.getCommand()).thenReturn(command);
        when(messageBlock.getDigest()).thenReturn(digest);
        when(messageBlock.getResponse()).thenReturn(response);
        
        // When - simulate a typical usage sequence
        messageBlock.setMid(mid);
        messageBlock.setCommand(command);
        messageBlock.setUid(uid);
        messageBlock.setSessionId(sessionId);
        messageBlock.setExtendedSecurity(true);
        messageBlock.setDigest(digest);
        messageBlock.setResponse(response);
        
        // Then - verify all operations
        assertEquals(mid, messageBlock.getMid());
        assertEquals(command, messageBlock.getCommand());
        assertEquals(digest, messageBlock.getDigest());
        assertEquals(response, messageBlock.getResponse());
        
        // Reset and verify
        messageBlock.reset();
        verify(messageBlock).reset();
    }
    
    @Test
    @DisplayName("Test encode and decode round trip")
    void testEncodeDecodeRoundTrip() throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[512];
        int encodeIndex = 0;
        int decodeIndex = 0;
        int encodeLength = 100;
        int decodeLength = 100;
        
        when(messageBlock.encode(buffer, encodeIndex)).thenReturn(encodeLength);
        when(messageBlock.decode(buffer, decodeIndex)).thenReturn(decodeLength);
        
        // When
        int encoded = messageBlock.encode(buffer, encodeIndex);
        int decoded = messageBlock.decode(buffer, decodeIndex);
        
        // Then
        assertEquals(encodeLength, encoded);
        assertEquals(decodeLength, decoded);
        verify(messageBlock).encode(buffer, encodeIndex);
        verify(messageBlock).decode(buffer, decodeIndex);
    }
    
    @Test
    @DisplayName("Test implementation with concrete mock")
    void testConcreteImplementation() throws SMBProtocolDecodingException {
        // Create a concrete implementation for testing
        CommonServerMessageBlock concreteBlock = new CommonServerMessageBlock() {
            private long mid;
            private int command;
            private SMBSigningDigest digest;
            private CommonServerMessageBlockResponse response;
            
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
            public void reset() {
                this.mid = 0;
                this.command = 0;
                this.digest = null;
                this.response = null;
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
        
        // Test the concrete implementation
        concreteBlock.setMid(555L);
        assertEquals(555L, concreteBlock.getMid());
        
        concreteBlock.setCommand(0x42);
        assertEquals(0x42, concreteBlock.getCommand());
        
        concreteBlock.setDigest(digest);
        assertEquals(digest, concreteBlock.getDigest());
        
        concreteBlock.setResponse(response);
        assertEquals(response, concreteBlock.getResponse());
        
        byte[] buffer = new byte[10];
        assertEquals(4, concreteBlock.encode(buffer, 0));
        assertEquals(4, concreteBlock.decode(buffer, 0));
        
        concreteBlock.reset();
        assertEquals(0L, concreteBlock.getMid());
        assertEquals(0, concreteBlock.getCommand());
        assertNull(concreteBlock.getDigest());
        assertNull(concreteBlock.getResponse());
    }
}
