package org.codelibs.jcifs.smb.util.transport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class ResponseTest {

    @Mock
    private Response mockResponse;

    @BeforeEach
    void setUp() {
        // Reset mock before each test to ensure clean state
        // MockitoExtension handles this automatically for @Mock fields, but good to be aware.
    }

    @Test
    void testIsReceived() {
        // Test initial state (should be false by default for a fresh mock)
        assertFalse(mockResponse.isReceived());

        // Simulate received status
        when(mockResponse.isReceived()).thenReturn(true);
        assertTrue(mockResponse.isReceived());

        // Verify the method was called
        verify(mockResponse, times(2)).isReceived();
    }

    @Test
    void testReceived() {
        // Call the method
        mockResponse.received();

        // Verify that the method was called
        verify(mockResponse, times(1)).received();
    }

    @Test
    void testClearReceived() {
        // Call the method
        mockResponse.clearReceived();

        // Verify that the method was called
        verify(mockResponse, times(1)).clearReceived();
    }

    @Test
    void testGetGrantedCredits() {
        // Simulate granted credits
        when(mockResponse.getGrantedCredits()).thenReturn(100);
        assertEquals(100, mockResponse.getGrantedCredits());

        // Verify the method was called
        verify(mockResponse, times(1)).getGrantedCredits();
    }

    @Test
    void testGetErrorCode() {
        // Simulate error code
        when(mockResponse.getErrorCode()).thenReturn(-1);
        assertEquals(-1, mockResponse.getErrorCode());

        // Verify the method was called
        verify(mockResponse, times(1)).getErrorCode();
    }

    @Test
    void testSetMid() {
        long mid = 12345L;
        mockResponse.setMid(mid);

        // Verify that the method was called with the correct argument
        verify(mockResponse, times(1)).setMid(mid);
    }

    @Test
    void testGetMid() {
        long mid = 54321L;
        when(mockResponse.getMid()).thenReturn(mid);
        assertEquals(mid, mockResponse.getMid());

        // Verify the method was called
        verify(mockResponse, times(1)).getMid();
    }

    @Test
    void testVerifySignature() {
        byte[] buffer = new byte[] { 1, 2, 3 };
        int offset = 0;
        int size = 3;

        // Simulate successful verification
        when(mockResponse.verifySignature(buffer, offset, size)).thenReturn(true);
        assertTrue(mockResponse.verifySignature(buffer, offset, size));

        // Simulate failed verification
        when(mockResponse.verifySignature(buffer, offset, size)).thenReturn(false);
        assertFalse(mockResponse.verifySignature(buffer, offset, size));

        // Verify the method was called
        verify(mockResponse, times(2)).verifySignature(buffer, offset, size);
    }

    @Test
    void testIsVerifyFailed() {
        // Simulate verification failed status
        when(mockResponse.isVerifyFailed()).thenReturn(true);
        assertTrue(mockResponse.isVerifyFailed());

        // Verify the method was called
        verify(mockResponse, times(1)).isVerifyFailed();
    }

    @Test
    void testIsError() {
        // Test initial state (should be false by default for a fresh mock)
        assertFalse(mockResponse.isError());

        // Simulate error status
        when(mockResponse.isError()).thenReturn(true);
        assertTrue(mockResponse.isError());

        // Verify the method was called
        verify(mockResponse, times(2)).isError();
    }

    @Test
    void testError() {
        // Call the method
        mockResponse.error();

        // Verify that the method was called
        verify(mockResponse, times(1)).error();
    }

    @Test
    void testGetExpiration() {
        Long expiration = 123456789L;
        when(mockResponse.getExpiration()).thenReturn(expiration);
        assertEquals(expiration, mockResponse.getExpiration());

        // Test null expiration
        when(mockResponse.getExpiration()).thenReturn(null);
        assertNull(mockResponse.getExpiration());

        // Verify the method was called
        verify(mockResponse, times(2)).getExpiration();
    }

    @Test
    void testSetExpiration() {
        Long expiration = 987654321L;
        mockResponse.setExpiration(expiration);

        // Verify that the method was called with the correct argument
        verify(mockResponse, times(1)).setExpiration(expiration);
    }

    @Test
    void testReset() {
        // Call the method
        mockResponse.reset();

        // Verify that the method was called
        verify(mockResponse, times(1)).reset();
    }

    @Test
    void testGetException() {
        Exception testException = new RuntimeException("Test Exception");
        when(mockResponse.getException()).thenReturn(testException);
        assertEquals(testException, mockResponse.getException());

        // Test null exception
        when(mockResponse.getException()).thenReturn(null);
        assertNull(mockResponse.getException());

        // Verify the method was called
        verify(mockResponse, times(2)).getException();
    }

    @Test
    void testException() {
        Exception testException = new IllegalArgumentException("Another Test Exception");
        mockResponse.exception(testException);

        // Verify that the method was called with the correct argument
        verify(mockResponse, times(1)).exception(testException);
    }

    @Test
    void testGetNextResponse() {
        Response nextResponseMock = mock(Response.class);
        when(mockResponse.getNextResponse()).thenReturn(nextResponseMock);
        assertEquals(nextResponseMock, mockResponse.getNextResponse());

        // Test null next response
        when(mockResponse.getNextResponse()).thenReturn(null);
        assertNull(mockResponse.getNextResponse());

        // Verify the method was called
        verify(mockResponse, times(2)).getNextResponse();
    }
}
