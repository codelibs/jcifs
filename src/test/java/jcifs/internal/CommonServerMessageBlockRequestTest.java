package jcifs.internal;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Test class for CommonServerMessageBlockRequest interface
 */
@ExtendWith(MockitoExtension.class)
class CommonServerMessageBlockRequestTest {

    @Mock
    private CommonServerMessageBlockRequest request;
    
    @Mock
    private CommonServerMessageBlockRequest nextRequest;
    
    @Mock
    private CommonServerMessageBlockRequest splitRequest;
    
    @Mock
    private CommonServerMessageBlockRequest cancelRequest;

    @BeforeEach
    void setUp() {
        // Reset mocks before each test
        reset(request, nextRequest, splitRequest, cancelRequest);
    }

    @Test
    @DisplayName("Test isResponseAsync returns true when response is async")
    void testIsResponseAsyncTrue() {
        // Given
        when(request.isResponseAsync()).thenReturn(true);
        
        // When
        boolean result = request.isResponseAsync();
        
        // Then
        assertTrue(result);
        verify(request, times(1)).isResponseAsync();
    }

    @Test
    @DisplayName("Test isResponseAsync returns false when response is not async")
    void testIsResponseAsyncFalse() {
        // Given
        when(request.isResponseAsync()).thenReturn(false);
        
        // When
        boolean result = request.isResponseAsync();
        
        // Then
        assertFalse(result);
        verify(request, times(1)).isResponseAsync();
    }

    @Test
    @DisplayName("Test getNext returns next chained message")
    void testGetNextWithChainedMessage() {
        // Given
        when(request.getNext()).thenReturn(nextRequest);
        
        // When
        CommonServerMessageBlockRequest result = request.getNext();
        
        // Then
        assertNotNull(result);
        assertEquals(nextRequest, result);
        verify(request, times(1)).getNext();
    }

    @Test
    @DisplayName("Test getNext returns null when no chained message")
    void testGetNextWithNoChainedMessage() {
        // Given
        when(request.getNext()).thenReturn(null);
        
        // When
        CommonServerMessageBlockRequest result = request.getNext();
        
        // Then
        assertNull(result);
        verify(request, times(1)).getNext();
    }

    @Test
    @DisplayName("Test split returns following message")
    void testSplitWithFollowingMessage() {
        // Given
        when(request.split()).thenReturn(splitRequest);
        
        // When
        CommonServerMessageBlockRequest result = request.split();
        
        // Then
        assertNotNull(result);
        assertEquals(splitRequest, result);
        verify(request, times(1)).split();
    }

    @Test
    @DisplayName("Test split returns null when no following message")
    void testSplitWithNoFollowingMessage() {
        // Given
        when(request.split()).thenReturn(null);
        
        // When
        CommonServerMessageBlockRequest result = request.split();
        
        // Then
        assertNull(result);
        verify(request, times(1)).split();
    }

    @Test
    @DisplayName("Test size returns positive message size")
    void testSizeReturnsPositiveValue() {
        // Given
        int expectedSize = 1024;
        when(request.size()).thenReturn(expectedSize);
        
        // When
        int result = request.size();
        
        // Then
        assertEquals(expectedSize, result);
        verify(request, times(1)).size();
    }

    @Test
    @DisplayName("Test size returns zero for empty message")
    void testSizeReturnsZero() {
        // Given
        when(request.size()).thenReturn(0);
        
        // When
        int result = request.size();
        
        // Then
        assertEquals(0, result);
        verify(request, times(1)).size();
    }

    @Test
    @DisplayName("Test size returns large value for large message")
    void testSizeReturnsLargeValue() {
        // Given
        int largeSize = Integer.MAX_VALUE;
        when(request.size()).thenReturn(largeSize);
        
        // When
        int result = request.size();
        
        // Then
        assertEquals(largeSize, result);
        verify(request, times(1)).size();
    }

    @Test
    @DisplayName("Test createCancel returns cancel request")
    void testCreateCancelReturnsRequest() {
        // Given
        when(request.createCancel()).thenReturn(cancelRequest);
        
        // When
        CommonServerMessageBlockRequest result = request.createCancel();
        
        // Then
        assertNotNull(result);
        assertEquals(cancelRequest, result);
        verify(request, times(1)).createCancel();
    }

    @Test
    @DisplayName("Test createCancel returns null when cancel not supported")
    void testCreateCancelReturnsNull() {
        // Given
        when(request.createCancel()).thenReturn(null);
        
        // When
        CommonServerMessageBlockRequest result = request.createCancel();
        
        // Then
        assertNull(result);
        verify(request, times(1)).createCancel();
    }

    @Test
    @DisplayName("Test allowChain returns true when chaining is allowed")
    void testAllowChainReturnsTrue() {
        // Given
        when(request.allowChain(nextRequest)).thenReturn(true);
        
        // When
        boolean result = request.allowChain(nextRequest);
        
        // Then
        assertTrue(result);
        verify(request, times(1)).allowChain(nextRequest);
    }

    @Test
    @DisplayName("Test allowChain returns false when chaining is not allowed")
    void testAllowChainReturnsFalse() {
        // Given
        when(request.allowChain(nextRequest)).thenReturn(false);
        
        // When
        boolean result = request.allowChain(nextRequest);
        
        // Then
        assertFalse(result);
        verify(request, times(1)).allowChain(nextRequest);
    }

    @Test
    @DisplayName("Test allowChain with null parameter")
    void testAllowChainWithNull() {
        // Given
        when(request.allowChain(null)).thenReturn(false);
        
        // When
        boolean result = request.allowChain(null);
        
        // Then
        assertFalse(result);
        verify(request, times(1)).allowChain(null);
    }

    @Test
    @DisplayName("Test setTid with positive value")
    void testSetTidWithPositiveValue() {
        // Given
        int tid = 12345;
        doNothing().when(request).setTid(tid);
        
        // When
        request.setTid(tid);
        
        // Then
        verify(request, times(1)).setTid(tid);
    }

    @Test
    @DisplayName("Test setTid with zero value")
    void testSetTidWithZero() {
        // Given
        int tid = 0;
        doNothing().when(request).setTid(tid);
        
        // When
        request.setTid(tid);
        
        // Then
        verify(request, times(1)).setTid(tid);
    }

    @Test
    @DisplayName("Test setTid with negative value")
    void testSetTidWithNegativeValue() {
        // Given
        int tid = -1;
        doNothing().when(request).setTid(tid);
        
        // When
        request.setTid(tid);
        
        // Then
        verify(request, times(1)).setTid(tid);
    }

    @Test
    @DisplayName("Test setTid with maximum integer value")
    void testSetTidWithMaxValue() {
        // Given
        int tid = Integer.MAX_VALUE;
        doNothing().when(request).setTid(tid);
        
        // When
        request.setTid(tid);
        
        // Then
        verify(request, times(1)).setTid(tid);
    }

    @Test
    @DisplayName("Test getOverrideTimeout returns custom timeout")
    void testGetOverrideTimeoutReturnsCustomValue() {
        // Given
        Integer expectedTimeout = 5000;
        when(request.getOverrideTimeout()).thenReturn(expectedTimeout);
        
        // When
        Integer result = request.getOverrideTimeout();
        
        // Then
        assertNotNull(result);
        assertEquals(expectedTimeout, result);
        verify(request, times(1)).getOverrideTimeout();
    }

    @Test
    @DisplayName("Test getOverrideTimeout returns null when no override")
    void testGetOverrideTimeoutReturnsNull() {
        // Given
        when(request.getOverrideTimeout()).thenReturn(null);
        
        // When
        Integer result = request.getOverrideTimeout();
        
        // Then
        assertNull(result);
        verify(request, times(1)).getOverrideTimeout();
    }

    @Test
    @DisplayName("Test getOverrideTimeout with zero timeout")
    void testGetOverrideTimeoutWithZero() {
        // Given
        Integer zeroTimeout = 0;
        when(request.getOverrideTimeout()).thenReturn(zeroTimeout);
        
        // When
        Integer result = request.getOverrideTimeout();
        
        // Then
        assertNotNull(result);
        assertEquals(0, result.intValue());
        verify(request, times(1)).getOverrideTimeout();
    }

    @Test
    @DisplayName("Test getOverrideTimeout with large timeout value")
    void testGetOverrideTimeoutWithLargeValue() {
        // Given
        Integer largeTimeout = Integer.MAX_VALUE;
        when(request.getOverrideTimeout()).thenReturn(largeTimeout);
        
        // When
        Integer result = request.getOverrideTimeout();
        
        // Then
        assertNotNull(result);
        assertEquals(Integer.MAX_VALUE, result.intValue());
        verify(request, times(1)).getOverrideTimeout();
    }

    @Test
    @DisplayName("Test multiple method invocations")
    void testMultipleMethodInvocations() {
        // Given
        when(request.isResponseAsync()).thenReturn(true);
        when(request.size()).thenReturn(100);
        when(request.getOverrideTimeout()).thenReturn(3000);
        when(request.allowChain(any())).thenReturn(true);
        
        // When
        boolean async = request.isResponseAsync();
        int size = request.size();
        Integer timeout = request.getOverrideTimeout();
        boolean canChain = request.allowChain(nextRequest);
        
        // Then
        assertTrue(async);
        assertEquals(100, size);
        assertEquals(3000, timeout);
        assertTrue(canChain);
        verify(request).isResponseAsync();
        verify(request).size();
        verify(request).getOverrideTimeout();
        verify(request).allowChain(nextRequest);
    }

    @Test
    @DisplayName("Test chaining scenario with multiple requests")
    void testChainingScenario() {
        // Given
        CommonServerMessageBlockRequest thirdRequest = mock(CommonServerMessageBlockRequest.class);
        when(request.getNext()).thenReturn(nextRequest);
        when(nextRequest.getNext()).thenReturn(thirdRequest);
        when(thirdRequest.getNext()).thenReturn(null);
        when(request.allowChain(nextRequest)).thenReturn(true);
        when(nextRequest.allowChain(thirdRequest)).thenReturn(true);
        
        // When
        CommonServerMessageBlockRequest second = request.getNext();
        CommonServerMessageBlockRequest third = second.getNext();
        CommonServerMessageBlockRequest fourth = third.getNext();
        boolean firstAllowsSecond = request.allowChain(nextRequest);
        boolean secondAllowsThird = nextRequest.allowChain(thirdRequest);
        
        // Then
        assertEquals(nextRequest, second);
        assertEquals(thirdRequest, third);
        assertNull(fourth);
        assertTrue(firstAllowsSecond);
        assertTrue(secondAllowsThird);
    }

    @Test
    @DisplayName("Test interface implementation verification")
    void testInterfaceImplementation() {
        // Given
        CommonServerMessageBlockRequest implementation = mock(CommonServerMessageBlockRequest.class);
        
        // When/Then - Verify the interface extends the expected interfaces
        assertTrue(CommonServerMessageBlock.class.isAssignableFrom(CommonServerMessageBlockRequest.class));
        assertTrue(jcifs.util.transport.Request.class.isAssignableFrom(CommonServerMessageBlockRequest.class));
    }
}
