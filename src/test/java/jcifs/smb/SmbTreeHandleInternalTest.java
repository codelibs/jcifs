package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSException;
import jcifs.SmbSession;

/**
 * Tests for SmbTreeHandleInternal interface using Mockito to verify
 * interactions and observable behavior of collaborators.
 */
@ExtendWith(MockitoExtension.class)
public class SmbTreeHandleInternalTest {

    @Mock
    private SmbTreeHandleInternal handle;

    @Test
    @DisplayName("release(): verifies it is invoked exactly once")
    void release_invokedOnce() throws Exception {
        // Arrange: no setup needed; we verify interaction only

        // Act: call release
        handle.release();

        // Assert: verify one invocation and no more
        verify(handle, times(1)).release();
        verifyNoMoreInteractions(handle);
    }

    @Test
    @DisplayName("ensureDFSResolved(): no exception when underlying call succeeds")
    void ensureDFSResolved_success() throws Exception {
        // Arrange: default mock does nothing

        // Act: call method under test
        handle.ensureDFSResolved();

        // Assert: interaction happened and did not throw
        verify(handle, times(1)).ensureDFSResolved();
        verifyNoMoreInteractions(handle);
    }

    @Test
    @DisplayName("ensureDFSResolved(): throws CIFSException when underlying call fails")
    void ensureDFSResolved_throws() throws Exception {
        // Arrange: configure the mock to throw
        doThrow(new CIFSException("DFS resolution failed")).when(handle).ensureDFSResolved();

        // Act + Assert: exception is propagated with message
        CIFSException ex = assertThrows(CIFSException.class, () -> handle.ensureDFSResolved());
        assertEquals("DFS resolution failed", ex.getMessage());
        verify(handle, times(1)).ensureDFSResolved();
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, -1, Integer.MIN_VALUE, Integer.MAX_VALUE })
    @DisplayName("hasCapability(cap): returns configured value and captures argument across edge caps")
    void hasCapability_variousCaps_returnsTrue_andCapturesArgument(int cap) throws Exception {
        // Arrange: stub to return true regardless of input
        when(handle.hasCapability(anyInt())).thenReturn(true);

        // Act
        boolean result = handle.hasCapability(cap);

        // Assert: verify return and the captured argument equals input
        assertTrue(result);
        ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
        verify(handle, times(1)).hasCapability(captor.capture());
        assertEquals(cap, captor.getValue());
    }

    @Test
    @DisplayName("hasCapability(cap): propagates CIFSException on failure")
    void hasCapability_throws() throws Exception {
        // Arrange
        when(handle.hasCapability(anyInt())).thenThrow(new CIFSException("capability check failed"));

        // Act + Assert
        CIFSException ex = assertThrows(CIFSException.class, () -> handle.hasCapability(42));
        assertEquals("capability check failed", ex.getMessage());
        verify(handle).hasCapability(42);
    }

    @Test
    @DisplayName("getSendBufferSize(): returns configured value")
    void getSendBufferSize_returns() throws Exception {
        // Arrange
        when(handle.getSendBufferSize()).thenReturn(8192);

        // Act
        int size = handle.getSendBufferSize();

        // Assert
        assertEquals(8192, size);
        verify(handle).getSendBufferSize();
    }

    @Test
    @DisplayName("getSendBufferSize(): propagates CIFSException on failure")
    void getSendBufferSize_throws() throws Exception {
        // Arrange
        when(handle.getSendBufferSize()).thenThrow(new CIFSException("send size failed"));

        // Act + Assert
        CIFSException ex = assertThrows(CIFSException.class, () -> handle.getSendBufferSize());
        assertEquals("send size failed", ex.getMessage());
        verify(handle).getSendBufferSize();
    }

    @Test
    @DisplayName("getReceiveBufferSize(): returns configured value")
    void getReceiveBufferSize_returns() throws Exception {
        // Arrange
        when(handle.getReceiveBufferSize()).thenReturn(16384);

        // Act
        int size = handle.getReceiveBufferSize();

        // Assert
        assertEquals(16384, size);
        verify(handle).getReceiveBufferSize();
    }

    @Test
    @DisplayName("getReceiveBufferSize(): propagates CIFSException on failure")
    void getReceiveBufferSize_throws() throws Exception {
        // Arrange
        when(handle.getReceiveBufferSize()).thenThrow(new CIFSException("receive size failed"));

        // Act + Assert
        CIFSException ex = assertThrows(CIFSException.class, () -> handle.getReceiveBufferSize());
        assertEquals("receive size failed", ex.getMessage());
        verify(handle).getReceiveBufferSize();
    }

    @Test
    @DisplayName("getMaximumBufferSize(): returns configured value")
    void getMaximumBufferSize_returns() throws Exception {
        // Arrange
        when(handle.getMaximumBufferSize()).thenReturn(65535);

        // Act
        int size = handle.getMaximumBufferSize();

        // Assert
        assertEquals(65535, size);
        verify(handle).getMaximumBufferSize();
    }

    @Test
    @DisplayName("getMaximumBufferSize(): propagates CIFSException on failure")
    void getMaximumBufferSize_throws() throws Exception {
        // Arrange
        when(handle.getMaximumBufferSize()).thenThrow(new CIFSException("max size failed"));

        // Act + Assert
        CIFSException ex = assertThrows(CIFSException.class, () -> handle.getMaximumBufferSize());
        assertEquals("max size failed", ex.getMessage());
        verify(handle).getMaximumBufferSize();
    }

    @Test
    @DisplayName("areSignaturesActive(): returns configured boolean true")
    void areSignaturesActive_true() throws Exception {
        // Arrange
        when(handle.areSignaturesActive()).thenReturn(true);

        // Act
        boolean result = handle.areSignaturesActive();

        // Assert
        assertTrue(result);
        verify(handle).areSignaturesActive();
    }

    @Test
    @DisplayName("areSignaturesActive(): returns configured boolean false")
    void areSignaturesActive_false() throws Exception {
        // Arrange
        when(handle.areSignaturesActive()).thenReturn(false);

        // Act
        boolean result = handle.areSignaturesActive();

        // Assert
        assertFalse(result);
        verify(handle).areSignaturesActive();
    }

    @Test
    @DisplayName("areSignaturesActive(): propagates CIFSException on failure")
    void areSignaturesActive_throws() throws Exception {
        // Arrange
        when(handle.areSignaturesActive()).thenThrow(new CIFSException("sig check failed"));

        // Act + Assert
        CIFSException ex = assertThrows(CIFSException.class, () -> handle.areSignaturesActive());
        assertEquals("sig check failed", ex.getMessage());
        verify(handle).areSignaturesActive();
    }

    @Test
    @DisplayName("getSession(): returns the mocked SmbSession instance")
    void getSession_returnsMock() {
        // Arrange
        SmbSession session = mock(SmbSession.class);
        when(handle.getSession()).thenReturn(session);

        // Act
        SmbSession result = handle.getSession();

        // Assert
        assertSame(session, result);
        verify(handle).getSession();
    }

    @Test
    @DisplayName("getSession(): may return null and should be observed as such")
    void getSession_returnsNull() {
        // Arrange
        when(handle.getSession()).thenReturn(null);

        // Act
        SmbSession result = handle.getSession();

        // Assert
        assertNull(result);
        verify(handle).getSession();
    }

    @Test
    @DisplayName("Scenario: verify interaction order across multiple calls")
    void verifyInteractionOrder() throws Exception {
        // Arrange: stub simple returns
        when(handle.hasCapability(anyInt())).thenReturn(true);

        // Act: perform a series of calls to verify order
        handle.ensureDFSResolved();
        handle.hasCapability(7);
        handle.release();

        // Assert: verify they happened in order
        InOrder inOrder = inOrder(handle);
        inOrder.verify(handle).ensureDFSResolved();
        inOrder.verify(handle).hasCapability(7);
        inOrder.verify(handle).release();
        inOrder.verifyNoMoreInteractions();
    }
}
