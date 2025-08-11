package jcifs.smb;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.lang.reflect.Field;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.internal.smb1.trans.TransPeekNamedPipe;
import jcifs.internal.smb1.trans.TransPeekNamedPipeResponse;
import jcifs.internal.smb2.ioctl.Smb2IoctlRequest;
import jcifs.internal.smb2.ioctl.Smb2IoctlResponse;
import jcifs.internal.smb2.ioctl.SrvPipePeekResponse;

@ExtendWith(MockitoExtension.class)
class SmbPipeInputStreamTest {

    @Mock SmbPipeHandleImpl handle;
    @Mock SmbNamedPipe pipe;
    @Mock SmbTreeHandleImpl tree;
    @Mock SmbFileHandleImpl fd;
    @Mock Configuration config;

    private SmbPipeInputStream newStreamWithInit(boolean smb2) throws CIFSException {
        when(handle.getPipe()).thenReturn(pipe);
        // init(th) behavior inside SmbFileInputStream constructor
        when(tree.isSMB2()).thenReturn(smb2);
        when(tree.getReceiveBufferSize()).thenReturn(4096);
        when(tree.getMaximumBufferSize()).thenReturn(65535);
        when(tree.hasCapability(anyInt())).thenReturn(false);
        return new SmbPipeInputStream(handle, tree);
    }

    private SmbPipeInputStream newStreamWithMinimalStubs(boolean smb2) throws CIFSException {
        when(handle.getPipe()).thenReturn(pipe);
        when(tree.isSMB2()).thenReturn(smb2);
        return new SmbPipeInputStream(handle, tree);
    }

    @Test
    @DisplayName("available() on SMB2 returns peeked byte count and interacts with tree")
    void available_smb2_happyPath() throws Exception {
        // Verify SMB2 path: IOCTL peek result is returned and resources are closed
        SmbPipeInputStream stream = newStreamWithMinimalStubs(true);

        // Arrange mocks for available()
        when(handle.ensureOpen()).thenReturn(fd);
        when(fd.getTree()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(true);
        when(tree.getConfig()).thenReturn(config);
        when(config.getTransactionBufferSize()).thenReturn(65535);

        Smb2IoctlResponse ioResp = mock(Smb2IoctlResponse.class);
        SrvPipePeekResponse peek = mock(SrvPipePeekResponse.class);
        when(peek.getReadDataAvailable()).thenReturn(7);
        when(ioResp.getOutputData()).thenReturn(peek);

        when(tree.send(any(Smb2IoctlRequest.class), eq(RequestParam.NO_RETRY))).thenReturn(ioResp);

        // Act
        int available = stream.available();

        // Assert
        assertEquals(7, available, "Should return available bytes reported by server");

        // Interactions: ensure open, use tree, send IOCTL and close resources
        InOrder inOrder = inOrder(handle, fd, tree);
        inOrder.verify(handle, times(1)).ensureOpen();
        inOrder.verify(fd, times(1)).getTree();
        inOrder.verify(tree, times(1)).send(any(Smb2IoctlRequest.class), eq(RequestParam.NO_RETRY));
        verify(fd, times(1)).close();
        verify(tree, times(1)).close();
    }

    @ParameterizedTest
    @ValueSource(ints = { TransPeekNamedPipeResponse.STATUS_DISCONNECTED, TransPeekNamedPipeResponse.STATUS_SERVER_END_CLOSED })
    @DisplayName("available() on SMB1 returns 0 and marks closed on disconnected statuses")
    void available_smb1_disconnectedStatuses(int status) throws Exception {
        // Verify SMB1 path: disconnected/server-closed statuses yield 0 and mark fd closed
        SmbPipeInputStream stream = newStreamWithInit(false);

        when(handle.ensureOpen()).thenReturn(fd);
        when(fd.getTree()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(false);
        when(tree.getConfig()).thenReturn(config);
        when(config.getPid()).thenReturn(1234);

        // Stub send to populate the provided response instance via reflection
        Mockito.doAnswer(inv -> {
            Object resp = inv.getArgument(1);
            // Set private fields: status on SmbComTransactionResponse and available on TransPeekNamedPipeResponse
            Field statusField = jcifs.internal.smb1.trans.SmbComTransactionResponse.class.getDeclaredField("status");
            statusField.setAccessible(true);
            statusField.setInt(resp, status);
            Field availField = TransPeekNamedPipeResponse.class.getDeclaredField("available");
            availField.setAccessible(true);
            availField.setInt(resp, 123);
            return resp;
        }).when(tree).send(any(TransPeekNamedPipe.class), any(TransPeekNamedPipeResponse.class), eq(RequestParam.NO_RETRY));

        int available = stream.available();
        assertEquals(0, available, "Disconnected/server-closed should yield 0 available");

        verify(fd, times(1)).markClosed();
        verify(tree, times(1)).close();
        verify(fd, times(1)).close();
    }

    @Test
    @DisplayName("available() on SMB1 returns reported available when connected")
    void available_smb1_connected() throws Exception {
        // Verify SMB1 path: non-disconnected status returns 'available' from response
        SmbPipeInputStream stream = newStreamWithInit(false);

        when(handle.ensureOpen()).thenReturn(fd);
        when(fd.getTree()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(false);
        when(tree.getConfig()).thenReturn(config);
        when(config.getPid()).thenReturn(1234);

        // Set status to CONNECTION_OK and available to 42
        Mockito.doAnswer(inv -> {
            Object resp = inv.getArgument(1);
            Field statusField = jcifs.internal.smb1.trans.SmbComTransactionResponse.class.getDeclaredField("status");
            statusField.setAccessible(true);
            statusField.setInt(resp, TransPeekNamedPipeResponse.STATUS_CONNECTION_OK);
            Field availField = TransPeekNamedPipeResponse.class.getDeclaredField("available");
            availField.setAccessible(true);
            availField.setInt(resp, 42);
            return resp;
        }).when(tree).send(any(TransPeekNamedPipe.class), any(TransPeekNamedPipeResponse.class), eq(RequestParam.NO_RETRY));

        int available = stream.available();
        assertEquals(42, available, "Should return available bytes reported by SMB1 peek");

        verify(fd, never()).markClosed();
    }

    @Test
    @DisplayName("available() wraps SmbException to IOException")
    void available_wrapsException() throws Exception {
        // Verify exceptions from th.send are converted to IOException via seToIoe
        SmbPipeInputStream stream = newStreamWithMinimalStubs(true);

        when(handle.ensureOpen()).thenReturn(fd);
        when(fd.getTree()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(true);
        when(tree.getConfig()).thenReturn(config);
        when(config.getTransactionBufferSize()).thenReturn(65535);
        when(tree.send(any(Smb2IoctlRequest.class), eq(RequestParam.NO_RETRY)))
                .thenThrow(new SmbException("boom"));

        IOException ex = assertThrows(IOException.class, stream::available, "Should convert SmbException to IOException");
        assertTrue(ex.getMessage().contains("boom"));
    }

    @Test
    @DisplayName("ensureTreeConnected delegates to handle")
    void ensureTreeConnected_delegates() throws Exception {
        // Verify ensureTreeConnected() delegates to SmbPipeHandleImpl
        SmbPipeInputStream stream = newStreamWithMinimalStubs(true);
        when(handle.ensureTreeConnected()).thenReturn(tree);

        SmbTreeHandleImpl result = stream.ensureTreeConnected();
        assertSame(tree, result);
        verify(handle, times(1)).ensureTreeConnected();
    }

    @Test
    @DisplayName("ensureOpen delegates to handle")
    void ensureOpen_delegates() throws Exception {
        // Verify ensureOpen() delegates to SmbPipeHandleImpl
        SmbPipeInputStream stream = newStreamWithMinimalStubs(true);
        when(handle.ensureOpen()).thenReturn(fd);

        SmbFileHandleImpl result = stream.ensureOpen();
        assertSame(fd, result);
        verify(handle, times(1)).ensureOpen();
    }

    @Test
    @DisplayName("close() does nothing (no delegate interactions)")
    void close_isNoop() throws Exception {
        // Verify close() is a no-op and does not call handle/tree/fd
        SmbPipeInputStream stream = newStreamWithInit(true);

        // reset to ignore constructor interactions
        reset(handle, tree, fd);

        assertDoesNotThrow(stream::close);
        verify(handle, never()).ensureOpen();
        verifyNoInteractions(tree, fd);
    }

    @Nested
    @DisplayName("Constructor input validation")
    class CtorValidation {
        @Test
        @DisplayName("null handle throws NPE")
        void nullHandle() {
            assertThrows(NullPointerException.class, () -> new SmbPipeInputStream(null, tree));
        }

        @Test
        @DisplayName("null tree throws NPE")
        void nullTree() {
            assertThrows(NullPointerException.class, () -> new SmbPipeInputStream(handle, null));
        }
    }
}
