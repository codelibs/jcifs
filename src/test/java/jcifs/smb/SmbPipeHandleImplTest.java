package jcifs.smb;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.IOException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSException;
import jcifs.SmbPipeResource;
import jcifs.internal.smb1.trans.TransCallNamedPipe;
import jcifs.internal.smb1.trans.TransTransactNamedPipe;
import jcifs.internal.smb1.trans.TransWaitNamedPipe;
import jcifs.internal.smb2.ioctl.Smb2IoctlRequest;
import jcifs.internal.smb2.ioctl.Smb2IoctlResponse;

@ExtendWith(MockitoExtension.class)
class SmbPipeHandleImplTest {

    @Mock
    SmbNamedPipe pipe;

    @Mock
    SmbTreeHandleImpl tree;

    @Mock
    SmbFileHandleImpl fileHandle;

    private SmbPipeHandleImpl target;

    @BeforeEach
    void setUp() {
        // Default pipe characteristics: neither transact nor call; RDWR for access
        when(pipe.getPipeType()).thenReturn(SmbPipeResource.PIPE_TYPE_RDWR);
        when(pipe.getUncPath()).thenReturn("\\\\pipe\\\\my-pipe");
        target = new SmbPipeHandleImpl(pipe);
    }

    @Test
    @DisplayName("unwrap returns self for assignable type; throws for incompatible and null")
    void testUnwrap() {
        // Happy path: unwrap to concrete type
        SmbPipeHandleImpl unwrapped = target.unwrap(SmbPipeHandleImpl.class);
        assertSame(target, unwrapped);

        // Incompatible type: expect ClassCastException
        assertThrows(ClassCastException.class, () -> target.unwrap(SmbNamedPipe.class));

        // Null input: document current behavior (NPE from isAssignableFrom)
        assertThrows(NullPointerException.class, () -> target.unwrap(null));
    }

    @Test
    @DisplayName("getPipe, getPipeType, getUncPath delegate to underlying pipe")
    void testBasicAccessors() {
        when(pipe.getPipeType()).thenReturn(0x123456);
        assertSame(pipe, target.getPipe());
        assertEquals(0x123456, target.getPipeType());
        assertEquals("\\\\pipe\\\\my-pipe", target.getUncPath());
    }

    @Test
    @DisplayName("ensureTreeConnected caches tree and acquires on each call")
    void testEnsureTreeConnectedCaching() throws CIFSException {
        // Arrange: first ensureTreeConnected comes from pipe
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree); // method returns itself per implementation
        when(tree.isConnected()).thenReturn(true);

        // Act: call twice
        try (SmbTreeHandleImpl t1 = target.ensureTreeConnected();
             SmbTreeHandleImpl t2 = target.ensureTreeConnected()) {
            assertSame(tree, t1);
            assertSame(tree, t2);
        }

        // Assert: pipe.ensureTreeConnected invoked once, acquire twice
        verify(pipe, times(1)).ensureTreeConnected();
        verify(tree, times(2)).acquire();
    }

    @Test
    @DisplayName("isOpen and isStale reflect underlying handle validity")
    void testIsOpenAndIsStale() throws CIFSException {
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(true);

        // SMB2 branch in ensureOpen uses openUnshared(String, ...)
        when(pipe.openUnshared(anyString(), anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenReturn(fileHandle);
        when(fileHandle.acquire()).thenReturn(fileHandle);
        when(fileHandle.isValid()).thenReturn(true);
        when(fileHandle.getTree()).thenReturn(tree);

        // Initially not open
        assertFalse(target.isOpen());
        assertTrue(target.isStale());

        // After ensureOpen, handle valid -> open
        SmbFileHandleImpl fh = target.ensureOpen();
        assertSame(fileHandle, fh);
        assertTrue(target.isOpen());
        assertFalse(target.isStale());

        // If handle becomes invalid, reflect stale
        when(fileHandle.isValid()).thenReturn(false);
        assertFalse(target.isOpen());
        assertTrue(target.isStale());
    }

    @Test
    @DisplayName("getInput and getOutput create once and cache; throw after close")
    void testGetInputOutputAndClosed() throws CIFSException {
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);

        // First calls create streams using tree; subsequent calls reuse cached instances
        SmbPipeInputStream in1 = target.getInput();
        SmbPipeInputStream in2 = target.getInput();
        assertNotNull(in1);
        assertSame(in1, in2);

        SmbPipeOutputStream out1 = target.getOutput();
        SmbPipeOutputStream out2 = target.getOutput();
        assertNotNull(out1);
        assertSame(out1, out2);

        // ensureTreeConnected should be called only once (first creation path)
        verify(pipe, times(1)).ensureTreeConnected();

        // After closing the handle, further calls throw
        target.close();
        CIFSException e1 = assertThrows(SmbException.class, target::getInput);
        assertTrue(e1.getMessage().contains("Already closed"));
        CIFSException e2 = assertThrows(SmbException.class, target::getOutput);
        assertTrue(e2.getMessage().contains("Already closed"));
    }

    @Test
    @DisplayName("ensureOpen throws after close() is called")
    void testEnsureOpenAfterClose() throws CIFSException {
        target.close();
        CIFSException ex = assertThrows(SmbException.class, () -> target.ensureOpen());
        assertTrue(ex.getMessage().contains("Pipe handle already closed"));
    }

    @Test
    @DisplayName("close() calls handle.close when open and handle.release otherwise; releases tree")
    void testCloseBehavior() throws CIFSException {
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(true);
        when(pipe.openUnshared(anyString(), anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenReturn(fileHandle);
        when(fileHandle.acquire()).thenReturn(fileHandle);
        when(fileHandle.isValid()).thenReturn(true);
        when(fileHandle.getTree()).thenReturn(tree);

        // Create streams to ensure they get closed/cleared
        target.getInput();
        target.getOutput();

        // When handle is valid, expect close()
        target.ensureOpen();
        target.close();
        verify(fileHandle, times(1)).close();
        verify(fileHandle, never()).release();
        verify(tree, atLeastOnce()).release();

        // Re-prepare state for second branch: not open but handle set
        when(fileHandle.isValid()).thenReturn(false);
        // Need to reopen logic to set handle again
        // Reset open flag by reconstructing target
        target = new SmbPipeHandleImpl(pipe);
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(true);
        when(pipe.openUnshared(anyString(), anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenReturn(fileHandle);
        when(fileHandle.acquire()).thenReturn(fileHandle);
        when(fileHandle.getTree()).thenReturn(tree);

        target.ensureOpen(); // handle present but invalid per isValid=false
        target.close();
        verify(fileHandle, atLeastOnce()).release();
    }

    @Test
    @DisplayName("getSessionKey fetches via tree->session and returns bytes")
    void testGetSessionKey() throws CIFSException {
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);
        SmbSessionImpl session = mock(SmbSessionImpl.class);
        when(tree.getSession()).thenReturn(session);
        when(session.getSessionKey()).thenReturn(new byte[] {1,2,3});

        byte[] key = target.getSessionKey();
        assertArrayEquals(new byte[] {1,2,3}, key);
        verify(tree, times(1)).getSession();
        verify(session, times(1)).getSessionKey();
    }

    @Test
    @DisplayName("sendrecv SMB2 path issues IOCTL and returns response length")
    void testSendRecvSmb2() throws IOException, CIFSException {
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);

        // ensureOpen path
        when(tree.isSMB2()).thenReturn(true);
        when(pipe.openUnshared(anyString(), anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenReturn(fileHandle);
        when(fileHandle.acquire()).thenReturn(fileHandle);
        when(fileHandle.getTree()).thenReturn(tree);

        // Mock response and send behavior
        Smb2IoctlResponse resp = mock(Smb2IoctlResponse.class);
        when(resp.getOutputLength()).thenReturn(42);
        when(tree.send(any(Smb2IoctlRequest.class), any())).thenReturn(resp);

        byte[] out = new byte[10];
        int read = target.sendrecv(new byte[] {9,8,7}, 0, 3, out, 1024);
        assertEquals(42, read);

        // Verify we issued an SMB2 IOCTL
        ArgumentCaptor<Smb2IoctlRequest> captor = ArgumentCaptor.forClass(Smb2IoctlRequest.class);
        verify(tree).send(captor.capture(), any());
        assertNotNull(captor.getValue());
    }

    @Test
    @DisplayName("sendrecv transact/call and stream fallback paths are exercised")
    void testSendRecvOtherPaths() throws Exception {
        // Setup common: SMB1 (not SMB2)
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(false);

        // Use an acquired handle to satisfy ensureOpen
        when(pipe.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenReturn(fileHandle);
        when(pipe.openUnshared(anyString(), anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenReturn(fileHandle);
        when(fileHandle.acquire()).thenReturn(fileHandle);
        when(fileHandle.getTree()).thenReturn(tree);

        byte[] recvBuf = new byte[16];

        // 1) Transact path
        when(pipe.getPipeType()).thenReturn(SmbPipeResource.PIPE_TYPE_TRANSACT | SmbPipeResource.PIPE_TYPE_RDWR);
        int r1 = target.sendrecv(new byte[] {1}, 0, 1, recvBuf, 64);
        assertEquals(0, r1, "Default mocked response length should be 0");
        verify(tree, atLeastOnce()).send(isA(TransTransactNamedPipe.class), any(), any());

        // 2) Call path
        when(pipe.getPipeType()).thenReturn(SmbPipeResource.PIPE_TYPE_CALL | SmbPipeResource.PIPE_TYPE_RDWR);
        int r2 = target.sendrecv(new byte[] {2}, 0, 1, recvBuf, 64);
        assertEquals(0, r2);
        verify(tree, atLeastOnce()).send(isA(TransWaitNamedPipe.class), any());
        verify(tree, atLeastOnce()).send(isA(TransCallNamedPipe.class), any());

        // 3) Fallback stream path: spy and stub input/output
        SmbPipeHandleImpl spyTarget = spy(new SmbPipeHandleImpl(pipe));
        SmbPipeInputStream in = mock(SmbPipeInputStream.class);
        SmbPipeOutputStream out = mock(SmbPipeOutputStream.class);
        when(in.read(any())).thenReturn(5);
        doReturn(out).when(spyTarget).getOutput();
        doReturn(in).when(spyTarget).getInput();

        int r3 = spyTarget.sendrecv(new byte[] {3,4}, 0, 2, recvBuf, 64);
        assertEquals(5, r3);
        verify(out).write(new byte[] {3,4}, 0, 2);
        verify(in).read(recvBuf);
    }

    @Test
    @DisplayName("recv delegates to input.readDirect and returns its value")
    void testRecvDelegation() throws Exception {
        SmbPipeHandleImpl spyTarget = spy(target);
        SmbPipeInputStream in = mock(SmbPipeInputStream.class);
        doReturn(in).when(spyTarget).getInput();
        when(in.readDirect(any(), anyInt(), anyInt())).thenReturn(7);

        byte[] b = new byte[10];
        int n = spyTarget.recv(b, 2, 4);
        assertEquals(7, n);
        verify(in).readDirect(b, 2, 4);
    }

    @Test
    @DisplayName("send delegates to output.writeDirect with provided args")
    void testSendDelegation() throws Exception {
        SmbPipeHandleImpl spyTarget = spy(target);
        SmbPipeOutputStream out = mock(SmbPipeOutputStream.class);
        doReturn(out).when(spyTarget).getOutput();

        byte[] b = new byte[] {10, 11, 12};
        spyTarget.send(b, 1, 2);
        verify(out).writeDirect(b, 1, 2, 1);
    }

    @Test
    @DisplayName("sendrecv with null buffers throws relevant exceptions")
    void testSendRecvInvalidInputs() {
        // Null out buffer for SMB2 path -> expect NPE when building request
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(true);
        when(pipe.openUnshared(anyString(), anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenReturn(fileHandle);
        when(fileHandle.acquire()).thenReturn(fileHandle);
        when(fileHandle.getTree()).thenReturn(tree);

        assertThrows(NullPointerException.class, () -> target.sendrecv(null, 0, 0, new byte[1], 0));
    }
}

