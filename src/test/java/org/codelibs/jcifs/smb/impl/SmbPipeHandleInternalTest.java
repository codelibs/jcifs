package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.SmbPipeHandle;
import org.codelibs.jcifs.smb.SmbPipeResource;
import org.codelibs.jcifs.smb.internal.smb1.trans.TransCallNamedPipe;
import org.codelibs.jcifs.smb.internal.smb1.trans.TransCallNamedPipeResponse;
import org.codelibs.jcifs.smb.internal.smb1.trans.TransTransactNamedPipe;
import org.codelibs.jcifs.smb.internal.smb1.trans.TransTransactNamedPipeResponse;
import org.codelibs.jcifs.smb.internal.smb1.trans.TransWaitNamedPipe;
import org.codelibs.jcifs.smb.internal.smb1.trans.TransWaitNamedPipeResponse;
import org.codelibs.jcifs.smb.internal.smb2.ioctl.Smb2IoctlRequest;
import org.codelibs.jcifs.smb.internal.smb2.ioctl.Smb2IoctlResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SmbPipeHandleInternalTest {

    @Mock
    private SmbNamedPipe pipe;

    @Mock
    private SmbTreeHandleImpl tree;

    @Mock
    private SmbFileHandleImpl fh;

    @Mock
    private Smb2IoctlResponse ioctlResp;

    @Mock
    private Configuration config;

    @Mock
    private SmbSessionImpl session;

    @BeforeEach
    void setUp() {
        lenient().when(tree.getConfig()).thenReturn(config);
    }

    private SmbPipeHandleImpl newHandleWithBasicStubs(int pipeType, String unc) {
        when(pipe.getPipeType()).thenReturn(pipeType);
        when(pipe.getUncPath()).thenReturn(unc);
        return new SmbPipeHandleImpl(pipe);
    }

    @Test
    @DisplayName("ensureTreeConnected acquires and reuses the tree handle")
    void ensureTreeConnected_acquireAndReuse() throws Exception {
        // Arrange
        SmbPipeHandleImpl handle = newHandleWithBasicStubs(0, "\\\\pipe\\\\test");
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);

        // Act
        SmbTreeHandleInternal t1 = handle.ensureTreeConnected();
        SmbTreeHandleInternal t2 = handle.ensureTreeConnected();

        // Assert
        assertSame(tree, t1, "First acquire returns provided tree");
        assertSame(tree, t2, "Subsequent acquire returns same tree instance");
        verify(pipe, times(1)).ensureTreeConnected();
        verify(tree, times(2)).acquire();
    }

    @Test
    @DisplayName("getInput/getOutput return cached streams when open; throw when closed")
    void getInputOutput_caching_and_closed() throws Exception {
        // Arrange: minimal stubs so stream construction works
        SmbPipeHandleImpl handle = newHandleWithBasicStubs(0, "\\\\pipe\\\\foo");
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(true); // simplifies stream init
        when(tree.getReceiveBufferSize()).thenReturn(4096);

        // Act: first calls construct streams, second calls return cached
        SmbPipeInputStream in1 = handle.getInput();
        SmbPipeInputStream in2 = handle.getInput();
        SmbPipeOutputStream out1 = handle.getOutput();
        SmbPipeOutputStream out2 = handle.getOutput();

        // Assert: same instances are returned subsequently
        assertSame(in1, in2, "Input stream should be cached");
        assertSame(out1, out2, "Output stream should be cached");

        // Close and verify subsequent calls throw
        handle.close();
        CIFSException ex1 = assertThrows(CIFSException.class, handle::getInput, "getInput after close must throw");
        assertTrue(ex1.getMessage().contains("Already closed"));
        CIFSException ex2 = assertThrows(CIFSException.class, handle::getOutput, "getOutput after close must throw");
        assertTrue(ex2.getMessage().contains("Already closed"));
    }

    @Test
    @DisplayName("ensureOpen opens SMB2 via UNC path and marks open")
    void ensureOpen_smb2_opens() throws Exception {
        // Arrange
        SmbPipeHandleImpl handle = newHandleWithBasicStubs(0, "\\\\pipe\\\\foo");
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(true);
        when(pipe.openUnshared(eq("\\\\pipe\\\\foo"), eq(0), anyInt(), anyInt(), eq(SmbConstants.ATTR_NORMAL), eq(0))).thenReturn(fh);
        when(fh.acquire()).thenReturn(fh);
        when(fh.isValid()).thenReturn(true);

        // Act
        SmbFileHandleImpl opened = handle.ensureOpen();

        // Assert
        assertSame(fh, opened);
        assertTrue(handle.isOpen(), "Handle should report open after ensureOpen");
        verify(pipe, times(1)).openUnshared(eq("\\\\pipe\\\\foo"), eq(0), anyInt(), anyInt(), eq(SmbConstants.ATTR_NORMAL), eq(0));
    }

    @Test
    @DisplayName("ensureOpen throws when handle already closed")
    void ensureOpen_whenClosed_throws() throws Exception {
        SmbPipeHandleImpl handle = newHandleWithBasicStubs(0, "\\\\pipe\\\\bar");
        handle.close();
        SmbException ex = assertThrows(SmbException.class, handle::ensureOpen);
        assertTrue(ex.getMessage().contains("Pipe handle already closed"));
    }

    @Test
    @DisplayName("sendrecv uses SMB2 ioctl when tree is SMB2")
    void sendrecv_smb2_ioctl() throws Exception {
        // Arrange
        SmbPipeHandleImpl handle = newHandleWithBasicStubs(0, "\\\\pipe\\\\x");

        // Setup the tree handle properly
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);

        // Setup for ensureOpen
        when(tree.isSMB2()).thenReturn(true);
        when(pipe.openUnshared(anyString(), anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenReturn(fh);
        when(fh.acquire()).thenReturn(fh);
        lenient().when(fh.isValid()).thenReturn(true);
        lenient().when(fh.getTree()).thenReturn(tree);
        when(fh.getFileId()).thenReturn(new byte[16]);

        // Setup for ioctl request
        when(tree.send(any(Smb2IoctlRequest.class), eq(RequestParam.NO_RETRY))).thenReturn(ioctlResp);
        when(ioctlResp.getOutputLength()).thenReturn(42);

        byte[] in = new byte[128];
        byte[] out = new byte[256];

        // Act
        int n = handle.sendrecv(out, 1, 10, in, 128);

        // Assert
        assertEquals(42, n);
        ArgumentCaptor<Smb2IoctlRequest> cap = ArgumentCaptor.forClass(Smb2IoctlRequest.class);
        verify(tree).send(cap.capture(), eq(RequestParam.NO_RETRY));
        assertNotNull(cap.getValue()); // captured request should be present
    }

    @Test
    @DisplayName("sendrecv uses TransactNamedPipe when PIPE_TYPE_TRANSACT is set")
    void sendrecv_transact_branch() throws Exception {
        // Arrange
        int type = SmbPipeResource.PIPE_TYPE_TRANSACT | SmbPipeResource.PIPE_TYPE_RDWR;
        SmbPipeHandleImpl handle = newHandleWithBasicStubs(type, "\\\\pipe\\\\t");

        // Setup the tree handle properly
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);

        // Setup for ensureOpen
        when(tree.isSMB2()).thenReturn(false);
        when(tree.hasCapability(SmbConstants.CAP_NT_SMBS)).thenReturn(true);
        when(pipe.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenReturn(fh);
        when(fh.acquire()).thenReturn(fh);
        lenient().when(fh.isValid()).thenReturn(true);
        lenient().when(fh.getTree()).thenReturn(tree);
        when(fh.getFid()).thenReturn(99);

        // Mock send to just echo the provided response instance
        when(tree.send(any(TransTransactNamedPipe.class), any(TransTransactNamedPipeResponse.class), eq(RequestParam.NO_RETRY)))
                .thenAnswer(inv -> inv.getArgument(1));

        int n = handle.sendrecv(new byte[10], 0, 0, new byte[20], 100);
        assertEquals(0, n, "Default response length is 0 unless protocol fills it");
    }

    @Test
    @DisplayName("sendrecv uses CallNamedPipe when PIPE_TYPE_CALL is set")
    void sendrecv_call_branch() throws Exception {
        int type = SmbPipeResource.PIPE_TYPE_CALL | SmbPipeResource.PIPE_TYPE_RDWR;
        SmbPipeHandleImpl handle = newHandleWithBasicStubs(type, "\\\\pipe\\\\c");

        // Setup the tree handle properly
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);

        // Setup for ensureOpen
        when(tree.isSMB2()).thenReturn(false);
        when(tree.hasCapability(SmbConstants.CAP_NT_SMBS)).thenReturn(true);
        when(pipe.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenReturn(fh);
        when(fh.acquire()).thenReturn(fh);
        lenient().when(fh.isValid()).thenReturn(true);
        lenient().when(fh.getTree()).thenReturn(tree);

        // Mock both sends and return response
        when(tree.send(any(TransWaitNamedPipe.class), any(TransWaitNamedPipeResponse.class))).thenAnswer(inv -> inv.getArgument(1));
        when(tree.send(any(TransCallNamedPipe.class), any(TransCallNamedPipeResponse.class))).thenAnswer(inv -> inv.getArgument(1));

        int n = handle.sendrecv(new byte[3], 0, 3, new byte[8], 64);
        assertEquals(0, n, "Default response length is 0 unless protocol fills it");
    }

    @Test
    @DisplayName("sendrecv falls back to stream write/read when no call/transact")
    void sendrecv_stream_fallback_uses_streams() throws Exception {
        // Arrange - use non-transact, non-call pipe type
        SmbPipeHandleImpl handle = newHandleWithBasicStubs(SmbPipeResource.PIPE_TYPE_RDWR, "\\\\pipe\\\\x");

        // Setup for ensureOpen to avoid NullPointer
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(false); // Set to SMB1 to avoid SMB2 ioctl path
        when(tree.hasCapability(SmbConstants.CAP_NT_SMBS)).thenReturn(true);
        when(pipe.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenReturn(fh);
        when(fh.acquire()).thenReturn(fh);
        lenient().when(fh.isValid()).thenReturn(true);
        lenient().when(fh.getTree()).thenReturn(tree);
        lenient().when(tree.getReceiveBufferSize()).thenReturn(4096);

        // Mock the streams
        SmbPipeInputStream mockIn = mock(SmbPipeInputStream.class);
        SmbPipeOutputStream mockOut = mock(SmbPipeOutputStream.class);

        // Create spy and override getInput/getOutput
        SmbPipeHandleImpl spyHandle = spy(handle);
        doReturn(mockIn).when(spyHandle).getInput();
        doReturn(mockOut).when(spyHandle).getOutput();

        // Setup mock behavior
        when(mockIn.read(any(byte[].class))).thenReturn(7);

        // Act
        byte[] buf = new byte[16];
        byte[] recv = new byte[16];
        int r = spyHandle.sendrecv(buf, 2, 4, recv, 16);

        // Assert
        assertEquals(7, r);
        verify(mockOut).write(eq(buf), eq(2), eq(4));
        verify(mockIn).read(eq(recv));
    }

    @Test
    @DisplayName("recv delegates to input.readDirect with args")
    void recv_delegates_readDirect() throws Exception {
        SmbPipeHandleImpl handle = newHandleWithBasicStubs(0, "\\\\pipe\\\\y");

        // Mock the stream directly
        SmbPipeInputStream mockIn = mock(SmbPipeInputStream.class);

        // Create spy and override getInput
        SmbPipeHandleImpl spyHandle = spy(handle);
        doReturn(mockIn).when(spyHandle).getInput();

        when(mockIn.readDirect(any(byte[].class), anyInt(), anyInt())).thenReturn(5);

        byte[] b = new byte[10];
        int n = spyHandle.recv(b, 1, 3);
        assertEquals(5, n);
        verify(mockIn).readDirect(eq(b), eq(1), eq(3));
    }

    @Test
    @DisplayName("send delegates to output.writeDirect with args")
    void send_delegates_writeDirect() throws Exception {
        SmbPipeHandleImpl handle = newHandleWithBasicStubs(0, "\\\\pipe\\\\y");

        // Mock the stream directly
        SmbPipeOutputStream mockOut = mock(SmbPipeOutputStream.class);

        // Create spy and override getOutput
        SmbPipeHandleImpl spyHandle = spy(handle);
        doReturn(mockOut).when(spyHandle).getOutput();

        byte[] b = new byte[10];
        spyHandle.send(b, 2, 4);
        verify(mockOut).writeDirect(eq(b), eq(2), eq(4), eq(1));
    }

    @Test
    @DisplayName("unwrap returns this for compatible types and throws otherwise")
    void unwrap_success_and_failure() {
        SmbPipeHandleImpl handle = newHandleWithBasicStubs(0, "\\\\pipe\\\\z");

        // Happy path: unwrap to interface and concrete type
        SmbPipeHandle unwrapped1 = handle.unwrap(SmbPipeHandle.class);
        SmbPipeHandleImpl unwrapped2 = handle.unwrap(SmbPipeHandleImpl.class);
        assertSame(handle, unwrapped1);
        assertSame(handle, unwrapped2);

        // Invalid type
        class OtherPipeHandle implements SmbPipeHandle {
            @Override
            public SmbPipeResource getPipe() {
                return mock(SmbPipeResource.class);
            }

            @Override
            public SmbPipeInputStream getInput() throws CIFSException {
                return null;
            }

            @Override
            public SmbPipeOutputStream getOutput() throws CIFSException {
                return null;
            }

            @Override
            public boolean isOpen() {
                return false;
            }

            @Override
            public boolean isStale() {
                return false;
            }

            @Override
            public void close() throws CIFSException {
            }

            @Override
            public <T extends SmbPipeHandle> T unwrap(Class<T> type) {
                return null;
            }
        }
        assertThrows(ClassCastException.class, () -> {
            OtherPipeHandle result = handle.unwrap(OtherPipeHandle.class);
        });
    }

    @Test
    @DisplayName("getPipeType and getPipe delegate to SmbNamedPipe")
    void pipeType_and_getPipe() {
        when(pipe.getPipeType()).thenReturn(12345);
        SmbPipeHandleImpl handle = new SmbPipeHandleImpl(pipe);
        assertEquals(12345, handle.getPipeType());
        assertSame(pipe, handle.getPipe());
    }

    @Test
    @DisplayName("isOpen/isStale reflect handle validity and lifecycle")
    void isOpen_isStale_transitions() throws Exception {
        SmbPipeHandleImpl handle = newHandleWithBasicStubs(0, "\\\\pipe\\\\w");
        assertFalse(handle.isOpen(), "Initially not open");
        assertFalse(handle.isStale(), "Initially not stale");

        // After ensureOpen with valid fh
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(true);
        when(pipe.openUnshared(eq("\\\\pipe\\\\w"), eq(0), anyInt(), anyInt(), eq(SmbConstants.ATTR_NORMAL), eq(0))).thenReturn(fh);
        when(fh.acquire()).thenReturn(fh);
        when(fh.isValid()).thenReturn(true, false); // first true, then false

        handle.ensureOpen();
        assertTrue(handle.isOpen());

        // Simulate invalidation
        assertFalse(handle.isOpen(), "Becomes not open when underlying handle invalid");

        // After close, report stale
        handle.close();
        assertTrue(handle.isStale(), "Closed handle reports stale");
    }

    @Test
    @DisplayName("getSessionKey propagates CIFSException from session acquisition")
    void getSessionKey_exception_propagates() throws Exception {
        SmbPipeHandleImpl handle = newHandleWithBasicStubs(0, "\\\\pipe\\\\sess");
        when(pipe.ensureTreeConnected()).thenReturn(tree);
        when(tree.acquire()).thenReturn(tree);

        // Use doThrow for unchecked exception wrapping the CIFSException
        doThrow(new RuntimeException(new CIFSException("session fail"))).when(tree).getSession();

        Exception ex = assertThrows(Exception.class, handle::getSessionKey);
        assertTrue(
                ex.getMessage().contains("session fail") || (ex.getCause() != null && ex.getCause().getMessage().contains("session fail")));
    }
}