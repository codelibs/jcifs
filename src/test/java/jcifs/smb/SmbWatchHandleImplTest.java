package jcifs.smb;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.FileNotifyInformation;
import jcifs.SmbConstants;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.NotifyResponse;
import jcifs.internal.smb1.trans.nt.NtTransNotifyChange;
import jcifs.internal.smb2.notify.Smb2ChangeNotifyRequest;

/**
 * Tests for SmbWatchHandleImpl focusing on behavior and interactions.
 */
@ExtendWith(MockitoExtension.class)
class SmbWatchHandleImplTest {

    @Mock
    SmbFileHandleImpl handle;

    @Mock
    SmbTreeHandleImpl tree;

    // Prepare SMB2 flow with a given response
    private void setupSmb2(NotifyResponse resp, byte[] fileId) throws Exception {
        when(handle.isValid()).thenReturn(true);
        when(handle.getTree()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(true);
        when(tree.getConfig()).thenReturn(mock(Configuration.class));
        when(handle.getFileId()).thenReturn(fileId);
        when(tree.send(any(CommonServerMessageBlockRequest.class), any(), any(), any())).thenReturn(resp);
    }

    // Prepare SMB1 flow with a given response
    private void setupSmb1(NotifyResponse resp, int fid) throws Exception {
        when(handle.isValid()).thenReturn(true);
        when(handle.getTree()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(false);
        when(tree.getConfig()).thenReturn(mock(Configuration.class));
        when(tree.hasCapability(SmbConstants.CAP_NT_SMBS)).thenReturn(true);
        when(handle.getFid()).thenReturn(fid);
        when(tree.send(any(CommonServerMessageBlockRequest.class), any(), any(), any())).thenReturn(resp);
    }

    // Ensures watch() fails fast if the underlying handle is invalid
    @Test
    @DisplayName("watch() throws when handle invalid")
    void watch_invalidHandle_throwsSmbException() throws Exception {
        when(handle.isValid()).thenReturn(false);
        SmbWatchHandleImpl sut = new SmbWatchHandleImpl(handle, 0, false);

        SmbException ex = assertThrows(SmbException.class, sut::watch, "Expected SmbException when handle invalid");
        assertTrue(ex.getMessage().contains("Watch was broken by tree disconnect"));
    }

    // Happy path for SMB2: a response is received and the list is returned; tree is closed
    @Test
    @DisplayName("watch() SMB2 happy path returns notifications and closes tree")
    void watch_smb2_success_returnsList_andClosesTree() throws Exception {
        List<FileNotifyInformation> info = new ArrayList<>();
        NotifyResponse resp = mock(NotifyResponse.class);
        when(resp.isReceived()).thenReturn(true);
        when(resp.getErrorCode()).thenReturn(0);
        when(resp.getNotifyInformation()).thenReturn(info);
        setupSmb2(resp, new byte[16]);
        SmbWatchHandleImpl sut = new SmbWatchHandleImpl(handle, 0x1234, true);

        List<FileNotifyInformation> result = sut.watch();

        assertSame(info, result, "Should return response notify information");
        ArgumentCaptor<CommonServerMessageBlockRequest> reqCap = ArgumentCaptor.forClass(CommonServerMessageBlockRequest.class);
        verify(tree).send(reqCap.capture(), any(), any(), any());
        assertTrue(reqCap.getValue() instanceof Smb2ChangeNotifyRequest, "SMB2 request must be used");
        verify(tree, times(1)).close(); // try-with-resources must close
        verify(handle, never()).markClosed();
        verify(tree, never()).hasCapability(anyInt()); // not checked on SMB2
    }

    // SMB1 path: without CAP_NT_SMBS it should throw SmbUnsupportedOperationException
    @Test
    @DisplayName("watch() SMB1 without capability throws unsupported")
    void watch_smb1_noCapability_throwsUnsupported() throws Exception {
        when(handle.isValid()).thenReturn(true);
        when(handle.getTree()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(false);
        when(tree.hasCapability(SmbConstants.CAP_NT_SMBS)).thenReturn(false);
        SmbWatchHandleImpl sut = new SmbWatchHandleImpl(handle, 0, false);

        assertThrows(SmbUnsupportedOperationException.class, sut::watch);
        verify(tree, times(1)).close();
    }

    // SMB1 path: on error code 0x10B the handle should be marked closed
    @Test
    @DisplayName("watch() SMB1 marks handle closed on error 0x10B")
    void watch_smb1_marksClosed_onError10B() throws Exception {
        NotifyResponse resp = mock(NotifyResponse.class);
        when(resp.isReceived()).thenReturn(true);
        when(resp.getErrorCode()).thenReturn(0x10B);
        when(resp.getNotifyInformation()).thenReturn(new ArrayList<>());
        setupSmb1(resp, 42);
        SmbWatchHandleImpl sut = new SmbWatchHandleImpl(handle, 0xFF, false);

        List<FileNotifyInformation> result = sut.watch();

        assertNotNull(result);
        verify(handle, times(1)).markClosed();
        ArgumentCaptor<CommonServerMessageBlockRequest> reqCap = ArgumentCaptor.forClass(CommonServerMessageBlockRequest.class);
        verify(tree).send(reqCap.capture(), any(), any(), any());
        assertTrue(reqCap.getValue() instanceof NtTransNotifyChange, "SMB1 notify request must be used");
    }

    // If a response is not marked as received, throw a CIFSException
    @Test
    @DisplayName("watch() throws CIFSException when response not received")
    void watch_responseNotReceived_throwsCIFSException() throws Exception {
        NotifyResponse resp = mock(NotifyResponse.class);
        when(resp.isReceived()).thenReturn(false);
        setupSmb2(resp, new byte[16]);
        SmbWatchHandleImpl sut = new SmbWatchHandleImpl(handle, 0, false);

        CIFSException ex = assertThrows(CIFSException.class, sut::watch);
        assertTrue(ex.getMessage().contains("Did not receive response"));
    }

    // If the request is cancelled (NTSTATUS 0xC0000120), return null
    @Test
    @DisplayName("watch() returns null when request cancelled (NTSTATUS 0xC0000120)")
    void watch_sendCancelled_returnsNull() throws Exception {
        when(handle.isValid()).thenReturn(true);
        when(handle.getTree()).thenReturn(tree);
        when(tree.isSMB2()).thenReturn(true);
        when(tree.getConfig()).thenReturn(mock(Configuration.class));
        when(handle.getFileId()).thenReturn(new byte[16]);
        when(tree.send(any(CommonServerMessageBlockRequest.class), any(), any(), any()))
            .thenThrow(new SmbException(0xC0000120, (Throwable) null));
        SmbWatchHandleImpl sut = new SmbWatchHandleImpl(handle, 0, false);

        List<FileNotifyInformation> result = sut.watch();

        assertNull(result, "Cancelled watch should return null");
        verify(tree, times(1)).close();
    }

    // Error code 0x10C should clear the notify list and return it
    @Test
    @DisplayName("watch() clears notify list on error 0x10C and returns it")
    void watch_clearsList_onError10C() throws Exception {
        List<FileNotifyInformation> info = spy(new ArrayList<FileNotifyInformation>());
        info.add(mock(FileNotifyInformation.class));
        NotifyResponse resp = mock(NotifyResponse.class);
        when(resp.isReceived()).thenReturn(true);
        when(resp.getErrorCode()).thenReturn(0x10C);
        when(resp.getNotifyInformation()).thenReturn(info);
        setupSmb2(resp, new byte[16]);
        SmbWatchHandleImpl sut = new SmbWatchHandleImpl(handle, 0, false);

        List<FileNotifyInformation> result = sut.watch();

        assertSame(info, result, "Should return same list instance");
        verify(info, times(1)).clear();
        assertTrue(result.isEmpty(), "List should be cleared");
    }

    // Parameterized test to exercise SMB2 with different recursive and filter values
    @ParameterizedTest(name = "SMB2 param: recursive={0}, filter={1}")
    @CsvSource({
        "true, 0",
        "false, -1"
    })
    @DisplayName("watch() SMB2 parameterized branches execute without error")
    void watch_smb2_parameterized(boolean recursive, int filter) throws Exception {
        NotifyResponse resp = mock(NotifyResponse.class);
        when(resp.isReceived()).thenReturn(true);
        when(resp.getErrorCode()).thenReturn(0);
        when(resp.getNotifyInformation()).thenReturn(new ArrayList<>());
        setupSmb2(resp, new byte[16]);
        SmbWatchHandleImpl sut = new SmbWatchHandleImpl(handle, filter, recursive);

        List<FileNotifyInformation> result = sut.watch();

        assertNotNull(result);
        ArgumentCaptor<CommonServerMessageBlockRequest> reqCap = ArgumentCaptor.forClass(CommonServerMessageBlockRequest.class);
        verify(tree).send(reqCap.capture(), any(), any(), any());
        assertTrue(reqCap.getValue() instanceof Smb2ChangeNotifyRequest);
    }

    // call() should delegate to watch() and return the same list
    @Test
    @DisplayName("call() delegates to watch() and returns same result")
    void call_delegatesToWatch() throws Exception {
        List<FileNotifyInformation> info = new ArrayList<>();
        NotifyResponse resp = mock(NotifyResponse.class);
        when(resp.isReceived()).thenReturn(true);
        when(resp.getErrorCode()).thenReturn(0);
        when(resp.getNotifyInformation()).thenReturn(info);
        setupSmb2(resp, new byte[16]);
        SmbWatchHandleImpl sut = new SmbWatchHandleImpl(handle, 0, false);

        List<FileNotifyInformation> result = sut.call();

        assertSame(info, result);
        verify(tree, atLeastOnce()).send(any(CommonServerMessageBlockRequest.class), any(), any(), any());
    }

    // close() should close underlying handle with 0L when valid
    @Test
    @DisplayName("close() closes underlying handle when valid")
    void close_validHandle_invokesClose() throws Exception {
        when(handle.isValid()).thenReturn(true);
        SmbWatchHandleImpl sut = new SmbWatchHandleImpl(handle, 0, false);

        sut.close();

        verify(handle, times(1)).close(0L);
    }

    // close() should do nothing when handle is invalid
    @Test
    @DisplayName("close() does nothing when handle invalid")
    void close_invalidHandle_doesNothing() throws Exception {
        when(handle.isValid()).thenReturn(false);
        SmbWatchHandleImpl sut = new SmbWatchHandleImpl(handle, 0, false);

        sut.close();

        verify(handle, never()).close(anyLong());
    }

    // Invalid input: constructing with null handle and invoking watch() NPEs
    @Test
    @DisplayName("Null handle causes NPE on watch() (invalid input)")
    void constructor_nullHandle_watch_throwsNPE() {
        SmbWatchHandleImpl sut = new SmbWatchHandleImpl(null, 0, false);

        assertThrows(NullPointerException.class, () -> {
            sut.watch();
        });
    }
}

