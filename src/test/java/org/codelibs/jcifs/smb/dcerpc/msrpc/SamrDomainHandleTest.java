package org.codelibs.jcifs.smb.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;

import org.codelibs.jcifs.smb.dcerpc.DcerpcHandle;
import org.codelibs.jcifs.smb.dcerpc.rpc;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SamrDomainHandleTest {

    @Mock
    private DcerpcHandle mockDcerpcHandle;
    @Mock
    private SamrPolicyHandle mockPolicyHandle;
    @Mock
    private rpc.sid_t mockSid;

    // Use ArgumentCaptor to capture the MsrpcSamrOpenDomain instance passed to sendrecv
    private ArgumentCaptor<MsrpcSamrOpenDomain> openDomainCaptor;
    // Use ArgumentCaptor to capture the MsrpcSamrCloseHandle instance passed to sendrecv
    private ArgumentCaptor<MsrpcSamrCloseHandle> closeHandleCaptor;

    @BeforeEach
    void setUp() {
        // Initialize mocks and captors before each test
        MockitoAnnotations.openMocks(this);
        openDomainCaptor = ArgumentCaptor.forClass(MsrpcSamrOpenDomain.class);
        closeHandleCaptor = ArgumentCaptor.forClass(MsrpcSamrCloseHandle.class);
    }

    @Test
    void constructor_shouldOpenDomainSuccessfully() throws IOException {
        // Arrange
        int access = 0x01; // Example access value
        // Simulate successful RPC call
        doAnswer(invocation -> {
            MsrpcSamrOpenDomain rpc = invocation.getArgument(0);
            rpc.retval = 0; // Success
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrOpenDomain.class));

        // Act
        SamrDomainHandle handle = new SamrDomainHandle(mockDcerpcHandle, mockPolicyHandle, access, mockSid);

        // Assert
        assertNotNull(handle);
        // Verify sendrecv was called once with the correct RPC message
        verify(mockDcerpcHandle, times(1)).sendrecv(openDomainCaptor.capture());
        MsrpcSamrOpenDomain capturedRpc = openDomainCaptor.getValue();
        assertNotNull(capturedRpc);
        assertEquals(mockPolicyHandle, capturedRpc.handle);
        assertEquals(access, capturedRpc.access_mask);
        assertEquals(mockSid, capturedRpc.sid);
        assertEquals(handle, capturedRpc.domain_handle); // Ensure the handle itself is passed for output
    }

    @Test
    void constructor_shouldThrowSmbExceptionOnRpcError() throws IOException {
        // Arrange
        int access = 0x01;
        int errorCode = 0xC0000022; // Example error code (STATUS_ACCESS_DENIED)
        // Simulate RPC error
        doAnswer(invocation -> {
            MsrpcSamrOpenDomain rpc = invocation.getArgument(0);
            rpc.retval = errorCode; // Simulate error
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrOpenDomain.class));

        // Act & Assert
        SmbException thrown = assertThrows(SmbException.class, () -> {
            new SamrDomainHandle(mockDcerpcHandle, mockPolicyHandle, access, mockSid);
        });
        assertEquals(errorCode, thrown.getNtStatus());
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcSamrOpenDomain.class));
    }

    @Test
    void constructor_shouldThrowIOExceptionOnSendRecvFailure() throws IOException {
        // Arrange
        int access = 0x01;
        IOException expectedException = new IOException("Network error");
        // Simulate IOException during RPC call
        doThrow(expectedException).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrOpenDomain.class));

        // Act & Assert
        IOException thrown = assertThrows(IOException.class, () -> {
            new SamrDomainHandle(mockDcerpcHandle, mockPolicyHandle, access, mockSid);
        });
        assertEquals(expectedException, thrown);
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcSamrOpenDomain.class));
    }

    @Test
    void close_shouldCloseHandleSuccessfully() throws IOException {
        // Arrange
        int access = 0x01;
        // Simulate successful open
        doAnswer(invocation -> {
            MsrpcSamrOpenDomain rpc = invocation.getArgument(0);
            rpc.retval = 0;
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrOpenDomain.class));

        SamrDomainHandle handle = new SamrDomainHandle(mockDcerpcHandle, mockPolicyHandle, access, mockSid);

        // Simulate successful close
        doAnswer(invocation -> {
            MsrpcSamrCloseHandle rpc = invocation.getArgument(0);
            rpc.retval = 0; // Success
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrCloseHandle.class));

        // Act
        handle.close();

        // Assert
        // Verify sendrecv was called for open and then for close
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcSamrOpenDomain.class));
        verify(mockDcerpcHandle, times(1)).sendrecv(closeHandleCaptor.capture());
        MsrpcSamrCloseHandle capturedRpc = closeHandleCaptor.getValue();
        assertNotNull(capturedRpc);
        assertEquals(handle, capturedRpc.handle); // Ensure the handle itself is passed for closing
    }

    @Test
    void close_shouldDoNothingIfAlreadyClosed() throws IOException {
        // Arrange
        int access = 0x01;
        // Simulate successful open
        doAnswer(invocation -> {
            MsrpcSamrOpenDomain rpc = invocation.getArgument(0);
            rpc.retval = 0;
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrOpenDomain.class));

        SamrDomainHandle handle = new SamrDomainHandle(mockDcerpcHandle, mockPolicyHandle, access, mockSid);

        // Simulate successful close
        doAnswer(invocation -> {
            MsrpcSamrCloseHandle rpc = invocation.getArgument(0);
            rpc.retval = 0;
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrCloseHandle.class));

        // First close call
        handle.close();

        // Act
        // Second close call
        handle.close();

        // Assert
        // sendrecv for open is called once
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcSamrOpenDomain.class));
        // sendrecv for close is called only once, even if close() is called multiple times
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcSamrCloseHandle.class));
    }

    @Test
    void close_shouldThrowSmbExceptionOnRpcError() throws IOException {
        // Arrange
        int access = 0x01;
        // Simulate successful open
        doAnswer(invocation -> {
            MsrpcSamrOpenDomain rpc = invocation.getArgument(0);
            rpc.retval = 0;
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrOpenDomain.class));

        SamrDomainHandle handle = new SamrDomainHandle(mockDcerpcHandle, mockPolicyHandle, access, mockSid);

        int errorCode = 0xC0000022; // Example error code
        // Simulate RPC error during close
        doAnswer(invocation -> {
            MsrpcSamrCloseHandle rpc = invocation.getArgument(0);
            rpc.retval = errorCode; // Simulate error
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrCloseHandle.class));

        // Act & Assert
        SmbException thrown = assertThrows(SmbException.class, handle::close);
        assertEquals(errorCode, thrown.getNtStatus());
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcSamrOpenDomain.class));
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcSamrCloseHandle.class));
    }

    @Test
    void close_shouldThrowIOExceptionOnSendRecvFailure() throws IOException {
        // Arrange
        int access = 0x01;
        // Simulate successful open
        doAnswer(invocation -> {
            MsrpcSamrOpenDomain rpc = invocation.getArgument(0);
            rpc.retval = 0;
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrOpenDomain.class));

        SamrDomainHandle handle = new SamrDomainHandle(mockDcerpcHandle, mockPolicyHandle, access, mockSid);

        IOException expectedException = new IOException("Network error during close");
        // Simulate IOException during close RPC call
        doThrow(expectedException).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrCloseHandle.class));

        // Act & Assert
        IOException thrown = assertThrows(IOException.class, handle::close);
        assertEquals(expectedException, thrown);
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcSamrOpenDomain.class));
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcSamrCloseHandle.class));
    }
}
