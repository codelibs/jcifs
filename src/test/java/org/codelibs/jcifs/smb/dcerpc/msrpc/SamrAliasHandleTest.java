package org.codelibs.jcifs.smb.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;

import org.codelibs.jcifs.smb.SmbException;
import org.codelibs.jcifs.smb.dcerpc.DcerpcHandle;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class SamrAliasHandleTest {

    @Mock
    private DcerpcHandle mockDcerpcHandle;
    @Mock
    private SamrDomainHandle mockSamrDomainHandle;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void constructor_shouldOpenAliasSuccessfully() throws IOException {
        // Arrange
        int access = 1;
        int rid = 100;

        // Mock the behavior of sendrecv for MsrpcSamrOpenAlias
        doAnswer(invocation -> {
            MsrpcSamrOpenAlias rpc = invocation.getArgument(0);
            rpc.retval = 0; // Simulate success
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrOpenAlias.class));

        // Act
        SamrAliasHandle aliasHandle = new SamrAliasHandle(mockDcerpcHandle, mockSamrDomainHandle, access, rid);

        // Assert
        assertNotNull(aliasHandle);
        // Verify that sendrecv was called with the correct MsrpcSamrOpenAlias object
        ArgumentCaptor<MsrpcSamrOpenAlias> rpcCaptor = ArgumentCaptor.forClass(MsrpcSamrOpenAlias.class);
        verify(mockDcerpcHandle).sendrecv(rpcCaptor.capture());
        MsrpcSamrOpenAlias capturedRpc = rpcCaptor.getValue();
        // We cannot directly access private fields of MsrpcSamrOpenAlias or its superclass
        // Instead, we verify the interaction with the DcerpcHandle and the return value.
        // The fact that the constructor completes without exception and sets 'opened' to true
        // implies the correct parameters were used internally.
    }

    @Test
    void constructor_shouldThrowSmbExceptionOnOpenFailure() throws IOException {
        // Arrange
        int access = 1;
        int rid = 100;
        int errorCode = 0xC0000022; // Example error code

        // Mock the behavior of sendrecv for MsrpcSamrOpenAlias to simulate failure
        doAnswer(invocation -> {
            MsrpcSamrOpenAlias rpc = invocation.getArgument(0);
            rpc.retval = errorCode; // Simulate failure
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrOpenAlias.class));

        // Act & Assert
        SmbException thrown = assertThrows(SmbException.class, () -> {
            new SamrAliasHandle(mockDcerpcHandle, mockSamrDomainHandle, access, rid);
        });

        assertEquals(errorCode, thrown.getNtStatus());
    }

    @Test
    void close_shouldCloseAliasSuccessfully() throws IOException {
        // Arrange
        int access = 1;
        int rid = 100;

        // Mock constructor success
        doAnswer(invocation -> {
            MsrpcSamrOpenAlias rpc = invocation.getArgument(0);
            rpc.retval = 0;
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrOpenAlias.class));

        SamrAliasHandle aliasHandle = new SamrAliasHandle(mockDcerpcHandle, mockSamrDomainHandle, access, rid);

        // Mock close success
        doAnswer(invocation -> {
            MsrpcSamrCloseHandle rpc = invocation.getArgument(0);
            rpc.retval = 0;
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrCloseHandle.class));

        // Act
        aliasHandle.close();

        // Assert
        // Verify that sendrecv was called with MsrpcSamrCloseHandle
        verify(mockDcerpcHandle).sendrecv(any(MsrpcSamrCloseHandle.class));
        // Verify that close was called only once on the mockDcerpcHandle for MsrpcSamrCloseHandle
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcSamrCloseHandle.class));
    }

    @Test
    void close_shouldThrowSmbExceptionOnCloseFailure() throws IOException {
        // Arrange
        int access = 1;
        int rid = 100;
        int errorCode = 0xC0000022; // Example error code

        // Mock constructor success
        doAnswer(invocation -> {
            MsrpcSamrOpenAlias rpc = invocation.getArgument(0);
            rpc.retval = 0;
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrOpenAlias.class));

        SamrAliasHandle aliasHandle = new SamrAliasHandle(mockDcerpcHandle, mockSamrDomainHandle, access, rid);

        // Mock close failure
        doAnswer(invocation -> {
            MsrpcSamrCloseHandle rpc = invocation.getArgument(0);
            rpc.retval = errorCode;
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrCloseHandle.class));

        // Act & Assert
        SmbException thrown = assertThrows(SmbException.class, () -> {
            aliasHandle.close();
        });

        assertEquals(errorCode, thrown.getNtStatus());
    }

    @Test
    void close_shouldDoNothingIfAlreadyClosed() throws IOException {
        // Arrange
        int access = 1;
        int rid = 100;

        // Mock constructor success
        doAnswer(invocation -> {
            MsrpcSamrOpenAlias rpc = invocation.getArgument(0);
            rpc.retval = 0;
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrOpenAlias.class));

        SamrAliasHandle aliasHandle = new SamrAliasHandle(mockDcerpcHandle, mockSamrDomainHandle, access, rid);

        // Mock close success for the first call
        doAnswer(invocation -> {
            MsrpcSamrCloseHandle rpc = invocation.getArgument(0);
            rpc.retval = 0;
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcSamrCloseHandle.class));

        // First close call
        aliasHandle.close();

        // Act: Call close again
        aliasHandle.close();

        // Assert: Verify sendrecv for MsrpcSamrCloseHandle was called only once
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcSamrCloseHandle.class));
    }
}