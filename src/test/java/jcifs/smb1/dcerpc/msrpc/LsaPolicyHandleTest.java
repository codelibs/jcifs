package jcifs.smb1.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.smb1.dcerpc.DcerpcHandle;
import jcifs.smb1.smb1.SmbException;

@ExtendWith(MockitoExtension.class)
class LsaPolicyHandleTest {

    @Mock
    private DcerpcHandle mockDcerpcHandle;

    @BeforeEach
    void setUp() {
        // Setup is handled by MockitoExtension
    }

    @Test
    void constructor_shouldOpenPolicySuccessfully() throws IOException {
        // Arrange
        String server = "testServer";
        int access = 123;

        // Mock the behavior of sendrecv for MsrpcLsarOpenPolicy2
        doAnswer(invocation -> {
            MsrpcLsarOpenPolicy2 rpc = invocation.getArgument(0);
            rpc.retval = 0; // Simulate success
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcLsarOpenPolicy2.class));

        // Act
        LsaPolicyHandle handle = new LsaPolicyHandle(mockDcerpcHandle, server, access);

        // Assert
        assertNotNull(handle);
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcLsarOpenPolicy2.class));
    }

    @Test
    void constructor_shouldHandleNullServerSuccessfully() throws IOException {
        // Arrange
        String server = null;
        int access = 123;

        doAnswer(invocation -> {
            MsrpcLsarOpenPolicy2 rpc = invocation.getArgument(0);
            rpc.retval = 0; // Simulate success
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcLsarOpenPolicy2.class));

        // Act
        LsaPolicyHandle handle = new LsaPolicyHandle(mockDcerpcHandle, server, access);

        // Assert
        assertNotNull(handle);
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcLsarOpenPolicy2.class));
    }

    @Test
    void constructor_shouldThrowSmbExceptionOnRpcError() throws IOException {
        // Arrange
        String server = "testServer";
        int access = 123;
        int errorCode = 12345;

        doAnswer(invocation -> {
            MsrpcLsarOpenPolicy2 rpc = invocation.getArgument(0);
            rpc.retval = errorCode; // Simulate RPC error
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcLsarOpenPolicy2.class));

        // Act & Assert
        SmbException thrown = assertThrows(SmbException.class, () -> {
            new LsaPolicyHandle(mockDcerpcHandle, server, access);
        });

        // In smb1, non-NTSTATUS error codes get mapped to NT_STATUS_UNSUCCESSFUL (0xC0000001)
        assertEquals(0xC0000001, thrown.getNtStatus()); // NT_STATUS_UNSUCCESSFUL
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcLsarOpenPolicy2.class));
    }

    @Test
    void constructor_shouldThrowIOExceptionOnSendRecvFailure() throws IOException {
        // Arrange
        String server = "testServer";
        int access = 123;

        doThrow(new IOException("Network error")).when(mockDcerpcHandle).sendrecv(any(MsrpcLsarOpenPolicy2.class));

        // Act & Assert
        IOException thrown = assertThrows(IOException.class, () -> {
            new LsaPolicyHandle(mockDcerpcHandle, server, access);
        });

        assertEquals("Network error", thrown.getMessage());
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcLsarOpenPolicy2.class));
    }

    @Test
    void close_shouldClosePolicySuccessfully() throws IOException {
        // Arrange
        // First, successfully create an LsaPolicyHandle instance
        doAnswer(invocation -> {
            MsrpcLsarOpenPolicy2 rpc = invocation.getArgument(0);
            rpc.retval = 0;
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcLsarOpenPolicy2.class));

        LsaPolicyHandle handle = new LsaPolicyHandle(mockDcerpcHandle, "server", 123);

        // Now, mock the behavior for MsrpcLsarClose
        doAnswer(invocation -> {
            MsrpcLsarClose rpc = invocation.getArgument(0);
            rpc.retval = 0; // Simulate success
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcLsarClose.class));

        // Act
        handle.close();

        // Assert
        // Verify sendrecv was called once for open and once for close
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcLsarOpenPolicy2.class));
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcLsarClose.class));
    }

    @Test
    void close_shouldThrowSmbExceptionOnRpcError() throws IOException {
        // Arrange
        int errorCode = 54321;

        // First, successfully create an LsaPolicyHandle instance
        doAnswer(invocation -> {
            MsrpcLsarOpenPolicy2 rpc = invocation.getArgument(0);
            rpc.retval = 0;
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcLsarOpenPolicy2.class));

        LsaPolicyHandle handle = new LsaPolicyHandle(mockDcerpcHandle, "server", 123);

        // Now, mock the behavior for MsrpcLsarClose to throw an error
        doAnswer(invocation -> {
            MsrpcLsarClose rpc = invocation.getArgument(0);
            rpc.retval = errorCode; // Simulate RPC error
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcLsarClose.class));

        // Act & Assert
        SmbException thrown = assertThrows(SmbException.class, () -> {
            handle.close();
        });

        // In smb1, non-NTSTATUS error codes get mapped to NT_STATUS_UNSUCCESSFUL (0xC0000001)
        assertEquals(0xC0000001, thrown.getNtStatus()); // NT_STATUS_UNSUCCESSFUL
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcLsarOpenPolicy2.class));
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcLsarClose.class));
    }

    @Test
    void close_shouldThrowIOExceptionOnSendRecvFailure() throws IOException {
        // Arrange
        // First, successfully create an LsaPolicyHandle instance
        doAnswer(invocation -> {
            MsrpcLsarOpenPolicy2 rpc = invocation.getArgument(0);
            rpc.retval = 0;
            return null;
        }).when(mockDcerpcHandle).sendrecv(any(MsrpcLsarOpenPolicy2.class));

        LsaPolicyHandle handle = new LsaPolicyHandle(mockDcerpcHandle, "server", 123);

        // Now, mock the behavior for MsrpcLsarClose to throw IOException
        doThrow(new IOException("Close network error")).when(mockDcerpcHandle).sendrecv(any(MsrpcLsarClose.class));

        // Act & Assert
        IOException thrown = assertThrows(IOException.class, () -> {
            handle.close();
        });

        assertEquals("Close network error", thrown.getMessage());
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcLsarOpenPolicy2.class));
        verify(mockDcerpcHandle, times(1)).sendrecv(any(MsrpcLsarClose.class));
    }
}