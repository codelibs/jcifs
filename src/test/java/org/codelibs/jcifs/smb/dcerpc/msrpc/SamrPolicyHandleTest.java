package org.codelibs.jcifs.smb.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;

import org.codelibs.jcifs.smb.dcerpc.DcerpcError;
import org.codelibs.jcifs.smb.dcerpc.DcerpcException;
import org.codelibs.jcifs.smb.dcerpc.DcerpcHandle;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SamrPolicyHandleTest {

    @Mock
    private DcerpcHandle mockHandle;

    @BeforeEach
    void setUp() {
        // Reset mocks before each test
        reset(mockHandle);
    }

    @Test
    void testConstructor_SuccessfulConnect4() throws IOException {
        // Test case: Constructor with successful MsrpcSamrConnect4
        String server = "testServer";
        int access = 123;

        // No exception thrown by sendrecv for MsrpcSamrConnect4
        doNothing().when(mockHandle).sendrecv(any(MsrpcSamrConnect4.class));

        try (SamrPolicyHandle handle = new SamrPolicyHandle(mockHandle, server, access)) {
            assertNotNull(handle);
            // Verify that sendrecv was called with MsrpcSamrConnect4
            verify(mockHandle, times(1)).sendrecv(any(MsrpcSamrConnect4.class));
            verify(mockHandle, never()).sendrecv(any(MsrpcSamrConnect2.class));
        }
    }

    @Test
    void testConstructor_NullServer() throws IOException {
        // Test case: Constructor with null server, should default to "\\\\"
        String server = null;
        int access = 123;

        doNothing().when(mockHandle).sendrecv(any(MsrpcSamrConnect4.class));

        try (SamrPolicyHandle handle = new SamrPolicyHandle(mockHandle, server, access)) {
            assertNotNull(handle);
            ArgumentCaptor<MsrpcSamrConnect4> captor = ArgumentCaptor.forClass(MsrpcSamrConnect4.class);
            verify(mockHandle).sendrecv(captor.capture());
            assertEquals("\\\\", captor.getValue().system_name); // Verify server name in RPC call
        }
    }

    @Test
    void testConstructor_FallbackToConnect2() throws IOException {
        // Test case: Constructor with DCERPC_FAULT_OP_RNG_ERROR, should fallback to MsrpcSamrConnect2
        String server = "testServer";
        int access = 123;

        // Simulate DCERPC_FAULT_OP_RNG_ERROR for MsrpcSamrConnect4
        doThrow(new DcerpcException("Operation range error") {
            @Override
            public int getErrorCode() {
                return DcerpcError.DCERPC_FAULT_OP_RNG_ERROR;
            }
        }).when(mockHandle).sendrecv(any(MsrpcSamrConnect4.class));
        // Subsequent call for MsrpcSamrConnect2 should succeed
        doNothing().when(mockHandle).sendrecv(any(MsrpcSamrConnect2.class));

        try (SamrPolicyHandle handle = new SamrPolicyHandle(mockHandle, server, access)) {
            assertNotNull(handle);
            // Verify that sendrecv was called with MsrpcSamrConnect4 and then MsrpcSamrConnect2
            verify(mockHandle, times(1)).sendrecv(any(MsrpcSamrConnect4.class));
            verify(mockHandle, times(1)).sendrecv(any(MsrpcSamrConnect2.class));
        }
    }

    @Test
    void testConstructor_OtherDcerpcException() throws DcerpcException, IOException {
        // Test case: Constructor with other DcerpcException, should rethrow
        String server = "testServer";
        int access = 123;
        DcerpcException expectedException = new DcerpcException("Other error") {
            @Override
            public int getErrorCode() {
                return DcerpcError.DCERPC_FAULT_ACCESS_DENIED;
            }
        };

        // Simulate another DcerpcException for MsrpcSamrConnect4
        doThrow(expectedException).when(mockHandle).sendrecv(any(MsrpcSamrConnect4.class));

        DcerpcException thrown = assertThrows(DcerpcException.class, () -> {
            new SamrPolicyHandle(mockHandle, server, access);
        });

        assertEquals(expectedException, thrown);
        verify(mockHandle, times(1)).sendrecv(any(MsrpcSamrConnect4.class));
        verify(mockHandle, never()).sendrecv(any(MsrpcSamrConnect2.class));
    }

    @Test
    void testClose_Successful() throws IOException {
        // Test case: close() when opened and successful MsrpcSamrCloseHandle
        String server = "testServer";
        int access = 123;

        // Setup for successful constructor
        doNothing().when(mockHandle).sendrecv(any(MsrpcSamrConnect4.class));

        // Setup for successful close
        ArgumentCaptor<MsrpcSamrCloseHandle> closeCaptor = ArgumentCaptor.forClass(MsrpcSamrCloseHandle.class);
        doAnswer(invocation -> {
            MsrpcSamrCloseHandle rpc = invocation.getArgument(0);
            rpc.retval = 0; // Simulate success
            return null;
        }).when(mockHandle).sendrecv(closeCaptor.capture());

        SamrPolicyHandle handle = new SamrPolicyHandle(mockHandle, server, access);
        handle.close();

        // Verify close was called
        verify(mockHandle, times(1)).sendrecv(any(MsrpcSamrCloseHandle.class));
        assertEquals(handle, closeCaptor.getValue().handle); // Verify correct handle is passed
    }

    @Test
    void testClose_AlreadyClosed() throws IOException {
        // Test case: close() when already closed, should do nothing
        String server = "testServer";
        int access = 123;

        // Setup for successful constructor
        doNothing().when(mockHandle).sendrecv(any(MsrpcSamrConnect4.class));

        SamrPolicyHandle handle = new SamrPolicyHandle(mockHandle, server, access);
        handle.close(); // First close
        handle.close(); // Second close

        // Verify sendrecv for close was called only once
        verify(mockHandle, times(1)).sendrecv(any(MsrpcSamrCloseHandle.class));
    }

    @Test
    void testClose_SmbExceptionOnClose() throws IOException {
        // Test case: close() with non-zero retval from MsrpcSamrCloseHandle, should throw SmbException
        String server = "testServer";
        int access = 123;
        int errorRetval = 12345; // Simulate an error code

        // Setup for successful constructor
        doNothing().when(mockHandle).sendrecv(any(MsrpcSamrConnect4.class));

        // Setup for close to return an error
        ArgumentCaptor<MsrpcSamrCloseHandle> closeCaptor = ArgumentCaptor.forClass(MsrpcSamrCloseHandle.class);
        doAnswer(invocation -> {
            MsrpcSamrCloseHandle rpc = invocation.getArgument(0);
            rpc.retval = errorRetval; // Simulate error
            return null;
        }).when(mockHandle).sendrecv(closeCaptor.capture());

        SamrPolicyHandle handle = new SamrPolicyHandle(mockHandle, server, access);

        SmbException thrown = assertThrows(SmbException.class, handle::close);

        // SmbException constructor maps non-NT status codes to NT_STATUS_UNSUCCESSFUL
        assertEquals(0xC0000001, thrown.getNtStatus()); // NT_STATUS_UNSUCCESSFUL
        verify(mockHandle, times(1)).sendrecv(any(MsrpcSamrCloseHandle.class));
    }
}