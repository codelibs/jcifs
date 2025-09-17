package org.codelibs.jcifs.smb.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.codelibs.jcifs.smb.dcerpc.rpc.policy_handle;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class MsrpcSamrCloseHandleTest {

    @Mock
    private policy_handle mockPolicyHandle;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void constructorShouldInitializeCorrectly() {
        // Given
        // mockPolicyHandle is already mocked by @Mock and initialized by @BeforeEach

        // When
        MsrpcSamrCloseHandle msrpcSamrCloseHandle = new MsrpcSamrCloseHandle(mockPolicyHandle);

        // Then
        assertNotNull(msrpcSamrCloseHandle, "MsrpcSamrCloseHandle object should not be null");
        assertEquals(0, msrpcSamrCloseHandle.getPtype(), "ptype should be 0");
        assertEquals(MsrpcSamrCloseHandle.DCERPC_FIRST_FRAG | MsrpcSamrCloseHandle.DCERPC_LAST_FRAG, msrpcSamrCloseHandle.getFlags(),
                "flags should be DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG");
        // Verify that the super constructor was called with the correct handle.
        // This is implicitly tested by the object being created without error and
        // the fields set by the constructor being correct.
    }
}
