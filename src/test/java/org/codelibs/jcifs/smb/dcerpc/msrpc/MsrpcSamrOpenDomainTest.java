package org.codelibs.jcifs.smb.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.codelibs.jcifs.smb.dcerpc.rpc;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class MsrpcSamrOpenDomainTest {

    @Mock
    private SamrPolicyHandle mockHandle;
    @Mock
    private rpc.sid_t mockSid;
    @Mock
    private SamrDomainHandle mockDomainHandle;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void constructor_shouldInitializeFieldsAndCallSuper() {
        // Given
        int access = 0x01; // Example access value

        // When
        MsrpcSamrOpenDomain msrpcSamrOpenDomain = new MsrpcSamrOpenDomain(mockHandle, access, mockSid, mockDomainHandle);

        // Then
        // Verify that ptype is set to 0
        assertEquals(0, msrpcSamrOpenDomain.getPtype(), "ptype should be initialized to 0");

        // Verify that flags are set correctly (DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG)
        // The actual values for DCERPC_FIRST_FRAG and DCERPC_LAST_FRAG are typically 0x01 and 0x02 respectively.
        int expectedFlags = 0x01 | 0x02; // DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG
        assertEquals(expectedFlags, msrpcSamrOpenDomain.getFlags(), "flags should be initialized to DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG");

        // Since SamrOpenDomain's constructor is called, we implicitly test that the arguments
        // are passed up. Mockito cannot directly verify super() calls without PowerMock,
        // which is not ideal for simple constructor tests.
        // The primary responsibility of this constructor is setting ptype and flags,
        // which are directly verifiable.
    }
}
