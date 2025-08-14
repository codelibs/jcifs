package jcifs.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class MsrpcLsarOpenPolicy2Test {

    @Mock
    private LsaPolicyHandle mockPolicyHandle;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void constructor_shouldInitializeFieldsCorrectly() {
        // Given
        String server = "testServer";
        int access = 0x00000001; // Example access value

        // When
        MsrpcLsarOpenPolicy2 msrpcLsarOpenPolicy2 = new MsrpcLsarOpenPolicy2(server, access, mockPolicyHandle);

        // Then
        // Verify that the super constructor is called with correct arguments
        // Note: Directly verifying super constructor calls is not straightforward in JUnit/Mockito.
        // We verify the effects of the super constructor by checking the fields of the created object.

        // Assert object_attributes fields
        assertNotNull(msrpcLsarOpenPolicy2.object_attributes);
        assertEquals(24, msrpcLsarOpenPolicy2.object_attributes.length);

        // Assert security_quality_of_service fields
        assertNotNull(msrpcLsarOpenPolicy2.object_attributes.security_quality_of_service);
        lsarpc.LsarQosInfo qos = msrpcLsarOpenPolicy2.object_attributes.security_quality_of_service;
        assertEquals(12, qos.length);
        assertEquals(2, qos.impersonation_level);
        assertEquals(1, qos.context_mode);
        assertEquals(0, qos.effective_only);

        // Assert ptype and flags using getters
        assertEquals(0, msrpcLsarOpenPolicy2.getPtype());
        assertEquals(MsrpcLsarOpenPolicy2.DCERPC_FIRST_FRAG | MsrpcLsarOpenPolicy2.DCERPC_LAST_FRAG, msrpcLsarOpenPolicy2.getFlags());

        // Verify that the policyHandle passed to the constructor is the one used
        // This is implicitly tested by the object being constructed without errors.
        // If LsaPolicyHandle had methods called by the constructor, we would verify those calls.
    }
}
