package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.codelibs.jcifs.smb.dcerpc.DcerpcConstants;
import org.codelibs.jcifs.smb.dcerpc.msrpc.LsaPolicyHandle;
import org.codelibs.jcifs.smb.dcerpc.msrpc.MsrpcQueryInformationPolicy;
import org.codelibs.jcifs.smb.dcerpc.ndr.NdrObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class MsrpcQueryInformationPolicyTest {

    @Mock
    private LsaPolicyHandle mockPolicyHandle;

    @Mock
    private NdrObject mockNdrObject;

    /**
     * Test the constructor of MsrpcQueryInformationPolicy.
     * It should correctly call the super constructor and set ptype and flags.
     */
    @Test
    @DisplayName("Constructor should initialize fields and call super constructor")
    void constructorTest() {
        short level = 1;

        // Create an instance of the class under test
        MsrpcQueryInformationPolicy policy = new MsrpcQueryInformationPolicy(mockPolicyHandle, level, mockNdrObject);

        // Verify that the super constructor was called with the correct arguments
        // Note: Mockito cannot directly verify super constructor calls.
        // We assume if the object is created, the super constructor was called.
        // We can verify the state of the object after construction.

        // Verify ptype and flags are set correctly
        assertEquals(0, policy.getPtype(), "ptype should be 0");
        assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, policy.getFlags(),
                "flags should be DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG");
    }
}
