package jcifs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.dcerpc.DcerpcConstants;
import jcifs.dcerpc.rpc.policy_handle;
import jcifs.dcerpc.msrpc.MsrpcLsarClose;

class MsrpcLsarCloseTest {

    @Mock
    private policy_handle mockPolicyHandle;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testConstructor() {
        // Create an instance of MsrpcLsarClose
        MsrpcLsarClose msrpcLsarClose = new MsrpcLsarClose(mockPolicyHandle);

        // Assert that the object is not null
        assertNotNull(msrpcLsarClose, "MsrpcLsarClose object should not be null");

        // Verify that the constructor correctly sets ptype and flags
        // These values are inherited from LsarClose, but MsrpcLsarClose sets them in its constructor
        assertEquals(0, msrpcLsarClose.getPtype(), "ptype should be 0");
        assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, msrpcLsarClose.getFlags(),
                "flags should be DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG");

        // Although we cannot directly assert that super(handle) was called with Mockito for a constructor,
        // the fact that the object is successfully created and its inherited fields are accessible
        // implies the super constructor was invoked.
    }
}
