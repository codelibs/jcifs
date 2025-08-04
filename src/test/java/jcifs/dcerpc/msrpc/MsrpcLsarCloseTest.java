package jcifs.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import jcifs.dcerpc.DcerpcConstants;
import jcifs.dcerpc.rpc.policy_handle;

/**
 * Tests for the {@link MsrpcLsarClose} class.
 */
class MsrpcLsarCloseTest {

    private policy_handle mockHandle;

    @BeforeEach
    void setUp() {
        // Create a mock policy_handle for each test
        mockHandle = mock(policy_handle.class);
    }

    /**
     * Test case for the {@link MsrpcLsarClose#MsrpcLsarClose(policy_handle)} constructor.
     * Verifies that the handle, ptype, and flags are correctly initialized.
     */
    @Test
    void testConstructor() {
        // Create an instance of MsrpcLsarClose with the mock handle
        MsrpcLsarClose lsarClose = new MsrpcLsarClose(mockHandle);

        // Verify that the handle passed to the constructor is correctly set in the superclass
        assertEquals(mockHandle, lsarClose.handle, "The handle should be initialized correctly.");

        // Verify that the ptype is set to 0
        assertEquals(0, lsarClose.getPtype(), "The ptype should be set to 0.");

        // Verify that the flags are set to the combination of DCERPC_FIRST_FRAG and DCERPC_LAST_FRAG
        int expectedFlags = DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG;
        assertEquals(expectedFlags, lsarClose.getFlags(), "The flags should be set to DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG.");
    }
}
