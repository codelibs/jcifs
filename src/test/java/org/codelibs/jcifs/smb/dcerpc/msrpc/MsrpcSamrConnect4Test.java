package org.codelibs.jcifs.smb.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.codelibs.jcifs.smb.dcerpc.DcerpcConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Tests for {@link MsrpcSamrConnect4}.
 */
class MsrpcSamrConnect4Test implements DcerpcConstants {

    @Mock
    private SamrPolicyHandle policyHandle;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    /**
     * Test method for
     * {@link org.codelibs.jcifs.smb.dcerpc.msrpc.MsrpcSamrConnect4#MsrpcSamrConnect4(java.lang.String, int, org.codelibs.jcifs.smb.dcerpc.msrpc.SamrPolicyHandle)}.
     */
    @Test
    void testMsrpcSamrConnect4() {
        // Given
        final String server = "test-server";
        final int access = 1;

        // When
        final MsrpcSamrConnect4 request = new MsrpcSamrConnect4(server, access, this.policyHandle);

        // Then
        assertEquals(0, request.getPtype());
        assertEquals(DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG, request.getFlags());
    }
}
