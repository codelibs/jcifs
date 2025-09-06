package org.codelibs.jcifs.smb;

import static org.codelibs.jcifs.smb.dcerpc.DcerpcConstants.DCERPC_FIRST_FRAG;
import static org.codelibs.jcifs.smb.dcerpc.DcerpcConstants.DCERPC_LAST_FRAG;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.codelibs.jcifs.smb.dcerpc.msrpc.MsrpcGetMembersInAlias;
import org.codelibs.jcifs.smb.dcerpc.msrpc.SamrAliasHandle;
import org.codelibs.jcifs.smb.dcerpc.msrpc.lsarpc;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class MsrpcGetMembersInAliasTest {

    @Mock
    private SamrAliasHandle mockAliasHandle;

    @Mock
    private lsarpc.LsarSidArray mockSids;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    @DisplayName("Should correctly initialize MsrpcGetMembersInAlias with provided parameters")
    void testConstructorInitialization() {
        // Given
        // Mocks are already initialized by @BeforeEach

        // When
        MsrpcGetMembersInAlias msrpcGetMembersInAlias = new MsrpcGetMembersInAlias(mockAliasHandle, mockSids);

        // Then
        assertNotNull(msrpcGetMembersInAlias, "MsrpcGetMembersInAlias object should not be null");
        assertEquals(mockSids, msrpcGetMembersInAlias.sids, "sids should be set correctly");
        assertEquals(0, msrpcGetMembersInAlias.getPtype(), "ptype should be initialized to 0");
        assertEquals(DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG, msrpcGetMembersInAlias.getFlags(),
                "flags should be set to DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG");
    }
}
