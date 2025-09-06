package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.codelibs.jcifs.smb.dcerpc.DcerpcConstants;
import org.codelibs.jcifs.smb.dcerpc.msrpc.MsrpcEnumerateAliasesInDomain;
import org.codelibs.jcifs.smb.dcerpc.msrpc.SamrDomainHandle;
import org.codelibs.jcifs.smb.dcerpc.msrpc.samr;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class MsrpcEnumerateAliasesInDomainTest {

    @Mock
    private SamrDomainHandle mockDomainHandle;
    @Mock
    private samr.SamrSamArray mockSamArray;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void constructor_shouldInitializeFieldsCorrectly() {
        // Given
        int acctFlags = 123;

        // When
        MsrpcEnumerateAliasesInDomain msrpc = new MsrpcEnumerateAliasesInDomain(mockDomainHandle, acctFlags, mockSamArray);

        // Then
        // Verify that the 'sam' field is set correctly
        assertEquals(mockSamArray, msrpc.sam, "The 'sam' field should be initialized with the provided SamrSamArray.");

        // Verify that the 'ptype' field is set to 0
        assertEquals(0, msrpc.getPtype(), "The 'ptype' field should be initialized to 0.");

        // Verify that the 'flags' field is set to DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG
        int expectedFlags = DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG;
        assertEquals(expectedFlags, msrpc.getFlags(), "The 'flags' field should be initialized to DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG.");

        // Although we cannot directly verify the super constructor call with Mockito for a real class,
        // we can infer its correct behavior if the object is successfully constructed and its own fields are correct.
        // The super constructor is called with (domainHandle, 0, acct_flags, null, 0)
        // We can't directly assert these values on the superclass fields without reflection or a testable superclass.
        // For 100% coverage, we'd need to ensure the superclass constructor is indeed called with these values.
        // However, given the current structure, testing the fields set by MsrpcEnumerateAliasesInDomain itself is the primary focus.
    }
}
