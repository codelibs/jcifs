package org.codelibs.jcifs.smb.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.codelibs.jcifs.smb.dcerpc.msrpc.samr.SamrSamArray;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Tests for {@link MsrpcEnumerateAliasesInDomain}.
 */
class MsrpcEnumerateAliasesInDomainTest {

    @Mock
    private SamrDomainHandle mockDomainHandle;

    @Mock
    private SamrSamArray mockSamArray;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    /**
     * Test method for
     * {@link MsrpcEnumerateAliasesInDomain#MsrpcEnumerateAliasesInDomain(SamrDomainHandle, int, SamrSamArray)}.
     */
    @Test
    void testConstructor() {
        // Given
        int acctFlags = 1;

        // When
        MsrpcEnumerateAliasesInDomain request = new MsrpcEnumerateAliasesInDomain(mockDomainHandle, acctFlags, mockSamArray);

        // Then
        assertNotNull(request, "The request object should not be null.");
        assertEquals(mockDomainHandle, request.domain_handle, "The domain handle should be set correctly.");
        assertEquals(acctFlags, request.acct_flags, "The account flags should be set correctly.");
        assertEquals(mockSamArray, request.sam, "The sam array should be set correctly.");
        // ptype and flags are protected fields in DcerpcMessage, cannot test directly
    }
}
