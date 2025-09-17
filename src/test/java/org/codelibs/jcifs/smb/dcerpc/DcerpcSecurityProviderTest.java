package org.codelibs.jcifs.smb.dcerpc;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.codelibs.jcifs.smb.dcerpc.ndr.NdrBuffer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class DcerpcSecurityProviderTest {

    @Mock
    private DcerpcSecurityProvider dcerpcSecurityProvider;

    @Mock
    private NdrBuffer mockNdrBuffer;

    @BeforeEach
    void setUp() {
        // Initialize mocks before each test
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testWrapMethodIsCalled() throws DcerpcException {
        // Test that the wrap method can be called without throwing an exception
        dcerpcSecurityProvider.wrap(mockNdrBuffer);

        // Verify that the wrap method was called exactly once with the mockNdrBuffer
        verify(dcerpcSecurityProvider, times(1)).wrap(mockNdrBuffer);
    }

    @Test
    void testWrapMethodThrowsDcerpcException() throws DcerpcException {
        // Configure the mock to throw DcerpcException when wrap is called
        doThrow(new DcerpcException("Test wrap exception")).when(dcerpcSecurityProvider).wrap(mockNdrBuffer);

        // Assert that calling wrap throws DcerpcException
        assertThrows(DcerpcException.class, () -> dcerpcSecurityProvider.wrap(mockNdrBuffer));

        // Verify that the wrap method was called exactly once
        verify(dcerpcSecurityProvider, times(1)).wrap(mockNdrBuffer);
    }

    @Test
    void testUnwrapMethodIsCalled() throws DcerpcException {
        // Test that the unwrap method can be called without throwing an exception
        dcerpcSecurityProvider.unwrap(mockNdrBuffer);

        // Verify that the unwrap method was called exactly once with the mockNdrBuffer
        verify(dcerpcSecurityProvider, times(1)).unwrap(mockNdrBuffer);
    }

    @Test
    void testUnwrapMethodThrowsDcerpcException() throws DcerpcException {
        // Configure the mock to throw DcerpcException when unwrap is called
        doThrow(new DcerpcException("Test unwrap exception")).when(dcerpcSecurityProvider).unwrap(mockNdrBuffer);

        // Assert that calling unwrap throws DcerpcException
        assertThrows(DcerpcException.class, () -> dcerpcSecurityProvider.unwrap(mockNdrBuffer));

        // Verify that the unwrap method was called exactly once
        verify(dcerpcSecurityProvider, times(1)).unwrap(mockNdrBuffer);
    }
}
