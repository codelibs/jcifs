package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

/**
 * Test class for CloseableIterator interface functionality
 */
@DisplayName("CloseableIterator Tests")
class CloseableIteratorTest extends BaseTest {

    @Mock
    private CloseableIterator<SmbResource> mockIterator;

    @Test
    @DisplayName("Should define close method")
    void testCloseMethod() throws CIFSException {
        // When
        mockIterator.close();

        // Then
        verify(mockIterator).close();
    }

    @Test
    @DisplayName("Should extend Iterator and AutoCloseable")
    void testInterfaceInheritance() {
        // Then
        assertTrue(java.util.Iterator.class.isAssignableFrom(CloseableIterator.class));
        assertTrue(AutoCloseable.class.isAssignableFrom(CloseableIterator.class));
    }
}
