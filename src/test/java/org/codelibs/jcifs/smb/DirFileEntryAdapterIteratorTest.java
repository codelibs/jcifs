package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for {@link DirFileEntryAdapterIterator}.
 *
 * This test class verifies the basic functionality of DirFileEntryAdapterIterator.
 * Due to the iterator's constructor calling advance() immediately, which requires
 * the adapt() method to be functional, we test the behavior using simple mock
 * scenarios that don't require complex filter setups.
 */
@ExtendWith(MockitoExtension.class)
class DirFileEntryAdapterIteratorTest {

    @Mock
    private SmbResource mockParent;

    @Mock
    private CloseableIterator<FileEntry> mockDelegate;

    @Mock
    private ResourceFilter mockFilter;

    @Mock
    private FileEntry mockFileEntry1;

    @Mock
    private FileEntry mockFileEntry2;

    @Mock
    private FileEntry mockFileEntry3;

    @Mock
    private SmbResource mockResource1;

    @Mock
    private SmbResource mockResource2;

    @Mock
    private SmbResource mockResource3;

    @BeforeEach
    void setUp() {
        lenient().when(mockFileEntry1.getName()).thenReturn("file1.txt");
        lenient().when(mockFileEntry2.getName()).thenReturn("file2.txt");
        lenient().when(mockFileEntry3.getName()).thenReturn("file3.txt");

        lenient().when(mockResource1.getName()).thenReturn("file1.txt");
        lenient().when(mockResource2.getName()).thenReturn("file2.txt");
        lenient().when(mockResource3.getName()).thenReturn("file3.txt");
    }

    /**
     * Test iterator with no filter - all elements should be returned.
     */
    @Test
    void testIteratorWithoutFilter() {
        // Given
        when(mockDelegate.hasNext()).thenReturn(true, true, true, false);
        when(mockDelegate.next()).thenReturn(mockFileEntry1, mockFileEntry2, mockFileEntry3);

        // Create a simple test iterator that returns mocked resources
        DirFileEntryAdapterIterator iterator = new DirFileEntryAdapterIterator(mockParent, mockDelegate, null) {
            @Override
            protected SmbResource adapt(FileEntry e) {
                if (e == mockFileEntry1)
                    return mockResource1;
                if (e == mockFileEntry2)
                    return mockResource2;
                if (e == mockFileEntry3)
                    return mockResource3;
                return mockResource1;
            }
        };

        // When/Then
        assertTrue(iterator.hasNext(), "Should have first element");
        SmbResource first = iterator.next();
        assertNotNull(first, "First element should not be null");
        assertEquals("file1.txt", first.getName());

        assertTrue(iterator.hasNext(), "Should have second element");
        SmbResource second = iterator.next();
        assertNotNull(second, "Second element should not be null");
        assertEquals("file2.txt", second.getName());

        assertTrue(iterator.hasNext(), "Should have third element");
        SmbResource third = iterator.next();
        assertNotNull(third, "Third element should not be null");
        assertEquals("file3.txt", third.getName());

        assertFalse(iterator.hasNext(), "Should not have more elements");
    }

    /**
     * Test iterator with filter that accepts all elements.
     */
    @Test
    void testIteratorWithAcceptAllFilter() throws CIFSException {
        // Given
        when(mockDelegate.hasNext()).thenReturn(true, true, false);
        when(mockDelegate.next()).thenReturn(mockFileEntry1, mockFileEntry2);
        when(mockFilter.accept(any(SmbResource.class))).thenReturn(true);

        DirFileEntryAdapterIterator iterator = new DirFileEntryAdapterIterator(mockParent, mockDelegate, mockFilter) {
            @Override
            protected SmbResource adapt(FileEntry e) {
                if (e == mockFileEntry1)
                    return mockResource1;
                if (e == mockFileEntry2)
                    return mockResource2;
                return mockResource1;
            }
        };

        // When/Then
        assertTrue(iterator.hasNext(), "Should have first element");
        SmbResource first = iterator.next();
        assertNotNull(first, "First element should not be null");
        assertEquals("file1.txt", first.getName());

        assertTrue(iterator.hasNext(), "Should have second element");
        SmbResource second = iterator.next();
        assertNotNull(second, "Second element should not be null");
        assertEquals("file2.txt", second.getName());

        assertFalse(iterator.hasNext(), "Should not have more elements");

        // Verify filter was called for each element
        verify(mockFilter, times(2)).accept(any(SmbResource.class));
    }

    /**
     * Test iterator with filter that rejects all elements.
     */
    @Test
    void testIteratorWithFilterRejectingAll() throws CIFSException {
        // Given
        when(mockDelegate.hasNext()).thenReturn(true, true, false);
        when(mockDelegate.next()).thenReturn(mockFileEntry1, mockFileEntry2);
        when(mockFilter.accept(any(SmbResource.class))).thenReturn(false);

        DirFileEntryAdapterIterator iterator = new DirFileEntryAdapterIterator(mockParent, mockDelegate, mockFilter) {
            @Override
            protected SmbResource adapt(FileEntry e) {
                if (e == mockFileEntry1)
                    return mockResource1;
                if (e == mockFileEntry2)
                    return mockResource2;
                return mockResource1;
            }
        };

        // When/Then
        assertFalse(iterator.hasNext(), "Should not have elements when all are filtered");

        // Verify filter was called for each element
        verify(mockFilter, times(2)).accept(any(SmbResource.class));
    }

    /**
     * Test iterator with empty delegate.
     */
    @Test
    void testEmptyIterator() {
        // Given
        when(mockDelegate.hasNext()).thenReturn(false);

        DirFileEntryAdapterIterator iterator = new DirFileEntryAdapterIterator(mockParent, mockDelegate, null) {
            @Override
            protected SmbResource adapt(FileEntry e) {
                return mockResource1;
            }
        };

        // When/Then
        assertFalse(iterator.hasNext(), "Empty iterator should not have elements");
        // The iterator returns null when no elements, doesn't throw exception
        assertNull(iterator.next(), "Should return null when no elements");
    }

    /**
     * Test close method delegates to underlying iterator.
     */
    @Test
    void testClose() throws CIFSException {
        // Given
        when(mockDelegate.hasNext()).thenReturn(false);

        DirFileEntryAdapterIterator iterator = new DirFileEntryAdapterIterator(mockParent, mockDelegate, null) {
            @Override
            protected SmbResource adapt(FileEntry e) {
                return mockResource1;
            }
        };

        // When
        iterator.close();

        // Then
        verify(mockDelegate).close();
    }

    /**
     * Test close method propagates exception.
     */
    @Test
    void testCloseWithException() throws CIFSException {
        // Given
        when(mockDelegate.hasNext()).thenReturn(false);
        CIFSException exception = new CIFSException("Test exception");
        doThrow(exception).when(mockDelegate).close();

        DirFileEntryAdapterIterator iterator = new DirFileEntryAdapterIterator(mockParent, mockDelegate, null) {
            @Override
            protected SmbResource adapt(FileEntry e) {
                return mockResource1;
            }
        };

        // When/Then
        assertThrows(CIFSException.class, () -> iterator.close(), "Should propagate exception from delegate close");
    }

    /**
     * Test remove method delegates to underlying iterator.
     */
    @Test
    void testRemove() {
        // Given
        when(mockDelegate.hasNext()).thenReturn(true, false);
        when(mockDelegate.next()).thenReturn(mockFileEntry1);

        DirFileEntryAdapterIterator iterator = new DirFileEntryAdapterIterator(mockParent, mockDelegate, null) {
            @Override
            protected SmbResource adapt(FileEntry e) {
                return mockResource1;
            }
        };

        // When
        iterator.next(); // Move to first element
        iterator.remove();

        // Then
        verify(mockDelegate).remove();
    }

    /**
     * Test multiple calls to hasNext without calling next.
     */
    @Test
    void testMultipleHasNextCalls() {
        // Given
        when(mockDelegate.hasNext()).thenReturn(true, false);
        when(mockDelegate.next()).thenReturn(mockFileEntry1);

        DirFileEntryAdapterIterator iterator = new DirFileEntryAdapterIterator(mockParent, mockDelegate, null) {
            @Override
            protected SmbResource adapt(FileEntry e) {
                return mockResource1;
            }
        };

        // When/Then
        assertTrue(iterator.hasNext(), "First hasNext should return true");
        assertTrue(iterator.hasNext(), "Second hasNext should return true");
        assertTrue(iterator.hasNext(), "Third hasNext should return true");

        SmbResource result = iterator.next();
        assertNotNull(result, "Should still be able to get element");
        assertEquals("file1.txt", result.getName());

        assertFalse(iterator.hasNext(), "Should not have more elements");

        // Verify delegate.next() was only called once
        verify(mockDelegate, times(1)).next();
    }

    /**
     * Test constructor initializes correctly.
     */
    @Test
    void testConstructorInitialization() {
        // Given
        when(mockDelegate.hasNext()).thenReturn(false);

        // When
        DirFileEntryAdapterIterator iterator = new DirFileEntryAdapterIterator(mockParent, mockDelegate, mockFilter) {
            @Override
            protected SmbResource adapt(FileEntry e) {
                return mockResource1;
            }
        };

        // Then
        assertNotNull(iterator, "Iterator should be created");
        assertFalse(iterator.hasNext(), "Should not have elements");
    }

    /**
     * Test that the iterator handles null return from next correctly.
     */
    @Test
    void testNullReturnFromNext() {
        // Given
        when(mockDelegate.hasNext()).thenReturn(false);

        DirFileEntryAdapterIterator iterator = new DirFileEntryAdapterIterator(mockParent, mockDelegate, null) {
            @Override
            protected SmbResource adapt(FileEntry e) {
                return mockResource1;
            }
        };

        // When/Then
        assertFalse(iterator.hasNext(), "Should not have next when advance returns null");
        // The iterator returns null when no elements, doesn't throw exception
        assertNull(iterator.next(), "Should return null when no next element");
    }

    /**
     * Test multiple iterations with mixed filtering results.
     */
    @Test
    void testMultipleIterationsWithFilter() throws Exception {
        // Given
        when(mockDelegate.hasNext()).thenReturn(true, true, true, false);
        when(mockDelegate.next()).thenReturn(mockFileEntry1, mockFileEntry2, mockFileEntry3);

        // Create a mock filter that accepts file1 and file3 but not file2
        when(mockFilter.accept(mockResource1)).thenReturn(true);
        when(mockFilter.accept(mockResource2)).thenReturn(false);
        when(mockFilter.accept(mockResource3)).thenReturn(true);

        DirFileEntryAdapterIterator iterator = new DirFileEntryAdapterIterator(mockParent, mockDelegate, mockFilter) {
            @Override
            protected SmbResource adapt(FileEntry e) {
                if (e == mockFileEntry1)
                    return mockResource1;
                if (e == mockFileEntry2)
                    return mockResource2;
                if (e == mockFileEntry3)
                    return mockResource3;
                return mockResource1;
            }
        };

        // When
        assertTrue(iterator.hasNext(), "Should have first element");
        SmbResource first = iterator.next();
        assertNotNull(first, "First element should not be null");
        assertEquals("file1.txt", first.getName());

        assertTrue(iterator.hasNext(), "Should have second element (file3, file2 was filtered)");
        SmbResource second = iterator.next();
        assertNotNull(second, "Second element should not be null");
        assertEquals("file3.txt", second.getName());

        assertFalse(iterator.hasNext(), "Should not have more elements");

        // Then
        verify(mockDelegate, times(3)).next();
        verify(mockFilter).accept(mockResource1);
        verify(mockFilter).accept(mockResource2);
        verify(mockFilter).accept(mockResource3);
    }

    /**
     * Test that adapt method is actually used by the iterator.
     */
    @Test
    void testAdaptMethodIsUsed() {
        // Given
        when(mockDelegate.hasNext()).thenReturn(true, false);
        when(mockDelegate.next()).thenReturn(mockFileEntry1);

        // Create iterator with custom adapt implementation
        final boolean[] adaptCalled = { false };
        DirFileEntryAdapterIterator iterator = new DirFileEntryAdapterIterator(mockParent, mockDelegate, null) {
            @Override
            protected SmbResource adapt(FileEntry e) {
                adaptCalled[0] = true;
                assertEquals(mockFileEntry1, e, "Should adapt the correct entry");
                return mockResource1;
            }
        };

        // When
        SmbResource result = iterator.next();

        // Then
        assertTrue(adaptCalled[0], "Adapt method should have been called");
        assertNotNull(result, "Result should not be null");
        assertEquals("file1.txt", result.getName());
    }
}