package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class FileEntryAdapterIteratorTest {

    @Mock
    private CloseableIterator<FileEntry> delegate;

    @Mock
    private ResourceFilter filter;

    @Mock
    private SmbResource parent;

    @Mock
    private SmbResource resource;

    @Mock
    private FileEntry fileEntry;

    /**
     * Test implementation that always returns the same mock resource
     */
    private class TestIterator extends FileEntryAdapterIterator {
        TestIterator(ResourceFilter filter) {
            super(parent, delegate, filter);
        }

        @Override
        protected SmbResource adapt(FileEntry e) throws MalformedURLException {
            return resource;
        }
    }

    @BeforeEach
    void setUp() {
        lenient().when(fileEntry.getName()).thenReturn("test");
    }

    @Test
    @DisplayName("Iterator without filter - simple case")
    void iteratorWithoutFilter() {
        // Setup: constructor calls advance() once
        when(delegate.hasNext()).thenReturn(true, false);
        when(delegate.next()).thenReturn(fileEntry);

        TestIterator iterator = new TestIterator(null);

        // Verify iteration
        assertTrue(iterator.hasNext());
        assertSame(resource, iterator.next());
        assertFalse(iterator.hasNext());
        assertNull(iterator.next());

        // Without filter, resource should not be closed
        verify(resource, never()).close();
    }

    @Test
    @DisplayName("Iterator with accepting filter")
    void iteratorWithAcceptingFilter() throws Exception {
        // Setup
        when(delegate.hasNext()).thenReturn(true, false);
        when(delegate.next()).thenReturn(fileEntry);
        when(filter.accept(resource)).thenReturn(true);

        TestIterator iterator = new TestIterator(filter);

        // Verify iteration
        assertTrue(iterator.hasNext());
        assertSame(resource, iterator.next());
        assertFalse(iterator.hasNext());

        // With filter, resource should be closed due to try-with-resources
        verify(filter).accept(resource);
        verify(resource).close();
    }

    @Test
    @DisplayName("Iterator with rejecting filter - finds next acceptable")
    void iteratorWithRejectingFilter() throws Exception {
        // Setup: first entry rejected, second accepted
        FileEntry entry1 = mock(FileEntry.class);
        FileEntry entry2 = mock(FileEntry.class);

        when(delegate.hasNext()).thenReturn(true, true, false);
        when(delegate.next()).thenReturn(entry1, entry2);
        when(filter.accept(resource)).thenReturn(false, true);

        TestIterator iterator = new TestIterator(filter);

        // Verify iteration
        assertTrue(iterator.hasNext());
        assertSame(resource, iterator.next());
        assertFalse(iterator.hasNext());

        // Both resources should be closed
        verify(filter, times(2)).accept(resource);
        verify(resource, times(2)).close();
    }

    @Test
    @DisplayName("Iterator with filter throwing exception")
    void iteratorWithFilterException() throws Exception {
        // Setup: first attempt throws, second succeeds
        FileEntry entry1 = mock(FileEntry.class);
        FileEntry entry2 = mock(FileEntry.class);

        when(delegate.hasNext()).thenReturn(true, true, false);
        when(delegate.next()).thenReturn(entry1, entry2);
        when(filter.accept(resource)).thenThrow(new CIFSException("Error")).thenReturn(true);

        TestIterator iterator = new TestIterator(filter);

        // Verify iteration
        assertTrue(iterator.hasNext());
        assertSame(resource, iterator.next());
        assertFalse(iterator.hasNext());

        verify(filter, times(2)).accept(resource);
        verify(resource, times(2)).close();
    }

    @Test
    @DisplayName("Multiple iterations")
    void multipleIterations() {
        // Setup for three items
        FileEntry entry1 = mock(FileEntry.class);
        FileEntry entry2 = mock(FileEntry.class);
        FileEntry entry3 = mock(FileEntry.class);

        // Constructor gets entry1, first next() returns it and gets entry2,
        // second next() returns entry2 and gets entry3,
        // third next() returns entry3 and exhausts
        when(delegate.hasNext()).thenReturn(true, true, true, false);
        when(delegate.next()).thenReturn(entry1, entry2, entry3);

        TestIterator iterator = new TestIterator(null);

        // Verify iteration
        assertTrue(iterator.hasNext());
        assertSame(resource, iterator.next());

        assertTrue(iterator.hasNext());
        assertSame(resource, iterator.next());

        assertTrue(iterator.hasNext());
        assertSame(resource, iterator.next());

        assertFalse(iterator.hasNext());
        assertNull(iterator.next());

        verify(resource, never()).close();
    }

    @Test
    @DisplayName("Empty iterator")
    void emptyIterator() {
        when(delegate.hasNext()).thenReturn(false);

        TestIterator iterator = new TestIterator(null);

        assertFalse(iterator.hasNext());
        assertNull(iterator.next());
    }

    @Test
    @DisplayName("Close delegates to underlying iterator")
    void closeDelegation() throws CIFSException {
        when(delegate.hasNext()).thenReturn(false);

        TestIterator iterator = new TestIterator(null);
        iterator.close();

        verify(delegate).close();
    }

    @Test
    @DisplayName("Close propagates exception")
    void closeException() throws CIFSException {
        when(delegate.hasNext()).thenReturn(false);
        doThrow(new CIFSException("Close failed")).when(delegate).close();

        TestIterator iterator = new TestIterator(null);

        CIFSException ex = assertThrows(CIFSException.class, iterator::close);
        assertEquals("Close failed", ex.getMessage());
    }

    @Test
    @DisplayName("Remove delegates to underlying iterator")
    void removeDelegation() {
        when(delegate.hasNext()).thenReturn(false);

        TestIterator iterator = new TestIterator(null);
        iterator.remove();

        verify(delegate).remove();
    }

    @Test
    @DisplayName("Remove propagates UnsupportedOperationException")
    void removeException() {
        when(delegate.hasNext()).thenReturn(false);
        doThrow(new UnsupportedOperationException("Not supported")).when(delegate).remove();

        TestIterator iterator = new TestIterator(null);

        UnsupportedOperationException ex = assertThrows(UnsupportedOperationException.class, iterator::remove);
        assertEquals("Not supported", ex.getMessage());
    }

    @Test
    @DisplayName("Null delegate causes NPE")
    void nullDelegate() {
        assertThrows(NullPointerException.class, () -> {
            new FileEntryAdapterIterator(parent, null, null) {
                @Override
                protected SmbResource adapt(FileEntry e) {
                    return resource;
                }
            };
        });
    }

    @Test
    @DisplayName("Complex scenario with multiple filter conditions")
    void complexFilterScenario() throws Exception {
        // Setup: three entries with different filter results
        FileEntry entry1 = mock(FileEntry.class);
        FileEntry entry2 = mock(FileEntry.class);
        FileEntry entry3 = mock(FileEntry.class);

        when(delegate.hasNext()).thenReturn(true, true, true, false);
        when(delegate.next()).thenReturn(entry1, entry2, entry3);

        // First rejected, second throws exception, third accepted
        when(filter.accept(resource)).thenReturn(false).thenThrow(new CIFSException("Error")).thenReturn(true);

        TestIterator iterator = new TestIterator(filter);

        // Verify iteration
        assertTrue(iterator.hasNext());
        assertSame(resource, iterator.next());
        assertFalse(iterator.hasNext());

        // All three attempts should be made
        verify(filter, times(3)).accept(resource);
        // All three should be closed
        verify(resource, times(3)).close();
    }

    @Test
    @DisplayName("Adapter throwing MalformedURLException on all entries")
    void adapterThrowsOnAllEntries() {
        // Setup
        FileEntry entry1 = mock(FileEntry.class);
        FileEntry entry2 = mock(FileEntry.class);

        when(delegate.hasNext()).thenReturn(true, true, false);
        when(delegate.next()).thenReturn(entry1, entry2);

        // Adapter that always throws
        FileEntryAdapterIterator iterator = new FileEntryAdapterIterator(parent, delegate, null) {
            @Override
            protected SmbResource adapt(FileEntry e) throws MalformedURLException {
                throw new MalformedURLException("Always fails");
            }
        };

        // When all entries fail, iterator should be empty
        assertFalse(iterator.hasNext());
        assertNull(iterator.next());
    }

    @Test
    @DisplayName("Adapter returning null on all entries")
    void adapterReturnsNullOnAll() {
        // Setup
        FileEntry entry1 = mock(FileEntry.class);
        FileEntry entry2 = mock(FileEntry.class);

        when(delegate.hasNext()).thenReturn(true, true, false);
        when(delegate.next()).thenReturn(entry1, entry2);

        // Adapter that always returns null
        FileEntryAdapterIterator iterator = new FileEntryAdapterIterator(parent, delegate, null) {
            @Override
            protected SmbResource adapt(FileEntry e) throws MalformedURLException {
                return null;
            }
        };

        // When all entries return null, iterator should be empty
        assertFalse(iterator.hasNext());
        assertNull(iterator.next());
    }

}