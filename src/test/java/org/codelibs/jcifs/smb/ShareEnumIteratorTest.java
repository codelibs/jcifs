package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ShareEnumIteratorTest {

    @Mock
    ResourceFilter filter;

    // Helper to create a parent SmbFile that does not hit the network for simple operations
    private SmbFile newParent() throws MalformedURLException {
        // Valid share URL with trailing slash; constructing does not perform I/O
        return new SmbFile("smb://test-server/share/");
    }

    // Helper to create a minimal FileEntry mock
    private FileEntry entry(String name, int type) {
        FileEntry e = mock(FileEntry.class);
        when(e.getName()).thenReturn(name);
        when(e.getType()).thenReturn(type);
        return e;
    }

    @Test
    @DisplayName("Happy path without filter: iterates all entries in order")
    void happyPath_noFilter_returnsAll() throws Exception {
        SmbFile parent = newParent();
        List<FileEntry> entries = Arrays.asList(entry("foo", SmbConstants.TYPE_SHARE), entry("bar", SmbConstants.TYPE_SHARE));
        ShareEnumIterator it = new ShareEnumIterator(parent, entries.iterator(), null);

        // hasNext/next sequence over two elements
        assertTrue(it.hasNext(), "Expected first element available");
        SmbResource r1 = it.next();
        assertNotNull(r1);
        assertEquals("foo/", r1.getName(), "First child name should match with trailing slash");

        assertTrue(it.hasNext(), "Expected second element available");
        SmbResource r2 = it.next();
        assertNotNull(r2);
        assertEquals("bar/", r2.getName(), "Second child name should match with trailing slash");

        // End of iteration behavior
        assertFalse(it.hasNext(), "No more elements expected");
        assertNull(it.next(), "next() returns null when exhausted in this implementation");
    }

    @Test
    @DisplayName("With filter: only accepted entries are returned and filter is invoked per entry")
    void withFilter_acceptsSome_skipsOthers_andVerifiesInteractions() throws Exception {
        SmbFile parent = newParent();
        List<FileEntry> entries = Arrays.asList(entry("keep1", SmbConstants.TYPE_SHARE), entry("skip1", SmbConstants.TYPE_SHARE),
                entry("keep2", SmbConstants.TYPE_SHARE));

        // Filter accepts names starting with "keep"
        when(filter.accept(any())).thenAnswer(inv -> {
            SmbResource res = inv.getArgument(0);
            return res.getName().startsWith("keep");
        });

        ShareEnumIterator it = new ShareEnumIterator(parent, entries.iterator(), filter);

        // Returns only accepted resources
        assertTrue(it.hasNext());
        assertEquals("keep1/", it.next().getName());
        assertTrue(it.hasNext());
        assertEquals("keep2/", it.next().getName());
        assertFalse(it.hasNext());

        // Verify filter called once per entry
        verify(filter, times(3)).accept(any());
    }

    @Test
    @DisplayName("Filter throws CIFSException: entry is skipped and iteration continues")
    void filterThrows_skipsAndContinues() throws Exception {
        SmbFile parent = newParent();
        List<FileEntry> entries = Arrays.asList(entry("bad", SmbConstants.TYPE_SHARE), entry("good", SmbConstants.TYPE_SHARE));

        // First call throws, second accepts
        when(filter.accept(any())).thenThrow(new CIFSException("boom")).thenReturn(true);

        ShareEnumIterator it = new ShareEnumIterator(parent, entries.iterator(), filter);

        assertTrue(it.hasNext());
        SmbResource res = it.next();
        assertNotNull(res);
        assertEquals("good/", res.getName());
        assertFalse(it.hasNext());

        verify(filter, times(2)).accept(any());
    }

    static Stream<Arguments> invalidNamesAndFilterFlag() {
        return Stream.of(Arguments.of(null, false), Arguments.of("", false), Arguments.of(null, true), Arguments.of("", true));
    }

    @ParameterizedTest(name = "Invalid name=''{0}'' with filter={1} is skipped")
    @MethodSource("invalidNamesAndFilterFlag")
    void invalidNames_areSkipped_andNextValidReturned(String invalidName, boolean useFilter) throws Exception {
        SmbFile parent = newParent();

        FileEntry invalid = entry(invalidName, SmbConstants.TYPE_SHARE);
        FileEntry valid = entry("ok", SmbConstants.TYPE_SHARE);
        Iterator<FileEntry> delegate = Arrays.asList(invalid, valid).iterator();

        ResourceFilter f = useFilter ? filter : null;
        if (useFilter) {
            when(filter.accept(any())).thenReturn(true);
        }

        ShareEnumIterator it = new ShareEnumIterator(parent, delegate, f);
        assertTrue(it.hasNext());
        assertEquals("ok/", it.next().getName());
        assertFalse(it.hasNext());

        // When filter is used, it must not be called for the invalid entry
        if (useFilter) {
            verify(filter, times(1)).accept(any());
        }
    }

    @Test
    @DisplayName("close() clears pending element and hasNext() becomes false")
    void closeClearsNext() throws Exception {
        SmbFile parent = newParent();
        List<FileEntry> entries = Collections.singletonList(entry("one", SmbConstants.TYPE_SHARE));
        ShareEnumIterator it = new ShareEnumIterator(parent, entries.iterator(), null);

        assertTrue(it.hasNext());
        it.close();
        assertFalse(it.hasNext());
        assertNull(it.next());
    }

    @Test
    @DisplayName("remove() throws UnsupportedOperationException")
    void removeThrows() throws Exception {
        SmbFile parent = newParent();
        ShareEnumIterator it = new ShareEnumIterator(parent, Collections.<FileEntry> emptyList().iterator(), null);
        UnsupportedOperationException ex = assertThrows(UnsupportedOperationException.class, it::remove);
        assertEquals("remove", ex.getMessage());
    }

    @Nested
    @DisplayName("Invalid constructor inputs")
    class InvalidInputs {
        @Test
        @DisplayName("Null delegate causes NullPointerException during construction")
        void nullDelegate_throwsNPE() throws Exception {
            SmbFile parent = newParent();
            assertThrows(NullPointerException.class, () -> new ShareEnumIterator(parent, null, null));
        }

        @Test
        @DisplayName("Null parent with non-empty iterator causes NullPointerException during adapt")
        void nullParent_throwsNPE() {
            List<FileEntry> entries = Collections.singletonList(entry("x", SmbConstants.TYPE_SHARE));
            assertThrows(NullPointerException.class, () -> new ShareEnumIterator(null, entries.iterator(), null));
        }

        @Test
        @DisplayName("Empty iterator: hasNext() is false and next() returns null")
        void emptyIterator_behavesAsEmpty() throws Exception {
            SmbFile parent = newParent();
            ShareEnumIterator it = new ShareEnumIterator(parent, Collections.<FileEntry> emptyList().iterator(), null);
            assertFalse(it.hasNext());
            assertNull(it.next());
        }
    }
}
