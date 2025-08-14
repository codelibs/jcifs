package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSException;
import jcifs.ResourceNameFilter;
import jcifs.SmbResource;

@ExtendWith(MockitoExtension.class)
class DirFileEntryEnumIteratorBaseTest {

    // Simple FileEntry implementation used for tests
    private static FileEntry entry(String name) {
        return new FileEntry() {
            @Override
            public String getName() {
                return name;
            }

            @Override
            public int getType() {
                return 0;
            }

            @Override
            public int getAttributes() {
                return 0;
            }

            @Override
            public long createTime() {
                return 0;
            }

            @Override
            public long lastModified() {
                return 0;
            }

            @Override
            public long lastAccess() {
                return 0;
            }

            @Override
            public long length() {
                return 0;
            }

            @Override
            public int getFileIndex() {
                return 0;
            }

            @Override
            public String toString() {
                return "Entry(" + name + ")";
            }
        };
    }

    // Controllable concrete subclass to drive behavior deterministically
    private static class TestIterator extends DirFileEntryEnumIteratorBase {
        private static FileEntry staticInitial;
        private static List<FileEntry[]> staticPages;
        private static boolean staticThrowOnOpen;

        private int pageIdx = -1; // Start before first page
        private boolean done = false;
        private boolean throwOnFetch;
        private boolean throwOnCloseInternal;

        // Use static factory method to work around constructor ordering
        static TestIterator create(SmbTreeHandleImpl th, SmbResource parent, String wildcard, ResourceNameFilter filter,
                int searchAttributes, FileEntry initial, List<FileEntry[]> pages) throws CIFSException {
            staticInitial = initial;
            staticPages = new ArrayList<>(pages);
            // Don't reset staticThrowOnOpen here - it's controlled by tests
            return new TestIterator(th, parent, wildcard, filter, searchAttributes);
        }

        private TestIterator(SmbTreeHandleImpl th, SmbResource parent, String wildcard, ResourceNameFilter filter, int searchAttributes)
                throws CIFSException {
            super(th, parent, wildcard, filter, searchAttributes);
        }

        TestIterator throwOnOpen() {
            // This method doesn't make sense anymore with static approach
            return this;
        }

        TestIterator throwOnFetch() {
            this.throwOnFetch = true;
            return this;
        }

        TestIterator throwOnCloseInternal() {
            this.throwOnCloseInternal = true;
            return this;
        }

        @Override
        protected FileEntry open() throws CIFSException {
            if (staticThrowOnOpen)
                throw new CIFSException("open fail");
            // Simulate fetching first page during open
            if (staticPages != null && !staticPages.isEmpty()) {
                pageIdx = 0;
            }
            // Return the initial element if provided
            return staticInitial;
        }

        @Override
        protected boolean isDone() {
            return this.done;
        }

        @Override
        protected boolean fetchMore() throws CIFSException {
            if (throwOnFetch)
                throw new CIFSException("fetchMore fail");
            // Move to next page if available
            if (staticPages != null && pageIdx + 1 < staticPages.size()) {
                pageIdx++;
                return true;
            }
            // No more pages
            this.done = true;
            return false;
        }

        @Override
        protected FileEntry[] getResults() {
            // Return current page if valid
            if (staticPages != null && pageIdx >= 0 && pageIdx < staticPages.size()) {
                return staticPages.get(pageIdx);
            }
            return new FileEntry[0];
        }

        @Override
        protected void doCloseInternal() throws CIFSException {
            if (throwOnCloseInternal)
                throw new CIFSException("closeInternal fail");
        }
    }

    @Mock
    SmbTreeHandleImpl tree;
    @Mock
    SmbResource parent;
    @Mock
    ResourceNameFilter nameFilter;

    private void stubAcquireReturnsSelf() {
        when(tree.acquire()).thenReturn(tree);
    }

    @Test
    @DisplayName("Getters return constructor values and acquire is called")
    void gettersAndAcquire() throws Exception {
        // Arrange
        stubAcquireReturnsSelf();
        String wildcard = "*.*";
        int attrs = 123;
        FileEntry initial = entry("first");
        List<FileEntry[]> pages = List.of(new FileEntry[][] { new FileEntry[] {} });

        // Act
        TestIterator it = TestIterator.create(tree, parent, wildcard, null, attrs, initial, pages);

        // Assert
        assertSame(tree, it.getTreeHandle(), "tree handle should be same instance returned by acquire");
        assertEquals(attrs, it.getSearchAttributes());
        assertEquals(wildcard, it.getWildcard());
        assertSame(parent, it.getParent());
        verify(tree, times(1)).acquire();
    }

    @Test
    @DisplayName("Constructor with open() returning null closes immediately and hasNext=false")
    void constructorOpenNullCloses() throws Exception {
        // Arrange
        stubAcquireReturnsSelf();
        List<FileEntry[]> pages = List.of(new FileEntry[][] { new FileEntry[] {} });

        // Create iterator where open() returns null by giving null initial
        TestIterator it = TestIterator.create(tree, parent, "*", null, 0, null, pages);

        // Assert
        assertFalse(it.hasNext(), "No next when opened with null initial");
        verify(tree, times(1)).release(); // closed in constructor
    }

    @Test
    @DisplayName("open() throwing CIFSException triggers close and rethrow")
    void constructorOpenThrows() {
        // Arrange
        stubAcquireReturnsSelf();
        List<FileEntry[]> pages = List.of(new FileEntry[][] { new FileEntry[] { entry("x") } });

        // Act + Assert
        CIFSException ex = assertThrows(CIFSException.class, () -> {
            TestIterator.staticThrowOnOpen = true; // Set flag before constructor
            try {
                TestIterator.create(tree, parent, "*", null, 0, entry("first"), pages);
            } finally {
                TestIterator.staticThrowOnOpen = false; // Reset flag
            }
        });
        assertEquals("open fail", ex.getMessage());
        verify(tree, times(1)).release(); // closed on constructor failure
    }

    @Test
    @DisplayName("Iteration skips '.' and '..' and returns valid entries")
    void iterationSkipsDotAndDotDot() throws Exception {
        // Arrange
        stubAcquireReturnsSelf();
        FileEntry initial = entry("a");
        // Include entries that should be skipped by internal filter
        FileEntry[] page1 = new FileEntry[] { entry("."), entry(".."), entry("b") };
        TestIterator it = TestIterator.create(tree, parent, "*", null, 0, initial, List.of(new FileEntry[][] { page1 }));

        // Act + Assert
        assertTrue(it.hasNext());
        assertEquals("a", it.next().getName(), "First element should be initial from open()");
        assertTrue(it.hasNext());
        assertEquals("b", it.next().getName(), "Next element should skip '.' and '..'");
        assertFalse(it.hasNext(), "Iterator exhausted after valid entries");
        verify(tree, times(1)).release(); // closed after exhaustion
    }

    @ParameterizedTest
    @ValueSource(strings = { "", "file.txt", "subdir" })
    @DisplayName("Name filter interaction: accept calls and rejections")
    void nameFilterAccepts(String acceptedName) throws Exception {
        // Arrange
        stubAcquireReturnsSelf();
        when(nameFilter.accept(any(), any())).thenReturn(false);
        when(nameFilter.accept(parent, acceptedName)).thenReturn(true);

        FileEntry initial = entry("first");
        FileEntry[] page1 = new FileEntry[] { entry("."), entry(".."), entry("rejected"), entry(acceptedName) };
        TestIterator it = TestIterator.create(tree, parent, "*", nameFilter, 0, initial, List.of(new FileEntry[][] { page1 }));

        // Act
        assertTrue(it.hasNext());
        FileEntry e1 = it.next();
        assertTrue(it.hasNext());
        FileEntry e2 = it.next();

        // Assert
        assertNotNull(e1);
        assertNotNull(e2);
        assertEquals("first", e1.getName());
        assertEquals(acceptedName, e2.getName(), "Should return the first name accepted by filter");

        // Verify filter interactions: not called for '.' and '..', called for others
        verify(nameFilter, never()).accept(parent, ".");
        verify(nameFilter, never()).accept(parent, "..");
        ArgumentCaptor<String> nameCaptor = ArgumentCaptor.forClass(String.class);
        verify(nameFilter, atLeast(1)).accept(eq(parent), nameCaptor.capture());
        assertTrue(nameCaptor.getAllValues().contains(acceptedName));

        // After consuming accepted name, iterator should be exhausted and closed
        assertFalse(it.hasNext());
        verify(tree, times(1)).release();
    }

    @Test
    @DisplayName("Name filter throwing CIFSException results in skip, not failure")
    void nameFilterThrowsIsHandled() throws Exception {
        // Arrange
        stubAcquireReturnsSelf();
        when(nameFilter.accept(parent, "bad")).thenThrow(new CIFSException("bad name"));
        when(nameFilter.accept(parent, "good")).thenReturn(true);

        FileEntry initial = entry("first");
        FileEntry[] page1 = new FileEntry[] { entry("bad"), entry("good") };
        TestIterator it = TestIterator.create(tree, parent, "*", nameFilter, 0, initial, List.of(new FileEntry[][] { page1 }));

        // Act
        assertTrue(it.hasNext());
        assertEquals("first", it.next().getName()); // initial
        assertTrue(it.hasNext());
        FileEntry next = it.next();

        // Assert: "bad" was skipped due to filter exception, "good" returned
        assertNotNull(next);
        assertEquals("good", next.getName());
        assertFalse(it.hasNext());
        verify(tree, times(1)).release();
    }

    @Test
    @DisplayName("advance() path handles fetchMore throwing CIFSException in next()")
    void advanceFetchMoreThrows() throws Exception {
        // Arrange
        stubAcquireReturnsSelf();
        // No results in current page, not done, and fetchMore will throw
        FileEntry initial = entry("one");
        TestIterator it =
                TestIterator.create(tree, parent, "*", null, 0, initial, List.of(new FileEntry[][] { new FileEntry[0] })).throwOnFetch();

        // Act
        assertTrue(it.hasNext());
        assertEquals("one", it.next().getName()); // consume initial
        // Next call should handle CIFSException and close iterator
        assertFalse(it.hasNext()); // After error, hasNext should return false

        // Assert
        verify(tree, times(1)).release();
    }

    @Test
    @DisplayName("close() closes when there is a next element and releases handle")
    void explicitClose() throws Exception {
        // Arrange
        stubAcquireReturnsSelf();
        FileEntry initial = entry("x");
        FileEntry[] page1 = new FileEntry[] { entry("y") };
        TestIterator it = TestIterator.create(tree, parent, "*", null, 0, initial, List.of(new FileEntry[][] { page1 }));

        // Act
        assertTrue(it.hasNext());
        it.close();

        // Assert
        assertFalse(it.hasNext());
        verify(tree, times(1)).release();
    }

    @Test
    @DisplayName("doCloseInternal throwing still releases exactly once and next() recovers")
    void closeInternalThrowsButReleases() throws Exception {
        // Arrange
        stubAcquireReturnsSelf();
        FileEntry initial = entry("first");
        // Provide a page with no valid items so that advance returns null and triggers close in next()
        TestIterator it = TestIterator.create(tree, parent, "*", null, 0, initial, List.of(new FileEntry[][] { new FileEntry[] {} }))
                .throwOnCloseInternal();

        // Act: first next() returns initial, second triggers close which throws internally but is handled
        assertTrue(it.hasNext());
        assertEquals("first", it.next().getName());
        assertFalse(it.hasNext()); // After exhaustion, hasNext should return false

        // Assert
        verify(tree, times(1)).release(); // release called in finally exactly once
    }

    @Test
    @DisplayName("remove() throws UnsupportedOperationException with 'remove' message")
    void removeUnsupported() throws Exception {
        // Arrange
        stubAcquireReturnsSelf();
        TestIterator it = TestIterator.create(tree, parent, "*", null, 0, entry("a"), List.of(new FileEntry[][] { new FileEntry[] {} }));

        // Act + Assert
        UnsupportedOperationException ex = assertThrows(UnsupportedOperationException.class, it::remove);
        assertEquals("remove", ex.getMessage());
    }

    @Test
    @DisplayName("Null tree handle throws NullPointerException during construction")
    void nullTreeHandle() {
        // Arrange
        SmbTreeHandleImpl nullTree = null;

        // Act + Assert
        assertThrows(NullPointerException.class,
                () -> TestIterator.create(nullTree, parent, "*", null, 0, entry("a"), List.of(new FileEntry[][] { new FileEntry[] {} })));
    }
}
