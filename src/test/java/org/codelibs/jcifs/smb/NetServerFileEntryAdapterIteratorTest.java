package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.context.SingletonContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for NetServerFileEntryAdapterIterator.
 *
 * Intent: Validate iteration behavior, filtering, invalid inputs handling,
 * and delegation to the underlying iterator.
 */
@ExtendWith(MockitoExtension.class)
class NetServerFileEntryAdapterIteratorTest {

    @Mock
    NetServerEnumIterator delegate;

    @Mock
    ResourceFilter filter;

    @Mock
    SmbResource parent;

    @Mock
    SmbResourceLocator parentLocator;

    private CIFSContext ctx;

    @BeforeEach
    void setup() {
        // Use a real CIFS context to provide a working URLStreamHandler for smb:// URLs
        this.ctx = SingletonContext.getInstance();
    }

    private void setupParentForUrlCreation() throws CIFSException {
        // Only set up parent mocks when they're actually needed for URL creation
        when(parent.getContext()).thenReturn(this.ctx);
        when(parent.getLocator()).thenReturn(parentLocator);
        // Make the parent appear as a workgroup to use the simpler URL code-path
        when(parentLocator.isWorkgroup()).thenReturn(true);
    }

    /** Simple implementation of FileEntry for controlled inputs in tests. */
    private static final class StubFileEntry implements FileEntry {
        private final String name;
        private final int type;

        StubFileEntry(String name, int type) {
            this.name = name;
            this.type = type;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public int getType() {
            return type;
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
    }

    @Test
    @DisplayName("Happy path: iterates and adapts entries without filter")
    void happyPath_noFilter_returnsAdaptedResources() throws Exception {
        // Arrange: two valid entries
        setupParentForUrlCreation();
        StubFileEntry e1 = new StubFileEntry("SERVER1", SmbConstants.TYPE_SERVER);
        StubFileEntry e2 = new StubFileEntry("SERVER2", SmbConstants.TYPE_SERVER);
        when(delegate.hasNext()).thenReturn(true, true, false);
        when(delegate.next()).thenReturn(e1, e2);

        NetServerFileEntryAdapterIterator itr = new NetServerFileEntryAdapterIterator(parent, delegate, null);

        // Act & Assert
        assertTrue(itr.hasNext(), "Should have first element ready");
        SmbResource r1 = itr.next();
        assertNotNull(r1, "First adapted resource must not be null");
        // For workgroup/server entries, names end with '/'
        assertTrue(r1.getName().endsWith("/"), "Name should end with '/'");

        assertTrue(itr.hasNext(), "Should have second element ready");
        SmbResource r2 = itr.next();
        assertNotNull(r2, "Second adapted resource must not be null");
        assertTrue(r2.getName().endsWith("/"), "Name should end with '/'");

        assertFalse(itr.hasNext(), "No more elements after consuming two");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @DisplayName("Invalid names are skipped; next valid is returned")
    void skipsMalformedNames_thenReturnsValid(String badName) throws Exception {
        // Arrange: first entry is invalid (null or empty), second is valid
        setupParentForUrlCreation();
        StubFileEntry bad = new StubFileEntry(badName, SmbConstants.TYPE_SERVER);
        StubFileEntry good = new StubFileEntry("OKSERVER", SmbConstants.TYPE_SERVER);
        when(delegate.hasNext()).thenReturn(true, true, false);
        when(delegate.next()).thenReturn(bad, good);

        NetServerFileEntryAdapterIterator itr = new NetServerFileEntryAdapterIterator(parent, delegate, null);

        // Act: first valid next should be the second element
        assertTrue(itr.hasNext());
        SmbResource r = itr.next();

        // Assert: the invalid name was skipped, valid one returned
        assertNotNull(r);
        assertTrue(r.getName().startsWith("OKSERVER"), "Expected valid entry to be adapted");
        assertFalse(itr.hasNext());
    }

    @Test
    @DisplayName("Filter rejects first, accepts second; interactions verified")
    void filterRejectsThenAccepts_nextYieldsAccepted() throws Exception {
        // Arrange: two entries; filter rejects first, accepts second
        setupParentForUrlCreation();
        StubFileEntry skip = new StubFileEntry("SKIPME", SmbConstants.TYPE_SERVER);
        StubFileEntry take = new StubFileEntry("TAKEME", SmbConstants.TYPE_SERVER);
        when(delegate.hasNext()).thenReturn(true, true, false);
        when(delegate.next()).thenReturn(skip, take);

        // First call: reject, Second call: accept
        when(filter.accept(any(SmbResource.class))).thenReturn(false, true);

        NetServerFileEntryAdapterIterator itr = new NetServerFileEntryAdapterIterator(parent, delegate, filter);

        // Act
        assertTrue(itr.hasNext());
        SmbResource r = itr.next();

        // Assert: filter was invoked twice and we got the accepted one
        ArgumentCaptor<SmbResource> captor = ArgumentCaptor.forClass(SmbResource.class);
        verify(filter, times(2)).accept(captor.capture());
        assertNotNull(r);
        assertTrue(r.getName().startsWith("TAKEME"));

        // The first filtered resource name should correspond to the rejected entry
        assertTrue(captor.getAllValues().get(0).getName().startsWith("SKIPME"));
    }

    @Test
    @DisplayName("close() delegates to underlying iterator")
    void closeDelegates() throws Exception {
        // Arrange: no elements - no parent setup needed since no URLs are created
        when(delegate.hasNext()).thenReturn(false);
        NetServerFileEntryAdapterIterator itr = new NetServerFileEntryAdapterIterator(parent, delegate, null);

        // Act
        itr.close();

        // Assert
        verify(delegate, times(1)).close();
    }

    @Test
    @DisplayName("remove() delegates to underlying iterator")
    void removeDelegates() {
        // Arrange: no elements - no parent setup needed since no URLs are created
        when(delegate.hasNext()).thenReturn(false);
        NetServerFileEntryAdapterIterator itr = new NetServerFileEntryAdapterIterator(parent, delegate, null);

        // Act
        itr.remove();

        // Assert
        verify(delegate, times(1)).remove();
    }

    @Test
    @DisplayName("Edge: empty delegate yields no elements")
    void emptyDelegate_hasNoNext() {
        // Arrange - no parent setup needed since no URLs are created
        when(delegate.hasNext()).thenReturn(false);

        NetServerFileEntryAdapterIterator itr = new NetServerFileEntryAdapterIterator(parent, delegate, null);

        // Assert
        assertFalse(itr.hasNext());
    }
}
