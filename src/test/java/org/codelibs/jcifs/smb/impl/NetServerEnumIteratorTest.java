package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.net.URL;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.ResourceNameFilter;
import org.codelibs.jcifs.smb.RuntimeCIFSException;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.SmbResource;
import org.codelibs.jcifs.smb.SmbResourceLocator;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Unit tests for NetServerEnumIterator.
 * Tests focus on constructor validation and basic iterator contract.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class NetServerEnumIteratorTest {

    @Mock
    private SmbResourceLocator locator;
    @Mock
    private SmbTreeHandleImpl treeHandle;
    @Mock
    private Configuration config;
    @Mock
    private ResourceNameFilter nameFilter;

    private SmbFile parent;

    @BeforeAll
    static void setupURLHandler() {
        // Register the SMB URL handler to avoid MalformedURLException
        String pkgs = System.getProperty("java.protocol.handler.pkgs");
        if (pkgs == null) {
            System.setProperty("java.protocol.handler.pkgs", "org.codelibs.jcifs.smb");
        } else if (!pkgs.contains("org.codelibs.jcifs.smb")) {
            System.setProperty("java.protocol.handler.pkgs", pkgs + "|org.codelibs.jcifs.smb");
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        parent = mock(SmbFile.class);
        when(parent.getLocator()).thenReturn(locator);
        when(treeHandle.getConfig()).thenReturn(config);
        when(treeHandle.acquire()).thenReturn(treeHandle);
        when(treeHandle.getOEMDomainName()).thenReturn("TESTDOMAIN");
    }

    @Test
    @DisplayName("Constructor should throw SmbException for non-workgroup type with host")
    void testConstructor_NonWorkgroupType_ThrowsException() throws Exception {
        // Given: A non-workgroup type with a host
        when(locator.getType()).thenReturn(SmbConstants.TYPE_SERVER);
        when(locator.getURL()).thenReturn(createSmbURL("smb://server/"));

        // When & Then: Constructor should throw SmbException
        SmbException exception = assertThrows(SmbException.class, () -> new NetServerEnumIterator(parent, treeHandle, "*", 0, null));

        assertTrue(exception.getMessage().contains("invalid"));
        verify(treeHandle, never()).acquire();
    }

    @Test
    @DisplayName("Constructor should handle null parent")
    void testConstructor_NullParent_ThrowsNPE() {
        // When & Then: Null parent should cause NullPointerException
        assertThrows(NullPointerException.class, () -> new NetServerEnumIterator(null, treeHandle, "*", 0, null));
    }

    @Test
    @DisplayName("Constructor should handle null tree handle")
    void testConstructor_NullTreeHandle_ThrowsNPE() throws Exception {
        // Given: Valid parent but null tree handle
        when(locator.getType()).thenReturn(SmbConstants.TYPE_WORKGROUP);
        when(locator.getURL()).thenReturn(createSmbURL("smb://"));

        // When & Then: Null tree handle should cause NullPointerException
        assertThrows(NullPointerException.class, () -> new NetServerEnumIterator(parent, null, "*", 0, null));
    }

    @Test
    @DisplayName("Remove operation should throw UnsupportedOperationException")
    void testRemove_ThrowsUnsupportedOperationException() throws Exception {
        // Given: A valid iterator setup that will complete immediately
        when(locator.getType()).thenReturn(SmbConstants.TYPE_WORKGROUP);
        when(locator.getURL()).thenReturn(createSmbURL("smb://"));

        // Mock successful but empty response
        when(treeHandle.send(any(), any(), (RequestParam[]) any())).thenAnswer(invocation -> {
            // The response is the second argument
            Object response = invocation.getArgument(1);
            // Return it unchanged (which will have default values = empty results)
            return response;
        });

        // When: Create iterator
        NetServerEnumIterator iterator = new NetServerEnumIterator(parent, treeHandle, "*", 0, null);

        // Then: Remove should throw UnsupportedOperationException
        UnsupportedOperationException exception = assertThrows(UnsupportedOperationException.class, iterator::remove);
        assertEquals("remove", exception.getMessage());
    }

    @Test
    @DisplayName("Close should be idempotent")
    void testClose_Idempotent() throws Exception {
        // Given: A valid iterator setup
        when(locator.getType()).thenReturn(SmbConstants.TYPE_WORKGROUP);
        when(locator.getURL()).thenReturn(createSmbURL("smb://"));

        // Mock successful but empty response
        when(treeHandle.send(any(), any(), (RequestParam[]) any())).thenAnswer(invocation -> {
            return invocation.getArgument(1);
        });

        // When: Create iterator and close multiple times
        NetServerEnumIterator iterator = new NetServerEnumIterator(parent, treeHandle, "*", 0, null);

        iterator.close();
        iterator.close(); // Second close should be safe

        // Then: Tree handle should be released only once
        verify(treeHandle, times(1)).release();
    }

    @Test
    @DisplayName("Iterator should handle filter that rejects all entries")
    void testIterator_FilterRejectsAll() throws Exception {
        // Given: A filter that rejects everything
        when(locator.getType()).thenReturn(SmbConstants.TYPE_WORKGROUP);
        when(locator.getURL()).thenReturn(createSmbURL("smb://"));
        when(nameFilter.accept(any(SmbResource.class), anyString())).thenReturn(false);

        // Mock response with one entry
        when(treeHandle.send(any(), any(), (RequestParam[]) any())).thenAnswer(invocation -> {
            return invocation.getArgument(1);
        });

        // When: Create iterator with rejecting filter
        NetServerEnumIterator iterator = new NetServerEnumIterator(parent, treeHandle, "*", 0, nameFilter);

        // Then: Iterator should have no elements
        assertFalse(iterator.hasNext());

        // Cleanup
        iterator.close();
    }

    @Test
    @DisplayName("Iterator should handle filter that throws CIFSException")
    void testIterator_FilterThrowsException() throws Exception {
        // Given: A filter that throws exception
        when(locator.getType()).thenReturn(SmbConstants.TYPE_WORKGROUP);
        when(locator.getURL()).thenReturn(createSmbURL("smb://"));
        when(nameFilter.accept(any(SmbResource.class), anyString())).thenThrow(new CIFSException("Filter error"));

        // Mock response
        when(treeHandle.send(any(), any(), (RequestParam[]) any())).thenAnswer(invocation -> {
            return invocation.getArgument(1);
        });

        // When: Create iterator with throwing filter
        NetServerEnumIterator iterator = new NetServerEnumIterator(parent, treeHandle, "*", 0, nameFilter);

        // Then: Iterator should skip the entry (log error and continue)
        assertFalse(iterator.hasNext());

        // Cleanup
        iterator.close();
    }

    @Test
    @DisplayName("Constructor should handle workgroup type with empty host")
    void testConstructor_WorkgroupEmptyHost() throws Exception {
        // Given: Workgroup type with empty host
        when(locator.getType()).thenReturn(SmbConstants.TYPE_WORKGROUP);
        when(locator.getURL()).thenReturn(createSmbURL("smb://"));

        // Mock successful response
        when(treeHandle.send(any(), any(), (RequestParam[]) any())).thenAnswer(invocation -> {
            return invocation.getArgument(1);
        });

        // When: Create iterator
        NetServerEnumIterator iterator = new NetServerEnumIterator(parent, treeHandle, "*", 0, null);

        // Then: Should create successfully
        assertNotNull(iterator);
        assertFalse(iterator.hasNext()); // Empty results

        // Verify tree handle was acquired
        verify(treeHandle).acquire();

        // Cleanup
        iterator.close();
    }

    @Test
    @DisplayName("Constructor should handle workgroup type with non-empty host")
    void testConstructor_WorkgroupNonEmptyHost() throws Exception {
        // Given: Workgroup type with non-empty host
        when(locator.getType()).thenReturn(SmbConstants.TYPE_WORKGROUP);
        when(locator.getURL()).thenReturn(createSmbURL("smb://workgroup/"));

        // Mock successful response
        when(treeHandle.send(any(), any(), (RequestParam[]) any())).thenAnswer(invocation -> {
            return invocation.getArgument(1);
        });

        // When: Create iterator
        NetServerEnumIterator iterator = new NetServerEnumIterator(parent, treeHandle, "*", 0, null);

        // Then: Should create successfully
        assertNotNull(iterator);
        assertFalse(iterator.hasNext()); // Empty results

        // Verify tree handle was acquired
        verify(treeHandle).acquire();

        // Cleanup
        iterator.close();
    }

    @Test
    @DisplayName("A browse cut short by a failure is reported, not passed off as the end of the list")
    void testIterator_FetchFailureIsReported() throws Exception {
        // Given: a first page that reports more data to come, so the iterator has an entry to hand out and a reason
        // to go back for another page
        when(locator.getType()).thenReturn(SmbConstants.TYPE_WORKGROUP);
        when(locator.getURL()).thenReturn(createSmbURL("smb://"));

        // The iterator calls the two-argument send(request, response), which reaches the varargs overload with an
        // empty array. A (RequestParam[]) any() matcher expects an array argument and does not match that, which is
        // why stubbing it that way leaves the page empty.
        final java.util.concurrent.atomic.AtomicInteger sends = new java.util.concurrent.atomic.AtomicInteger();
        when(treeHandle.send(any(CommonServerMessageBlockRequest.class), any())).thenAnswer(invocation -> {
            if (sends.incrementAndGet() > 1) {
                // The second page is the one that fails - a dropped connection, a revoked session, anything
                throw new CIFSException("browse fetch failed");
            }
            final Object response = invocation.getArgument(1);
            // ERROR_MORE_DATA makes advance() yield numEntries - 1 entries and then go back for the rest
            setPrivate(response, "status", 234); // WinError.ERROR_MORE_DATA
            setPrivate(response, "numEntries", 2);
            setPrivate(response, "results", new FileEntry[] { serverEntry("ALPHA"), serverEntry("BETA") });
            return response;
        });

        NetServerEnumIterator iterator = new NetServerEnumIterator(parent, treeHandle, "*", 0, null);

        // Then: the entry read before the failure is still handed out ...
        assertTrue(iterator.hasNext());
        assertEquals("ALPHA", iterator.next().getName());

        // ... and the caller is told the browse failed, rather than seeing it end quietly at one entry
        RuntimeCIFSException ex = assertThrows(RuntimeCIFSException.class, iterator::next);
        assertNotNull(ex.getCause(), "the failure that ended the browse should be the cause");
        assertEquals("browse fetch failed", ex.getCause().getMessage());
        assertFalse(iterator.hasNext(), "the iterator is finished once it has reported the failure");
    }

    /** Sets a private field declared anywhere up the hierarchy; the transaction response keeps these package private. */
    private static void setPrivate(Object target, String name, Object value) throws Exception {
        for (Class<?> c = target.getClass(); c != null; c = c.getSuperclass()) {
            try {
                java.lang.reflect.Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                f.set(target, value);
                return;
            } catch (NoSuchFieldException e) {
                // keep walking up
            }
        }
        throw new NoSuchFieldException(name);
    }

    private static FileEntry serverEntry(String name) {
        return new FileEntry() {
            @Override
            public String getName() {
                return name;
            }

            @Override
            public int getType() {
                return SmbConstants.TYPE_SERVER;
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
        };
    }

    // Helper method to create SMB URLs with proper handler
    private static URL createSmbURL(String urlString) throws MalformedURLException {
        return new URL(null, urlString, new org.codelibs.jcifs.smb.impl.Handler());
    }
}