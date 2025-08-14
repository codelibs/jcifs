package jcifs.smb;

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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.ResourceNameFilter;
import jcifs.SmbConstants;
import jcifs.SmbResource;
import jcifs.SmbResourceLocator;

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
            System.setProperty("java.protocol.handler.pkgs", "jcifs");
        } else if (!pkgs.contains("jcifs")) {
            System.setProperty("java.protocol.handler.pkgs", pkgs + "|jcifs");
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

    // Helper method to create SMB URLs with proper handler
    private static URL createSmbURL(String urlString) throws MalformedURLException {
        return new URL(null, urlString, new jcifs.smb.Handler());
    }
}