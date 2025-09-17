package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;
import java.util.ArrayList;
import java.util.List;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.ResourceNameFilter;
import org.codelibs.jcifs.smb.SmbResource;
import org.codelibs.jcifs.smb.SmbResourceLocator;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComFindClose2;
import org.codelibs.jcifs.smb.internal.smb1.trans2.Trans2FindFirst2;
import org.codelibs.jcifs.smb.internal.smb1.trans2.Trans2FindFirst2Response;
import org.codelibs.jcifs.smb.internal.smb1.trans2.Trans2FindNext2;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DirFileEntryEnumIterator1Test {

    @Mock
    SmbTreeHandleImpl tree;
    @Mock
    SmbResource parent;
    @Mock
    SmbResourceLocator locator;
    @Mock
    Configuration config;

    private static boolean handlerRegistered = false;

    // Register SMB URL handler once for all tests
    @BeforeAll
    static void registerSmbHandler() {
        if (!handlerRegistered) {
            try {
                // Try to register the handler factory
                URL.setURLStreamHandlerFactory(new URLStreamHandlerFactory() {
                    @Override
                    public URLStreamHandler createURLStreamHandler(String protocol) {
                        if ("smb".equals(protocol)) {
                            return new Handler();
                        }
                        return null;
                    }
                });
                handlerRegistered = true;
            } catch (Error e) {
                // Factory already set, that's fine
                handlerRegistered = true;
            }
        }
    }

    @BeforeEach
    void setup() throws MalformedURLException, CIFSException {
        // Common happy-path defaults
        // Use lenient() to avoid strict stubbing issues with Mockito
        lenient().when(tree.acquire()).thenReturn(tree);
        lenient().when(tree.getConfig()).thenReturn(config);
        lenient().when(config.getListCount()).thenReturn(10);
        lenient().when(config.getListSize()).thenReturn(4096);

        lenient().when(parent.getLocator()).thenReturn(locator);
        lenient().when(locator.getUNCPath()).thenReturn("\\\\SERVER\\Share\\dir\\"); // ends with \\

        // Create URL with registered handler
        URL smbUrl = new URL("smb://server/share/dir/");
        lenient().when(locator.getURL()).thenReturn(smbUrl);
    }

    // Helper: reflectively set private/protected field on an object
    private static void setField(Object target, Class<?> declaring, String name, Object value) {
        try {
            Field f = declaring.getDeclaredField(name);
            f.setAccessible(true);
            f.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Simple FileEntry stub for tests
    private static final class FE implements FileEntry {
        private final String name;

        FE(String name) {
            this.name = name;
        }

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
    }

    @Test
    @DisplayName("open(): invalid URL path without trailing slash throws SmbException")
    void invalidUrlPathThrows() throws Exception {
        // Override the default setup for this specific test
        URL invalidUrl = new URL("smb://server/share/dir"); // no trailing '/'
        when(locator.getURL()).thenReturn(invalidUrl);

        SmbException ex =
                assertThrows(SmbException.class, () -> new DirFileEntryEnumIterator1(tree, parent, "*", (ResourceNameFilter) null, 0));
        assertTrue(ex.getMessage().contains("directory must end with '/'"));
        verify(tree, times(1)).acquire();
        verify(tree, times(1)).release(); // closed after failure
    }

    @Test
    @DisplayName("open(): invalid UNC without trailing backslash throws SmbException")
    void invalidUncThrows() throws Exception {
        // Override the default setup for this specific test
        when(locator.getUNCPath()).thenReturn("\\\\SERVER\\Share\\dir"); // missing trailing \\

        SmbException ex =
                assertThrows(SmbException.class, () -> new DirFileEntryEnumIterator1(tree, parent, "*", (ResourceNameFilter) null, 0));
        assertTrue(ex.getMessage().contains("UNC must end with '\\'"), "Actual message: " + ex.getMessage());
        verify(tree, times(1)).acquire();
        verify(tree, times(1)).release();
    }

    @Test
    @DisplayName("Happy path: iterates entries, fetchMore(), then closes with FindClose2")
    void iteratesAndFetchesMoreThenCloses() throws Exception {
        // Arrange: program send() to simulate first, next, next(NO_MORE_FILES)
        List<String[]> batches = new ArrayList<>();
        batches.add(new String[] { ".", "..", "a", "b" }); // first batch, dot entries filtered
        batches.add(new String[] { "c" }); // second batch
        batches.add(new String[] {}); // last -> NO_MORE_FILES

        // send() answer that mutates the provided response
        when(tree.send(any(Trans2FindFirst2.class), any(Trans2FindFirst2Response.class))).thenAnswer((InvocationOnMock inv) -> {
            Trans2FindFirst2Response resp = inv.getArgument(1);
            // First response content
            FE[] res = java.util.Arrays.stream(batches.get(0)).map(FE::new).toArray(FE[]::new);
            setField(resp, org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransactionResponse.class, "results", res);
            setField(resp, Trans2FindFirst2Response.class, "sid", 42);
            setField(resp, Trans2FindFirst2Response.class, "resumeKey", 100);
            setField(resp, Trans2FindFirst2Response.class, "lastName", "b");
            setField(resp, org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransactionResponse.class, "status", 0);
            resp.received();
            return resp;
        });

        // For Trans2FindNext2 calls
        final int[] nextCall = { 0 };
        when(tree.send(any(Trans2FindNext2.class), any(Trans2FindFirst2Response.class))).thenAnswer((InvocationOnMock inv) -> {
            Trans2FindFirst2Response resp = inv.getArgument(1);
            int call = nextCall[0]++;
            String[] names = batches.get(call + 1);
            FE[] res = java.util.Arrays.stream(names).map(FE::new).toArray(FE[]::new);
            setField(resp, org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransactionResponse.class, "results", res);
            if (call == 0) {
                // first next
                setField(resp, Trans2FindFirst2Response.class, "resumeKey", 200);
                setField(resp, Trans2FindFirst2Response.class, "lastName", "c");
                setField(resp, org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransactionResponse.class, "status", 0);
            } else {
                // second next -> no more files
                setField(resp, org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransactionResponse.class, "status",
                        NtStatus.NT_STATUS_NO_MORE_FILES);
                setField(resp, Trans2FindFirst2Response.class, "lastName", null);
            }
            resp.received();
            return resp;
        });

        DirFileEntryEnumIterator1 it = new DirFileEntryEnumIterator1(tree, parent, "*", null, 0);

        // Act & Assert: entries a, b, c (dot entries filtered) then end
        assertTrue(it.hasNext());
        assertEquals("a", it.next().getName());
        assertTrue(it.hasNext());
        assertEquals("b", it.next().getName());
        assertTrue(it.hasNext());
        assertEquals("c", it.next().getName());
        assertFalse(it.hasNext());

        // Verify interactions
        verify(tree, times(1)).send(isA(Trans2FindFirst2.class), any(Trans2FindFirst2Response.class));
        // Verify that Trans2FindNext2 was sent twice for fetching more entries
        verify(tree, times(2)).send(isA(Trans2FindNext2.class), any(Trans2FindFirst2Response.class));

        // Close should have sent FindClose2 exactly once
        ArgumentCaptor<SmbComFindClose2> captor = ArgumentCaptor.forClass(SmbComFindClose2.class);
        verify(tree, times(1)).send(captor.capture(), any());
        assertNotNull(captor.getValue());

        // Tree handle is released after close
        verify(tree, atLeastOnce()).release();
    }

    @Test
    @DisplayName("open(): server returns NO_SUCH_FILE after receiving response -> iterator empty, closed")
    void openHandlesNoSuchFileGracefully() throws Exception {
        when(tree.send(any(Trans2FindFirst2.class), any(Trans2FindFirst2Response.class))).thenAnswer((InvocationOnMock inv) -> {
            Trans2FindFirst2Response resp = inv.getArgument(1);
            resp.received(); // mark as received
            throw new SmbException(NtStatus.NT_STATUS_NO_SUCH_FILE, (Throwable) null);
        });

        DirFileEntryEnumIterator1 it = new DirFileEntryEnumIterator1(tree, parent, "*", null, 0);
        assertFalse(it.hasNext(), "Iterator should be empty when server reports no such file");

        // FindClose2 is sent during cleanup
        verify(tree, times(1)).send(isA(SmbComFindClose2.class), any());
        verify(tree, atLeastOnce()).release();
    }

    @ParameterizedTest
    @ValueSource(strings = { "", " ", "*", "?" })
    @DisplayName("Supports various wildcard values without throwing (edge cases)")
    void wildcardEdgeCases(String wildcard) throws Exception {
        // minimal successful first response with a single entry
        when(tree.send(any(Trans2FindFirst2.class), any(Trans2FindFirst2Response.class))).thenAnswer((InvocationOnMock inv) -> {
            Trans2FindFirst2Response resp = inv.getArgument(1);
            setField(resp, org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransactionResponse.class, "results",
                    new FileEntry[] { new FE("x") });
            setField(resp, Trans2FindFirst2Response.class, "sid", 7);
            setField(resp, org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransactionResponse.class, "status", 0);
            resp.received();
            return resp;
        });

        DirFileEntryEnumIterator1 it = new DirFileEntryEnumIterator1(tree, parent, wildcard, null, 0);
        assertTrue(it.hasNext());
        assertEquals("x", it.next().getName());
    }

    @Test
    @DisplayName("Empty initial results with end-of-search -> closes immediately")
    void emptyInitialResultsEndOfSearchCloses() throws Exception {
        when(tree.send(any(Trans2FindFirst2.class), any(Trans2FindFirst2Response.class))).thenAnswer((InvocationOnMock inv) -> {
            Trans2FindFirst2Response resp = inv.getArgument(1);
            setField(resp, org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransactionResponse.class, "results", new FileEntry[0]);
            setField(resp, Trans2FindFirst2Response.class, "isEndOfSearch", true);
            setField(resp, Trans2FindFirst2Response.class, "sid", 9);
            setField(resp, org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransactionResponse.class, "status", 0);
            resp.received();
            return resp;
        });

        DirFileEntryEnumIterator1 it = new DirFileEntryEnumIterator1(tree, parent, "*", null, 0);
        assertFalse(it.hasNext(), "Iterator should be closed when no results and end-of-search");
        verify(tree, times(1)).send(isA(SmbComFindClose2.class), any());
    }
}