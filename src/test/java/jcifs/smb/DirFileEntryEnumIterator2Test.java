package jcifs.smb;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.ResourceNameFilter;
import jcifs.SmbResource;
import jcifs.SmbResourceLocator;
import jcifs.smb.SmbException;
import jcifs.smb.NtStatus;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.CommonServerMessageBlockResponse;
import jcifs.internal.Request;
import jcifs.internal.smb2.create.Smb2CloseRequest;
import jcifs.internal.smb2.create.Smb2CreateRequest;
import jcifs.internal.smb2.create.Smb2CreateResponse;
import jcifs.internal.smb2.info.Smb2QueryDirectoryRequest;
import jcifs.internal.smb2.info.Smb2QueryDirectoryResponse;

@ExtendWith(MockitoExtension.class)
class DirFileEntryEnumIterator2Test {

    @Mock
    private SmbTreeHandleImpl tree;

    @Mock
    private SmbResource parent;

    @Mock
    private SmbResourceLocator locator;

    @Mock
    private Configuration config;

    @Mock
    private CIFSContext cifsContext;

    @BeforeEach
    void setup() {
        // Tree handle lifecycle and config
        lenient().when(tree.acquire()).thenReturn(tree);
        lenient().when(tree.isConnected()).thenReturn(true);
        
        // CIFS context returns same config to build responses during initResponse
        lenient().when(cifsContext.getConfig()).thenReturn(config);
    }

    @AfterEach
    void teardown() {
        // No global state to reset beyond mocks
    }

    static Stream<String> wildcardProvider() {
        return Stream.of(null, "", "*");
    }

    @ParameterizedTest
    @MethodSource("wildcardProvider")
    @DisplayName("open() happy path: yields entries and closes with Smb2CloseRequest on close()")
    void happyPath_enumerates_and_closes(String wildcard) throws Exception {
        // Setup required for this test
        when(parent.getLocator()).thenReturn(locator);
        when(locator.getUNCPath()).thenReturn("\\\\server\\share\\dir\\");
        when(tree.getConfig()).thenReturn(config);
        when(config.getMaximumBufferSize()).thenReturn(65535);
        when(config.getListSize()).thenReturn(65535);
        
        // Arrange: initial page with two entries, then one more entry, then no more files
        FileEntry fe1 = mock(FileEntry.class);
        lenient().when(fe1.getName()).thenReturn("file1");
        lenient().when(fe1.getFileIndex()).thenReturn(1);

        FileEntry fe2 = mock(FileEntry.class);
        lenient().when(fe2.getName()).thenReturn("file2");
        when(fe2.getFileIndex()).thenReturn(2);

        FileEntry fe3 = mock(FileEntry.class);
        lenient().when(fe3.getName()).thenReturn("file3");
        when(fe3.getFileIndex()).thenReturn(3);

        // Track query count to handle multiple queries properly
        final int[] queryCount = {0};
        
        // Mock send(create) to wire a query response with fe1, fe2
        doAnswer(inv -> {
            Object arg = inv.getArgument(0);
            if (arg instanceof Smb2CreateRequest) {
                Smb2CreateRequest create = (Smb2CreateRequest) arg;
                // Initialize response chain (also for chained query)
                Smb2CreateResponse cr = create.initResponse(cifsContext);

                // Access chained Smb2QueryDirectoryRequest via reflection
                Smb2QueryDirectoryRequest q = (Smb2QueryDirectoryRequest) getNextOf(create);

                // Provide a query response with two entries
                Smb2QueryDirectoryResponse qr = new Smb2QueryDirectoryResponse(config, Smb2QueryDirectoryRequest.FILE_BOTH_DIRECTORY_INFO);
                setResults(qr, new FileEntry[] { fe1, fe2 });
                q.setResponse(qr);
                return cr;
            }
            if (arg instanceof Smb2QueryDirectoryRequest) {
                queryCount[0]++;
                if (queryCount[0] == 1) {
                    // This is the second page: one more file
                    Smb2QueryDirectoryResponse qr = new Smb2QueryDirectoryResponse(config, Smb2QueryDirectoryRequest.FILE_BOTH_DIRECTORY_INFO);
                    setResults(qr, new FileEntry[] { fe3 });
                    return qr;
                } else {
                    // Third query: no more files
                    throw new SmbException(NtStatus.NT_STATUS_NO_MORE_FILES, false);
                }
            }
            return null;
        }).when(tree).send(any(Request.class));

        // Act: create iterator and enumerate
        DirFileEntryEnumIterator2 it = new DirFileEntryEnumIterator2(tree, parent, wildcard, (ResourceNameFilter) null, 0);

        // Assert: first page
        assertTrue(it.hasNext(), "Iterator should have first element");
        assertSame(fe1, it.next(), "First element must match first page");
        assertTrue(it.hasNext(), "Iterator should have second element");
        assertSame(fe2, it.next(), "Second element must match first page");

        // Next page fetched via fetchMore()
        assertTrue(it.hasNext(), "Iterator should have third element after fetchMore");
        assertSame(fe3, it.next(), "Third element from second page");

        // After last element, hasNext should be false and calling close() should send Smb2CloseRequest once
        assertFalse(it.hasNext(), "Iterator should be exhausted");

        // Close explicitly to exercise doCloseInternal
        it.close();

        // Verify interactions: one create, two additional directory queries (for fetchMore), one close
        verify(tree, times(1)).send(argThat((Request<?> r) -> r instanceof Smb2CreateRequest));
        verify(tree, times(2)).send(argThat((Request<?> r) -> r instanceof Smb2QueryDirectoryRequest));
        verify(tree, times(1)).send(argThat((Request<?> r) -> r instanceof Smb2CloseRequest));
    }

    @Test
    @DisplayName("fetchMore() handles NT_STATUS_NO_MORE_FILES via exception")
    void fetchMore_handles_no_more_files_exception() throws Exception {
        // Setup required for this test
        when(parent.getLocator()).thenReturn(locator);
        when(locator.getUNCPath()).thenReturn("\\\\server\\share\\dir\\");
        when(tree.getConfig()).thenReturn(config);
        when(config.getMaximumBufferSize()).thenReturn(65535);
        when(config.getListSize()).thenReturn(65535);
        
        // Arrange: initial page with one entry; then query throws NO_MORE_FILES
        FileEntry fe1 = mock(FileEntry.class);
        lenient().when(fe1.getName()).thenReturn("file1");
        when(fe1.getFileIndex()).thenReturn(1);

        doAnswer(inv -> {
            Object arg = inv.getArgument(0);
            if (arg instanceof Smb2CreateRequest) {
                Smb2CreateRequest create = (Smb2CreateRequest) arg;
                Smb2CreateResponse cr = create.initResponse(cifsContext);
                Smb2QueryDirectoryRequest q = (Smb2QueryDirectoryRequest) getNextOf(create);
                Smb2QueryDirectoryResponse qr = new Smb2QueryDirectoryResponse(config, Smb2QueryDirectoryRequest.FILE_BOTH_DIRECTORY_INFO);
                setResults(qr, new FileEntry[] { fe1 });
                q.setResponse(qr);
                return cr;
            }
            if (arg instanceof Smb2QueryDirectoryRequest) {
                throw new SmbException(NtStatus.NT_STATUS_NO_MORE_FILES, false);
            }
            return null;
        }).when(tree).send(any(Request.class));

        DirFileEntryEnumIterator2 it = new DirFileEntryEnumIterator2(tree, parent, "*", null, 0);

        // Consume the only element
        assertTrue(it.hasNext());
        assertSame(fe1, it.next());
        // After exception path, iterator should be exhausted
        assertFalse(it.hasNext());

        // Closing should send a single Smb2CloseRequest
        it.close();
        verify(tree).send(argThat((Request<?> r) -> r instanceof Smb2CloseRequest));
    }

    @Test
    @DisplayName("open() gracefully handles NT_STATUS_NO_SUCH_FILE (empty listing)")
    void open_handles_no_such_file_and_yields_empty() throws Exception {
        // Setup required for this test
        when(parent.getLocator()).thenReturn(locator);
        when(locator.getUNCPath()).thenReturn("\\\\server\\share\\dir\\");
        when(tree.getConfig()).thenReturn(config);
        when(config.getMaximumBufferSize()).thenReturn(65535);
        when(config.getListSize()).thenReturn(65535);
        
        // Arrange: create send throws, chained query response indicates NO_SUCH_FILE
        doAnswer(inv -> {
            Object arg = inv.getArgument(0);
            if (arg instanceof Smb2CreateRequest) {
                Smb2CreateRequest create = (Smb2CreateRequest) arg;
                // Initialize response chain so query exists
                create.initResponse(cifsContext);
                Smb2QueryDirectoryRequest q = (Smb2QueryDirectoryRequest) getNextOf(create);
                Smb2QueryDirectoryResponse qr = new Smb2QueryDirectoryResponse(config, Smb2QueryDirectoryRequest.FILE_BOTH_DIRECTORY_INFO);
                // Mark response as received and set status = NT_STATUS_NO_SUCH_FILE
                setStatus(qr, NtStatus.NT_STATUS_NO_SUCH_FILE);
                qr.received();
                q.setResponse(qr);
                // Now emulate error thrown by transport for create chain
                throw new SmbException(NtStatus.NT_STATUS_NO_SUCH_FILE, false);
            }
            return null;
        }).when(tree).send(any(Request.class));

        // Act: constructing the iterator must not throw and results in empty iterator
        DirFileEntryEnumIterator2 it = new DirFileEntryEnumIterator2(tree, parent, "*", null, 0);

        // Assert: enumeration is empty and close produced no extra close call (no fileId opened)
        assertFalse(it.hasNext(), "Empty listing should produce no elements");
        it.close();
        // No close should be sent because directory was never successfully opened
        verify(tree, never()).send(argThat((Request<?> r) -> r instanceof Smb2CloseRequest));
    }

    @Test
    @DisplayName("remove() throws UnsupportedOperationException")
    void remove_throws_unsupported() throws Exception {
        // Setup required for this test
        when(parent.getLocator()).thenReturn(locator);
        when(locator.getUNCPath()).thenReturn("\\\\server\\share\\dir\\");
        when(tree.getConfig()).thenReturn(config);
        when(config.getMaximumBufferSize()).thenReturn(65535);
        when(config.getListSize()).thenReturn(65535);
        
        // Arrange minimal successful open with one entry
        FileEntry fe1 = mock(FileEntry.class);
        lenient().when(fe1.getName()).thenReturn("x");
        when(fe1.getFileIndex()).thenReturn(1);

        doAnswer(inv -> {
            Object arg = inv.getArgument(0);
            if (arg instanceof Smb2CreateRequest) {
                Smb2CreateRequest create = (Smb2CreateRequest) arg;
                Smb2CreateResponse cr = create.initResponse(cifsContext);
                Smb2QueryDirectoryRequest q = (Smb2QueryDirectoryRequest) getNextOf(create);
                Smb2QueryDirectoryResponse qr = new Smb2QueryDirectoryResponse(config, Smb2QueryDirectoryRequest.FILE_BOTH_DIRECTORY_INFO);
                setResults(qr, new FileEntry[] { fe1 });
                q.setResponse(qr);
                return cr;
            }
            if (arg instanceof Smb2QueryDirectoryRequest) {
                // No more files
                Smb2QueryDirectoryResponse qr = new Smb2QueryDirectoryResponse(config, Smb2QueryDirectoryRequest.FILE_BOTH_DIRECTORY_INFO);
                setStatus(qr, NtStatus.NT_STATUS_NO_MORE_FILES);
                return qr;
            }
            return null;
        }).when(tree).send(any());

        DirFileEntryEnumIterator2 it = new DirFileEntryEnumIterator2(tree, parent, "*", null, 0);
        assertTrue(it.hasNext());
        // Act + Assert
        assertThrows(UnsupportedOperationException.class, it::remove);
        // Consume and close to keep lifecycle tidy
        it.next();
        it.close();
    }

    // --- Helpers ---

    /**
     * Reflectively get the chained next request from a SMB2 request.
     */
    private static Object getNextOf(Object req) throws Exception {
        Class<?> cls = req.getClass().getSuperclass(); // ServerMessageBlock2Request
        Field f = cls.getSuperclass().getDeclaredField("next"); // ServerMessageBlock2.next
        f.setAccessible(true);
        return f.get(req);
    }

    /**
     * Reflectively set the private 'results' field on Smb2QueryDirectoryResponse.
     */
    private static void setResults(Smb2QueryDirectoryResponse resp, FileEntry[] results) throws Exception {
        Field f = Smb2QueryDirectoryResponse.class.getDeclaredField("results");
        f.setAccessible(true);
        f.set(resp, results);
    }

    /**
     * Reflectively set the 'status' on a SMB2 response to drive control flow.
     */
    private static void setStatus(jcifs.internal.smb2.ServerMessageBlock2Response resp, int status) throws Exception {
        Field f = jcifs.internal.smb2.ServerMessageBlock2.class.getDeclaredField("status");
        f.setAccessible(true);
        f.setInt(resp, status);
    }
}
