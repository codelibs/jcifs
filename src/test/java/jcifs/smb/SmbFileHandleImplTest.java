package jcifs.smb;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.smb1.com.SmbComBlankResponse;
import jcifs.internal.smb1.com.SmbComClose;
import jcifs.internal.smb2.create.Smb2CloseRequest;

@ExtendWith(MockitoExtension.class)
class SmbFileHandleImplTest {

    @Mock
    Configuration cfg;

    @Mock
    SmbTreeHandleImpl tree;

    private void stubValidTree(long treeId, boolean connected, boolean smb2) {
        lenient().when(tree.acquire()).thenReturn(tree);
        lenient().when(tree.getTreeId()).thenReturn(treeId);
        lenient().when(tree.isConnected()).thenReturn(connected);
        lenient().when(tree.isSMB2()).thenReturn(smb2);
    }

    @Test
    @DisplayName("Constructor with null tree throws NPE (byte[] fid variant)")
    void constructor_nullTree_byteArray_throwsNPE() {
        lenient().when(cfg.isTraceResourceUsage()).thenReturn(false);
        assertThrows(NullPointerException.class, () ->
            new SmbFileHandleImpl(cfg, new byte[] {1,2}, null, "//server/share", 0, 0, 0, 0, 0L)
        );
    }

    @Test
    @DisplayName("Constructor with null cfg throws NPE")
    void constructor_nullCfg_throwsNPE() {
        stubValidTree(7L, true, true);
        assertThrows(NullPointerException.class, () ->
            new SmbFileHandleImpl(null, 42, tree, "//server/share", 0, 0, 0, 0, 0L)
        );
    }

    @Test
    @DisplayName("getTree() acquires and returns same tree instance")
    void getTree_acquiresAndReturnsTree() {
        when(cfg.isTraceResourceUsage()).thenReturn(false);
        stubValidTree(7L, true, true);

        SmbFileHandleImpl h = new SmbFileHandleImpl(cfg, 123, tree, "//server/share", 0, 0, 0, 0, 0L);

        SmbTreeHandleImpl t1 = h.getTree();
        SmbTreeHandleImpl t2 = h.getTree();

        assertSame(tree, t1, "Expected same mocked tree");
        assertSame(tree, t2, "Expected same mocked tree");

        // acquire is called once in ctor + once per getTree() call
        verify(tree, times(3)).acquire();
    }

    @Test
    @DisplayName("isValid() true when open, same tree id, connected")
    void isValid_true_whenOpenSameTreeConnected() {
        when(cfg.isTraceResourceUsage()).thenReturn(false);
        stubValidTree(99L, true, true);
        SmbFileHandleImpl h = new SmbFileHandleImpl(cfg, 1, tree, "//server/share", 0, 0, 0, 0, 0L);
        assertTrue(h.isValid());
    }

    @Test
    @DisplayName("isValid() false when tree id changed or disconnected or closed")
    void isValid_false_inVariousCases() {
        when(cfg.isTraceResourceUsage()).thenReturn(false);
        stubValidTree(10L, true, true);
        SmbFileHandleImpl h = new SmbFileHandleImpl(cfg, new byte[]{0x01}, tree, "//x", 0, 0, 0, 0, 0L);

        assertTrue(h.isValid());

        // Tree id change makes it invalid
        when(tree.getTreeId()).thenReturn(11L);
        assertFalse(h.isValid());

        // Connected=false makes it invalid
        when(tree.getTreeId()).thenReturn(10L);
        when(tree.isConnected()).thenReturn(false);
        assertFalse(h.isValid());

        // Mark closed makes it invalid
        when(tree.isConnected()).thenReturn(true);
        assertTrue(h.isValid());
        h.markClosed();
        assertFalse(h.isValid());
    }

    @Test
    @DisplayName("getFid/getFileId throw SmbException when invalid")
    void getters_throw_whenInvalid() {
        when(cfg.isTraceResourceUsage()).thenReturn(false);
        stubValidTree(1L, true, true);
        SmbFileHandleImpl h = new SmbFileHandleImpl(cfg, new byte[]{0x01, 0x02}, tree, "//x", 0, 0, 0, 0, 0L);
        // invalidate
        h.markClosed();

        SmbException ex1 = assertThrows(SmbException.class, h::getFid);
        assertEquals("Descriptor is no longer valid", ex1.getMessage());
        SmbException ex2 = assertThrows(SmbException.class, h::getFileId);
        assertEquals("Descriptor is no longer valid", ex2.getMessage());
    }

    @Test
    @DisplayName("close(long) sends SMB2 close request and releases tree when SMB2")
    void close_withLastWrite_smb2_sendsCloseAndReleases() throws CIFSException {
        when(cfg.isTraceResourceUsage()).thenReturn(false);
        stubValidTree(5L, true, true);

        byte[] fileId = new byte[] {0x0A, 0x0B};
        SmbFileHandleImpl h = new SmbFileHandleImpl(cfg, fileId, tree, "//server/share/path", 0x1, 0x2, 0x3, 0x4, 123L);

        h.close(777L);

        // Verify SMB2 close path
        verify(tree, times(1)).send(isA(Smb2CloseRequest.class), eq(RequestParam.NO_RETRY));
        // Tree is always released in finally
        verify(tree, times(1)).release();
    }

    @Test
    @DisplayName("close(long) sends SMB1 close request and releases tree when SMB1")
    void close_withLastWrite_smb1_sendsCloseAndReleases() throws CIFSException {
        when(cfg.isTraceResourceUsage()).thenReturn(false);
        stubValidTree(6L, true, false); // SMB1

        SmbFileHandleImpl h = new SmbFileHandleImpl(cfg, 42, tree, "//s/share", 0xA, 0xB, 0xC, 0xD, 0L);

        long lastWrite = 123456789L;
        h.close(lastWrite);

        // Verify SMB1 close path uses request + response overload
        ArgumentCaptor<CommonServerMessageBlockRequest> reqCap = ArgumentCaptor.forClass(CommonServerMessageBlockRequest.class);
        ArgumentCaptor<SmbComBlankResponse> respCap = ArgumentCaptor.forClass(SmbComBlankResponse.class);
        verify(tree, times(1)).send(reqCap.capture(), respCap.capture(), eq(RequestParam.NO_RETRY));
        assertTrue(reqCap.getValue() instanceof SmbComClose, "Expected SmbComClose request");
        assertNotNull(respCap.getValue(), "Expected SmbComBlankResponse");

        verify(tree, times(1)).release();
    }

    @Test
    @DisplayName("close() does not send when invalid but still releases")
    void close_invalid_doesNotSend_butReleases() throws CIFSException {
        when(cfg.isTraceResourceUsage()).thenReturn(false);
        stubValidTree(3L, true, true);
        SmbFileHandleImpl h = new SmbFileHandleImpl(cfg, 9, tree, "//x", 0, 0, 0, 0, 0L);

        // Make invalid beforehand
        when(tree.isConnected()).thenReturn(false);
        h.close();

        verify(tree, never()).send(isA(Smb2CloseRequest.class), any());
        verify(tree, never()).send(any(CommonServerMessageBlockRequest.class), any(SmbComBlankResponse.class), any(RequestParam[].class));
        verify(tree, times(1)).release();
    }

    @Test
    @DisplayName("release() decrements usage; closes only when count reaches zero")
    void release_decrementsAndClosesOnZero() throws CIFSException {
        when(cfg.isTraceResourceUsage()).thenReturn(false);
        stubValidTree(8L, true, true);

        SmbFileHandleImpl h = new SmbFileHandleImpl(cfg, new byte[]{1,2,3}, tree, "//srv/share", 0, 0, 0, 0, 0L);

        // Increase usage to 2
        h.acquire();

        // First release: should not close yet
        h.release();
        verify(tree, never()).send(isA(Smb2CloseRequest.class), any());
        verify(tree, never()).send(any(CommonServerMessageBlockRequest.class), any(SmbComBlankResponse.class), any(RequestParam[].class));

        // Second release: should close now via SMB2 path
        h.release();
        verify(tree, times(1)).send(isA(Smb2CloseRequest.class), eq(RequestParam.NO_RETRY));
        verify(tree, times(1)).release();
    }

    @Test
    @DisplayName("finalize() logs a warning when not closed (no exception)")
    void finalize_logsWhenNotClosed() throws Throwable {
        when(cfg.isTraceResourceUsage()).thenReturn(true); // exercise backtrace branch
        stubValidTree(2L, true, true);
        SmbFileHandleImpl h = new SmbFileHandleImpl(cfg, 1, tree, "//host/share", 0, 0, 0, 0, 0L);
        // Calling finalize directly to execute the logic; should not throw
        h.finalize();
    }

    @Test
    @DisplayName("toString() contains UNC and id representation")
    void toString_containsExpected() {
        when(cfg.isTraceResourceUsage()).thenReturn(false);
        stubValidTree(1L, true, true);

        byte[] fidBytes = new byte[] {0x01, 0x02};
        SmbFileHandleImpl h1 = new SmbFileHandleImpl(cfg, fidBytes, tree, "//u/one", 0x10, 0x20, 0x30, 0x40, 0L);
        String s1 = h1.toString();
        assertTrue(s1.contains("//u/one"));
        assertTrue(s1.contains("0102"), "Expected hex fileId in string");

        SmbFileHandleImpl h2 = new SmbFileHandleImpl(cfg, 77, tree, "//u/two", -1, -2, -3, -4, 0L);
        String s2 = h2.toString();
        assertTrue(s2.contains("//u/two"));
        assertTrue(s2.contains("77"), "Expected numeric fid in string");
    }

    static Stream<Arguments> equalsHashParams() {
        return Stream.of(
            // byte[] id based equality (same id and tree id)
            Arguments.of(new byte[]{0x0A, 0x0B}, new byte[]{0x0A, 0x0B}, 100L, true),
            // fid based equality (null fileId, same fid and tree id)
            Arguments.of(null, null, 200L, true)
        );
    }

    @ParameterizedTest(name = "equals/hashCode consistent for treeId={2}")
    @MethodSource("equalsHashParams")
    void equalsAndHashCode_consistency(byte[] id1, byte[] id2, long treeId, boolean expectEqual) {
        lenient().when(cfg.isTraceResourceUsage()).thenReturn(false);

        // Prepare two separate tree mocks but with same tree id
        SmbTreeHandleImpl tA = mock(SmbTreeHandleImpl.class);
        SmbTreeHandleImpl tB = mock(SmbTreeHandleImpl.class);
        lenient().when(tA.acquire()).thenReturn(tA);
        lenient().when(tB.acquire()).thenReturn(tB);
        lenient().when(tA.getTreeId()).thenReturn(treeId);
        lenient().when(tB.getTreeId()).thenReturn(treeId);
        lenient().when(tA.isConnected()).thenReturn(true);
        lenient().when(tB.isConnected()).thenReturn(true);

        SmbFileHandleImpl hA = id1 != null
            ? new SmbFileHandleImpl(cfg, id1, tA, "//eq/a", 0, 0, 0, 0, 0L)
            : new SmbFileHandleImpl(cfg, 33, tA, "//eq/a", 0, 0, 0, 0, 0L);

        SmbFileHandleImpl hB = id2 != null
            ? new SmbFileHandleImpl(cfg, id2, tB, "//eq/b", 0, 0, 0, 0, 0L)
            : new SmbFileHandleImpl(cfg, 33, tB, "//eq/b", 0, 0, 0, 0, 0L);

        if (expectEqual) {
            assertEquals(hA, hB);
            assertEquals(hA.hashCode(), hB.hashCode());
        } else {
            assertNotEquals(hA, hB);
        }

        // Test negative case with different tree id handles
        SmbTreeHandleImpl tC = mock(SmbTreeHandleImpl.class);
        lenient().when(tC.acquire()).thenReturn(tC);
        lenient().when(tC.getTreeId()).thenReturn(treeId + 1);
        lenient().when(tC.isConnected()).thenReturn(true);
        
        SmbFileHandleImpl hC = id2 != null
            ? new SmbFileHandleImpl(cfg, id2, tC, "//eq/c", 0, 0, 0, 0, 0L)
            : new SmbFileHandleImpl(cfg, 33, tC, "//eq/c", 0, 0, 0, 0, 0L);
        
        assertNotEquals(hA, hC);
    }

    @Test
    @DisplayName("getInitialSize returns constructor value")
    void getInitialSize_returnsValue() {
        when(cfg.isTraceResourceUsage()).thenReturn(false);
        stubValidTree(1L, true, true);
        SmbFileHandleImpl h = new SmbFileHandleImpl(cfg, 1, tree, "//size", 0, 0, 0, 0, 987654321L);
        assertEquals(987654321L, h.getInitialSize());
    }
}
