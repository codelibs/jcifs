package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class SmbCopyUtilTest {

    // --- Tests for openCopyTargetFile ---

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    @DisplayName("openCopyTargetFile sets correct access flags depending on alsoRead")
    void openCopyTargetFile_accessMask_respectsAlsoRead(boolean alsoRead) throws Exception {
        // Arrange
        SmbFile dest = mock(SmbFile.class);
        SmbFileHandleImpl handle = mock(SmbFileHandleImpl.class);
        when(dest.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenReturn(handle);

        int attrs = SmbConstants.ATTR_NORMAL;

        // Act
        SmbFileHandleImpl result = SmbCopyUtil.openCopyTargetFile(dest, attrs, alsoRead);

        // Assert
        assertSame(handle, result, "Should return handle from dest.openUnshared");

        ArgumentCaptor<Integer> accessCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(dest, times(1)).openUnshared(anyInt(), accessCaptor.capture(), anyInt(), eq(attrs), anyInt());
        int access = accessCaptor.getValue();
        boolean hasReadData = (access & SmbConstants.FILE_READ_DATA) != 0;
        assertEquals(alsoRead, hasReadData, "FILE_READ_DATA flag presence should match alsoRead");
    }

    @Test
    @DisplayName("openCopyTargetFile retries after removing READONLY and succeeds")
    void openCopyTargetFile_retryOnReadonly_thenSuccess() throws Exception {
        // Arrange
        SmbFile dest = mock(SmbFile.class);
        SmbFileHandleImpl handle = mock(SmbFileHandleImpl.class);
        SmbAuthException authEx = new SmbAuthException("denied");

        when(dest.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenThrow(authEx) // first attempt fails with auth
                .thenReturn(handle); // second attempt succeeds

        // dest currently has READONLY attribute set
        int currentAttrs = SmbConstants.ATTR_READONLY | SmbConstants.ATTR_ARCHIVE;
        when(dest.getAttributes()).thenReturn(currentAttrs);

        int desiredAttrs = SmbConstants.ATTR_NORMAL;

        // Act
        SmbFileHandleImpl result = SmbCopyUtil.openCopyTargetFile(dest, desiredAttrs, false);

        // Assert
        assertSame(handle, result, "Should return handle after retry");
        // Verify we removed READONLY on the path before retrying
        verify(dest).setPathInformation(currentAttrs & ~SmbConstants.ATTR_READONLY, 0L, 0L, 0L);
        verify(dest, times(2)).openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt());
    }

    @Test
    @DisplayName("openCopyTargetFile rethrows when not READONLY")
    void openCopyTargetFile_rethrowsWhenNotReadonly() throws Exception {
        // Arrange
        SmbFile dest = mock(SmbFile.class);
        SmbAuthException authEx = new SmbAuthException("denied");
        when(dest.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenThrow(authEx);
        when(dest.getAttributes()).thenReturn(SmbConstants.ATTR_ARCHIVE); // no READONLY bit

        // Act + Assert
        SmbAuthException thrown =
                assertThrows(SmbAuthException.class, () -> SmbCopyUtil.openCopyTargetFile(dest, SmbConstants.ATTR_NORMAL, false));
        assertSame(authEx, thrown, "Should rethrow the same SmbAuthException instance");
        verify(dest, times(1)).getAttributes();
        verify(dest, never()).setPathInformation(anyInt(), anyLong(), anyLong(), anyLong());
    }

    @Test
    @DisplayName("openCopyTargetFile throws NPE on null dest (invalid input)")
    void openCopyTargetFile_nullDest_throwsNPE() {
        // Arrange
        SmbFile dest = null;

        // Act + Assert
        assertThrows(NullPointerException.class, () -> SmbCopyUtil.openCopyTargetFile(dest, SmbConstants.ATTR_NORMAL, false));
    }

    // --- Tests for copyFile exception handling branch ---

    @Nested
    class CopyFileExceptions {

        private SmbTreeHandleImpl newTreeHandle(boolean isSmb2) throws Exception {
            SmbTreeHandleImpl th = mock(SmbTreeHandleImpl.class);
            lenient().when(th.isSMB2()).thenReturn(isSmb2);
            return th;
        }

        private CIFSContext ctxWithIgnore(boolean ignore) {
            CIFSContext ctx = mock(CIFSContext.class);
            Configuration cfg = mock(Configuration.class);
            when(cfg.isIgnoreCopyToException()).thenReturn(ignore);
            when(ctx.getConfig()).thenReturn(cfg);
            return ctx;
        }

        @Test
        @DisplayName("copyFile wraps and throws when ignoreCopyToException=false")
        void copyFile_throwsWhenIgnoreFalse() throws Exception {
            // Arrange
            SmbFile src = mock(SmbFile.class, RETURNS_DEEP_STUBS);
            SmbFile dest = mock(SmbFile.class);
            CIFSContext ctx = ctxWithIgnore(false);
            when(src.getContext()).thenReturn(ctx);

            // Force failure before any stream construction
            when(src.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenThrow(new SmbException("boom"));

            SmbTreeHandleImpl sh = newTreeHandle(false); // force non-SMB2 path to avoid server-side branch
            SmbTreeHandleImpl dh = newTreeHandle(false);

            byte[][] buffers = new byte[][] { new byte[8], new byte[8] };

            when(src.toString()).thenReturn("smb://src");
            when(dest.toString()).thenReturn("smb://dest");

            // Act + Assert
            SmbException ex =
                    assertThrows(SmbException.class, () -> SmbCopyUtil.copyFile(src, dest, buffers, 8, new WriterThread(), sh, dh));
            assertTrue(ex.getMessage().contains("smb://src"));
            assertTrue(ex.getMessage().contains("smb://dest"));
        }

        @Test
        @DisplayName("copyFile swallows when ignoreCopyToException=true")
        void copyFile_swallowsWhenIgnoreTrue() throws Exception {
            // Arrange
            SmbFile src = mock(SmbFile.class, RETURNS_DEEP_STUBS);
            SmbFile dest = mock(SmbFile.class);
            CIFSContext ctx = ctxWithIgnore(true);
            when(src.getContext()).thenReturn(ctx);
            when(src.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenThrow(new SmbException("boom"));

            SmbTreeHandleImpl sh = newTreeHandle(false);
            SmbTreeHandleImpl dh = newTreeHandle(false);

            byte[][] buffers = new byte[][] { new byte[8], new byte[8] };

            // Act + Assert (no exception)
            assertDoesNotThrow(() -> SmbCopyUtil.copyFile(src, dest, buffers, 8, new WriterThread(), sh, dh));
        }
    }

    // --- Server-side copy path (SMB2 + same tree) for zero-length files ---

    @Test
    @DisplayName("copyFile uses server-side copy for zero-length and returns")
    void copyFile_serverSide_zeroLength_happyPath() throws Exception {
        // Arrange
        SmbFile src = mock(SmbFile.class);
        SmbFile dest = mock(SmbFile.class);

        SmbTreeHandleImpl sh = mock(SmbTreeHandleImpl.class);
        SmbTreeHandleImpl dh = mock(SmbTreeHandleImpl.class);
        when(sh.isSMB2()).thenReturn(true);
        when(dh.isSMB2()).thenReturn(true);
        when(sh.isSameTree(dh)).thenReturn(true);

        // Source open returns a handle that reports size 0
        SmbFileHandleImpl sfd = mock(SmbFileHandleImpl.class);
        when(sfd.getInitialSize()).thenReturn(0L);
        when(src.openUnshared(eq(0), eq(SmbConstants.O_RDONLY), eq(SmbConstants.FILE_SHARE_READ), eq(SmbConstants.ATTR_NORMAL), eq(0)))
                .thenReturn(sfd);

        // openCopyTargetFile should be called by serverSideCopy, so dest.openUnshared must succeed
        SmbFileHandleImpl dfd = mock(SmbFileHandleImpl.class);
        when(dest.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenReturn(dfd);
        when(src.getAttributes()).thenReturn(SmbConstants.ATTR_NORMAL);

        byte[][] buffers = new byte[][] { new byte[1], new byte[1] };

        // Act + Assert (no exception expected)
        assertDoesNotThrow(() -> SmbCopyUtil.copyFile(src, dest, buffers, 1, new WriterThread(), sh, dh));

        // Verify that server-side path engaged at least the initial opens
        verify(src, times(1)).openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt());
        verify(dest, times(1)).openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt());
    }

    // --- WriterThread behavior ---

    @Test
    @DisplayName("WriterThread writes provided buffer and stops on -1")
    void writerThread_writes_and_stops() throws Exception {
        // Arrange
        WriterThread w = new WriterThread();
        SmbFileOutputStream out = mock(SmbFileOutputStream.class);
        byte[] payload = new byte[] { 1, 2, 3, 4 };

        w.start();

        // Wait until writer thread signals readiness
        synchronized (w) {
            long deadline = System.currentTimeMillis() + 2000;
            while (!w.isReady() && System.currentTimeMillis() < deadline) {
                w.wait(10);
            }
            assertTrue(w.isReady(), "WriterThread should be ready to accept work");

            // Act: submit a write
            w.write(payload, 3, out);
        }

        // Assert: verify the underlying stream was called
        verify(out, timeout(1000)).write(payload, 0, 3);

        // Stop the thread by sending n = -1
        synchronized (w) {
            w.write(new byte[0], -1, out);
        }

        w.join(2000);
        assertFalse(w.isAlive(), "WriterThread should stop after -1 sentinel");
    }

    @Test
    @DisplayName("WriterThread surfaces SmbSystemException via checkException")
    void writerThread_propagates_exception() throws Exception {
        // Arrange
        WriterThread w = new WriterThread();
        SmbFileOutputStream out = mock(SmbFileOutputStream.class);
        byte[] payload = new byte[] { 9, 8, 7 };

        doThrow(new SmbException("fail")).when(out).write(any(byte[].class), anyInt(), anyInt());

        w.start();

        // Wait until writer thread is ready
        synchronized (w) {
            long deadline = System.currentTimeMillis() + 2000;
            while (!w.isReady() && System.currentTimeMillis() < deadline) {
                w.wait(10);
            }
            assertTrue(w.isReady(), "WriterThread should be ready");

            // Submit a write that will throw inside the writer thread
            w.write(payload, payload.length, out);

            // Give the writer thread time to process and set exception
            w.wait(100);
        }

        // Wait a bit more to ensure exception is captured
        Thread.sleep(100);

        // Act + Assert: checkException should throw the SmbSystemException captured by the thread
        assertThrows(SmbException.class, w::checkException);

        // Stop the thread
        synchronized (w) {
            w.write(new byte[0], -1, out);
        }
        w.join(2000);
    }
}
