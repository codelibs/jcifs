package jcifs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for the {@link SmbFileHandle} interface.
 */
@ExtendWith(MockitoExtension.class)
class SmbFileHandleTest {

    @Mock
    private SmbFileHandle smbFileHandle;

    @Mock
    private SmbTreeHandle smbTreeHandle;

    @BeforeEach
    void setUp() throws CIFSException {
        // Reset mock before each test if necessary, though MockitoExtension does this.
    }

    /**
     * Test that getTree() returns the correct SmbTreeHandle.
     */
    @Test
    void testGetTree() {
        when(smbFileHandle.getTree()).thenReturn(smbTreeHandle);
        SmbTreeHandle result = smbFileHandle.getTree();
        assertEquals(smbTreeHandle, result, "getTree should return the mocked SmbTreeHandle.");
        verify(smbFileHandle, times(1)).getTree();
    }

    /**
     * Test isValid() when the handle is valid.
     */
    @Test
    void testIsValid_whenValid() {
        when(smbFileHandle.isValid()).thenReturn(true);
        assertTrue(smbFileHandle.isValid(), "isValid should return true when the handle is valid.");
        verify(smbFileHandle, times(1)).isValid();
    }

    /**
     * Test isValid() when the handle is invalid.
     */
    @Test
    void testIsValid_whenInvalid() {
        when(smbFileHandle.isValid()).thenReturn(false);
        assertFalse(smbFileHandle.isValid(), "isValid should return false when the handle is invalid.");
        verify(smbFileHandle, times(1)).isValid();
    }

    /**
     * Test close(long) successfully.
     *
     * @throws CIFSException
     */
    @Test
    void testCloseWithLastWriteTime_success() throws CIFSException {
        long lastWriteTime = System.currentTimeMillis();
        smbFileHandle.close(lastWriteTime);
        verify(smbFileHandle, times(1)).close(lastWriteTime);
    }

    /**
     * Test close(long) when a CIFSException is thrown.
     *
     * @throws CIFSException
     */
    @Test
    void testCloseWithLastWriteTime_throwsCIFSException() throws CIFSException {
        long lastWriteTime = System.currentTimeMillis();
        doThrow(new CIFSException("Failed to close")).when(smbFileHandle).close(lastWriteTime);
        assertThrows(CIFSException.class, () -> smbFileHandle.close(lastWriteTime),
                "close(long) should throw CIFSException when closing fails.");
        verify(smbFileHandle, times(1)).close(lastWriteTime);
    }

    /**
     * Test close() successfully.
     *
     * @throws CIFSException
     */
    @Test
    void testClose_success() throws CIFSException {
        smbFileHandle.close();
        verify(smbFileHandle, times(1)).close();
    }

    /**
     * Test close() when a CIFSException is thrown.
     *
     * @throws CIFSException
     */
    @Test
    void testClose_throwsCIFSException() throws CIFSException {
        doThrow(new CIFSException("Failed to close")).when(smbFileHandle).close();
        assertThrows(CIFSException.class, () -> smbFileHandle.close(), "close() should throw CIFSException when closing fails.");
        verify(smbFileHandle, times(1)).close();
    }

    /**
     * Test release() successfully.
     *
     * @throws CIFSException
     */
    @Test
    void testRelease_success() throws CIFSException {
        smbFileHandle.release();
        verify(smbFileHandle, times(1)).release();
    }

    /**
     * Test release() when a CIFSException is thrown.
     *
     * @throws CIFSException
     */
    @Test
    void testRelease_throwsCIFSException() throws CIFSException {
        doThrow(new CIFSException("Failed to release")).when(smbFileHandle).release();
        assertThrows(CIFSException.class, () -> smbFileHandle.release(), "release() should throw CIFSException when releasing fails.");
        verify(smbFileHandle, times(1)).release();
    }

    /**
     * Test getInitialSize() returns the correct size.
     */
    @Test
    void testGetInitialSize() {
        long expectedSize = 1024L;
        when(smbFileHandle.getInitialSize()).thenReturn(expectedSize);
        long actualSize = smbFileHandle.getInitialSize();
        assertEquals(expectedSize, actualSize, "getInitialSize should return the correct initial file size.");
        verify(smbFileHandle, times(1)).getInitialSize();
    }

    /**
     * Test getInitialSize() when the size is zero.
     */
    @Test
    void testGetInitialSize_zero() {
        long expectedSize = 0L;
        when(smbFileHandle.getInitialSize()).thenReturn(expectedSize);
        long actualSize = smbFileHandle.getInitialSize();
        assertEquals(expectedSize, actualSize, "getInitialSize should return 0 for an empty file.");
        verify(smbFileHandle, times(1)).getInitialSize();
    }
}
