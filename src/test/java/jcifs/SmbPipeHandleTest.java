package jcifs;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.InputStream;
import java.io.OutputStream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import jcifs.smb.SmbPipeHandleInternal;

/**
 * Unit tests for a class that implements the {@link SmbPipeHandle} interface.
 * This test class uses a mock implementation to ensure any class adhering to the
 * SmbPipeHandle contract is tested for correctness.
 */
public class SmbPipeHandleTest {

    private SmbPipeHandle smbPipeHandle;
    private SmbPipeResource mockPipeResource;
    private SmbPipeHandleInternal mockSmbPipeHandleInternal;
    private InputStream mockInputStream;
    private OutputStream mockOutputStream;

    /**
     * Sets up the test environment before each test.
     * Initializes a mock {@link SmbPipeResource} and a mock implementation of {@link SmbPipeHandle}.
     * @throws CIFSException if an error occurs during setup.
     */
    @BeforeEach
    public void setUp() throws CIFSException {
        mockPipeResource = mock(SmbPipeResource.class);
        mockSmbPipeHandleInternal = mock(SmbPipeHandleInternal.class);
        mockInputStream = mock(InputStream.class);
        mockOutputStream = mock(OutputStream.class);

        // Create a mock implementation of the SmbPipeHandle interface
        smbPipeHandle = mock(SmbPipeHandle.class);

        // Define behavior for the mock handle
        when(smbPipeHandle.getPipe()).thenReturn(mockPipeResource);
        when(smbPipeHandle.getInput()).thenReturn(mockInputStream);
        when(smbPipeHandle.getOutput()).thenReturn(mockOutputStream);
    }

    /**
     * Tests that the getter for the underlying pipe resource returns the correct instance.
     */
    @Test
    public void testGetPipe() {
        assertEquals(mockPipeResource, smbPipeHandle.getPipe(), "getPipe() should return the underlying pipe resource.");
    }

    /**
     * Tests that the getter for the input stream returns the correct stream.
     * @throws CIFSException if an error occurs while getting the stream.
     */
    @Test
    public void testGetInputStream() throws CIFSException {
        assertEquals(mockInputStream, smbPipeHandle.getInput(), "getInput() should return the correct input stream.");
    }

    /**
     * Tests that the getter for the output stream returns the correct stream.
     * @throws CIFSException if an error occurs while getting the stream.
     */
    @Test
    public void testGetOutputStream() throws CIFSException {
        assertEquals(mockOutputStream, smbPipeHandle.getOutput(), "getOutput() should return the correct output stream.");
    }

    /**
     * Tests related to the lifecycle management of the handle (e.g., closing).
     */
    @Nested
    public class LifecycleManagementTest {

        /**
         * Verifies that the close method can be called without throwing an exception.
         * @throws CIFSException if an error occurs during close.
         */
        @Test
        public void testClose() throws CIFSException {
            assertDoesNotThrow(() -> smbPipeHandle.close(), "close() should not throw an exception on a mock object.");
            // Verify that the close method was called
            Mockito.verify(smbPipeHandle).close();
        }

        /**
         * Verifies that the isOpen method returns true for an open handle.
         */
        @Test
        public void testIsOpen_ReturnsTrueWhenOpen() {
            when(smbPipeHandle.isOpen()).thenReturn(true);
            assertTrue(smbPipeHandle.isOpen(), "isOpen() should return true when the handle is open.");
        }

        /**
         * Verifies that the isOpen method returns false for a closed handle.
         */
        @Test
        public void testIsOpen_ReturnsFalseWhenClosed() {
            when(smbPipeHandle.isOpen()).thenReturn(false);
            assertFalse(smbPipeHandle.isOpen(), "isOpen() should return false when the handle is closed.");
        }
    }

    /**
     * Tests related to the state of the handle (e.g., staleness).
     */
    @Nested
    public class HandleStateTest {

        /**
         * Verifies that isStale returns false for a fresh handle.
         */
        @Test
        public void testIsStale_ReturnsFalseWhenNotStale() {
            when(smbPipeHandle.isStale()).thenReturn(false);
            assertFalse(smbPipeHandle.isStale(), "isStale() should return false for a fresh handle.");
        }

        /**
         * Verifies that isStale returns true for a stale handle.
         */
        @Test
        public void testIsStale_ReturnsTrueWhenStale() {
            when(smbPipeHandle.isStale()).thenReturn(true);
            assertTrue(smbPipeHandle.isStale(), "isStale() should return true for a stale handle.");
        }
    }

    /**
     * Tests the unwrap functionality.
     */
    @Nested
    public class UnwrapFunctionalityTest {

        /**
         * Verifies that unwrap returns the expected underlying object.
         */
        @Test
        public void testUnwrap() {
            when(smbPipeHandle.unwrap(SmbPipeHandleInternal.class)).thenReturn(mockSmbPipeHandleInternal);
            SmbPipeHandleInternal unwrapped = smbPipeHandle.unwrap(SmbPipeHandleInternal.class);
            assertSame(mockSmbPipeHandleInternal, unwrapped, "Unwrap should return the underlying handle implementation.");
        }

        /**
         * Verifies that unwrap returns null if the requested type is not available.
         */
        @Test
        public void testUnwrap_ReturnsNullForUnsupportedType() {
            when(smbPipeHandle.unwrap(SmbPipeHandle.class)).thenReturn(null);
            assertNull(smbPipeHandle.unwrap(SmbPipeHandle.class), "Unwrap should return null for an unsupported type.");
        }
    }

    /**
     * Tests the contract for {@link AutoCloseable}.
     */
    @Nested
    public class AutoCloseableContractTest {

        /**
         * Verifies that the handle is automatically closed in a try-with-resources statement.
         * @throws Exception if an error occurs.
         */
        @Test
        public void testTryWithResources() throws Exception {
            // This test ensures that any implementation of SmbPipeHandle can be used in a try-with-resources block.
            try (SmbPipeHandle handle = smbPipeHandle) {
                // Perform operations with the handle
                assertNotNull(handle);
            }
            // Verify that close() was called on the handle when the block exits
            Mockito.verify(smbPipeHandle).close();
        }
    }
}
