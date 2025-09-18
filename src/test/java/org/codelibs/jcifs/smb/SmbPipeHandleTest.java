package org.codelibs.jcifs.smb;

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

import org.codelibs.jcifs.smb.impl.SmbPipeHandleInternal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

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

    @Test
    @DisplayName("Verify getPipe returns the correct underlying pipe resource")
    public void shouldReturnCorrectPipeResource() {
        assertEquals(mockPipeResource, smbPipeHandle.getPipe(), "getPipe() should return the underlying pipe resource.");
    }

    @Test
    @DisplayName("Verify getInput returns the correct input stream")
    public void shouldReturnCorrectInputStream() throws CIFSException {
        assertEquals(mockInputStream, smbPipeHandle.getInput(), "getInput() should return the correct input stream.");
    }

    @Test
    @DisplayName("Verify getOutput returns the correct output stream")
    public void shouldReturnCorrectOutputStream() throws CIFSException {
        assertEquals(mockOutputStream, smbPipeHandle.getOutput(), "getOutput() should return the correct output stream.");
    }

    /**
     * Tests related to the lifecycle management of the handle (e.g., closing).
     */
    @Nested
    public class LifecycleManagementTest {

        @Test
        @DisplayName("Verify close method can be called without throwing exception")
        public void shouldCloseWithoutException() throws CIFSException {
            assertDoesNotThrow(() -> smbPipeHandle.close(), "close() should not throw an exception on a mock object.");
            // Verify that the close method was called
            Mockito.verify(smbPipeHandle).close();
        }

        @Test
        @DisplayName("Verify isOpen returns true when handle is open")
        public void shouldReturnTrueWhenOpen() {
            when(smbPipeHandle.isOpen()).thenReturn(true);
            assertTrue(smbPipeHandle.isOpen(), "isOpen() should return true when the handle is open.");
        }

        @Test
        @DisplayName("Verify isOpen returns false when handle is closed")
        public void shouldReturnFalseWhenClosed() {
            when(smbPipeHandle.isOpen()).thenReturn(false);
            assertFalse(smbPipeHandle.isOpen(), "isOpen() should return false when the handle is closed.");
        }
    }

    /**
     * Tests related to the state of the handle (e.g., staleness).
     */
    @Nested
    public class HandleStateTest {

        @Test
        @DisplayName("Verify isStale returns false for fresh handle")
        public void shouldReturnFalseWhenNotStale() {
            when(smbPipeHandle.isStale()).thenReturn(false);
            assertFalse(smbPipeHandle.isStale(), "isStale() should return false for a fresh handle.");
        }

        @Test
        @DisplayName("Verify isStale returns true for stale handle")
        public void shouldReturnTrueWhenStale() {
            when(smbPipeHandle.isStale()).thenReturn(true);
            assertTrue(smbPipeHandle.isStale(), "isStale() should return true for a stale handle.");
        }
    }

    /**
     * Tests the unwrap functionality.
     */
    @Nested
    public class UnwrapFunctionalityTest {

        @Test
        @DisplayName("Verify unwrap returns expected underlying object")
        public void shouldUnwrapToExpectedType() {
            when(smbPipeHandle.unwrap(SmbPipeHandleInternal.class)).thenReturn(mockSmbPipeHandleInternal);
            SmbPipeHandleInternal unwrapped = smbPipeHandle.unwrap(SmbPipeHandleInternal.class);
            assertSame(mockSmbPipeHandleInternal, unwrapped, "Unwrap should return the underlying handle implementation.");
        }

        @Test
        @DisplayName("Verify unwrap returns null for unsupported type")
        public void shouldReturnNullForUnsupportedType() {
            when(smbPipeHandle.unwrap(SmbPipeHandle.class)).thenReturn(null);
            assertNull(smbPipeHandle.unwrap(SmbPipeHandle.class), "Unwrap should return null for an unsupported type.");
        }
    }

    /**
     * Tests the contract for {@link AutoCloseable}.
     */
    @Nested
    public class AutoCloseableContractTest {

        @Test
        @DisplayName("Verify handle is automatically closed in try-with-resources")
        public void shouldAutoCloseInTryWithResources() throws Exception {
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
