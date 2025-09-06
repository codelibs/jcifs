package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SmbPipeOutputStreamTest {

    @Mock
    SmbPipeHandleImpl handle;

    @Mock
    SmbTreeHandleImpl tree;

    @Mock
    SmbNamedPipe pipe;

    @Mock
    SmbFileHandleImpl fileHandle;

    private SmbPipeOutputStream newStream() throws CIFSException {
        // Arrange common constructor collaborators to avoid touching network/state
        when(handle.getPipe()).thenReturn(pipe);
        when(tree.isSMB2()).thenReturn(true);
        when(tree.getSendBufferSize()).thenReturn(4096);
        // Act
        return new SmbPipeOutputStream(handle, tree);
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    @DisplayName("isOpen delegates to handle.isOpen")
    void isOpen_delegates(boolean state) throws Exception {
        // Arrange
        SmbPipeOutputStream out = newStream();
        when(handle.isOpen()).thenReturn(state);

        // Act
        boolean result = out.isOpen();

        // Assert
        assertEquals(state, result, "isOpen should reflect handle state");
        verify(handle, times(1)).isOpen();
    }

    @Test
    @DisplayName("ensureTreeConnected delegates and returns the tree handle")
    void ensureTreeConnected_delegatesAndReturns() throws Exception {
        // Arrange
        SmbPipeOutputStream out = newStream();
        when(handle.ensureTreeConnected()).thenReturn(tree);

        // Act
        SmbTreeHandleImpl result = out.ensureTreeConnected();

        // Assert
        assertSame(tree, result, "ensureTreeConnected should return handle's tree");
        verify(handle, times(1)).ensureTreeConnected();
    }

    @Test
    @DisplayName("ensureTreeConnected propagates CIFSException from handle")
    void ensureTreeConnected_propagatesException() throws Exception {
        // Arrange
        SmbPipeOutputStream out = newStream();
        CIFSException boom = new CIFSException("tree-fail");
        when(handle.ensureTreeConnected()).thenThrow(boom);

        // Act + Assert
        CIFSException ex = assertThrows(CIFSException.class, out::ensureTreeConnected);
        assertEquals("tree-fail", ex.getMessage());
        verify(handle, times(1)).ensureTreeConnected();
    }

    @Test
    @DisplayName("ensureOpen delegates and returns the file handle")
    void ensureOpen_delegatesAndReturns() throws Exception {
        // Arrange
        SmbPipeOutputStream out = newStream();
        when(handle.ensureOpen()).thenReturn(fileHandle);

        // Act
        SmbFileHandleImpl result = out.ensureOpen();

        // Assert
        assertSame(fileHandle, result, "ensureOpen should return handle's file handle");
        verify(handle, times(1)).ensureOpen();
    }

    @Test
    @DisplayName("ensureOpen propagates CIFSException from handle")
    void ensureOpen_propagatesException() throws Exception {
        // Arrange
        SmbPipeOutputStream out = newStream();
        CIFSException boom = new CIFSException("open-fail");
        when(handle.ensureOpen()).thenThrow(boom);

        // Act + Assert
        CIFSException ex = assertThrows(CIFSException.class, out::ensureOpen);
        assertEquals("open-fail", ex.getMessage());
        verify(handle, times(1)).ensureOpen();
    }

    @Test
    @DisplayName("getHandle returns the exact handle instance")
    void getHandle_returnsHandle() throws Exception {
        // Arrange
        SmbPipeOutputStream out = newStream();

        // Act
        SmbPipeHandleImpl got = out.getHandle();

        // Assert
        assertSame(handle, got, "getHandle should expose the same instance passed to constructor");
    }

    @Test
    @DisplayName("close does nothing and does not touch handle")
    void close_doesNothing() throws Exception {
        // Arrange
        SmbPipeOutputStream out = newStream();
        // constructor already calls handle.getPipe(); clear interactions to focus on close()
        clearInvocations(handle);

        // Act
        out.close();

        // Assert
        verifyNoInteractions(handle);
    }

    @Nested
    @DisplayName("Constructor invalid inputs")
    class ConstructorInvalidInputs {
        @Test
        @DisplayName("Null handle triggers NullPointerException")
        void ctor_nullHandle_throwsNPE() {
            // Act + Assert
            assertThrows(NullPointerException.class, () -> new SmbPipeOutputStream(null, tree));
        }

        @Test
        @DisplayName("Null tree handle triggers NullPointerException")
        void ctor_nullTree_throwsNPE() {
            // Arrange
            when(handle.getPipe()).thenReturn(pipe);

            // Act + Assert
            assertThrows(NullPointerException.class, () -> new SmbPipeOutputStream(handle, null));
        }
    }
}
