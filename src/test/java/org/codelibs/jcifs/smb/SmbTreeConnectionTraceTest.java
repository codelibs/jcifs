package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SmbTreeConnectionTraceTest {

    // Helper to build a minimal smb URL
    private static URL smbUrl(String spec) {
        try {
            return new URL(null, spec, new Handler());
        } catch (MalformedURLException e) {
            throw new AssertionError("Failed to create SMB URL: " + spec, e);
        }
    }

    // Utility to build a minimal locator for connect tests
    private static SmbResourceLocatorImpl newLocator(CIFSContext ctx) {
        return new SmbResourceLocatorImpl(ctx, smbUrl("smb://server/share"));
    }

    @Test
    @DisplayName("Constructor with CIFSContext: creates instance")
    void constructor_withContext_createsInstance() {
        // Arrange
        CIFSContext ctx = mock(CIFSContext.class);

        // Act
        SmbTreeConnectionTrace trace = new SmbTreeConnectionTrace(ctx);

        // Assert
        assertNotNull(trace, "Instance should be created");
    }

    @Test
    @DisplayName("Constructor with delegate: acquire() forwards to delegate and release() too")
    void constructor_withDelegate_acquireAndReleaseForwarded() {
        // Arrange: delegate we can spy on for interaction verification
        CIFSContext ctx = mock(CIFSContext.class);
        SmbTreeConnectionTrace delegate = Mockito.spy(new SmbTreeConnectionTrace(ctx));

        // Act: create wrapper using delegate, then acquire and release once
        SmbTreeConnectionTrace wrapper = new SmbTreeConnectionTrace(delegate);
        wrapper.acquire();
        wrapper.release();

        // Assert: delegate interactions occur when usage transitions happen
        verify(delegate, times(1)).acquire();
        verify(delegate, times(1)).release();
    }

    @Test
    @DisplayName("finalize() invokes checkRelease exactly once")
    void finalize_invokes_checkRelease() throws Throwable {
        // Arrange: spy to verify internal interaction with checkRelease()
        CIFSContext ctx = mock(CIFSContext.class);
        SmbTreeConnectionTrace trace = Mockito.spy(new SmbTreeConnectionTrace(ctx));

        // Act: directly invoke finalize to simulate GC finalization path
        trace.finalize();

        // Assert: verify that finalize delegated to checkRelease()
        verify(trace, times(1)).checkRelease();
    }

    @Test
    @DisplayName("checkRelease(): when connected and usage>0 performs check without throwing")
    void checkRelease_connectedAndInUse_doesNotThrow() {
        // Arrange: spy isConnected() to return true; increment usage via acquire()
        CIFSContext ctx = mock(CIFSContext.class);
        SmbTreeConnectionTrace trace = Mockito.spy(new SmbTreeConnectionTrace(ctx));
        doReturn(true).when(trace).isConnected();
        trace.acquire(); // usageCount becomes 1

        // Act & Assert: checkRelease should call isConnected() and not throw
        assertDoesNotThrow(trace::checkRelease);
        verify(trace, atLeastOnce()).isConnected();
    }

    @Test
    @DisplayName("release() below zero usage throws RuntimeCIFSException")
    void release_withoutAcquire_throwsRuntimeCIFSException() {
        // Arrange
        CIFSContext ctx = mock(CIFSContext.class);
        SmbTreeConnectionTrace trace = new SmbTreeConnectionTrace(ctx);

        // Act & Assert: calling release without prior acquire drops usage below zero
        RuntimeException ex = assertThrows(RuntimeException.class, trace::release);
        assertTrue(ex.getMessage() != null && ex.getMessage().contains("Usage count dropped below zero"));
    }

    @Test
    @DisplayName("getTreeId(): no tree returns -1")
    void getTreeId_noTree_returnsMinusOne() {
        // Arrange
        CIFSContext ctx = mock(CIFSContext.class);
        SmbTreeConnectionTrace trace = new SmbTreeConnectionTrace(ctx);

        // Act & Assert
        assertEquals(-1L, trace.getTreeId());
    }

    @Test
    @DisplayName("getConfig(): delegates to context")
    void getConfig_delegatesToContext() {
        // Arrange
        CIFSContext ctx = mock(CIFSContext.class);
        Configuration cfg = mock(Configuration.class);
        when(ctx.getConfig()).thenReturn(cfg);
        SmbTreeConnectionTrace trace = new SmbTreeConnectionTrace(ctx);

        // Act
        Configuration result = trace.getConfig();

        // Assert
        assertSame(cfg, result);
        verify(ctx, times(1)).getConfig();
    }

    @Test
    @DisplayName("hasCapability(): without session/tree throws SmbSystemException")
    void hasCapability_withoutTree_throwsSmbException() {
        // Arrange
        CIFSContext ctx = mock(CIFSContext.class);
        SmbTreeConnectionTrace trace = new SmbTreeConnectionTrace(ctx);

        // Act & Assert
        CIFSException ex = assertThrows(CIFSException.class, () -> trace.hasCapability(0));
        assertTrue(ex.getMessage() != null && ex.getMessage().contains("Not connected"));
    }

    static java.util.stream.Stream<Arguments> npePublicGetters() {
        return java.util.stream.Stream.of(Arguments.of("getTreeType()", (org.junit.jupiter.api.function.Executable) () -> {
            CIFSContext ctx = mock(CIFSContext.class);
            new SmbTreeConnectionTrace(ctx).getTreeType();
        }), Arguments.of("getConnectedShare()", (org.junit.jupiter.api.function.Executable) () -> {
            CIFSContext ctx = mock(CIFSContext.class);
            new SmbTreeConnectionTrace(ctx).getConnectedShare();
        }));
    }

    @ParameterizedTest(name = "Invalid usage causes NPE: {0}")
    @MethodSource("npePublicGetters")
    void getters_withoutTree_throwNPE(String name, org.junit.jupiter.api.function.Executable call) {
        // Each call is invalid without a held tree and should throw NPE
        assertThrows(NullPointerException.class, call);
    }

    static java.util.stream.Stream<Arguments> wrapExceptions() {
        CIFSContext ctx = mock(CIFSContext.class);
        SmbResourceLocatorImpl loc = new SmbResourceLocatorImpl(ctx, smbUrl("smb://server/share"));
        return java.util.stream.Stream.of(Arguments.of(loc, new UnknownHostException("host not found")),
                Arguments.of(loc, new IOException("io failed")));
    }

    @ParameterizedTest(name = "connectWrapException wraps {1} into SmbSystemException")
    @MethodSource("wrapExceptions")
    void connectWrapException_wrapsToSmbException(SmbResourceLocatorImpl loc, Exception thrown) throws Exception {
        // Arrange: spy on instance to force connect() failure with specific exception
        CIFSContext ctx = mock(CIFSContext.class);
        SmbTreeConnectionTrace trace = Mockito.spy(new SmbTreeConnectionTrace(ctx));
        doThrow(thrown).when(trace).connect(loc);

        // Act & Assert: both UnknownHostException and IOException should become CIFSException (SmbSystemException)
        CIFSException ex = assertThrows(CIFSException.class, () -> trace.connectWrapException(loc));
        assertTrue(ex.getMessage() != null && ex.getMessage().contains("Failed to connect to server"));
        assertSame(thrown, ex.getCause());
    }

    @Test
    @DisplayName("connectWrapException: rethrows SmbSystemException unchanged")
    void connectWrapException_rethrowsSmbException() throws Exception {
        // Arrange
        CIFSContext ctx = mock(CIFSContext.class);
        SmbResourceLocatorImpl loc = newLocator(ctx);
        SmbTreeConnectionTrace trace = Mockito.spy(new SmbTreeConnectionTrace(ctx));
        SmbException original = new SmbException("original");
        doThrow(original).when(trace).connect(loc);

        // Act & Assert
        SmbException ex = assertThrows(SmbException.class, () -> trace.connectWrapException(loc));
        assertSame(original, ex);
    }
}
