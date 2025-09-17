package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.SmbTree;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockResponse;
import org.codelibs.jcifs.smb.internal.Request;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for SmbTreeInternal interface behavior via mocks.
 * Since this is an interface, we validate its public API contract
 * through interaction testing and generic type usage.
 */
@ExtendWith(MockitoExtension.class)
class SmbTreeInternalTest {

    @Mock
    private SmbTreeInternal tree;

    @Mock
    private CIFSContext context;

    @Mock
    private Request<CommonServerMessageBlockResponse> request;

    @Mock
    private CommonServerMessageBlockResponse response;

    @Test
    @DisplayName("connectLogon invokes underlying implementation")
    void connectLogon_invocation_isForwarded() throws Exception {
        // Act
        tree.connectLogon(context);

        // Assert - verify interaction with dependency
        verify(tree, times(1)).connectLogon(context);
        verify(tree, never()).close();
    }

    @Test
    @DisplayName("connectLogon accepts null context but still invokes")
    void connectLogon_withNull_isInvoked() throws Exception {
        // Act
        tree.connectLogon(null);

        // Assert - even null should be passed through to implementation
        verify(tree).connectLogon(null);
    }

    @Test
    @DisplayName("connectLogon propagates SmbException from implementation")
    void connectLogon_throws_propagates() throws Exception {
        // Arrange
        doThrow(new SmbException("login failed")).when(tree).connectLogon(context);

        // Act + Assert
        SmbException ex = assertThrows(SmbException.class, () -> tree.connectLogon(context));
        assertEquals("login failed", ex.getMessage());
        verify(tree).connectLogon(context);
    }

    @Test
    @DisplayName("send without params returns the stubbed response")
    void send_noParams_returnsResponse() throws Exception {
        // Arrange - generic return type respected
        when(tree.send(request)).thenReturn(response);

        // Act
        CommonServerMessageBlockResponse out = tree.send(request);

        // Assert
        assertSame(response, out);
        verify(tree).send(request);
    }

    @Test
    @DisplayName("send with multiple params returns the stubbed response")
    void send_withParams_returnsResponse() throws Exception {
        // Arrange
        when(tree.send(eq(request), eq(RequestParam.NO_TIMEOUT), eq(RequestParam.NO_RETRY))).thenReturn(response);

        // Act
        CommonServerMessageBlockResponse out = tree.send(request, RequestParam.NO_TIMEOUT, RequestParam.NO_RETRY);

        // Assert
        assertSame(response, out);
        verify(tree).send(request, RequestParam.NO_TIMEOUT, RequestParam.NO_RETRY);
    }

    @Test
    @DisplayName("send throws CIFSException for null request when implementation does")
    void send_nullRequest_throws() throws Exception {
        // Arrange
        when(tree.send(isNull())).thenThrow(new CIFSException("null request"));

        // Act
        CIFSException ex = assertThrows(CIFSException.class, () -> tree.send(null));

        // Assert
        assertEquals("null request", ex.getMessage());
        verify(tree).send((Request<CommonServerMessageBlockResponse>) isNull());
    }

    @Test
    @DisplayName("send with explicit null varargs propagates exception from implementation")
    void send_nullVarargsArray_throws() throws Exception {
        // Arrange: passing explicit null vararg array is edge scenario
        when(tree.send(eq(request), isNull())).thenThrow(new CIFSException("null params"));

        // Act + Assert
        CIFSException ex = assertThrows(CIFSException.class, () -> tree.send(request, (RequestParam[]) null));
        assertEquals("null params", ex.getMessage());
        verify(tree).send(eq(request), isNull());
    }

    @ParameterizedTest(name = "send with single param: {0}")
    @EnumSource(RequestParam.class)
    @DisplayName("send handles each RequestParam enum constant")
    void send_eachRequestParam_isAccepted(RequestParam param) throws Exception {
        // Arrange: stub per-call return to ensure interaction with the exact enum
        when(tree.send(eq(request), eq(param))).thenReturn(response);

        // Act
        CommonServerMessageBlockResponse out = tree.send(request, param);

        // Assert
        assertSame(response, out);
        verify(tree).send(request, param);
    }

    @Test
    @DisplayName("unwrap and close are available via SmbTree")
    void unwrap_and_close_interactions() {
        // Arrange
        when(tree.unwrap(SmbTreeInternal.class)).thenReturn(tree);

        // Act
        SmbTree unwrapped = tree.unwrap(SmbTreeInternal.class);
        tree.close();

        // Assert
        assertNotNull(unwrapped);
        verify(tree).unwrap(SmbTreeInternal.class);
        verify(tree).close();
    }
}
