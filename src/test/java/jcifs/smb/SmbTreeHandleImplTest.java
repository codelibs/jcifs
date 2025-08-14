package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.EnumSet;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.Configuration;
import jcifs.RuntimeCIFSException;
import jcifs.SmbTreeHandle;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.CommonServerMessageBlockResponse;
import jcifs.internal.Request;
import jcifs.internal.SmbNegotiationResponse;
import jcifs.internal.smb1.com.SmbComNegotiateResponse;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmbTreeHandleImplTest {

    @Mock
    SmbResourceLocatorImpl resourceLoc;

    @Mock
    SmbTreeConnection treeConnection;

    @Mock
    SmbSessionImpl session;

    @Mock
    SmbTransportImpl transport;

    @Mock
    Configuration config;

    private SmbTreeHandleImpl handle;

    @BeforeEach
    void setUp() {
        // Tree connection is acquired in the constructor and should return itself
        when(treeConnection.acquire()).thenReturn(treeConnection);
        when(treeConnection.getSession()).thenReturn(session);
        when(session.getTransport()).thenReturn(transport);
        handle = new SmbTreeHandleImpl(resourceLoc, treeConnection);
    }

    @Test
    @DisplayName("Constructor acquires tree connection; getConfig/isConnected delegate")
    void constructorAndSimpleDelegations() {
        // Ensures constructor acquires tree connection and simple delegate methods forward correctly
        // Verify constructor invoked acquire once
        verify(treeConnection, times(1)).acquire();

        // getConfig delegates
        when(treeConnection.getConfig()).thenReturn(config);
        assertSame(config, handle.getConfig());
        verify(treeConnection).getConfig();

        // isConnected delegates
        when(treeConnection.isConnected()).thenReturn(true, false);
        assertTrue(handle.isConnected());
        assertFalse(handle.isConnected());
        verify(treeConnection, times(2)).isConnected();
    }

    @Test
    @DisplayName("getSession returns underlying session from tree connection")
    void getSessionReturnsUnderlying() {
        // Verifies getSession() exposes the session provided by the connection
        assertSame(session, handle.getSession());
        verify(treeConnection).getSession();
    }

    @Test
    @DisplayName("ensureDFSResolved forwards to tree connection with locator")
    void ensureDFSResolvedDelegates() throws Exception {
        // Confirms DFS resolution is delegated with the correct locator
        // Act
        handle.ensureDFSResolved();
        // Assert & interaction verify
        verify(treeConnection).ensureDFSResolved(resourceLoc);
    }

    @Test
    @DisplayName("hasCapability delegates and propagates exceptions")
    void hasCapabilityDelegates() throws Exception {
        // Happy path delegates; invalid case propagates SmbException
        when(treeConnection.hasCapability(123)).thenReturn(true);
        assertTrue(handle.hasCapability(123));
        verify(treeConnection).hasCapability(123);

        // Exception path
        when(treeConnection.hasCapability(999)).thenThrow(new SmbException("Not connected"));
        SmbException ex = assertThrows(SmbException.class, () -> handle.hasCapability(999));
        assertTrue(ex.getMessage().contains("Not connected"));
    }

    @Test
    @DisplayName("getTreeId delegates")
    void getTreeIdDelegates() {
        // Ensures tree id is forwarded from connection
        when(treeConnection.getTreeId()).thenReturn(42L);
        assertEquals(42L, handle.getTreeId());
        verify(treeConnection).getTreeId();
    }

    @Test
    @DisplayName("send(Request, varargs) delegates with null response")
    void sendWithRequestVarargsDelegates() throws Exception {
        // Verifies Request<T> overload forwards to the varargs form with a null response
        @SuppressWarnings("unchecked")
        Request<CommonServerMessageBlockResponse> req = mock(Request.class);
        CommonServerMessageBlockResponse resp = mock(CommonServerMessageBlockResponse.class);

        // Stub tree send for varargs
        when(treeConnection.send(eq(resourceLoc), any(CommonServerMessageBlockRequest.class), isNull(), any(RequestParam[].class)))
                .thenReturn(resp);

        CommonServerMessageBlockResponse out = handle.send(req, RequestParam.NO_RETRY);
        assertSame(resp, out);

        verify(treeConnection, times(1)).send(eq(resourceLoc), eq((CommonServerMessageBlockRequest) req), isNull(),
                any(RequestParam[].class));
    }

    @Test
    @DisplayName("send(request, response, varargs) forwards directly")
    void sendRequestResponseVarargsDelegates() throws Exception {
        // Confirms varargs overload passes through to the underlying connection
        CommonServerMessageBlockRequest request = mock(CommonServerMessageBlockRequest.class);
        CommonServerMessageBlockResponse response = mock(CommonServerMessageBlockResponse.class);

        when(treeConnection.send(eq(resourceLoc), eq(request), eq(response), any(RequestParam[].class))).thenReturn(response);

        CommonServerMessageBlockResponse out = handle.send(request, response, RequestParam.NO_RETRY);
        assertSame(response, out);
        verify(treeConnection).send(eq(resourceLoc), eq(request), eq(response), any(RequestParam[].class));
    }

    @Test
    @DisplayName("send(request, response, set) forwards directly")
    void sendRequestResponseSetDelegates() throws Exception {
        // Confirms Set<RequestParam> overload passes through to the underlying connection
        CommonServerMessageBlockRequest request = mock(CommonServerMessageBlockRequest.class);
        CommonServerMessageBlockResponse response = mock(CommonServerMessageBlockResponse.class);
        Set<RequestParam> params = EnumSet.of(RequestParam.NO_RETRY);

        when(treeConnection.send(resourceLoc, request, response, params)).thenReturn(response);

        CommonServerMessageBlockResponse out = handle.send(request, response, params);
        assertSame(response, out);
        verify(treeConnection).send(resourceLoc, request, response, params);
    }

    @Test
    @DisplayName("close calls release and decrements usage; double release throws")
    void closeAndReleaseBehavior() {
        // Validates usage counting and that an extra release() throws RuntimeCIFSException
        // First close -> usage 1 -> 0, triggers treeConnection.release()
        handle.close();
        verify(treeConnection, times(1)).release();

        // Second release -> usage 0 -> -1 triggers RuntimeCIFSException
        RuntimeCIFSException ex = assertThrows(RuntimeCIFSException.class, () -> handle.release());
        assertTrue(ex.getMessage().contains("below zero"));
        verify(treeConnection, times(1)).release(); // still only once
    }

    @Test
    @DisplayName("acquire after release reacquires underlying tree connection")
    void acquireAfterReleaseReacquires() {
        // After dropping to zero, acquire() should reacquire the underlying connection
        // Drop usage to zero
        handle.release();
        verify(treeConnection, times(1)).release();

        // Acquire from 0 -> 1 should acquire underlying
        when(treeConnection.acquire()).thenReturn(treeConnection);
        SmbTreeHandleImpl out = handle.acquire();
        assertSame(handle, out);
        verify(treeConnection, times(2)).acquire(); // constructor + here
    }

    @Test
    @DisplayName("getRemoteHostName returns transport value and closes resources")
    void getRemoteHostNameHappyPath() {
        // Ensures remote host name is sourced from transport and resources are closed
        when(transport.getRemoteHostName()).thenReturn("remote.example");
        String name = handle.getRemoteHostName();
        assertEquals("remote.example", name);
        // try-with-resources should close both
        verify(session).close();
        verify(transport).close();
    }

    @Test
    @DisplayName("getServerTimeZoneOffset: SMB1 negotiate path multiplies minutes to millis")
    void getServerTimeZoneOffsetSmb1() throws Exception {
        // Uses concrete SMB1 negotiate response to exercise SMB1-specific branch
        // Build a concrete SMB1 negotiate response to expose ServerData fields
        jcifs.CIFSContext ctx = mock(jcifs.CIFSContext.class);
        when(ctx.getConfig()).thenReturn(config);
        when(config.getCapabilities()).thenReturn(0);
        when(config.getFlags2()).thenReturn(0);
        when(config.getMaxMpxCount()).thenReturn(1);
        when(config.getSendBufferSize()).thenReturn(4096);
        when(config.getReceiveBufferSize()).thenReturn(4096);
        when(config.getTransactionBufferSize()).thenReturn(4096);
        when(config.isUseUnicode()).thenReturn(true);

        SmbComNegotiateResponse nego = new SmbComNegotiateResponse(ctx);
        // Set server timezone (in minutes) and domain
        nego.getServerData().serverTimeZone = 60; // 60 minutes
        nego.getServerData().oemDomainName = "DOMAIN";

        when(transport.getNegotiateResponse()).thenReturn(nego);

        assertEquals(60L * 1000L * 60L, handle.getServerTimeZoneOffset());
        assertEquals("DOMAIN", handle.getOEMDomainName());
        verify(session, times(2)).close();
        verify(transport, times(2)).close();
    }

    @Test
    @DisplayName("getServerTimeZoneOffset/OEMDomainName: non-SMB1 negotiate returns 0/null")
    void getServerTimeZoneOffsetNonSmb1() throws Exception {
        // For non-SMB1 responses, timezone is 0 and domain is null
        SmbNegotiationResponse otherNego = mock(SmbNegotiationResponse.class);
        when(transport.getNegotiateResponse()).thenReturn(otherNego);

        assertEquals(0L, handle.getServerTimeZoneOffset());
        assertNull(handle.getOEMDomainName());
    }

    @Test
    @DisplayName("Tree properties delegate: getTreeType/getConnectedShare")
    void treePropertiesDelegate() {
        // Validates simple property delegation to the connection
        when(treeConnection.getTreeType()).thenReturn(7);
        when(treeConnection.getConnectedShare()).thenReturn("SHARE");
        assertEquals(7, handle.getTreeType());
        assertEquals("SHARE", handle.getConnectedShare());
        verify(treeConnection).getTreeType();
        verify(treeConnection).getConnectedShare();
    }

    @Test
    @DisplayName("isSameTree: different types and delegated compare")
    void isSameTreeCoversBranches() {
        // Covers non-impl (false) and impl path delegating to connection comparison
        // Not an impl -> false
        assertFalse(handle.isSameTree(mock(SmbTreeHandle.class)));

        // Impl case delegates to treeConnection.isSame
        SmbTreeConnection otherConn = mock(SmbTreeConnection.class);
        when(otherConn.acquire()).thenReturn(otherConn);
        SmbTreeHandleImpl other = new SmbTreeHandleImpl(resourceLoc, otherConn);

        when(treeConnection.isSame(otherConn)).thenReturn(true, false);
        assertTrue(handle.isSameTree(other));
        assertFalse(handle.isSameTree(other));
        verify(treeConnection, times(2)).isSame(otherConn);
    }

    @Test
    @DisplayName("Buffer sizes and signing flags from negotiate response")
    void bufferSizesAndSigning() throws Exception {
        // Validate buffer sizes and signing flag are read from negotiate response
        SmbNegotiationResponse nego = mock(SmbNegotiationResponse.class);
        when(transport.getNegotiateResponse()).thenReturn(nego);
        when(nego.getSendBufferSize()).thenReturn(1111);
        when(nego.getReceiveBufferSize()).thenReturn(2222);
        when(nego.getTransactionBufferSize()).thenReturn(3333);
        when(nego.isSigningNegotiated()).thenReturn(true);

        assertEquals(1111, handle.getSendBufferSize());
        assertEquals(2222, handle.getReceiveBufferSize());
        assertEquals(3333, handle.getMaximumBufferSize());
        assertTrue(handle.areSignaturesActive());

        verify(session, times(4)).close();
        verify(transport, times(4)).close();
    }

    @Test
    @DisplayName("isSMB2 true and exception fallback to false")
    void isSMB2Cases() throws Exception {
        // Happy path returns true; transport exception path returns false
        when(transport.isSMB2()).thenReturn(true);
        assertTrue(handle.isSMB2());

        reset(transport);
        when(session.getTransport()).thenReturn(transport);
        when(transport.isSMB2()).thenThrow(new SmbException("negotiation missing"));
        assertFalse(handle.isSMB2());
    }

    @Test
    @DisplayName("Null treeConnection throws NPE")
    void constructorNullTreeConnection() {
        // Null treeConnection throws NPE when acquire() is called
        assertThrows(NullPointerException.class, () -> new SmbTreeHandleImpl(resourceLoc, null));
    }

    @Test
    @DisplayName("Null resourceLoc is accepted but may cause issues later")
    void constructorNullResourceLoc() {
        // Null resourceLoc doesn't throw NPE immediately - it's stored and may cause issues when used
        // This test documents the current behavior
        SmbTreeConnection freshConnection = mock(SmbTreeConnection.class);
        when(freshConnection.acquire()).thenReturn(freshConnection);

        // Should not throw NPE during construction
        SmbTreeHandleImpl handleWithNullLoc = new SmbTreeHandleImpl(null, freshConnection);
        assertNotNull(handleWithNullLoc);

        // But operations that use resourceLoc might fail
        // For example, send methods would likely throw NPE when trying to use the null resourceLoc
    }
}
