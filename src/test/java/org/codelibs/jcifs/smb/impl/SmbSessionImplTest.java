package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.RuntimeCIFSException;
import org.codelibs.jcifs.smb.internal.SMBSigningDigest;
import org.codelibs.jcifs.smb.internal.smb2.Smb2EncryptionContext;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateRequest;
import org.codelibs.jcifs.smb.internal.smb2.session.Smb2SessionSetupResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmbSessionImplTest {

    @Mock
    private CIFSContext cifsContext;
    @Mock
    private Configuration configuration;
    @Mock
    private Credentials credentials;
    @Mock
    private CredentialsInternal credentialsInternal;
    @Mock
    private SmbTransportImpl transport;

    private SmbSessionImpl newSession() {
        return new SmbSessionImpl(cifsContext, "server.example", "EXAMPLE", transport);
    }

    private static final class NonInternalCredentials implements Credentials {
        @Override
        public <T extends Credentials> T unwrap(Class<T> type) {
            return null;
        }

        @Override
        public String getUserDomain() {
            return "DOMAIN";
        }

        @Override
        public boolean isAnonymous() {
            return false;
        }

        @Override
        public boolean isGuest() {
            return false;
        }
    }

    @BeforeEach
    void setup() {
        // Base context configuration - always needed
        when(cifsContext.getConfig()).thenReturn(configuration);

        // Context and credentials wiring - used by most tests
        when(cifsContext.getCredentials()).thenReturn(credentials);
        when(credentials.unwrap(CredentialsInternal.class)).thenReturn(credentialsInternal);
        when(credentialsInternal.clone()).thenReturn(credentialsInternal);

        // Transport wiring - used by most tests
        when(transport.acquire()).thenReturn(transport);
        when(transport.getContext()).thenReturn(cifsContext);
    }

    // Helper to set private fields for targeted edge cases
    private static void setField(Object target, String name, Object value) {
        try {
            Field f = target.getClass().getDeclaredField(name);
            f.setAccessible(true);
            f.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("getters and basic state (happy path)")
    void testGettersAndState() {
        SmbSessionImpl session = newSession();

        // Basic getters
        assertSame(configuration, session.getConfig(), "getConfig delegates to transportContext");
        assertEquals("EXAMPLE", session.getTargetDomain());
        assertEquals("server.example", session.getTargetHost());
        assertTrue(session.isInUse(), "New session starts in-use (usageCount=1)");

        // Transport and context delegation
        assertSame(cifsContext, session.getContext());
        clearInvocations(transport);
        assertSame(transport, session.getTransport());
        verify(transport, times(1)).acquire();
    }

    @Test
    @DisplayName("constructor fails fast when credentials cannot be unwrapped to internal credentials")
    void testConstructorRejectsNonInternalCredentials() {
        when(credentials.unwrap(CredentialsInternal.class)).thenReturn(null);

        IllegalArgumentException ex =
                assertThrows(IllegalArgumentException.class, () -> new SmbSessionImpl(cifsContext, "server.example", "EXAMPLE", transport));
        assertTrue(ex.getMessage().contains("Credentials must implement CredentialsInternal"));
    }

    @Test
    @DisplayName("constructor fails fast when context credentials are null")
    void testConstructorRejectsNullCredentials() {
        when(cifsContext.getCredentials()).thenReturn(null);

        IllegalArgumentException ex =
                assertThrows(IllegalArgumentException.class, () -> new SmbSessionImpl(cifsContext, "server.example", "EXAMPLE", transport));
        assertTrue(ex.getMessage().contains("but got: null"));
    }

    @Test
    @DisplayName("constructor error message includes provided credential type")
    void testConstructorErrorIncludesCredentialType() {
        when(cifsContext.getCredentials()).thenReturn(new NonInternalCredentials());

        IllegalArgumentException ex =
                assertThrows(IllegalArgumentException.class, () -> new SmbSessionImpl(cifsContext, "server.example", "EXAMPLE", transport));
        assertTrue(ex.getMessage().contains(NonInternalCredentials.class.getName()));
    }

    @Test
    @DisplayName("constructor uses cloned credentials instance")
    void testConstructorUsesClonedCredentialsInstance() {
        CredentialsInternal clonedInternal = mock(CredentialsInternal.class);
        when(credentialsInternal.clone()).thenReturn(clonedInternal);

        SmbSessionImpl session = newSession();
        assertSame(clonedInternal, session.getCredentials());
        verify(credentialsInternal, times(1)).clone();
    }

    @Test
    @DisplayName("close/release manage usage and transport lifecycle")
    void testReleaseLifecycle() {
        SmbSessionImpl session = newSession();

        // First release drops usage to zero and releases transport
        session.release();
        verify(transport, times(1)).release();
        assertFalse(session.isInUse());

        // Next release goes below zero and throws
        RuntimeException ex = assertThrows(RuntimeCIFSException.class, session::release);
        assertTrue(ex.getMessage().contains("below zero"));

        // Only one transport release should have occurred
        verify(transport, times(1)).release();
    }

    @Test
    @DisplayName("acquire after release reacquires transport")
    void testAcquireReacquiresTransport() {
        SmbSessionImpl session = newSession();

        // Drop usage to zero which releases transport and flips transportAcquired=false
        session.release();
        clearInvocations(transport);

        // Re-acquire should reacquire transport
        assertSame(session, session.acquire());
        verify(transport, times(1)).acquire();
        assertTrue(session.isInUse());
    }

    @Test
    @DisplayName("getSessionKey: throws when absent, returns when present")
    void testGetSessionKey() throws Exception {
        SmbSessionImpl session = newSession();

        // Absent key -> CIFSException
        CIFSException noKey = assertThrows(CIFSException.class, session::getSessionKey);
        assertTrue(noKey.getMessage().contains("No session key"));

        // Set a key via reflection and verify retrieval
        byte[] key = new byte[] { 1, 2, 3, 4 };
        setField(session, "sessionKey", key);
        assertArrayEquals(key, session.getSessionKey());
    }

    @Test
    @DisplayName("getSmbTree returns same instance for same share/service")
    void testGetSmbTreeReuses() {
        SmbSessionImpl session = newSession();
        SmbTreeImpl t1 = session.getSmbTree("IPC$", null);
        SmbTreeImpl t2 = session.getSmbTree("ipc$", null); // case-insensitive match
        assertSame(t1, t2, "Expected same tree instance to be reused");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @DisplayName("treeConnectLogon: invalid logon share throws SmbException")
    void testTreeConnectLogonInvalid(String logonShare) {
        SmbSessionImpl session = spy(newSession());
        when(configuration.getLogonShare()).thenReturn(logonShare);
        assertThrows(SmbException.class, session::treeConnectLogon);
        verify(session, never()).getSmbTree(anyString(), isNull());
    }

    @Test
    @DisplayName("treeConnectLogon: valid share connects via tree")
    void testTreeConnectLogonValid() throws Exception {
        SmbSessionImpl session = spy(newSession());
        when(configuration.getLogonShare()).thenReturn("LOGON$");

        // Mock tree and ensure it is returned by getSmbTree
        SmbTreeImpl tree = mock(SmbTreeImpl.class);
        doReturn(tree).when(session).getSmbTree(eq("LOGON$"), isNull());

        // Act
        session.treeConnectLogon();

        // Assert: treeConnect invoked once with null params
        verify(tree, times(1)).treeConnect(isNull(), isNull());
        // Close of try-with-resources should call close on the mock
        verify(tree, times(1)).close();
    }

    @Test
    @DisplayName("unwrap: returns self for compatible type and throws for incompatible")
    @SuppressWarnings({ "rawtypes", "unchecked" })
    void testUnwrap() {
        SmbSessionImpl session = newSession();

        // Happy path: ask for SmbSession and SmbSessionInternal
        assertSame(session, session.unwrap(SmbSessionInternal.class));
        assertSame(session, session.unwrap(org.codelibs.jcifs.smb.SmbSession.class));

        // Edge: force incompatible class via raw type to trigger ClassCastException
        assertThrows(ClassCastException.class, () -> session.unwrap((Class) String.class));
    }

    @Test
    @DisplayName("toString contains key identifiers")
    void testToString() {
        SmbSessionImpl session = newSession();
        String s = session.toString();
        assertTrue(s.contains("targetHost=server.example"));
        assertTrue(s.contains("targetDomain=EXAMPLE"));
    }

    @Test
    @DisplayName("getExpiration: null when unset, value when positive")
    void testGetExpiration() {
        SmbSessionImpl session = newSession();
        assertNull(session.getExpiration());
        setField(session, "expiration", 123L);
        assertEquals(123L, session.getExpiration());
        setField(session, "expiration", 0L);
        assertNull(session.getExpiration());
    }

    @Test
    @DisplayName("connection and failure status delegate to transport")
    void testConnectionAndFailureStatus() {
        SmbSessionImpl session = newSession();

        // Make session look connected via setSessionSetup
        Smb2SessionSetupResponse resp = mock(Smb2SessionSetupResponse.class);
        when(resp.getSessionId()).thenReturn(42L);
        session.setSessionSetup(resp);

        when(transport.isDisconnected()).thenReturn(false);
        when(transport.isFailed()).thenReturn(false);
        assertTrue(session.isConnected());
        assertFalse(session.isFailed());

        when(transport.isDisconnected()).thenReturn(true);
        when(transport.isFailed()).thenReturn(true);
        assertFalse(session.isConnected());
        assertTrue(session.isFailed());
    }

    @Test
    @DisplayName("encryption: context is exposed to the transport once it exists")
    void testEncryptionContextExposure() throws Exception {
        SmbSessionImpl session = newSession();

        // No encryption context -> the transport must not try to encrypt on this session
        assertFalse(session.isEncryptionEnabled());
        assertNull(session.getEncryptionContext());

        Smb2EncryptionContext enc = mock(Smb2EncryptionContext.class);
        setField(session, "encryptionContext", enc);

        assertTrue(session.isEncryptionEnabled());
        assertSame(enc, session.getEncryptionContext());
    }

    @Test
    @DisplayName("getTransport returns acquired transport instance")
    void testGetTransportAcquire() {
        SmbSessionImpl session = newSession();
        clearInvocations(transport);
        SmbTransportImpl t = session.getTransport();
        assertSame(transport, t);
        verify(transport, times(1)).acquire();
    }

    @Test
    @DisplayName("isSignatureSetupRequired depends on digest and negotiate flags")
    void testIsSignatureSetupRequired() throws Exception {
        SmbSessionImpl session = newSession();

        // Case 1: digest already set -> false
        SMBSigningDigest dg = mock(SMBSigningDigest.class);
        setField(session, "digest", dg);
        assertFalse(session.isSignatureSetupRequired());

        // Case 2: no digest, signing enforced by transport -> true
        setField(session, "digest", null);
        when(transport.isSigningEnforced()).thenReturn(true);
        assertTrue(session.isSignatureSetupRequired());

        // Case 3: not enforced, rely on negotiate response flag
        when(transport.isSigningEnforced()).thenReturn(false);
        org.codelibs.jcifs.smb.internal.SmbNegotiationResponse nego = mock(org.codelibs.jcifs.smb.internal.SmbNegotiationResponse.class);
        when(transport.getNegotiateResponse()).thenReturn(nego);

        when(nego.isSigningNegotiated()).thenReturn(true);
        assertTrue(session.isSignatureSetupRequired());
        when(nego.isSigningNegotiated()).thenReturn(false);
        assertFalse(session.isSignatureSetupRequired());
    }

    @Test
    @DisplayName("reauthenticate propagates transport failures")
    void testReauthenticatePropagates() throws Exception {
        SmbSessionImpl session = newSession();
        // Cause the inner reauthenticate to fail at first transport call
        when(transport.getNegotiateResponse()).thenThrow(new SmbException("fail"));
        assertThrows(CIFSException.class, session::reauthenticate);
    }

    /**
     * An oplock break names only the file it breaks. MS-SMB2 3.2.5.19.1 has the client find the open in
     * Session.OpenTable by that file id, because the acknowledgement has to carry the session and tree of the open -
     * the notification's own header carries TreeId 0 and, on several servers, SessionId 0.
     */
    @Test
    @DisplayName("an open is found by its file id once registered")
    void testOpenTableLookup() {
        SmbSessionImpl session = newSession();
        byte[] fileId = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        SmbFileHandleImpl handle = mock(SmbFileHandleImpl.class);

        assertNull(session.getOpen(fileId), "nothing is registered yet");

        session.registerOpen(fileId, handle);

        assertSame(handle, session.getOpen(fileId));
        assertSame(handle, session.getOpen(fileId.clone()), "lookup is by contents, not identity");
    }

    @Test
    @DisplayName("an open is gone from the table once unregistered")
    void testOpenTableUnregister() {
        SmbSessionImpl session = newSession();
        byte[] fileId = new byte[] { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
        SmbFileHandleImpl handle = mock(SmbFileHandleImpl.class);
        session.registerOpen(fileId, handle);

        session.unregisterOpen(fileId);

        assertNull(session.getOpen(fileId), "a closed open must not be left behind");
    }

    @Test
    @DisplayName("an unknown file id resolves to nothing rather than failing")
    void testOpenTableMiss() {
        SmbSessionImpl session = newSession();
        session.registerOpen(new byte[16], mock(SmbFileHandleImpl.class));

        // 3.2.5.19.1: a break naming no open of ours is ignored, so a miss must be quiet
        assertNull(session.getOpen(new byte[] { 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9 }));
        assertNull(session.getOpen(null));
    }

    @Test
    @DisplayName("the session id is readable for the break acknowledgement header")
    void testSessionIdAccessor() throws Exception {
        SmbSessionImpl session = newSession();
        assertEquals(0L, session.getSessionId(), "a session that has not authenticated has no id yet");

        setField(session, "sessionId", 0x4142434445464748L);

        assertEquals(0x4142434445464748L, session.getSessionId());
    }

    private SmbTreeHandleImpl stubbedTree() {
        SmbTreeHandleImpl tree = mock(SmbTreeHandleImpl.class);
        lenient().when(tree.acquire()).thenReturn(tree);
        lenient().when(tree.getTreeId()).thenReturn(7L);
        lenient().when(tree.isConnected()).thenReturn(true);
        lenient().when(tree.isSMB2()).thenReturn(true);
        return tree;
    }

    @Test
    @DisplayName("an open registers itself with its session and is found by file id")
    void testHandleRegistersWithSession() {
        SmbSessionImpl session = newSession();
        byte[] fileId = new byte[] { 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32 };
        SmbFileHandleImpl handle = new SmbFileHandleImpl(configuration, fileId, stubbedTree(), "//server/share/f", 0, 0, 0, 0, 0L);

        assertNull(session.getOpen(fileId), "an unattached handle is not in the table");

        handle.registerWith(session, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH);

        assertSame(handle, session.getOpen(fileId));
    }

    @Test
    @DisplayName("closing an open takes it out of the session's table")
    void testHandleUnregistersOnClose() throws Exception {
        SmbSessionImpl session = newSession();
        byte[] fileId = new byte[] { 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 4, 7, 11, 18, 29 };
        SmbFileHandleImpl handle = new SmbFileHandleImpl(configuration, fileId, stubbedTree(), "//server/share/f", 0, 0, 0, 0, 0L);
        handle.registerWith(session, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH);

        handle.close();

        assertNull(session.getOpen(fileId), "a closed open must not be left in the table");
    }

    @Test
    @DisplayName("an open marked closed without a close request is also taken out of the table")
    void testHandleUnregistersOnMarkClosed() {
        SmbSessionImpl session = newSession();
        byte[] fileId = new byte[] { 3, 6, 9, 12, 15, 18, 21, 24, 27, 30, 33, 36, 39, 42, 45, 48 };
        SmbFileHandleImpl handle = new SmbFileHandleImpl(configuration, fileId, stubbedTree(), "//server/share/f", 0, 0, 0, 0, 0L);
        handle.registerWith(session, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH);

        // A handle invalidated without a close request - a reconnect drops it - must not be left behind either,
        // or the table pins it for the life of the session.
        handle.markClosed();

        assertNull(session.getOpen(fileId), "an invalidated open must not be left in the table");
    }

    @Test
    @DisplayName("an open that was never attached to a session closes without failing")
    void testUnattachedHandleCloses() throws Exception {
        // Every existing caller builds handles without a session, and SMB1 handles have no file id at all.
        SmbFileHandleImpl handle = new SmbFileHandleImpl(configuration, 42, stubbedTree(), "//server/share/f", 0, 0, 0, 0, 0L);

        handle.close();
        handle.markClosed();
    }
}
