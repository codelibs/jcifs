package jcifs.smb;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.junit.jupiter.api.extension.ExtendWith;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.Credentials;
import jcifs.RuntimeCIFSException;
import jcifs.internal.SMBSigningDigest;
import jcifs.internal.smb2.Smb2EncryptionContext;
import jcifs.internal.smb2.session.Smb2SessionSetupResponse;
import jcifs.smb.SmbException;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmbSessionImplTest {

    @Mock private CIFSContext cifsContext;
    @Mock private Configuration configuration;
    @Mock private Credentials credentials;
    @Mock private CredentialsInternal credentialsInternal;
    @Mock private SmbTransportImpl transport;

    private SmbSessionImpl newSession() {
        return new SmbSessionImpl(cifsContext, "server.example", "EXAMPLE", transport);
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
        }
        catch (Exception e) {
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
        assertSame(session, session.unwrap(jcifs.SmbSession.class));

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
    @DisplayName("encryption: flags, encryption, and decryption delegation")
    void testEncryptionDelegation() throws Exception {
        SmbSessionImpl session = newSession();

        // No encryption context -> throws
        CIFSException notEnabled = assertThrows(CIFSException.class, () -> session.encryptMessage(new byte[] {1}));
        assertTrue(notEnabled.getMessage().contains("Encryption not enabled"));
        assertThrows(CIFSException.class, () -> session.decryptMessage(new byte[] {1}));

        // Set encryption context and verify delegation
        Smb2EncryptionContext enc = mock(Smb2EncryptionContext.class);
        setField(session, "encryptionContext", enc);
        setField(session, "sessionId", 99L);

        when(enc.encryptMessage(any(byte[].class), eq(99L))).thenReturn(new byte[] {9, 9});
        when(enc.decryptMessage(any(byte[].class))).thenReturn(new byte[] {7, 7});

        assertTrue(session.isEncryptionEnabled());
        assertSame(enc, session.getEncryptionContext());

        byte[] encOut = session.encryptMessage(new byte[] {1, 2, 3});
        assertArrayEquals(new byte[] {9, 9}, encOut);
        verify(enc, times(1)).encryptMessage(eq(new byte[] {1, 2, 3}), eq(99L));

        byte[] decOut = session.decryptMessage(new byte[] {5});
        assertArrayEquals(new byte[] {7, 7}, decOut);
        verify(enc, times(1)).decryptMessage(eq(new byte[] {5}));
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
        jcifs.internal.SmbNegotiationResponse nego = mock(jcifs.internal.SmbNegotiationResponse.class);
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
}
