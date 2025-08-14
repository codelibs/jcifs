package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.DialectVersion;
import jcifs.SmbConstants;
import jcifs.SmbTransport;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.SMBSigningDigest;
import jcifs.internal.SmbNegotiationResponse;
import jcifs.internal.smb1.com.ServerData;
import jcifs.internal.smb1.com.SmbComNegotiateResponse;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.smb2.Smb2EncryptionContext;
import jcifs.internal.smb2.nego.EncryptionNegotiateContext;
import jcifs.internal.smb2.nego.Smb2NegotiateResponse;
import jcifs.util.transport.Request;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmbTransportImplTest {

    @Mock
    private CIFSContext ctx;
    @Mock
    private Configuration cfg;
    @Mock
    private Address address;

    private SmbTransportImpl transport;

    @BeforeEach
    void setUp() throws Exception {
        when(ctx.getConfig()).thenReturn(cfg);
        when(cfg.isSigningEnforced()).thenReturn(false);
        when(cfg.getSessionTimeout()).thenReturn(30_000);
        when(cfg.getResponseTimeout()).thenReturn(5_000);
        when(address.getHostAddress()).thenReturn("127.0.0.1");
        when(address.getHostName()).thenReturn("localhost");

        // Create the transport with safe defaults (no real sockets)
        transport = new SmbTransportImpl(ctx, address, 445, null, 0, false);

        // Reset MID to a known starting point for deterministic behavior
        setField(transport, "mid", new AtomicLong());
    }

    // Utility: reflectively set a private/protected field (searches up the hierarchy)
    private static void setField(Object target, String name, Object value) {
        try {
            Field f = findField(target.getClass(), name);
            f.setAccessible(true);
            f.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Utility: reflectively get a private/protected field (searches up the hierarchy)
    private static Object getField(Object target, String name) {
        try {
            Field f = findField(target.getClass(), name);
            f.setAccessible(true);
            return f.get(target);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Helper: find field in class hierarchy
    private static Field findField(Class<?> clazz, String name) throws NoSuchFieldException {
        Class<?> current = clazz;
        while (current != null) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException e) {
                current = current.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    @Test
    @DisplayName("getResponseTimeout returns override for SMB requests")
    void getResponseTimeout_override() {
        // Arrange
        CommonServerMessageBlockRequest req = mock(CommonServerMessageBlockRequest.class);
        when(req.getOverrideTimeout()).thenReturn(1234);

        // Act
        int timeout = transport.getResponseTimeout(req);

        // Assert
        assertEquals(1234, timeout);
    }

    @Test
    @DisplayName("getResponseTimeout falls back to config for non-SMB requests")
    void getResponseTimeout_default() {
        // Arrange
        Request req = mock(Request.class);
        when(cfg.getResponseTimeout()).thenReturn(2222);

        // Act & Assert
        assertEquals(2222, transport.getResponseTimeout(req));
    }

    @Test
    @DisplayName("Basic getters: address, hostName, inflight, sessions")
    void basicGetters() {
        assertEquals(address, transport.getRemoteAddress());
        assertNull(transport.getRemoteHostName(), "tconHostName starts null");
        assertEquals(0, transport.getInflightRequests());
        assertEquals(0, transport.getNumSessions());
    }

    @Test
    @DisplayName("isDisconnected / isFailed reflect socket and state")
    void connectionStateChecks() throws Exception {
        // Arrange: simulate connected state and open socket
        setField(transport, "state", 3); // connected
        Socket s = mock(Socket.class);
        when(s.isClosed()).thenReturn(false);
        setField(transport, "socket", s);

        // Act & Assert
        assertFalse(transport.isDisconnected());
        assertFalse(transport.isFailed());

        // Close socket -> both should be true
        when(s.isClosed()).thenReturn(true);
        assertTrue(transport.isDisconnected());
        assertTrue(transport.isFailed());
    }

    @Test
    @DisplayName("capability query delegates to negotiation state")
    void hasCapability_delegates() throws Exception {
        // Arrange
        SmbNegotiationResponse nego = mock(SmbNegotiationResponse.class);
        setField(transport, "negotiated", nego);
        when(nego.haveCapabilitiy(SmbConstants.CAP_DFS)).thenReturn(true);

        // Act & Assert
        assertTrue(transport.hasCapability(SmbConstants.CAP_DFS));
        verify(nego, times(1)).haveCapabilitiy(SmbConstants.CAP_DFS);
    }

    @Test
    @DisplayName("SMB version detection via flag or response type")
    void isSMB2_variants() throws Exception {
        // 1) smb2 flag set
        setField(transport, "smb2", true);
        assertTrue(transport.isSMB2());

        // 2) smb2 false but negotiated is SMB2 response
        setField(transport, "smb2", false);
        Smb2NegotiateResponse smb2 = new Smb2NegotiateResponse(cfg);
        setField(transport, "negotiated", smb2);
        assertTrue(transport.isSMB2());

        // 3) SMB1 negotiation
        SmbComNegotiateResponse smb1 = new SmbComNegotiateResponse(ctx);
        setField(transport, "negotiated", smb1);
        assertFalse(transport.isSMB2());
    }

    @Test
    @DisplayName("Digest setter/getter roundtrip")
    void digestRoundtrip() {
        SMBSigningDigest dg = mock(SMBSigningDigest.class);
        transport.setDigest(dg);
        assertSame(dg, transport.getDigest());
    }

    @Test
    @DisplayName("Context accessor returns constructor-provided context")
    void contextAccessor() {
        assertSame(ctx, transport.getContext());
    }

    @Test
    @DisplayName("acquire returns same instance")
    void acquireReturnsSameInstance() {
        SmbTransportImpl acquired = transport.acquire();
        assertSame(transport, acquired);
        transport.close(); // release once
    }

    @Test
    @DisplayName("Server encryption key is returned for SMB1 negotiation only")
    void serverEncryptionKey() {
        // No negotiation yet -> null
        assertNull(transport.getServerEncryptionKey());

        // SMB1 negotiation with server data
        SmbComNegotiateResponse smb1 = new SmbComNegotiateResponse(ctx);
        ServerData sd = smb1.getServerData();
        sd.encryptionKey = new byte[] { 1, 2, 3 };
        setField(transport, "negotiated", smb1);
        assertArrayEquals(new byte[] { 1, 2, 3 }, transport.getServerEncryptionKey());

        // SMB2 negotiation never exposes key via this API
        setField(transport, "negotiated", new Smb2NegotiateResponse(cfg));
        assertNull(transport.getServerEncryptionKey());
    }

    @Test
    @DisplayName("Signing enforced/optional adhere to flags and negotiation")
    void signingModes() throws Exception {
        // Enforced via constructor flag -> optional false, enforced true regardless of negotiation
        SmbTransportImpl enforced = new SmbTransportImpl(ctx, address, 445, null, 0, true);
        assertFalse(enforced.isSigningOptional());
        assertTrue(enforced.isSigningEnforced());

        // Negotiated required -> enforced true; negotiated enabled-only -> optional true
        SmbNegotiationResponse nego = mock(SmbNegotiationResponse.class);
        setField(transport, "negotiated", nego);
        when(nego.isSigningNegotiated()).thenReturn(true);
        when(nego.isSigningRequired()).thenReturn(false).thenReturn(true);

        assertTrue(transport.isSigningOptional());
        assertTrue(transport.isSigningEnforced());
    }

    @Test
    @DisplayName("unwrap returns this for compatible types and throws otherwise")
    void unwrapBehavior() {
        // Happy paths
        SmbTransport asIface = transport.unwrap(SmbTransport.class);
        assertSame(transport, asIface);
        SmbTransportInternal asInternal = transport.unwrap(SmbTransportInternal.class);
        assertSame(transport, asInternal);

        // Invalid type should throw
        class OtherTransport implements SmbTransport {
            @Override
            public String getRemoteHostName() {
                return "test";
            }

            @Override
            public Address getRemoteAddress() {
                return mock(Address.class);
            }

            @Override
            public CIFSContext getContext() {
                return mock(CIFSContext.class);
            }

            @Override
            public <T extends SmbTransport> T unwrap(Class<T> type) {
                if (type.isInstance(this)) {
                    return type.cast(this);
                }
                throw new ClassCastException("Cannot unwrap to " + type.getName());
            }

            @Override
            public void close() {
                // no-op for test
            }
        }
        assertThrows(ClassCastException.class, () -> transport.unwrap(OtherTransport.class));
    }

    @Test
    @DisplayName("getSmbSession creates and then reuses matching session")
    void getSmbSession_createAndReuse() {
        // Arrange: minimal credentials chain so SmbSessionImpl constructor succeeds
        CredentialsInternal creds = mock(CredentialsInternal.class);
        when(ctx.getCredentials()).thenReturn(creds);
        when(creds.unwrap(CredentialsInternal.class)).thenReturn(creds);
        when(creds.clone()).thenReturn(creds);

        assertEquals(0, transport.getNumSessions());

        // Act: create new session (happy path)
        SmbSessionImpl s1 = transport.getSmbSession(ctx);
        assertNotNull(s1);
        assertEquals(1, transport.getNumSessions());
        s1.close();

        // Act: request again with same context -> reuse existing
        SmbSessionImpl s2 = transport.getSmbSession(ctx);
        assertNotNull(s2);
        assertEquals(1, transport.getNumSessions(), "Should reuse existing session");
        s2.close();
    }

    @Test
    @DisplayName("DFS referrals: invalid double-slash prefix triggers exception")
    void dfsReferrals_invalidPath() {
        CIFSException ex = assertThrows(CIFSException.class, () -> transport.getDfsReferrals(ctx, "\\\\server\\share", null, null, 1));
        assertTrue(ex.getMessage().contains("double slash"));
    }

    @Nested
    @MockitoSettings(strictness = Strictness.LENIENT)
    class PreauthHashAndEncryption {
        @Test
        @DisplayName("calculatePreauthHash rejects non-SMB2 or missing negotiation")
        void preauthHash_rejectsWhenUnsupported() {
            // Not SMB2
            assertThrows(SmbUnsupportedOperationException.class, () -> transport.calculatePreauthHash(new byte[] { 1 }, 0, 1, null));

            // SMB2 flag set but no negotiation
            setField(transport, "smb2", true);
            assertThrows(SmbUnsupportedOperationException.class, () -> transport.calculatePreauthHash(new byte[] { 1 }, 0, 1, null));
        }

        @Test
        @DisplayName("calculatePreauthHash rejects dialects before SMB 3.1.1")
        void preauthHash_rejectsOldDialect() {
            setField(transport, "smb2", true);
            Smb2NegotiateResponse nego = new Smb2NegotiateResponse(cfg);
            // selectedDialect: SMB300
            setField(nego, "selectedDialect", DialectVersion.SMB300);
            setField(transport, "negotiated", nego);
            assertThrows(SmbUnsupportedOperationException.class, () -> transport.calculatePreauthHash(new byte[] { 1, 2, 3 }, 0, 3, null));
        }

        @Test
        @DisplayName("calculatePreauthHash computes SHA-512 chain for SMB 3.1.1")
        void preauthHash_happyPath() throws Exception {
            setField(transport, "smb2", true);
            Smb2NegotiateResponse nego = new Smb2NegotiateResponse(cfg);
            setField(nego, "selectedDialect", DialectVersion.SMB311);
            setField(nego, "selectedPreauthHash", 1); // 1 => SHA-512
            setField(transport, "negotiated", nego);

            byte[] input = new byte[] { 10, 20, 30, 40 };
            byte[] hash1 = transport.calculatePreauthHash(input, 0, input.length, null);
            assertNotNull(hash1);
            assertEquals(64, hash1.length, "SHA-512 size");

            byte[] hash2 = transport.calculatePreauthHash(new byte[] { 50 }, 0, 1, hash1);
            assertNotNull(hash2);
            assertEquals(64, hash2.length);
            assertNotEquals(new String(hash1), new String(hash2), "Chained hash should differ");
        }

        @Test
        @DisplayName("createEncryptionContext rejects when SMB2/3 not negotiated")
        void createEncryptionContext_rejects_noNegotiation() {
            assertThrows(SmbUnsupportedOperationException.class, () -> transport.createEncryptionContext(new byte[] { 1 }, null));
        }

        @Test
        @DisplayName("createEncryptionContext rejects pre-SMB3 dialect")
        void createEncryptionContext_rejects_oldDialect() throws Exception {
            setField(transport, "smb2", true);
            Smb2NegotiateResponse nego = new Smb2NegotiateResponse(cfg);
            setField(nego, "selectedDialect", DialectVersion.SMB210);
            setField(transport, "negotiated", nego);
            assertThrows(SmbUnsupportedOperationException.class, () -> transport.createEncryptionContext(new byte[] { 1, 2, 3, 4 }, null));
        }

        @Test
        @DisplayName("createEncryptionContext selects AES-CCM for SMB 3.0 and AES-GCM for SMB 3.1.1")
        void createEncryptionContext_happyDialects() throws Exception {
            byte[] sessionKey = new byte[16];
            byte[] preauth = new byte[16];

            // SMB 3.0 -> AES-128-CCM
            setField(transport, "smb2", true);
            Smb2NegotiateResponse smb300 = new Smb2NegotiateResponse(cfg);
            setField(smb300, "selectedDialect", DialectVersion.SMB300);
            setField(transport, "negotiated", smb300);
            Smb2EncryptionContext ccm = transport.createEncryptionContext(sessionKey, preauth);
            assertEquals(EncryptionNegotiateContext.CIPHER_AES128_CCM, ccm.getCipherId());
            assertEquals(DialectVersion.SMB300, ccm.getDialect());

            // SMB 3.1.1 -> default AES-128-GCM when server did not choose
            Smb2NegotiateResponse smb311 = new Smb2NegotiateResponse(cfg);
            setField(smb311, "selectedDialect", DialectVersion.SMB311);
            setField(smb311, "selectedCipher", -1);
            setField(transport, "negotiated", smb311);
            Smb2EncryptionContext gcm = transport.createEncryptionContext(sessionKey, preauth);
            assertEquals(EncryptionNegotiateContext.CIPHER_AES128_GCM, gcm.getCipherId());
            assertEquals(DialectVersion.SMB311, gcm.getDialect());
        }
    }

    @Test
    @DisplayName("getRequestSecurityMode honors enforced and server-required flags")
    void requestSecurityMode() {
        // Not enforced, server does not require -> enabled only
        Smb2NegotiateResponse first = mock(Smb2NegotiateResponse.class);
        when(first.isSigningRequired()).thenReturn(false);
        assertEquals(Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED, transport.getRequestSecurityMode(first));

        // Enforced -> required+enabled
        SmbTransportImpl enforced = new SmbTransportImpl(ctx, address, 445, null, 0, true);
        assertEquals(Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED | Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED,
                enforced.getRequestSecurityMode(first));

        // Server indicates required -> required+enabled
        Smb2NegotiateResponse firstReq = mock(Smb2NegotiateResponse.class);
        when(firstReq.isSigningRequired()).thenReturn(true);
        assertEquals(Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED | Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED,
                transport.getRequestSecurityMode(firstReq));
    }

    @Test
    @DisplayName("toString contains key fields without throwing")
    void toStringContainsInfo() {
        String s = transport.toString();
        assertNotNull(s);
        assertTrue(s.contains("state="));
        assertTrue(s.contains(":445"));
    }
}
