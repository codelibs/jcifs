package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.spnego.NegTokenInit;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class Kerb5ContextTest {

    @Mock
    private GSSManager gssManager;

    @Mock
    private GSSContext gssContext;

    @Mock
    private GSSName serviceName;

    @Mock
    private GSSName clientName;

    @Mock
    private GSSCredential clientCreds;

    private Kerb5Context ctx;
    private MockedStatic<GSSManager> mockedStatic;

    @BeforeEach
    void setUp() throws Exception {
        // Mock the static GSSManager.getInstance() method
        mockedStatic = mockStatic(GSSManager.class);
        mockedStatic.when(GSSManager::getInstance).thenReturn(gssManager);

        // Setup mock behavior for GSSManager with lenient matchers
        lenient().when(gssManager.createName(anyString(), any(), any())).thenReturn(serviceName);
        lenient().when(gssManager.createName(anyString(), any())).thenReturn(serviceName);
        lenient().when(gssManager.createContext(any(), any(), any(), anyInt())).thenReturn(gssContext);

        // Create Kerb5Context with mocked dependencies
        ctx = new Kerb5Context("host.example", "cifs", null, 0, 0, null);
    }

    @AfterEach
    void tearDown() {
        if (mockedStatic != null) {
            mockedStatic.close();
        }
    }

    private static void setPrivateField(Object target, String name, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(target, value);
    }

    static ASN1ObjectIdentifier[] supportedMechs() {
        return Kerb5Context.SUPPORTED_MECHS;
    }

    @ParameterizedTest
    @MethodSource("supportedMechs")
    @DisplayName("isSupported returns true for supported OIDs")
    void isSupported_supportedOids(ASN1ObjectIdentifier oid) {
        assertTrue(ctx.isSupported(oid));
        assertTrue(ctx.isPreferredMech(oid));
    }

    @Test
    @DisplayName("isSupported returns false for null/unknown OIDs")
    void isSupported_unknownOrNull() {
        assertFalse(ctx.isSupported(null));
        assertFalse(ctx.isPreferredMech(null));
        assertFalse(ctx.isSupported(new ASN1ObjectIdentifier("1.3.6.1.4.1.99999")));
    }

    @Test
    @DisplayName("getSupportedMechs returns expected array")
    void getSupportedMechs_happyPath() {
        ASN1ObjectIdentifier[] mechs = ctx.getSupportedMechs();
        assertNotNull(mechs);
        assertArrayEquals(Kerb5Context.SUPPORTED_MECHS, mechs);
    }

    @Test
    @DisplayName("getFlags with all false yields 0")
    void getFlags_allFalse() {
        when(gssContext.getCredDelegState()).thenReturn(false);
        when(gssContext.getMutualAuthState()).thenReturn(false);
        when(gssContext.getReplayDetState()).thenReturn(false);
        when(gssContext.getSequenceDetState()).thenReturn(false);
        when(gssContext.getAnonymityState()).thenReturn(false);
        when(gssContext.getConfState()).thenReturn(false);
        when(gssContext.getIntegState()).thenReturn(false);

        int flags = ctx.getFlags();
        assertEquals(0, flags);
    }

    @Test
    @DisplayName("getFlags combines all flag bits when true")
    void getFlags_allTrue() {
        when(gssContext.getCredDelegState()).thenReturn(true);
        when(gssContext.getMutualAuthState()).thenReturn(true);
        when(gssContext.getReplayDetState()).thenReturn(true);
        when(gssContext.getSequenceDetState()).thenReturn(true);
        when(gssContext.getAnonymityState()).thenReturn(true);
        when(gssContext.getConfState()).thenReturn(true);
        when(gssContext.getIntegState()).thenReturn(true);

        int flags = ctx.getFlags();
        int expected = NegTokenInit.DELEGATION | NegTokenInit.MUTUAL_AUTHENTICATION | NegTokenInit.REPLAY_DETECTION
                | NegTokenInit.SEQUENCE_CHECKING | NegTokenInit.ANONYMITY | NegTokenInit.CONFIDENTIALITY | NegTokenInit.INTEGRITY;
        assertEquals(expected, flags);
    }

    @Test
    @DisplayName("isEstablished reflects underlying context state")
    void isEstablished_behavior() throws Exception {
        when(gssContext.isEstablished()).thenReturn(true);
        assertTrue(ctx.isEstablished());

        // When gssContext is null, isEstablished returns false
        setPrivateField(ctx, "gssContext", null);
        assertFalse(ctx.isEstablished());
        // Put it back for subsequent tests
        setPrivateField(ctx, "gssContext", gssContext);
    }

    @Test
    @DisplayName("supportsIntegrity always true")
    void supportsIntegrity_alwaysTrue() {
        assertTrue(ctx.supportsIntegrity());
    }

    @Test
    @DisplayName("calculateMIC returns value from GSS and verifies interaction")
    void calculateMIC_success() throws Exception {
        byte[] data = new byte[] { 1, 2, 3 };
        byte[] mic = new byte[] { 9, 8 };
        when(gssContext.getMIC(eq(data), eq(0), eq(3), any())).thenReturn(mic);

        byte[] res = ctx.calculateMIC(data);
        assertArrayEquals(mic, res);
        verify(gssContext, times(1)).getMIC(eq(data), eq(0), eq(3), any());
    }

    @Test
    @DisplayName("calculateMIC wraps GSSException into CIFSException")
    void calculateMIC_failure_wraps() throws Exception {
        byte[] data = new byte[] { 0 };
        when(gssContext.getMIC(any(), anyInt(), anyInt(), any())).thenThrow(new GSSException(GSSException.FAILURE));

        CIFSException ex = assertThrows(CIFSException.class, () -> ctx.calculateMIC(data));
        assertTrue(ex.getMessage().contains("Failed to calculate MIC"));
    }

    @Test
    @DisplayName("calculateMIC with null data throws NPE")
    void calculateMIC_nullData() {
        assertThrows(NullPointerException.class, () -> ctx.calculateMIC(null));
    }

    @Test
    @DisplayName("verifyMIC delegates to GSS and succeeds")
    void verifyMIC_success() throws Exception {
        byte[] data = new byte[] { 1, 2 };
        byte[] mic = new byte[] { 3 };
        // No exception means success
        doNothing().when(gssContext).verifyMIC(eq(mic), eq(0), eq(1), eq(data), eq(0), eq(2), any());

        assertDoesNotThrow(() -> ctx.verifyMIC(data, mic));
        verify(gssContext, times(1)).verifyMIC(eq(mic), eq(0), eq(1), eq(data), eq(0), eq(2), any());
    }

    @Test
    @DisplayName("verifyMIC wraps GSSException into CIFSException")
    void verifyMIC_failure_wraps() throws Exception {
        byte[] data = new byte[] { 7 };
        byte[] mic = new byte[] { 8 };
        doThrow(new GSSException(GSSException.BAD_MIC)).when(gssContext)
                .verifyMIC(any(), anyInt(), anyInt(), any(), anyInt(), anyInt(), any());

        CIFSException ex = assertThrows(CIFSException.class, () -> ctx.verifyMIC(data, mic));
        assertTrue(ex.getMessage().contains("Failed to verify MIC"));
    }

    @Test
    @DisplayName("verifyMIC with null inputs throws NPE")
    void verifyMIC_nullInputs() {
        assertThrows(NullPointerException.class, () -> ctx.verifyMIC(null, new byte[] { 1 }));
        assertThrows(NullPointerException.class, () -> ctx.verifyMIC(new byte[] { 1 }, null));
    }

    @Test
    @DisplayName("isMICAvailable reflects GSS integ state")
    void isMICAvailable_behavior() {
        when(gssContext.getIntegState()).thenReturn(false).thenReturn(true);
        assertFalse(ctx.isMICAvailable());
        assertTrue(ctx.isMICAvailable());
    }

    @Test
    @DisplayName("getNetbiosName returns null")
    void getNetbiosName_null() {
        assertNull(ctx.getNetbiosName());
    }

    @Test
    @DisplayName("getSigningKey throws when ExtendedGSSContext not implemented")
    void getSigningKey_notImplementedByGSSContext() {
        SmbException ex = assertThrows(SmbException.class, () -> ctx.getSigningKey());
        assertTrue(ex.getMessage().contains("ExtendedGSSContext is not implemented"));
    }

    @Test
    @DisplayName("initSecContext returns token and verifies interaction")
    void initSecContext_success() throws Exception {
        byte[] in = new byte[] { 10, 11 };
        byte[] out = new byte[] { 12, 13, 14 };
        when(gssContext.initSecContext(eq(in), eq(0), eq(in.length))).thenReturn(out);

        byte[] res = ctx.initSecContext(in, 0, in.length);
        assertArrayEquals(out, res);
        verify(gssContext, times(1)).initSecContext(eq(in), eq(0), eq(in.length));
    }

    @Test
    @DisplayName("initSecContext wraps GSSException into SmbAuthException")
    void initSecContext_failure_wraps() throws Exception {
        when(gssContext.initSecContext(any(), anyInt(), anyInt())).thenThrow(new GSSException(GSSException.DEFECTIVE_TOKEN));
        assertThrows(SmbAuthException.class, () -> ctx.initSecContext(new byte[] {}, 0, 0));
    }

    @Test
    @DisplayName("searchSessionKey returns null when Subject has no tickets")
    void searchSessionKey_emptySubject() throws Exception {
        // Arrange GSS context so method can run without NPE
        GSSName src = mock(GSSName.class);
        GSSName targ = mock(GSSName.class);
        when(src.export()).thenReturn(buildExportName(new Oid("1.2.3"), "client"));
        when(targ.export()).thenReturn(buildExportName(new Oid("1.2.3"), "service"));
        when(gssContext.getSrcName()).thenReturn(src);
        when(gssContext.getTargName()).thenReturn(targ);
        when(gssContext.getMech()).thenReturn(new Oid("1.2.3"));

        assertNull(ctx.searchSessionKey(new javax.security.auth.Subject()));
    }

    @Test
    @DisplayName("toString shows basic info when not established")
    void toString_notEstablished() throws Exception {
        when(gssContext.isEstablished()).thenReturn(false);
        String s = ctx.toString();
        assertTrue(s.startsWith("KERB5["));
        assertTrue(s.contains("src=null"));
    }

    @Test
    @DisplayName("toString shows names and mech when established")
    void toString_established_ok() throws Exception {
        when(gssContext.isEstablished()).thenReturn(true);
        GSSName src = mock(GSSName.class);
        GSSName targ = mock(GSSName.class);
        when(src.toString()).thenReturn("client");
        when(targ.toString()).thenReturn("service");
        when(gssContext.getSrcName()).thenReturn(src);
        when(gssContext.getTargName()).thenReturn(targ);
        when(gssContext.getMech()).thenReturn(new Oid("1.2.3"));

        String s = ctx.toString();
        assertEquals("KERB5[src=client,targ=service,mech=1.2.3]", s);
    }

    @Test
    @DisplayName("toString falls back when GSS access fails")
    void toString_established_throws() throws Exception {
        when(gssContext.isEstablished()).thenReturn(true);
        when(gssContext.getSrcName()).thenThrow(new GSSException(GSSException.FAILURE));
        String s = ctx.toString();
        assertTrue(s.contains("org.codelibs.jcifs.smb.impl.Kerb5Context@"));
    }

    @Nested
    @DisplayName("Dispose Tests")
    class DisposeTests {
        @Test
        @DisplayName("dispose delegates to GSSContext")
        void dispose_success() throws Exception {
            assertDoesNotThrow(() -> ctx.dispose());
            verify(gssContext, times(1)).dispose();
        }

        @Test
        @DisplayName("dispose wraps GSSException into SmbException")
        void dispose_failure_wraps() throws Exception {
            doThrow(new GSSException(GSSException.FAILURE)).when(gssContext).dispose();
            SmbException ex = assertThrows(SmbException.class, () -> ctx.dispose());
            assertTrue(ex.getMessage().contains("Context disposal failed"));
        }

        @Test
        @DisplayName("dispose with null context is no-op")
        void dispose_nullContext_noop() throws Exception {
            setPrivateField(ctx, "gssContext", null);
            assertDoesNotThrow(() -> ctx.dispose());
        }
    }

    // Helper to build a minimal exported name token understood by MIEName(byte[])
    // Format: TOK_ID(2 bytes) | OID_LEN(2 bytes) | OID_DER | NAME_LEN(4 bytes) | NAME(bytes)
    private static byte[] buildExportName(Oid mech, String name) throws GSSException {
        byte[] der = mech.getDER();
        byte[] nb = name.getBytes();
        int len = 2 + 2 + der.length + 4 + nb.length;
        byte[] out = new byte[len];
        int i = 0;
        out[i++] = 0x04; // TOK_ID[0]
        out[i++] = 0x01; // TOK_ID[1]
        out[i++] = (byte) ((der.length >> 8) & 0xFF);
        out[i++] = (byte) (der.length & 0xFF);
        System.arraycopy(der, 0, out, i, der.length);
        i += der.length;
        out[i++] = (byte) ((nb.length >> 24) & 0xFF);
        out[i++] = (byte) ((nb.length >> 16) & 0xFF);
        out[i++] = (byte) ((nb.length >> 8) & 0xFF);
        out[i++] = (byte) (nb.length & 0xFF);
        System.arraycopy(nb, 0, out, i, nb.length);
        return out;
    }
}