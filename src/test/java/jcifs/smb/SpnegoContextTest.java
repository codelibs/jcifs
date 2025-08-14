package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSException;
import jcifs.Configuration;

/**
 * Tests for SpnegoContext focusing on delegation, error handling, and edge cases.
 */
@ExtendWith(MockitoExtension.class)
class SpnegoContextTest {

    @Mock
    Configuration config;

    @Mock
    SSPContext mechContext;

    private ASN1ObjectIdentifier[] mechs;

    @BeforeEach
    void setup() {
        // Default: do not enforce or disable SPNEGO integrity
        when(this.config.isEnforceSpnegoIntegrity()).thenReturn(false);
        when(this.config.isDisableSpnegoIntegrity()).thenReturn(false);
        this.mechs = new ASN1ObjectIdentifier[] { new ASN1ObjectIdentifier("1.2.3.4") };
    }

    private SpnegoContext newContext() {
        return new SpnegoContext(this.config, this.mechContext, this.mechs);
    }

    @Test
    @DisplayName("getSupportedMechs returns SPNEGO OID")
    void testGetSupportedMechs() {
        SpnegoContext ctx = newContext();
        ASN1ObjectIdentifier[] supported = ctx.getSupportedMechs();
        assertNotNull(supported);
        assertEquals(1, supported.length);
        assertEquals(new ASN1ObjectIdentifier("1.3.6.1.5.5.2"), supported[0]);
    }

    @Test
    @DisplayName("isSupported always returns false (prevents nesting)")
    void testIsSupportedAlwaysFalse() {
        SpnegoContext ctx = newContext();
        ASN1ObjectIdentifier any = new ASN1ObjectIdentifier("1.2.840.113554.1.2.2");
        assertFalse(ctx.isSupported(any));
        // Ensure delegate is not consulted
        verify(this.mechContext, never()).isSupported(any);
    }

    @Test
    @DisplayName("initSecContext with empty len returns initial NegTokenInit and delegates to mechContext")
    void testInitSecContextInitialToken() throws Exception {
        SpnegoContext ctx = newContext();

        // The initial token path should ask the mechanism for a zero-length optimistic token
        when(this.mechContext.getFlags()).thenReturn(0x1234);
        when(this.mechContext.initSecContext(any(byte[].class), eq(0), eq(0))).thenReturn(new byte[] { 0x01, 0x02 });

        // Act: len==0 triggers initial token construction
        byte[] out = ctx.initSecContext(null, 0, 0);

        // Assert: returns a SPNEGO token (opaque here but non-null/non-empty)
        assertNotNull(out);
        assertTrue(out.length > 0);

        // Verify interactions: flags and an empty optimistic token are used
        verify(this.mechContext, times(1)).getFlags();
        ArgumentCaptor<byte[]> cap = ArgumentCaptor.forClass(byte[].class);
        verify(this.mechContext, times(1)).initSecContext(cap.capture(), eq(0), eq(0));
        assertEquals(0, cap.getValue().length, "Optimistic token must be zero-length");
    }

    @ParameterizedTest
    @ValueSource(bytes = { 0x00, 0x7F, (byte) 0xFF })
    @DisplayName("initSecContext throws on invalid token type")
    void testInitSecContextInvalidTokenType(byte firstByte) throws Exception {
        SpnegoContext ctx = newContext();

        // Invalid first byte should be rejected by token parsing
        CIFSException ex = assertThrows(CIFSException.class, () -> ctx.initSecContext(new byte[] { firstByte }, 0, 1));
        assertEquals("Invalid token", ex.getMessage());

        // Ensure mechContext was not engaged due to early failure
        verify(this.mechContext, never()).initSecContext(any(), anyInt(), anyInt());
    }

    @Test
    @DisplayName("initSecContext with null buffer and non-zero len throws NPE")
    void testInitSecContextNullBufferNonZeroLen() throws Exception {
        SpnegoContext ctx = newContext();
        // A null buffer with non-zero len leads to NPE while slicing input
        assertThrows(NullPointerException.class, () -> ctx.initSecContext(null, 0, 1));
        verify(this.mechContext, never()).initSecContext(any(), anyInt(), anyInt());
    }

    @Test
    @DisplayName("getSigningKey delegates to underlying mechanism context")
    void testGetSigningKeyDelegates() throws Exception {
        SpnegoContext ctx = newContext();
        byte[] key = new byte[] { 1, 2, 3 };
        when(this.mechContext.getSigningKey()).thenReturn(key);
        assertSame(key, ctx.getSigningKey());
        verify(this.mechContext, times(1)).getSigningKey();
    }

    @Test
    @DisplayName("supportsIntegrity delegates to underlying mechanism context")
    void testSupportsIntegrityDelegates() {
        SpnegoContext ctx = newContext();
        when(this.mechContext.supportsIntegrity()).thenReturn(true);
        assertTrue(ctx.supportsIntegrity());
        verify(this.mechContext, times(1)).supportsIntegrity();
    }

    @Test
    @DisplayName("isPreferredMech delegates to underlying mechanism context")
    void testIsPreferredMechDelegates() {
        SpnegoContext ctx = newContext();
        ASN1ObjectIdentifier mech = new ASN1ObjectIdentifier("1.2.840.113554.1.2.2");
        when(this.mechContext.isPreferredMech(mech)).thenReturn(true);
        assertTrue(ctx.isPreferredMech(mech));
        verify(this.mechContext, times(1)).isPreferredMech(mech);
    }

    @Test
    @DisplayName("getFlags delegates to underlying mechanism context")
    void testGetFlagsDelegates() {
        SpnegoContext ctx = newContext();
        when(this.mechContext.getFlags()).thenReturn(0xCAFE);
        assertEquals(0xCAFE, ctx.getFlags());
        verify(this.mechContext, times(1)).getFlags();
    }

    @Test
    @DisplayName("dispose delegates to underlying mechanism context")
    void testDisposeDelegates() throws Exception {
        SpnegoContext ctx = newContext();
        ctx.dispose();
        verify(this.mechContext, times(1)).dispose();
    }

    @Test
    @DisplayName("calculateMIC throws when context not established")
    void testCalculateMICRequiresEstablished() throws Exception {
        SpnegoContext ctx = newContext();
        CIFSException ex = assertThrows(CIFSException.class, () -> ctx.calculateMIC(new byte[] { 1 }));
        assertEquals("Context is not established", ex.getMessage());
        verify(this.mechContext, never()).calculateMIC(any());
    }

    @Test
    @DisplayName("verifyMIC throws when context not established")
    void testVerifyMICRequiresEstablished() throws Exception {
        SpnegoContext ctx = newContext();
        CIFSException ex = assertThrows(CIFSException.class, () -> ctx.verifyMIC(new byte[] { 1 }, new byte[] { 2 }));
        assertEquals("Context is not established", ex.getMessage());
        verify(this.mechContext, never()).verifyMIC(any(), any());
    }

    @Test
    @DisplayName("isMICAvailable returns false before establishment and does not call delegate")
    void testIsMICAvailableBeforeEstablished() {
        SpnegoContext ctx = newContext();
        // The mock setup is unnecessary since we never call it
        assertFalse(ctx.isMICAvailable());
        verify(this.mechContext, never()).isMICAvailable();
    }

    @Test
    @DisplayName("isEstablished short-circuits on not completed and does not call delegate")
    void testIsEstablishedShortCircuit() {
        SpnegoContext ctx = newContext();
        // The mock setup is unnecessary since we never call it
        assertFalse(ctx.isEstablished());
        verify(this.mechContext, never()).isEstablished();
    }

    @Test
    @DisplayName("getNetbiosName returns null and does not call delegate")
    void testGetNetbiosName() {
        SpnegoContext ctx = newContext();
        // The mock setup is unnecessary since we never call it
        assertNull(ctx.getNetbiosName());
        verify(this.mechContext, never()).getNetbiosName();
    }

    @Test
    @DisplayName("getMechs returns configured mechs and setMechs updates them")
    void testGetSetMechs() {
        SpnegoContext ctx = newContext();
        assertArrayEquals(this.mechs, ctx.getMechs());
        ASN1ObjectIdentifier[] updated = new ASN1ObjectIdentifier[] { new ASN1ObjectIdentifier("1.2.840.113554.1.2.2") };
        ctx.setMechs(updated);
        assertArrayEquals(updated, ctx.getMechs());
    }

    @Test
    @DisplayName("toString includes wrapped mechanism context")
    void testToString() {
        SpnegoContext ctx = newContext();
        when(this.mechContext.toString()).thenReturn("MECHCTX");
        assertEquals("SPNEGO[MECHCTX]", ctx.toString());
    }
}
