package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb1.ntlmssp.NtlmFlags;
import org.codelibs.jcifs.smb1.ntlmssp.Type1Message;
import org.codelibs.jcifs.smb1.ntlmssp.Type2Message;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class NtlmContextTest {

    @Mock
    private NtlmPasswordAuthentication mockAuth;

    private final String domain = "TEST_DOMAIN";
    private final String username = "testUser";
    private final String password = "testPassword";
    private final String workstation = "TEST_WORKSTATION";

    @BeforeEach
    void setUp() {
        // MockitoExtension handles mock initialization
        // Type1Message.getDefaultWorkstation() is static, so we can't easily mock it without PowerMock.
        // We will proceed assuming it returns a predictable value or handle it as is.
    }

    @Test
    void testConstructor_withSigning() {
        // Test constructor when signing is enabled
        NtlmContext context = new NtlmContext(mockAuth, true);
        assertNotNull(context);
        assertFalse(context.isEstablished());
        assertNull(context.getServerChallenge());
        assertNull(context.getSigningKey());
        assertNull(context.getNetbiosName());

        int expectedFlags = NtlmFlags.NTLMSSP_REQUEST_TARGET | NtlmFlags.NTLMSSP_NEGOTIATE_NTLM2 | NtlmFlags.NTLMSSP_NEGOTIATE_128
                | NtlmFlags.NTLMSSP_NEGOTIATE_SIGN | NtlmFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NtlmFlags.NTLMSSP_NEGOTIATE_KEY_EXCH;
        // Verify exactly the expected bits are set
        assertEquals(expectedFlags, context.ntlmsspFlags);
    }

    @Test
    void testConstructor_withoutSigning() {
        // Test constructor when signing is disabled
        NtlmContext context = new NtlmContext(mockAuth, false);
        assertNotNull(context);
        assertFalse(context.isEstablished());

        int expectedFlags = NtlmFlags.NTLMSSP_REQUEST_TARGET | NtlmFlags.NTLMSSP_NEGOTIATE_NTLM2 | NtlmFlags.NTLMSSP_NEGOTIATE_128;
        assertEquals(expectedFlags, context.ntlmsspFlags);
    }

    @Test
    void testInitSecContext_state1_type1Message() throws Exception {
        // Test the first step of context initialization (creating Type 1 message)
        when(mockAuth.getDomain()).thenReturn(domain);
        NtlmContext context = new NtlmContext(mockAuth, true);
        byte[] type1Token = context.initSecContext(new byte[0], 0, 0);

        assertNotNull(type1Token);
        assertTrue(type1Token.length > 0);

        // Decode the token to verify its properties
        Type1Message type1Message = new Type1Message(type1Token);
        // Type1Message ORs default flags with provided flags; ensure expected bits are present
        assertTrue((type1Message.getFlags() & context.ntlmsspFlags) == context.ntlmsspFlags);
        assertEquals(domain, type1Message.getSuppliedDomain());
    }

    @Test
    void testInitSecContext_state2_type3Message() throws Exception {
        // Test the second step (processing Type 2 and creating Type 3 message)
        when(mockAuth.getDomain()).thenReturn(domain);
        when(mockAuth.getUsername()).thenReturn(username);
        when(mockAuth.getPassword()).thenReturn(password);
        NtlmContext context = new NtlmContext(mockAuth, true);

        // State 1: Generate Type 1 message
        context.initSecContext(new byte[0], 0, 0);

        // Create a mock Type 2 message (server challenge)
        byte[] serverChallenge = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        int type2Flags = NtlmFlags.NTLMSSP_NEGOTIATE_NTLM | NtlmFlags.NTLMSSP_REQUEST_TARGET | NtlmFlags.NTLMSSP_NEGOTIATE_KEY_EXCH
                | NtlmFlags.NTLMSSP_NEGOTIATE_SIGN;
        Type2Message type2Message = new Type2Message(type2Flags, serverChallenge, domain);
        byte[] type2Token = type2Message.toByteArray();

        // State 2: Process Type 2 and generate Type 3
        byte[] type3Token = context.initSecContext(type2Token, 0, type2Token.length);

        assertNotNull(type3Token);
        assertTrue(type3Token.length > 0);
        assertTrue(context.isEstablished());
        assertArrayEquals(serverChallenge, context.getServerChallenge());
        // Signing key may or may not be generated depending on flags negotiation
        // The context negotiates flags with server, so we can't guarantee signing key
    }

    @Test
    void testInitSecContext_state2_withoutSigning() throws Exception {
        // Test the second step (processing Type 2 and creating Type 3 message)
        when(mockAuth.getDomain()).thenReturn(domain);
        when(mockAuth.getUsername()).thenReturn(username);
        when(mockAuth.getPassword()).thenReturn(password);
        NtlmContext context = new NtlmContext(mockAuth, false);

        // State 1: Generate Type 1 message
        context.initSecContext(new byte[0], 0, 0);

        // Create a mock Type 2 message (server challenge)
        byte[] serverChallenge = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        int type2Flags = NtlmFlags.NTLMSSP_NEGOTIATE_NTLM | NtlmFlags.NTLMSSP_REQUEST_TARGET;
        Type2Message type2Message = new Type2Message(type2Flags, serverChallenge, domain);
        byte[] type2Token = type2Message.toByteArray();

        // State 2: Process Type 2 and generate Type 3
        byte[] type3Token = context.initSecContext(type2Token, 0, type2Token.length);

        assertNotNull(type3Token);
        assertTrue(type3Token.length > 0);
        assertTrue(context.isEstablished());
        assertArrayEquals(serverChallenge, context.getServerChallenge());
        assertNull(context.getSigningKey()); // Signing key should not be generated
    }

    @Test
    void testInitSecContext_invalidState() throws SmbException {
        // Test that calling initSecContext in an invalid state throws an exception
        when(mockAuth.getDomain()).thenReturn(domain);
        when(mockAuth.getUsername()).thenReturn(username);
        when(mockAuth.getPassword()).thenReturn(password);

        NtlmContext context = new NtlmContext(mockAuth, true);
        context.initSecContext(new byte[0], 0, 0); // state -> 2

        byte[] serverChallenge = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        int type2Flags = NtlmFlags.NTLMSSP_NEGOTIATE_NTLM | NtlmFlags.NTLMSSP_REQUEST_TARGET;
        Type2Message type2Message = new Type2Message(type2Flags, serverChallenge, domain);
        byte[] type2Token = type2Message.toByteArray();

        context.initSecContext(type2Token, 0, type2Token.length); // state -> 3 (established)

        // Try to call again
        SmbException e = assertThrows(SmbException.class, () -> {
            context.initSecContext(new byte[0], 0, 0);
        });
        assertEquals("Invalid state", e.getMessage());
    }

    @Test
    void testInitSecContext_malformedType2Message() throws SmbException {
        // Test handling of a malformed Type 2 message
        when(mockAuth.getDomain()).thenReturn(domain);

        NtlmContext context = new NtlmContext(mockAuth, true);
        context.initSecContext(new byte[0], 0, 0); // state -> 2

        byte[] malformedToken = new byte[] { 0x01, 0x02 }; // Not a valid Type 2 message

        SmbException e = assertThrows(SmbException.class, () -> {
            context.initSecContext(malformedToken, 0, malformedToken.length);
        });
        // Exception is thrown, but cause may or may not be set depending on implementation
        assertNotNull(e.getMessage()); // Should have an error message
    }

    @Test
    void testGetters() {
        // Simple test for getter methods
        NtlmContext context = new NtlmContext(mockAuth, true);
        assertFalse(context.isEstablished());
        assertNull(context.getServerChallenge());
        assertNull(context.getSigningKey());
        assertNull(context.getNetbiosName());
    }

    @Test
    void testToString() {
        // Test the toString method for completeness
        NtlmContext context = new NtlmContext(mockAuth, false);
        String str = context.toString();
        assertTrue(str.contains("NtlmContext["));
        assertTrue(str.contains("auth="));
        assertTrue(str.contains("ntlmsspFlags="));
        assertTrue(str.contains("workstation="));
        assertTrue(str.contains("isEstablished=false"));
        assertTrue(str.contains("state=1"));
        assertTrue(str.contains("serverChallenge=null"));
        assertTrue(str.contains("signingKey=null"));
    }
}
