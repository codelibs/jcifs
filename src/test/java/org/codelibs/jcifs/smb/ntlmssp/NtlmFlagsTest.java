package org.codelibs.jcifs.smb.ntlmssp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * Test class for NtlmFlags, verifying the values of all defined constants.
 */
public class NtlmFlagsTest {

    @Test
    void testNtlmNegotiateUnicode() {
        assertEquals(0x00000001, NtlmFlags.NTLMSSP_NEGOTIATE_UNICODE, "NTLMSSP_NEGOTIATE_UNICODE should be 0x00000001");
    }

    @Test
    void testNtlmNegotiateOem() {
        assertEquals(0x00000002, NtlmFlags.NTLMSSP_NEGOTIATE_OEM, "NTLMSSP_NEGOTIATE_OEM should be 0x00000002");
    }

    @Test
    void testNtlmRequestTarget() {
        assertEquals(0x00000004, NtlmFlags.NTLMSSP_REQUEST_TARGET, "NTLMSSP_REQUEST_TARGET should be 0x00000004");
    }

    @Test
    void testNtlmNegotiateSign() {
        assertEquals(0x00000010, NtlmFlags.NTLMSSP_NEGOTIATE_SIGN, "NTLMSSP_NEGOTIATE_SIGN should be 0x00000010");
    }

    @Test
    void testNtlmNegotiateSeal() {
        assertEquals(0x00000020, NtlmFlags.NTLMSSP_NEGOTIATE_SEAL, "NTLMSSP_NEGOTIATE_SEAL should be 0x00000020");
    }

    @Test
    void testNtlmNegotiateDatagramStyle() {
        assertEquals(0x00000040, NtlmFlags.NTLMSSP_NEGOTIATE_DATAGRAM_STYLE, "NTLMSSP_NEGOTIATE_DATAGRAM_STYLE should be 0x00000040");
    }

    @Test
    void testNtlmNegotiateLmKey() {
        assertEquals(0x00000080, NtlmFlags.NTLMSSP_NEGOTIATE_LM_KEY, "NTLMSSP_NEGOTIATE_LM_KEY should be 0x00000080");
    }

    @Test
    void testNtlmNegotiateNetware() {
        assertEquals(0x00000100, NtlmFlags.NTLMSSP_NEGOTIATE_NETWARE, "NTLMSSP_NEGOTIATE_NETWARE should be 0x00000100");
    }

    @Test
    void testNtlmNegotiateNtlm() {
        assertEquals(0x00000200, NtlmFlags.NTLMSSP_NEGOTIATE_NTLM, "NTLMSSP_NEGOTIATE_NTLM should be 0x00000200");
    }

    @Test
    void testNtlmNegotiateAnonymous() {
        assertEquals(0x00000800, NtlmFlags.NTLMSSP_NEGOTIATE_ANONYMOUS, "NTLMSSP_NEGOTIATE_ANONYMOUS should be 0x00000800");
    }

    @Test
    void testNtlmNegotiateOemDomainSupplied() {
        assertEquals(0x00001000, NtlmFlags.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED,
                "NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED should be 0x00001000");
    }

    @Test
    void testNtlmNegotiateOemWorkstationSupplied() {
        assertEquals(0x00002000, NtlmFlags.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED,
                "NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED should be 0x00002000");
    }

    @Test
    void testNtlmNegotiateLocalCall() {
        assertEquals(0x00004000, NtlmFlags.NTLMSSP_NEGOTIATE_LOCAL_CALL, "NTLMSSP_NEGOTIATE_LOCAL_CALL should be 0x00004000");
    }

    @Test
    void testNtlmNegotiateAlwaysSign() {
        assertEquals(0x00008000, NtlmFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN, "NTLMSSP_NEGOTIATE_ALWAYS_SIGN should be 0x00008000");
    }

    @Test
    void testNtlmTargetTypeDomain() {
        assertEquals(0x00010000, NtlmFlags.NTLMSSP_TARGET_TYPE_DOMAIN, "NTLMSSP_TARGET_TYPE_DOMAIN should be 0x00010000");
    }

    @Test
    void testNtlmTargetTypeServer() {
        assertEquals(0x00020000, NtlmFlags.NTLMSSP_TARGET_TYPE_SERVER, "NTLMSSP_TARGET_TYPE_SERVER should be 0x00020000");
    }

    @Test
    void testNtlmTargetTypeShare() {
        assertEquals(0x00040000, NtlmFlags.NTLMSSP_TARGET_TYPE_SHARE, "NTLMSSP_TARGET_TYPE_SHARE should be 0x00040000");
    }

    @Test
    void testNtlmNegotiateExtendedSessionSecurity() {
        assertEquals(0x00080000, NtlmFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
                "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY should be 0x00080000");
    }

    @Test
    void testNtlmRequestInitResponse() {
        assertEquals(0x00100000, NtlmFlags.NTLMSSP_REQUEST_INIT_RESPONSE, "NTLMSSP_REQUEST_INIT_RESPONSE should be 0x00100000");
    }

    @Test
    void testNtlmRequestAcceptResponse() {
        assertEquals(0x00200000, NtlmFlags.NTLMSSP_REQUEST_ACCEPT_RESPONSE, "NTLMSSP_REQUEST_ACCEPT_RESPONSE should be 0x00200000");
    }

    @Test
    void testNtlmRequestNonNtSessionKey() {
        assertEquals(0x00400000, NtlmFlags.NTLMSSP_REQUEST_NON_NT_SESSION_KEY, "NTLMSSP_REQUEST_NON_NT_SESSION_KEY should be 0x00400000");
    }

    @Test
    void testNtlmNegotiateTargetInfo() {
        assertEquals(0x00800000, NtlmFlags.NTLMSSP_NEGOTIATE_TARGET_INFO, "NTLMSSP_NEGOTIATE_TARGET_INFO should be 0x00800000");
    }

    @Test
    void testNtlmNegotiateVersion() {
        assertEquals(0x02000000, NtlmFlags.NTLMSSP_NEGOTIATE_VERSION, "NTLMSSP_NEGOTIATE_VERSION should be 0x02000000");
    }

    @Test
    void testNtlmNegotiate128() {
        assertEquals(0x20000000, NtlmFlags.NTLMSSP_NEGOTIATE_128, "NTLMSSP_NEGOTIATE_128 should be 0x20000000");
    }

    @Test
    void testNtlmNegotiateKeyExch() {
        assertEquals(0x40000000, NtlmFlags.NTLMSSP_NEGOTIATE_KEY_EXCH, "NTLMSSP_NEGOTIATE_KEY_EXCH should be 0x40000000");
    }

    @Test
    void testNtlmNegotiate56() {
        assertEquals(0x80000000, NtlmFlags.NTLMSSP_NEGOTIATE_56, "NTLMSSP_NEGOTIATE_56 should be 0x80000000");
    }
}
