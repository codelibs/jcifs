package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.ShortBufferException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.util.Encdec;

@ExtendWith(MockitoExtension.class)
class NtlmUtilTest {

    @Mock
    CIFSContext cifsContext;

    @Mock
    Configuration configuration;

    // Helper: decode hex string to bytes
    private static byte[] hex(String s) {
        String clean = s.replaceAll("[^0-9A-Fa-f]", "");
        int len = clean.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(clean.substring(i, i + 2), 16);
        }
        return out;
    }

    @Test
    @DisplayName("getNTHash: known vector for 'password'")
    void testGetNTHash_knownVector() {
        // Arrange
        String password = "password";
        // Known NT hash for "password" (UTF-16LE MD4)
        // This is a well-known test vector: password -> 8846F7EAEE8FB117AD06BDD830B7586C
        byte[] expected = hex("8846F7EAEE8FB117AD06BDD830B7586C");

        // Act
        byte[] actual = NtlmUtil.getNTHash(password);

        // Assert
        assertArrayEquals(expected, actual, "NT hash must match known test vector");
    }

    @Test
    @DisplayName("getNTHash: verify different passwords produce different hashes")
    void testGetNTHash_differentPasswords() {
        // Arrange
        String password1 = "password";
        String password2 = "Password";

        // Act
        byte[] hash1 = NtlmUtil.getNTHash(password1);
        byte[] hash2 = NtlmUtil.getNTHash(password2);

        // Assert
        assertFalse(Arrays.equals(hash1, hash2), "Different passwords should produce different hashes");
        assertEquals(16, hash1.length, "NT hash should be 16 bytes");
        assertEquals(16, hash2.length, "NT hash should be 16 bytes");
    }

    @Test
    @DisplayName("getNTHash: null password throws NPE with message")
    void testGetNTHash_null() {
        NullPointerException ex = assertThrows(NullPointerException.class, () -> NtlmUtil.getNTHash((String) null));
        assertEquals("Password parameter is required", ex.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = { "", "password", "pässwörd", "1234567890abcdef" })
    @DisplayName("nTOWFv1 equals getNTHash across inputs")
    void testNTOWFv1_delegatesToGetNTHash(String password) {
        // Act
        byte[] h1 = NtlmUtil.nTOWFv1(password);
        byte[] h2 = NtlmUtil.getNTHash(password);

        // Assert
        assertArrayEquals(h2, h1, "nTOWFv1 should return NT hash");
        assertEquals(16, h1.length, "NT hash length is 16 bytes");
    }

    @Test
    @DisplayName("nTOWFv2: overloads produce same result and domain affects key")
    void testNTOWFv2_overloadsAndDomainSensitivity() {
        // Arrange
        String domain = "Domain";
        String user = "User";
        String password = "password";

        // Act
        byte[] viaHash = NtlmUtil.nTOWFv2(domain, user, NtlmUtil.getNTHash(password));
        byte[] viaPassword = NtlmUtil.nTOWFv2(domain, user, password);

        // Assert: overloads consistent
        assertArrayEquals(viaHash, viaPassword, "Both overloads must compute same NTLMv2 key");

        // Changing domain should change the key (domain is part of MAC input)
        byte[] differentDomain = NtlmUtil.nTOWFv2("DOMAIN", user, password);
        assertFalse(Arrays.equals(viaPassword, differentDomain), "Different domain should produce a different key");
    }

    @Test
    @DisplayName("computeResponse: HMAC(server||clientData) prepended to clientData")
    void testComputeResponse_basic() {
        // Arrange
        byte[] key = hex("0102030405060708090A0B0C0D0E0F10");
        byte[] serverChallenge = hex("1122334455667788");
        byte[] clientData = hex("A0A1A2A3A4");

        // Act
        byte[] result = NtlmUtil.computeResponse(key, serverChallenge, clientData, 0, clientData.length);

        // Assert: result = mac(16) + clientData
        assertEquals(16 + clientData.length, result.length);
        assertArrayEquals(clientData, Arrays.copyOfRange(result, 16, 16 + clientData.length));
    }

    @Test
    @DisplayName("getLMv2Response(byte[]): delegates to computeResponse")
    void testGetLMv2Response_bytes_delegates() {
        // Arrange
        byte[] key = hex("000102030405060708090A0B0C0D0E0F");
        byte[] server = hex("0102030405060708");
        byte[] client = hex("FEEDFACECAFEBEEF");

        // Act
        byte[] expected = NtlmUtil.computeResponse(key, server, client, 0, client.length);
        byte[] actual = NtlmUtil.getLMv2Response(key, server, client);

        // Assert
        assertArrayEquals(expected, actual);
    }

    @Test
    @DisplayName("getLMv2Response(String,...): 24-byte response embeds client challenge")
    void testGetLMv2Response_strings_embedsClientChallenge() throws GeneralSecurityException {
        // Arrange
        String domain = "DOMAIN";
        String user = "User";
        String password = "password";
        byte[] challenge = hex("0102030405060708");
        byte[] clientChallenge = hex("0011223344556677");

        // Act
        byte[] resp = NtlmUtil.getLMv2Response(domain, user, password, challenge, clientChallenge);

        // Assert
        assertEquals(24, resp.length, "LMv2 response length must be 24");
        assertArrayEquals(clientChallenge, Arrays.copyOfRange(resp, 16, 24), "Client challenge must be copied to last 8 bytes");
        assertFalse(Arrays.equals(new byte[24], resp), "Response must not be all zeros");
    }

    @Test
    @DisplayName("getLMv2Response(byte[]): empty client data allowed")
    void testGetLMv2Response_bytes_emptyClientData() {
        // Arrange
        byte[] key = hex("000102030405060708090A0B0C0D0E0F");
        byte[] server = hex("0102030405060708");
        byte[] client = new byte[0];

        // Act
        byte[] resp = NtlmUtil.getLMv2Response(key, server, client);

        // Assert: HMAC(16) only
        assertEquals(16, resp.length);
    }

    @Test
    @DisplayName("getNTLMResponse: overloads produce equal 24-byte response")
    void testGetNTLMResponse_overloads() throws GeneralSecurityException {
        // Arrange
        String password = "password";
        byte[] challenge = hex("1122334455667788");

        // Act
        byte[] r1 = NtlmUtil.getNTLMResponse(password, challenge);
        byte[] r2 = NtlmUtil.getNTLMResponse(NtlmUtil.getNTHash(password), challenge);

        // Assert
        assertArrayEquals(r2, r1);
        assertEquals(24, r1.length);
    }

    @Test
    @DisplayName("getNTLM2Response: returns 24 bytes and changes with inputs")
    void testGetNTLM2Response_basic() throws GeneralSecurityException {
        // Arrange
        byte[] pwdHash = NtlmUtil.getNTHash("password");
        byte[] server = hex("0102030405060708");
        byte[] client = hex("DEADBEEFCAFEBABE");

        // Act
        byte[] a = NtlmUtil.getNTLM2Response(pwdHash, server, client);
        server[7] ^= 0x01; // mutate
        byte[] b = NtlmUtil.getNTLM2Response(pwdHash, server, client);

        // Assert
        assertEquals(24, a.length);
        assertFalse(Arrays.equals(a, b), "Changing server challenge must alter the response");
    }

    @Test
    @DisplayName("getNTLMv2Response: blob structure and computeResponse match")
    void testGetNTLMv2Response_blobAndCompute() {
        // Arrange
        byte[] key = NtlmUtil.nTOWFv2("Domain", "User", "password");
        byte[] server = hex("0102030405060708");
        byte[] clientChallenge = hex("0102030405060708");
        long nanos1601 = 0x1122334455667788L;
        byte[] avPairs = hex("A1A2A3A4");

        // Manually build the expected NTLMv2 blob (same as production code)
        int avPairsLength = avPairs.length;
        byte[] blob = new byte[28 + avPairsLength + 4];
        Encdec.enc_uint32le(0x00000101, blob, 0); // Header
        Encdec.enc_uint32le(0x00000000, blob, 4); // Reserved
        Encdec.enc_uint64le(nanos1601, blob, 8);
        System.arraycopy(clientChallenge, 0, blob, 16, 8);
        Encdec.enc_uint32le(0x00000000, blob, 24); // Unknown
        System.arraycopy(avPairs, 0, blob, 28, avPairsLength);
        Encdec.enc_uint32le(0x00000000, blob, 28 + avPairsLength);

        // Act
        byte[] expected = NtlmUtil.computeResponse(key, server, blob, 0, blob.length);
        byte[] actual = NtlmUtil.getNTLMv2Response(key, server, clientChallenge, nanos1601, avPairs);

        // Assert
        assertArrayEquals(expected, actual, "Computed response must match manual construction");
        // Also verify client challenge sits at mac(16) + blob offset 16
        assertArrayEquals(clientChallenge, Arrays.copyOfRange(actual, 16 + 16, 16 + 16 + 8));
    }

    @Test
    @DisplayName("getPreNTLMResponse: uses OEM bytes, truncates to 14, verifies interactions")
    void testGetPreNTLMResponse_basicAndInteractions() throws Exception {
        // Arrange
        when(cifsContext.getConfig()).thenReturn(configuration);
        when(configuration.getOemEncoding()).thenReturn("Cp850");
        String password14 = "ABCDEFGHIJKLMN"; // 14 chars
        String password15 = "ABCDEFGHIJKLMNO"; // 15 chars, same first 14
        byte[] challenge = hex("0102030405060708");

        // Act
        byte[] r14 = NtlmUtil.getPreNTLMResponse(cifsContext, password14, challenge);
        byte[] r15 = NtlmUtil.getPreNTLMResponse(cifsContext, password15, challenge);

        // Assert: equal because only first 14 OEM bytes are used
        assertArrayEquals(r14, r15, "Only first 14 OEM bytes affect Pre-NTLM response");
        assertEquals(24, r14.length);

        // Verify collaborator interactions
        verify(cifsContext, atLeastOnce()).getConfig();
        verify(configuration, atLeastOnce()).getOemEncoding();
        verifyNoMoreInteractions(cifsContext, configuration);
    }

    @Test
    @DisplayName("getPreNTLMResponse: unsupported OEM encoding propagates as runtime exception")
    void testGetPreNTLMResponse_invalidEncoding() {
        // Arrange
        when(cifsContext.getConfig()).thenReturn(configuration);
        when(configuration.getOemEncoding()).thenReturn("X-INVALID-ENCODING-NOT-EXISTENT");

        // Act + Assert
        RuntimeException ex = assertThrows(RuntimeException.class, () -> NtlmUtil.getPreNTLMResponse(cifsContext, "password", new byte[8]));
        assertTrue(ex.getMessage().contains("Unsupported OEM encoding"));
        verify(cifsContext, atLeastOnce()).getConfig();
        verify(configuration, atLeastOnce()).getOemEncoding();
    }

    @Test
    @DisplayName("E: splits 7-byte keys into 8-byte DES blocks and concatenates")
    void testE_blockSplitConsistency() throws ShortBufferException {
        // Arrange
        byte[] key14 = hex("01020304050607 11121314151617"); // two 7-byte chunks
        byte[] key7 = Arrays.copyOfRange(key14, 0, 7);
        byte[] data8 = NtlmUtil.S8;
        byte[] out14 = new byte[16];
        byte[] out7 = new byte[8];

        // Act
        NtlmUtil.E(key14, data8, out14);
        NtlmUtil.E(key7, data8, out7);

        // Assert: first block identical to single-chunk encryption
        assertArrayEquals(Arrays.copyOfRange(out14, 0, 8), out7);
        // And second block is present and not all zeros
        assertFalse(Arrays.equals(new byte[8], Arrays.copyOfRange(out14, 8, 16)));
    }
}
