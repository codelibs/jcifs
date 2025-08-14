package jcifs.pac;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;

import org.junit.jupiter.api.Test;

/**
 * Tests for the PacMac class.
 */
class PacMacTest {

    private static final byte[] TEST_DATA = "test data".getBytes();
    private static final KerberosPrincipal TEST_PRINCIPAL = new KerberosPrincipal("test@REALM");

    /**
     * Test method for
     * {@link jcifs.pac.PacMac#calculateMacArcfourHMACMD5(int, java.security.Key, byte[])}.
     *
     * @throws GeneralSecurityException
     */
    @Test
    void testCalculateMacArcfourHMACMD5() throws GeneralSecurityException {
        // Using a key with a known value for reproducibility
        SecretKeySpec key = new SecretKeySpec(new byte[16], "ARCFOUR");
        byte[] mac = PacMac.calculateMacArcfourHMACMD5(3, key, TEST_DATA);
        assertNotNull(mac);
        assertEquals(16, mac.length);

        // Test with a different key usage
        byte[] mac2 = PacMac.calculateMacArcfourHMACMD5(9, key, TEST_DATA);
        assertNotNull(mac2);
        assertEquals(16, mac2.length);

        // Test with another key usage
        byte[] mac3 = PacMac.calculateMacArcfourHMACMD5(23, key, TEST_DATA);
        assertNotNull(mac3);
        assertEquals(16, mac3.length);

        // Test with a standard usage
        byte[] mac4 = PacMac.calculateMacArcfourHMACMD5(15, key, TEST_DATA);
        assertNotNull(mac4);
        assertEquals(16, mac4.length);
    }

    /**
     * Test method for
     * {@link jcifs.pac.PacMac#calculateMacHMACAES(int, javax.security.auth.kerberos.KerberosKey, byte[])}.
     *
     * @throws GeneralSecurityException
     */
    @Test
    void testCalculateMacHMACAES() throws GeneralSecurityException {
        KerberosKey key = new KerberosKey(TEST_PRINCIPAL, new byte[16], PacSignature.ETYPE_AES128_CTS_HMAC_SHA1_96, 0);
        byte[] mac = PacMac.calculateMacHMACAES(17, key, TEST_DATA);
        assertNotNull(mac);
        assertEquals(12, mac.length);
    }

    /**
     * Test method for
     * {@link jcifs.pac.PacMac#deriveKeyAES(javax.security.auth.kerberos.KerberosKey, byte[])}.
     *
     * @throws GeneralSecurityException
     */
    @Test
    void testDeriveKeyAES() throws GeneralSecurityException {
        KerberosKey key = new KerberosKey(TEST_PRINCIPAL, new byte[16], PacSignature.ETYPE_AES128_CTS_HMAC_SHA1_96, 0);
        byte[] constant = "constant".getBytes();
        byte[] derivedKey = PacMac.deriveKeyAES(key, constant);
        assertNotNull(derivedKey);
        assertEquals(16, derivedKey.length);

        // Test with a different key size
        KerberosKey key256 = new KerberosKey(TEST_PRINCIPAL, new byte[32], PacSignature.ETYPE_AES256_CTS_HMAC_SHA1_96, 0);
        byte[] derivedKey256 = PacMac.deriveKeyAES(key256, constant);
        assertNotNull(derivedKey256);
        assertEquals(32, derivedKey256.length);
    }

    /**
     * Test method for {@link jcifs.pac.PacMac#expandNFold(byte[], int)}.
     */
    @Test
    void testExpandNFold() {
        // Test basic functionality
        byte[] data = { 1, 2, 3 };
        int outlen = 5;
        byte[] expanded = PacMac.expandNFold(data, outlen);
        assertNotNull(expanded);
        assertEquals(outlen, expanded.length);

        // Test vectors from RFC 3961 Appendix A.1
        // 64-fold("012345")
        verifyNfold("012345", 8,
                new byte[] { (byte) 0xbe, (byte) 0x07, (byte) 0x26, (byte) 0x31, (byte) 0x27, (byte) 0x6b, (byte) 0x19, (byte) 0x55 });

        // 56-fold("password")
        verifyNfold("password", 7,
                new byte[] { (byte) 0x78, (byte) 0xa0, (byte) 0x7b, (byte) 0x6c, (byte) 0xaf, (byte) 0x85, (byte) 0xfa });

        // 64-fold("Rough Consensus, and Running Code")
        verifyNfold("Rough Consensus, and Running Code", 8,
                new byte[] { (byte) 0xbb, (byte) 0x6e, (byte) 0xd3, (byte) 0x08, (byte) 0x70, (byte) 0xb7, (byte) 0xf0, (byte) 0xe0 });

        // 64-fold("kerberos")
        verifyNfold("kerberos", 8,
                new byte[] { (byte) 0x6b, (byte) 0x65, (byte) 0x72, (byte) 0x62, (byte) 0x65, (byte) 0x72, (byte) 0x6f, (byte) 0x73 });
    }

    /**
     * Helper method to verify n-fold expansion.
     */
    private void verifyNfold(String input, int outlen, byte[] expected) {
        byte[] result = PacMac.expandNFold(input.getBytes(), outlen);
        assertArrayEquals(expected, result, String.format("n-fold expansion failed for input '%s'", input));
    }

    /**
     * Test method for
     * {@link jcifs.pac.PacMac#calculateMac(int, java.util.Map, byte[])}.
     *
     * @throws PACDecodingException
     */
    @Test
    void testCalculateMac() throws PACDecodingException {
        Map<Integer, KerberosKey> keys = new HashMap<>();
        KerberosKey hmacKey = new KerberosKey(TEST_PRINCIPAL, new byte[16], PacSignature.ETYPE_ARCFOUR_HMAC, 0);
        KerberosKey aes128Key = new KerberosKey(TEST_PRINCIPAL, new byte[16], PacSignature.ETYPE_AES128_CTS_HMAC_SHA1_96, 0);
        KerberosKey aes256Key = new KerberosKey(TEST_PRINCIPAL, new byte[32], PacSignature.ETYPE_AES256_CTS_HMAC_SHA1_96, 0);

        keys.put(PacSignature.ETYPE_ARCFOUR_HMAC, hmacKey);
        keys.put(PacSignature.ETYPE_AES128_CTS_HMAC_SHA1_96, aes128Key);
        keys.put(PacSignature.ETYPE_AES256_CTS_HMAC_SHA1_96, aes256Key);

        // Test HMAC-MD5
        byte[] mac1 = PacMac.calculateMac(PacSignature.KERB_CHECKSUM_HMAC_MD5, keys, TEST_DATA);
        assertNotNull(mac1);
        assertEquals(16, mac1.length);

        // Test AES128
        byte[] mac2 = PacMac.calculateMac(PacSignature.HMAC_SHA1_96_AES128, keys, TEST_DATA);
        assertNotNull(mac2);
        assertEquals(12, mac2.length);

        // Test AES256
        byte[] mac3 = PacMac.calculateMac(PacSignature.HMAC_SHA1_96_AES256, keys, TEST_DATA);
        assertNotNull(mac3);
        assertEquals(12, mac3.length);
    }

    /**
     * Test calculateMac with a missing key.
     */
    @Test
    void testCalculateMacMissingKey() {
        Map<Integer, KerberosKey> keys = new HashMap<>(); // Empty map
        PACDecodingException e =
                assertThrows(PACDecodingException.class, () -> PacMac.calculateMac(PacSignature.KERB_CHECKSUM_HMAC_MD5, keys, TEST_DATA));
        assertEquals("Missing key", e.getMessage());
    }

    /**
     * Test calculateMac with an invalid algorithm type.
     */
    @Test
    void testCalculateMacInvalidAlgorithm() {
        Map<Integer, KerberosKey> keys = new HashMap<>();
        KerberosKey hmacKey = new KerberosKey(TEST_PRINCIPAL, new byte[16], PacSignature.ETYPE_ARCFOUR_HMAC, 0);
        keys.put(PacSignature.ETYPE_ARCFOUR_HMAC, hmacKey);

        PACDecodingException e = assertThrows(PACDecodingException.class, () -> PacMac.calculateMac(-1, keys, TEST_DATA)); // Invalid type
        assertEquals("Invalid MAC algorithm", e.getMessage());
    }
}
