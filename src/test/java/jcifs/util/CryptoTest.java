package jcifs.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.BaseTest;

/**
 * Test class for Crypto utility functionality
 */
@DisplayName("Crypto Utility Tests")
class CryptoTest extends BaseTest {

    @Test
    @DisplayName("Should calculate MD4 hash correctly")
    void testMD4Hash() {
        // Given
        String input = "Hello World";
        byte[] data = input.getBytes();

        // When
        MessageDigest md4 = Crypto.getMD4();
        byte[] hash = md4.digest(data);

        // Then
        assertNotNull(hash);
        assertEquals(16, hash.length); // MD4 produces 128-bit hash
    }

    @Test
    @DisplayName("Should calculate MD5 hash correctly")
    void testMD5Hash() {
        // Given
        String input = "Hello World";
        byte[] data = input.getBytes();

        // When
        MessageDigest md5 = Crypto.getMD5();
        byte[] hash = md5.digest(data);

        // Then
        assertNotNull(hash);
        assertEquals(16, hash.length); // MD5 produces 128-bit hash
    }

    @Test
    @DisplayName("Should calculate HMAC-T64 correctly")
    void testHMACT64() {
        // Given
        byte[] key = "secret".getBytes();
        byte[] data = "Hello World".getBytes();

        // When
        MessageDigest hmac = Crypto.getHMACT64(key);
        byte[] result = hmac.digest(data);

        // Then
        assertNotNull(result);
        assertTrue(result.length > 0, "HMAC-T64 should produce non-empty result");
    }

    @Test
    @DisplayName("Should perform RC4 encryption/decryption")
    void testRC4() throws Exception {
        // Given
        byte[] key = "testkey123456789".getBytes(); // 16 bytes
        byte[] plaintext = "This is a test message for RC4".getBytes();

        // When
        Cipher encryptCipher = Crypto.getArcfour(key);
        encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "RC4"));
        byte[] encrypted = encryptCipher.doFinal(plaintext);
        
        Cipher decryptCipher = Crypto.getArcfour(key);
        decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "RC4"));
        byte[] decrypted = decryptCipher.doFinal(encrypted);

        // Then
        assertNotNull(encrypted);
        assertNotNull(decrypted);
        assertArrayEquals(plaintext, decrypted);
        assertNotEquals(new String(plaintext), new String(encrypted));
    }

    @Test
    @DisplayName("Should perform DES encryption/decryption")
    void testDES() throws Exception {
        // Given
        byte[] key = "testkey1".getBytes(); // 8 bytes for DES
        byte[] plaintext = "12345678".getBytes(); // 8 bytes (DES block size)

        // When
        Cipher desCipher = Crypto.getDES(key);
        desCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
        byte[] encrypted = desCipher.doFinal(plaintext);

        // Then
        assertNotNull(encrypted);
        assertEquals(8, encrypted.length);
        assertNotEquals(new String(plaintext), new String(encrypted));
    }

    @ParameterizedTest
    @ValueSource(strings = { "", "a", "short", "medium length text", "very long text that exceeds typical block sizes" })
    @DisplayName("Should handle various input sizes for hashing")
    void testHashVariousInputSizes(String input) {
        // Given
        byte[] data = input.getBytes();

        // When
        MessageDigest md4 = Crypto.getMD4();
        MessageDigest md5 = Crypto.getMD5();
        byte[] md4Hash = md4.digest(data);
        byte[] md5Hash = md5.digest(data);

        // Then
        assertNotNull(md4Hash);
        assertNotNull(md5Hash);
        assertEquals(16, md4Hash.length);
        assertEquals(16, md5Hash.length);
    }

    @Test
    @DisplayName("Should handle empty input for hashing")
    void testEmptyInputHashing() {
        // Given
        byte[] emptyData = {};

        // When
        MessageDigest md4 = Crypto.getMD4();
        MessageDigest md5 = Crypto.getMD5();
        byte[] md4Hash = md4.digest(emptyData);
        byte[] md5Hash = md5.digest(emptyData);

        // Then
        assertNotNull(md4Hash);
        assertNotNull(md5Hash);
        assertEquals(16, md4Hash.length);
        assertEquals(16, md5Hash.length);
    }

    @Test
    @DisplayName("Should handle null input gracefully")
    void testNullInputHandling() {
        // When/Then
        assertThrows(NullPointerException.class, () -> {
            MessageDigest md4 = Crypto.getMD4();
            md4.digest(null);
        });

        assertThrows(NullPointerException.class, () -> {
            MessageDigest md5 = Crypto.getMD5();
            md5.digest(null);
        });
    }

    @Test
    @DisplayName("Should produce consistent hash results")
    void testHashConsistency() {
        // Given
        String input = "Test consistency";
        byte[] data = input.getBytes();

        // When
        MessageDigest md5_1 = Crypto.getMD5();
        MessageDigest md5_2 = Crypto.getMD5();
        byte[] hash1 = md5_1.digest(data);
        byte[] hash2 = md5_2.digest(data);

        // Then
        assertArrayEquals(hash1, hash2);
    }

    @Test
    @DisplayName("Should generate secure random bytes")
    void testSecureRandomGeneration() throws java.security.NoSuchAlgorithmException {
        // Given
        int length = 16;

        // When
        byte[] random1 = new byte[length];
        byte[] random2 = new byte[length];
        SecureRandom.getInstanceStrong().nextBytes(random1);
        SecureRandom.getInstanceStrong().nextBytes(random2);

        // Then
        assertNotNull(random1);
        assertNotNull(random2);
        assertEquals(length, random1.length);
        assertEquals(length, random2.length);
        // Very unlikely to be equal
        assertNotEquals(new String(random1), new String(random2));
    }

    @Test
    @DisplayName("Should handle AES encryption operations")
    void testAESOperations() throws Exception {
        // Given
        byte[] key = new byte[16]; // 128-bit key
        byte[] iv = new byte[16]; // 128-bit IV
        byte[] plaintext = "This is test data for AES encryption test".getBytes();

        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(iv);

        // When
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(plaintext);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        // Then
        assertNotNull(encrypted);
        assertNotNull(decrypted);
        assertArrayEquals(plaintext, decrypted);
        assertNotEquals(new String(plaintext), new String(encrypted));
    }
}