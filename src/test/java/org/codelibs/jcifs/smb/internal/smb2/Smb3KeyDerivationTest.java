package org.codelibs.jcifs.smb.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Test class for Smb3KeyDerivation.
 * Tests the SMB3 SP800-108 Counter Mode Key Derivation implementation.
 */
@DisplayName("Smb3KeyDerivation Tests")
class Smb3KeyDerivationTest {

    private byte[] sessionKey;
    private byte[] preauthIntegrity;

    @BeforeEach
    void setUp() {
        // Initialize test keys
        sessionKey = new byte[16]; // 128-bit session key
        preauthIntegrity = new byte[64]; // Preauth integrity hash
        new SecureRandom().nextBytes(sessionKey);
        new SecureRandom().nextBytes(preauthIntegrity);
    }

    @Test
    @DisplayName("Should derive signing key for SMB 3.0.0 dialect")
    void testDeriveSigningKey_SMB300() {
        // Given
        int dialect = Smb2Constants.SMB2_DIALECT_0300;

        // When
        byte[] signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, preauthIntegrity);

        // Then
        assertNotNull(signingKey, "Signing key should not be null");
        assertEquals(16, signingKey.length, "Signing key should be 16 bytes");
        assertFalse(Arrays.equals(sessionKey, signingKey), "Signing key should be different from session key");
    }

    @Test
    @DisplayName("Should derive signing key for SMB 3.0.2 dialect")
    void testDeriveSigningKey_SMB302() {
        // Given
        int dialect = Smb2Constants.SMB2_DIALECT_0302;

        // When
        byte[] signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, preauthIntegrity);

        // Then
        assertNotNull(signingKey, "Signing key should not be null");
        assertEquals(16, signingKey.length, "Signing key should be 16 bytes");
        assertFalse(Arrays.equals(sessionKey, signingKey), "Signing key should be different from session key");
    }

    @Test
    @DisplayName("Should derive signing key for SMB 3.1.1 dialect")
    void testDeriveSigningKey_SMB311() {
        // Given
        int dialect = Smb2Constants.SMB2_DIALECT_0311;

        // When
        byte[] signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, preauthIntegrity);

        // Then
        assertNotNull(signingKey, "Signing key should not be null");
        assertEquals(16, signingKey.length, "Signing key should be 16 bytes");
        assertFalse(Arrays.equals(sessionKey, signingKey), "Signing key should be different from session key");
    }

    @Test
    @DisplayName("Should derive different signing keys for different dialects")
    void testDeriveSigningKey_DifferentDialects() {
        // When
        byte[] signingKey300 = Smb3KeyDerivation.deriveSigningKey(Smb2Constants.SMB2_DIALECT_0300, sessionKey, preauthIntegrity);
        byte[] signingKey311 = Smb3KeyDerivation.deriveSigningKey(Smb2Constants.SMB2_DIALECT_0311, sessionKey, preauthIntegrity);

        // Then
        assertFalse(Arrays.equals(signingKey300, signingKey311), "Signing keys should be different for different dialects");
    }

    @Test
    @DisplayName("Should derive application key for SMB 3.0.0 dialect")
    void testDeriveApplicationKey_SMB300() {
        // Given
        int dialect = Smb2Constants.SMB2_DIALECT_0300;

        // When
        byte[] appKey = Smb3KeyDerivation.dervieApplicationKey(dialect, sessionKey, preauthIntegrity);

        // Then
        assertNotNull(appKey, "Application key should not be null");
        assertEquals(16, appKey.length, "Application key should be 16 bytes");
        assertFalse(Arrays.equals(sessionKey, appKey), "Application key should be different from session key");
    }

    @Test
    @DisplayName("Should derive application key for SMB 3.1.1 dialect")
    void testDeriveApplicationKey_SMB311() {
        // Given
        int dialect = Smb2Constants.SMB2_DIALECT_0311;

        // When
        byte[] appKey = Smb3KeyDerivation.dervieApplicationKey(dialect, sessionKey, preauthIntegrity);

        // Then
        assertNotNull(appKey, "Application key should not be null");
        assertEquals(16, appKey.length, "Application key should be 16 bytes");
        assertFalse(Arrays.equals(sessionKey, appKey), "Application key should be different from session key");
    }

    @Test
    @DisplayName("Should derive different application keys for different dialects")
    void testDeriveApplicationKey_DifferentDialects() {
        // When
        byte[] appKey300 = Smb3KeyDerivation.dervieApplicationKey(Smb2Constants.SMB2_DIALECT_0300, sessionKey, preauthIntegrity);
        byte[] appKey311 = Smb3KeyDerivation.dervieApplicationKey(Smb2Constants.SMB2_DIALECT_0311, sessionKey, preauthIntegrity);

        // Then
        assertFalse(Arrays.equals(appKey300, appKey311), "Application keys should be different for different dialects");
    }

    @Test
    @DisplayName("Should derive encryption key for SMB 3.0.0 dialect")
    void testDeriveEncryptionKey_SMB300() {
        // Given
        int dialect = Smb2Constants.SMB2_DIALECT_0300;

        // When
        byte[] encKey = Smb3KeyDerivation.deriveEncryptionKey(dialect, sessionKey, preauthIntegrity);

        // Then
        assertNotNull(encKey, "Encryption key should not be null");
        assertEquals(16, encKey.length, "Encryption key should be 16 bytes");
        assertFalse(Arrays.equals(sessionKey, encKey), "Encryption key should be different from session key");
    }

    @Test
    @DisplayName("Should derive encryption key for SMB 3.1.1 dialect")
    void testDeriveEncryptionKey_SMB311() {
        // Given
        int dialect = Smb2Constants.SMB2_DIALECT_0311;

        // When
        byte[] encKey = Smb3KeyDerivation.deriveEncryptionKey(dialect, sessionKey, preauthIntegrity);

        // Then
        assertNotNull(encKey, "Encryption key should not be null");
        assertEquals(16, encKey.length, "Encryption key should be 16 bytes");
        assertFalse(Arrays.equals(sessionKey, encKey), "Encryption key should be different from session key");
    }

    @Test
    @DisplayName("Should derive different encryption keys for different dialects")
    void testDeriveEncryptionKey_DifferentDialects() {
        // When
        byte[] encKey300 = Smb3KeyDerivation.deriveEncryptionKey(Smb2Constants.SMB2_DIALECT_0300, sessionKey, preauthIntegrity);
        byte[] encKey311 = Smb3KeyDerivation.deriveEncryptionKey(Smb2Constants.SMB2_DIALECT_0311, sessionKey, preauthIntegrity);

        // Then
        assertFalse(Arrays.equals(encKey300, encKey311), "Encryption keys should be different for different dialects");
    }

    @Test
    @DisplayName("Should derive decryption key for SMB 3.0.0 dialect")
    void testDeriveDecryptionKey_SMB300() {
        // Given
        int dialect = Smb2Constants.SMB2_DIALECT_0300;

        // When
        byte[] decKey = Smb3KeyDerivation.deriveDecryptionKey(dialect, sessionKey, preauthIntegrity);

        // Then
        assertNotNull(decKey, "Decryption key should not be null");
        assertEquals(16, decKey.length, "Decryption key should be 16 bytes");
        assertFalse(Arrays.equals(sessionKey, decKey), "Decryption key should be different from session key");
    }

    @Test
    @DisplayName("Should derive decryption key for SMB 3.1.1 dialect")
    void testDeriveDecryptionKey_SMB311() {
        // Given
        int dialect = Smb2Constants.SMB2_DIALECT_0311;

        // When
        byte[] decKey = Smb3KeyDerivation.deriveDecryptionKey(dialect, sessionKey, preauthIntegrity);

        // Then
        assertNotNull(decKey, "Decryption key should not be null");
        assertEquals(16, decKey.length, "Decryption key should be 16 bytes");
        assertFalse(Arrays.equals(sessionKey, decKey), "Decryption key should be different from session key");
    }

    @Test
    @DisplayName("Should derive different decryption keys for different dialects")
    void testDeriveDecryptionKey_DifferentDialects() {
        // When
        byte[] decKey300 = Smb3KeyDerivation.deriveDecryptionKey(Smb2Constants.SMB2_DIALECT_0300, sessionKey, preauthIntegrity);
        byte[] decKey311 = Smb3KeyDerivation.deriveDecryptionKey(Smb2Constants.SMB2_DIALECT_0311, sessionKey, preauthIntegrity);

        // Then
        assertFalse(Arrays.equals(decKey300, decKey311), "Decryption keys should be different for different dialects");
    }

    @Test
    @DisplayName("Should derive different keys for different purposes with same dialect")
    void testDeriveKeys_DifferentPurposes() {
        // Given
        int dialect = Smb2Constants.SMB2_DIALECT_0311;

        // When
        byte[] signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, preauthIntegrity);
        byte[] appKey = Smb3KeyDerivation.dervieApplicationKey(dialect, sessionKey, preauthIntegrity);
        byte[] encKey = Smb3KeyDerivation.deriveEncryptionKey(dialect, sessionKey, preauthIntegrity);
        byte[] decKey = Smb3KeyDerivation.deriveDecryptionKey(dialect, sessionKey, preauthIntegrity);

        // Then - all keys should be different from each other
        assertFalse(Arrays.equals(signingKey, appKey), "Signing and application keys should be different");
        assertFalse(Arrays.equals(signingKey, encKey), "Signing and encryption keys should be different");
        assertFalse(Arrays.equals(signingKey, decKey), "Signing and decryption keys should be different");
        assertFalse(Arrays.equals(appKey, encKey), "Application and encryption keys should be different");
        assertFalse(Arrays.equals(appKey, decKey), "Application and decryption keys should be different");
        assertFalse(Arrays.equals(encKey, decKey), "Encryption and decryption keys should be different");
    }

    @Test
    @DisplayName("Should produce consistent keys for same input")
    void testDeriveKeys_Consistency() {
        // Given
        int dialect = Smb2Constants.SMB2_DIALECT_0311;

        // When - derive same key twice
        byte[] signingKey1 = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, preauthIntegrity);
        byte[] signingKey2 = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, preauthIntegrity);

        // Then - should produce identical results
        assertArrayEquals(signingKey1, signingKey2, "Same input should produce same output");
    }

    @Test
    @DisplayName("Should handle empty session key")
    void testDeriveKeys_EmptySessionKey() {
        // Given
        byte[] emptySessionKey = new byte[0];
        int dialect = Smb2Constants.SMB2_DIALECT_0311;

        // When
        byte[] signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, emptySessionKey, preauthIntegrity);

        // Then
        assertNotNull(signingKey, "Should handle empty session key");
        assertEquals(16, signingKey.length, "Should still produce 16-byte key");
    }

    @Test
    @DisplayName("Should handle null preauth integrity for SMB 3.0.0")
    void testDeriveKeys_NullPreauthForSMB300() {
        // Given
        int dialect = Smb2Constants.SMB2_DIALECT_0300;

        // When - SMB 3.0.0 doesn't use preauth integrity, so null should be acceptable
        byte[] signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, null);

        // Then
        assertNotNull(signingKey, "Should handle null preauth for SMB 3.0.0");
        assertEquals(16, signingKey.length, "Should produce 16-byte key");
    }

    @Test
    @DisplayName("Should handle large session key")
    void testDeriveKeys_LargeSessionKey() {
        // Given
        byte[] largeSessionKey = new byte[256]; // Larger than typical 16-byte key
        new SecureRandom().nextBytes(largeSessionKey);
        int dialect = Smb2Constants.SMB2_DIALECT_0311;

        // When
        byte[] signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, largeSessionKey, preauthIntegrity);

        // Then
        assertNotNull(signingKey, "Should handle large session key");
        assertEquals(16, signingKey.length, "Should still produce 16-byte key");
    }

    @ParameterizedTest
    @ValueSource(ints = { 0x0300, 0x0302, 0x0310 }) // Non-3.1.1 dialects
    @DisplayName("Should use SMB 3.0.x context for non-3.1.1 dialects")
    void testDeriveKeys_NonSMB311Dialects(int dialect) {
        // When
        byte[] signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, preauthIntegrity);

        // Then
        assertNotNull(signingKey, "Should derive key for dialect: " + dialect);
        assertEquals(16, signingKey.length, "Should produce 16-byte key");

        // Verify it's different from SMB 3.1.1
        byte[] signingKey311 = Smb3KeyDerivation.deriveSigningKey(Smb2Constants.SMB2_DIALECT_0311, sessionKey, preauthIntegrity);
        assertFalse(Arrays.equals(signingKey, signingKey311), "Should be different from SMB 3.1.1 key");
    }

    @Test
    @DisplayName("Should derive keys with specific test vectors")
    void testDeriveKeys_TestVectors() {
        // Given - Use known test vector (simplified for demonstration)
        byte[] testSessionKey = new byte[16];
        Arrays.fill(testSessionKey, (byte) 0xAA);
        byte[] testPreauth = new byte[64];
        Arrays.fill(testPreauth, (byte) 0xBB);

        // When
        byte[] signingKey300 = Smb3KeyDerivation.deriveSigningKey(Smb2Constants.SMB2_DIALECT_0300, testSessionKey, testPreauth);
        byte[] signingKey311 = Smb3KeyDerivation.deriveSigningKey(Smb2Constants.SMB2_DIALECT_0311, testSessionKey, testPreauth);

        // Then - Verify keys are derived and different
        assertNotNull(signingKey300);
        assertNotNull(signingKey311);
        assertEquals(16, signingKey300.length);
        assertEquals(16, signingKey311.length);
        assertFalse(Arrays.equals(signingKey300, signingKey311));
    }

    @Test
    @DisplayName("Should handle different session key sizes")
    void testDeriveKeys_DifferentSessionKeySizes() {
        // Test with various session key sizes
        int[] keySizes = { 8, 16, 24, 32, 64, 128 };
        int dialect = Smb2Constants.SMB2_DIALECT_0311;

        for (int size : keySizes) {
            // Given
            byte[] testKey = new byte[size];
            new SecureRandom().nextBytes(testKey);

            // When
            byte[] derivedKey = Smb3KeyDerivation.deriveSigningKey(dialect, testKey, preauthIntegrity);

            // Then
            assertNotNull(derivedKey, "Should handle " + size + "-byte session key");
            assertEquals(16, derivedKey.length, "Should always produce 16-byte key regardless of input size");
        }
    }

    @Test
    @DisplayName("Should derive unique keys for different session keys")
    void testDeriveKeys_UniqueSessionKeys() {
        // Given
        byte[] sessionKey1 = new byte[16];
        byte[] sessionKey2 = new byte[16];
        new SecureRandom().nextBytes(sessionKey1);
        new SecureRandom().nextBytes(sessionKey2);
        int dialect = Smb2Constants.SMB2_DIALECT_0311;

        // When
        byte[] signingKey1 = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey1, preauthIntegrity);
        byte[] signingKey2 = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey2, preauthIntegrity);

        // Then
        assertFalse(Arrays.equals(signingKey1, signingKey2), "Different session keys should produce different derived keys");
    }

    @Test
    @DisplayName("Should derive unique keys for different preauth values")
    void testDeriveKeys_UniquePreauthValues() {
        // Given
        byte[] preauth1 = new byte[64];
        byte[] preauth2 = new byte[64];
        new SecureRandom().nextBytes(preauth1);
        new SecureRandom().nextBytes(preauth2);
        int dialect = Smb2Constants.SMB2_DIALECT_0311;

        // When
        byte[] signingKey1 = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, preauth1);
        byte[] signingKey2 = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, preauth2);

        // Then
        assertFalse(Arrays.equals(signingKey1, signingKey2),
                "Different preauth values should produce different derived keys for SMB 3.1.1");
    }

    @Test
    @DisplayName("Should handle edge case with all zero session key")
    void testDeriveKeys_AllZeroSessionKey() {
        // Given
        byte[] zeroSessionKey = new byte[16]; // All zeros
        int dialect = Smb2Constants.SMB2_DIALECT_0311;

        // When
        byte[] signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, zeroSessionKey, preauthIntegrity);

        // Then
        assertNotNull(signingKey, "Should handle all-zero session key");
        assertEquals(16, signingKey.length, "Should produce 16-byte key");
        assertFalse(Arrays.equals(zeroSessionKey, signingKey), "Derived key should be different from all-zero input");
    }

    @Test
    @DisplayName("Should handle edge case with all 0xFF session key")
    void testDeriveKeys_AllFFSessionKey() {
        // Given
        byte[] ffSessionKey = new byte[16];
        Arrays.fill(ffSessionKey, (byte) 0xFF);
        int dialect = Smb2Constants.SMB2_DIALECT_0311;

        // When
        byte[] signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, ffSessionKey, preauthIntegrity);

        // Then
        assertNotNull(signingKey, "Should handle all-0xFF session key");
        assertEquals(16, signingKey.length, "Should produce 16-byte key");
        assertFalse(Arrays.equals(ffSessionKey, signingKey), "Derived key should be different from all-0xFF input");
    }
}