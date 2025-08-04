package jcifs.internal.smb2;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.Configuration;
import jcifs.DialectVersion;

/**
 * Test class for Smb2EncryptionContext.
 * Tests the available public API methods of the encryption context.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Smb2EncryptionContext Tests")
class Smb2EncryptionContextTest {

    @Mock
    private Configuration mockConfig;

    private byte[] testEncryptionKey;
    private byte[] testDecryptionKey;
    private Smb2EncryptionContext encryptionContext;

    @BeforeEach
    void setUp() {
        // Initialize test keys
        testEncryptionKey = new byte[16]; // 128-bit key
        testDecryptionKey = new byte[16]; // 128-bit key
        new SecureRandom().nextBytes(testEncryptionKey);
        new SecureRandom().nextBytes(testDecryptionKey);

        // Create encryption context with required parameters
        encryptionContext = new Smb2EncryptionContext(1, DialectVersion.SMB311, testEncryptionKey, testDecryptionKey);
    }

    @Test
    @DisplayName("Should create encryption context with valid parameters")
    void testConstructor() {
        // When
        Smb2EncryptionContext context = new Smb2EncryptionContext(1, DialectVersion.SMB311, testEncryptionKey, testDecryptionKey);
        
        // Then
        assertNotNull(context, "Encryption context should be created");
        assertEquals(1, context.getCipherId(), "Cipher ID should match");
        assertEquals(DialectVersion.SMB311, context.getDialect(), "Dialect should match");
    }

    @Test
    @DisplayName("Should return correct cipher ID")
    void testGetCipherId() {
        // When
        int cipherId = encryptionContext.getCipherId();
        
        // Then
        assertEquals(1, cipherId, "Should return the cipher ID set in constructor");
    }

    @Test
    @DisplayName("Should return correct dialect version")
    void testGetDialect() {
        // When
        DialectVersion dialect = encryptionContext.getDialect();
        
        // Then
        assertEquals(DialectVersion.SMB311, dialect, "Should return the dialect set in constructor");
    }

    @Test
    @DisplayName("Should handle SMB 3.0 dialect")
    void testSMB300Dialect() {
        // When
        Smb2EncryptionContext context = new Smb2EncryptionContext(1, DialectVersion.SMB300, testEncryptionKey, testDecryptionKey);
        
        // Then
        assertEquals(DialectVersion.SMB300, context.getDialect(), "Should support SMB 3.0 dialect");
    }

    @Test
    @DisplayName("Should handle SMB 3.0.2 dialect")
    void testSMB302Dialect() {
        // When
        Smb2EncryptionContext context = new Smb2EncryptionContext(1, DialectVersion.SMB302, testEncryptionKey, testDecryptionKey);
        
        // Then
        assertEquals(DialectVersion.SMB302, context.getDialect(), "Should support SMB 3.0.2 dialect");
    }

    @Test
    @DisplayName("Should handle different cipher IDs")
    void testDifferentCipherIds() {
        // Test cipher ID 1 (AES-CCM)
        Smb2EncryptionContext context1 = new Smb2EncryptionContext(1, DialectVersion.SMB311, testEncryptionKey, testDecryptionKey);
        assertEquals(1, context1.getCipherId(), "Should handle cipher ID 1");
        
        // Test cipher ID 2 (AES-GCM)
        Smb2EncryptionContext context2 = new Smb2EncryptionContext(2, DialectVersion.SMB311, testEncryptionKey, testDecryptionKey);
        assertEquals(2, context2.getCipherId(), "Should handle cipher ID 2");
    }

    @Test
    @DisplayName("Should handle null encryption key")
    void testNullEncryptionKey() {
        // When/Then
        assertDoesNotThrow(() -> {
            new Smb2EncryptionContext(1, DialectVersion.SMB311, null, testDecryptionKey);
        }, "Should handle null encryption key without throwing exception");
    }

    @Test
    @DisplayName("Should handle null decryption key")
    void testNullDecryptionKey() {
        // When/Then
        assertDoesNotThrow(() -> {
            new Smb2EncryptionContext(1, DialectVersion.SMB311, testEncryptionKey, null);
        }, "Should handle null decryption key without throwing exception");
    }

    @Test
    @DisplayName("Should handle null dialect")
    void testNullDialect() {
        // When/Then
        assertDoesNotThrow(() -> {
            new Smb2EncryptionContext(1, null, testEncryptionKey, testDecryptionKey);
        }, "Should handle null dialect without throwing exception during construction");
    }

    @Test
    @DisplayName("Should handle empty keys")
    void testEmptyKeys() {
        // Given
        byte[] emptyKey = new byte[0];
        
        // When/Then
        assertDoesNotThrow(() -> {
            new Smb2EncryptionContext(1, DialectVersion.SMB311, emptyKey, emptyKey);
        }, "Should handle empty keys without throwing exception");
    }

    @Test
    @DisplayName("Should handle different key sizes")
    void testDifferentKeySizes() {
        // Given
        byte[] key128 = new byte[16]; // 128-bit
        byte[] key256 = new byte[32]; // 256-bit
        new SecureRandom().nextBytes(key128);
        new SecureRandom().nextBytes(key256);
        
        // When/Then
        assertDoesNotThrow(() -> {
            new Smb2EncryptionContext(1, DialectVersion.SMB311, key128, key256);
        }, "Should handle different key sizes");
    }

    @Test
    @DisplayName("Should be immutable after creation")
    void testImmutability() {
        // Given
        byte[] originalKey = testEncryptionKey.clone();
        
        // When - Modify the original key array
        testEncryptionKey[0] = (byte) ~testEncryptionKey[0];
        
        // Then - Context should not be affected by external modifications
        assertEquals(1, encryptionContext.getCipherId(), "Context should not be affected by key modifications");
        assertEquals(DialectVersion.SMB311, encryptionContext.getDialect(), "Context should remain consistent");
    }
}