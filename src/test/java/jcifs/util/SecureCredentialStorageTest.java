/*
 * © 2025 CodeLibs, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package jcifs.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.security.auth.DestroyFailedException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/**
 * Test cases for SecureCredentialStorage
 */
@TestInstance(Lifecycle.PER_METHOD)
public class SecureCredentialStorageTest {

    private SecureCredentialStorage storage;
    private char[] masterPassword;

    @BeforeEach
    public void setUp() throws Exception {
        masterPassword = "MasterPassword123!@#".toCharArray();
        storage = new SecureCredentialStorage(masterPassword.clone());
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (storage != null && !storage.isDestroyed()) {
            try {
                storage.close();
            } catch (Exception e) {
                // Ignore cleanup exceptions
            }
        }
        if (masterPassword != null) {
            Arrays.fill(masterPassword, '\0');
        }
    }

    @Test
    public void testEncryptDecrypt() throws Exception {
        char[] plaintext = "SecretPassword123".toCharArray();

        // Encrypt
        byte[] encrypted = storage.encryptCredentials(plaintext);
        assertNotNull(encrypted, "Encrypted data should not be null");
        assertTrue(encrypted.length > 0, "Encrypted data should have content");

        // Verify plaintext is not in encrypted data
        String encryptedStr = new String(encrypted);
        assertFalse(encryptedStr.contains("SecretPassword123"), "Plaintext should not be visible in encrypted data");

        // Decrypt
        char[] decrypted = storage.decryptCredentials(encrypted);
        assertNotNull(decrypted, "Decrypted data should not be null");
        assertArrayEquals(plaintext, decrypted, "Decrypted should match original");

        // Clean up sensitive data
        Arrays.fill(plaintext, '\0');
        Arrays.fill(decrypted, '\0');
    }

    @Test
    public void testEncryptDecryptEmpty() throws Exception {
        char[] plaintext = new char[0];

        byte[] encrypted = storage.encryptCredentials(plaintext);
        assertNotNull(encrypted, "Encrypted empty data should not be null");

        char[] decrypted = storage.decryptCredentials(encrypted);
        assertNotNull(decrypted, "Decrypted empty data should not be null");
        assertEquals(0, decrypted.length, "Decrypted empty array should have zero length");
    }

    @Test
    public void testEncryptDecryptNull() throws Exception {
        byte[] encrypted = storage.encryptCredentials(null);
        assertNull(encrypted, "Encrypting null should return null");

        char[] decrypted = storage.decryptCredentials(null);
        assertNull(decrypted, "Decrypting null should return null");
    }

    @Test
    public void testEncryptDecryptLongPassword() throws Exception {
        // Test with very long password
        char[] plaintext = new char[10000];
        Arrays.fill(plaintext, 'X');

        byte[] encrypted = storage.encryptCredentials(plaintext);
        assertNotNull(encrypted, "Encrypted long password should not be null");
        assertTrue(encrypted.length > plaintext.length, "Encrypted data should be larger due to IV and auth tag");

        char[] decrypted = storage.decryptCredentials(encrypted);
        assertArrayEquals(plaintext, decrypted, "Decrypted long password should match original");

        // Clean up
        Arrays.fill(plaintext, '\0');
        Arrays.fill(decrypted, '\0');
    }

    @Test
    public void testEncryptDecryptUnicode() throws Exception {
        // Test with Unicode characters
        char[] plaintext = "パスワード🔐密码".toCharArray();

        byte[] encrypted = storage.encryptCredentials(plaintext);
        char[] decrypted = storage.decryptCredentials(encrypted);

        assertArrayEquals(plaintext, decrypted, "Unicode should be preserved");

        // Clean up
        Arrays.fill(plaintext, '\0');
        Arrays.fill(decrypted, '\0');
    }

    @Test
    public void testDifferentEncryptionsProduceDifferentCiphertexts() throws Exception {
        char[] plaintext = "SamePassword".toCharArray();

        // Encrypt twice
        byte[] encrypted1 = storage.encryptCredentials(plaintext.clone());
        byte[] encrypted2 = storage.encryptCredentials(plaintext.clone());

        // Should produce different ciphertexts due to random IV
        assertFalse(Arrays.equals(encrypted1, encrypted2), "Different encryptions should produce different ciphertexts");

        // But both should decrypt to same plaintext
        char[] decrypted1 = storage.decryptCredentials(encrypted1);
        char[] decrypted2 = storage.decryptCredentials(encrypted2);

        assertArrayEquals(plaintext, decrypted1);
        assertArrayEquals(plaintext, decrypted2);

        // Clean up
        Arrays.fill(plaintext, '\0');
        Arrays.fill(decrypted1, '\0');
        Arrays.fill(decrypted2, '\0');
    }

    @Test
    public void testBase64StringOperations() throws Exception {
        char[] plaintext = "TestPassword456".toCharArray();

        // Encrypt to string
        String encryptedStr = storage.encryptToString(plaintext);
        assertNotNull(encryptedStr, "Encrypted string should not be null");
        assertFalse(encryptedStr.contains("TestPassword456"), "Plaintext should not be visible in encrypted string");

        // Should be valid base64
        assertTrue(encryptedStr.matches("^[A-Za-z0-9+/]*={0,2}$"), "Should be valid Base64 format");

        // Decrypt from string
        char[] decrypted = storage.decryptFromString(encryptedStr);
        assertArrayEquals(plaintext, decrypted, "Decrypted string should match original");

        // Clean up
        Arrays.fill(plaintext, '\0');
        Arrays.fill(decrypted, '\0');
    }

    @Test
    public void testDecryptWithTamperedData() throws Exception {
        char[] plaintext = "SecureData".toCharArray();
        byte[] encrypted = storage.encryptCredentials(plaintext);

        // Tamper with the encrypted data
        encrypted[encrypted.length - 1] ^= 0xFF;

        // Should throw exception due to authentication tag failure
        assertThrows(GeneralSecurityException.class, () -> {
            storage.decryptCredentials(encrypted);
        }, "Should throw GeneralSecurityException when decrypting tampered data");

        // Clean up
        Arrays.fill(plaintext, '\0');
    }

    @Test
    public void testDecryptWithWrongSalt() throws Exception {
        char[] plaintext = "TestData".toCharArray();

        // Encrypt with first storage
        byte[] encrypted = storage.encryptCredentials(plaintext);

        // Create new storage with different salt
        SecureCredentialStorage storage2 = new SecureCredentialStorage(masterPassword.clone());

        try {
            // Should fail because keys are different
            assertThrows(GeneralSecurityException.class, () -> {
                storage2.decryptCredentials(encrypted);
            }, "Should throw GeneralSecurityException when decrypting with wrong salt");
        } finally {
            storage2.close();
        }

        // Clean up
        Arrays.fill(plaintext, '\0');
    }

    @Test
    public void testSaltRetrieval() throws Exception {
        byte[] salt = storage.getSalt();
        assertNotNull(salt, "Salt should not be null");
        assertEquals(32, salt.length, "Salt should be 32 bytes");

        // Salt should be different for each instance
        SecureCredentialStorage storage2 = new SecureCredentialStorage(masterPassword.clone());
        try {
            byte[] salt2 = storage2.getSalt();
            assertFalse(Arrays.equals(salt, salt2), "Different instances should have different salts");
        } finally {
            storage2.close();
        }
    }

    @Test
    public void testReuseWithSameSalt() throws Exception {
        char[] plaintext = "ReusablePassword".toCharArray();
        byte[] salt = storage.getSalt();

        // Encrypt with first storage
        byte[] encrypted = storage.encryptCredentials(plaintext);

        // Create new storage with same salt
        SecureCredentialStorage storage2 = new SecureCredentialStorage(masterPassword.clone(), salt);

        try {
            // Should be able to decrypt with same salt and password
            char[] decrypted = storage2.decryptCredentials(encrypted);
            assertArrayEquals(plaintext, decrypted, "Should decrypt correctly with same salt and password");
            Arrays.fill(decrypted, '\0');
        } finally {
            storage2.close();
        }

        Arrays.fill(plaintext, '\0');
    }

    @Test
    public void testDestroy() throws Exception {
        char[] plaintext = "DestroyTest".toCharArray();
        byte[] encrypted = storage.encryptCredentials(plaintext);

        assertFalse(storage.isDestroyed(), "Storage should not be destroyed initially");

        // Destroy the storage - may throw DestroyFailedException if SecretKey doesn't support destroy
        try {
            storage.destroy();
        } catch (DestroyFailedException e) {
            // This is acceptable - not all JVM implementations support destroying SecretKey
            // The important part is that the storage is marked as destroyed
        }

        assertTrue(storage.isDestroyed(), "Storage should be marked as destroyed");

        // Operations should fail after destroy
        assertThrows(IllegalStateException.class, () -> {
            storage.encryptCredentials(plaintext);
        }, "Should throw IllegalStateException after destroy");

        assertThrows(IllegalStateException.class, () -> {
            storage.decryptCredentials(encrypted);
        }, "Should throw IllegalStateException after destroy");

        // Clean up
        Arrays.fill(plaintext, '\0');
    }

    @Test
    public void testAutoCloseable() throws Exception {
        char[] plaintext = "AutoCloseTest".toCharArray();
        SecureCredentialStorage autoStorage = null;

        try {
            autoStorage = new SecureCredentialStorage(masterPassword.clone());
            byte[] encrypted = autoStorage.encryptCredentials(plaintext);
            assertNotNull(encrypted, "Encrypted data should not be null");
            assertFalse(autoStorage.isDestroyed(), "Storage should not be destroyed during use");
        } finally {
            if (autoStorage != null) {
                autoStorage.close();
                assertTrue(autoStorage.isDestroyed(), "Storage should be destroyed after close");
            }
        }

        // Clean up
        Arrays.fill(plaintext, '\0');
    }

    @Test
    public void testNullMasterPassword() {
        assertThrows(IllegalArgumentException.class, () -> {
            new SecureCredentialStorage(null);
        }, "Should throw IllegalArgumentException for null master password");
    }

    @Test
    public void testEmptyMasterPassword() {
        assertThrows(IllegalArgumentException.class, () -> {
            new SecureCredentialStorage(new char[0]);
        }, "Should throw IllegalArgumentException for empty master password");
    }

    @Test
    public void testSpecialCharacters() throws Exception {
        // Test with all special characters
        char[] plaintext = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\t\n\r".toCharArray();

        byte[] encrypted = storage.encryptCredentials(plaintext);
        char[] decrypted = storage.decryptCredentials(encrypted);

        assertArrayEquals(plaintext, decrypted, "Special characters should be preserved");

        // Clean up
        Arrays.fill(plaintext, '\0');
        Arrays.fill(decrypted, '\0');
    }
}
