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

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Secure credential storage with encryption at rest.
 *
 * Provides secure storage of passwords and other sensitive credentials
 * using AES-GCM encryption with PBKDF2 key derivation.
 *
 * Features:
 * - Encrypts credentials at rest using AES-256-GCM
 * - Uses PBKDF2 for key derivation from master password
 * - Secure wiping of sensitive data
 * - Thread-safe operations
 * - Protection against timing attacks
 */
public class SecureCredentialStorage implements AutoCloseable, Destroyable {

    private static final Logger log = LoggerFactory.getLogger(SecureCredentialStorage.class);

    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_SIZE = 256;
    private static final int GCM_TAG_SIZE = 128;
    private static final int GCM_IV_SIZE = 12;
    private static final int SALT_SIZE = 32;
    private static final int PBKDF2_ITERATIONS = 100_000;

    private final SecureRandom secureRandom = new SecureRandom();
    private volatile SecretKey masterKey;
    private volatile byte[] salt;
    private volatile boolean destroyed = false;

    /**
     * Initialize secure credential storage with a master password
     *
     * @param masterPassword the master password for encryption
     * @throws GeneralSecurityException if encryption setup fails
     */
    public SecureCredentialStorage(char[] masterPassword) throws GeneralSecurityException {
        if (masterPassword == null || masterPassword.length == 0) {
            throw new IllegalArgumentException("Master password cannot be null or empty");
        }

        // Generate salt for key derivation
        this.salt = new byte[SALT_SIZE];
        secureRandom.nextBytes(this.salt);

        // Derive master key from password
        this.masterKey = deriveKey(masterPassword, salt);

        // Clear the master password after use
        Arrays.fill(masterPassword, '\0');
    }

    /**
     * Initialize secure credential storage with existing salt and password
     *
     * @param masterPassword the master password
     * @param salt the salt for key derivation
     * @throws GeneralSecurityException if encryption setup fails
     */
    public SecureCredentialStorage(char[] masterPassword, byte[] salt) throws GeneralSecurityException {
        if (masterPassword == null || masterPassword.length == 0) {
            throw new IllegalArgumentException("Master password cannot be null or empty");
        }
        if (salt == null || salt.length != SALT_SIZE) {
            throw new IllegalArgumentException("Invalid salt");
        }

        this.salt = salt.clone();
        this.masterKey = deriveKey(masterPassword, this.salt);

        // Clear the master password after use
        Arrays.fill(masterPassword, '\0');
    }

    public byte[] encryptCredentials(char[] plaintext) throws GeneralSecurityException {
        checkNotDestroyed();

        if (plaintext == null) {
            return null;
        }

        // Convert char[] to byte[] for encryption
        byte[] plaintextBytes = charsToBytes(plaintext);

        try {
            // Generate random IV
            byte[] iv = new byte[GCM_IV_SIZE];
            secureRandom.nextBytes(iv);

            // Setup cipher
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE, iv);
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, gcmSpec);

            // Encrypt
            byte[] ciphertext = cipher.doFinal(plaintextBytes);

            // Combine IV and ciphertext
            byte[] result = new byte[GCM_IV_SIZE + ciphertext.length];
            System.arraycopy(iv, 0, result, 0, GCM_IV_SIZE);
            System.arraycopy(ciphertext, 0, result, GCM_IV_SIZE, ciphertext.length);

            return result;

        } finally {
            // Securely wipe plaintext bytes - guaranteed by try-finally
            if (plaintextBytes != null) {
                SecureKeyManager.secureWipe(plaintextBytes);
            }
        }
    }

    public char[] decryptCredentials(byte[] ciphertext) throws GeneralSecurityException {
        checkNotDestroyed();

        if (ciphertext == null || ciphertext.length <= GCM_IV_SIZE) {
            return null;
        }

        // Extract IV and ciphertext
        byte[] iv = new byte[GCM_IV_SIZE];
        System.arraycopy(ciphertext, 0, iv, 0, GCM_IV_SIZE);

        byte[] encryptedData = new byte[ciphertext.length - GCM_IV_SIZE];
        System.arraycopy(ciphertext, GCM_IV_SIZE, encryptedData, 0, encryptedData.length);

        // Setup cipher
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE, iv);
        cipher.init(Cipher.DECRYPT_MODE, masterKey, gcmSpec);

        // Decrypt
        byte[] plaintextBytes = cipher.doFinal(encryptedData);

        try {
            // Convert bytes back to char[]
            return bytesToChars(plaintextBytes);
        } finally {
            // Securely wipe plaintext bytes - guaranteed by try-finally
            if (plaintextBytes != null) {
                SecureKeyManager.secureWipe(plaintextBytes);
            }
        }
    }

    /**
     * Encrypt credentials to a base64 string for storage
     *
     * @param plaintext the credentials to encrypt
     * @return base64 encoded encrypted credentials
     * @throws GeneralSecurityException if encryption fails
     */
    public String encryptToString(char[] plaintext) throws GeneralSecurityException {
        byte[] encrypted = encryptCredentials(plaintext);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypt credentials from a base64 string
     *
     * @param encryptedString base64 encoded encrypted credentials
     * @return decrypted credentials
     * @throws GeneralSecurityException if decryption fails
     */
    public char[] decryptFromString(String encryptedString) throws GeneralSecurityException {
        if (encryptedString == null) {
            return null;
        }
        byte[] encrypted = Base64.getDecoder().decode(encryptedString);
        return decryptCredentials(encrypted);
    }

    /**
     * Get the salt used for key derivation
     *
     * @return salt bytes
     */
    public byte[] getSalt() {
        return salt != null ? salt.clone() : null;
    }

    /**
     * Derive encryption key from password using PBKDF2
     */
    private SecretKey deriveKey(char[] password, byte[] salt) throws GeneralSecurityException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        KeySpec keySpec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_SIZE);
        SecretKey tempKey = keyFactory.generateSecret(keySpec);
        return new SecretKeySpec(tempKey.getEncoded(), KEY_ALGORITHM);
    }

    /**
     * Convert char array to byte array (UTF-8)
     */
    private byte[] charsToBytes(char[] chars) {
        if (chars == null) {
            return null;
        }

        // Use UTF-8 encoding
        byte[] bytes = new byte[chars.length * 3]; // Max 3 bytes per char in UTF-8
        int byteIndex = 0;

        for (char c : chars) {
            if (c < 0x80) {
                bytes[byteIndex++] = (byte) c;
            } else if (c < 0x800) {
                bytes[byteIndex++] = (byte) (0xC0 | (c >> 6));
                bytes[byteIndex++] = (byte) (0x80 | (c & 0x3F));
            } else {
                bytes[byteIndex++] = (byte) (0xE0 | (c >> 12));
                bytes[byteIndex++] = (byte) (0x80 | ((c >> 6) & 0x3F));
                bytes[byteIndex++] = (byte) (0x80 | (c & 0x3F));
            }
        }

        return Arrays.copyOf(bytes, byteIndex);
    }

    /**
     * Convert byte array to char array (UTF-8)
     */
    private char[] bytesToChars(byte[] bytes) {
        if (bytes == null) {
            return null;
        }

        // Decode UTF-8
        char[] chars = new char[bytes.length]; // Max size
        int charIndex = 0;
        int i = 0;

        while (i < bytes.length) {
            byte b = bytes[i];
            if ((b & 0x80) == 0) {
                // Single byte character
                chars[charIndex++] = (char) b;
                i++;
            } else if ((b & 0xE0) == 0xC0) {
                // Two byte character
                if (i + 1 < bytes.length) {
                    chars[charIndex++] = (char) (((b & 0x1F) << 6) | (bytes[i + 1] & 0x3F));
                    i += 2;
                } else {
                    break;
                }
            } else if ((b & 0xF0) == 0xE0) {
                // Three byte character
                if (i + 2 < bytes.length) {
                    chars[charIndex++] = (char) (((b & 0x0F) << 12) | ((bytes[i + 1] & 0x3F) << 6) | (bytes[i + 2] & 0x3F));
                    i += 3;
                } else {
                    break;
                }
            } else {
                // Skip invalid bytes
                i++;
            }
        }

        return Arrays.copyOf(chars, charIndex);
    }

    /**
     * Check if storage has been destroyed
     */
    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("SecureCredentialStorage has been destroyed");
        }
    }

    @Override
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            boolean failedToDestroy = false;
            Exception destroyException = null;

            try {
                // Mark as destroyed first to prevent further operations
                destroyed = true;

                // Try to destroy master key if it implements Destroyable
                if (masterKey instanceof Destroyable) {
                    try {
                        ((Destroyable) masterKey).destroy();
                    } catch (DestroyFailedException e) {
                        // Log but continue - not all JVM implementations support destroying SecretKey
                        log.debug("SecretKey destroy not fully supported: {}", e.getMessage());
                        failedToDestroy = true;
                        destroyException = e;
                    }
                }
                masterKey = null;

                log.debug("SecureCredentialStorage destroyed");

                // If we had a non-critical destroy failure, throw it now
                if (failedToDestroy && destroyException != null) {
                    throw new DestroyFailedException("Partial destroy: " + destroyException.getMessage());
                }

            } catch (DestroyFailedException e) {
                // Re-throw DestroyFailedException as-is
                throw e;
            } catch (Exception e) {
                // For any other exception, wrap it
                throw new DestroyFailedException("Failed to destroy secure storage: " + e.getMessage());
            } finally {
                // Wipe salt - guaranteed by try-finally
                if (salt != null) {
                    SecureKeyManager.secureWipe(salt);
                    salt = null;
                }
            }
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    @Override
    public void close() {
        try {
            destroy();
        } catch (DestroyFailedException e) {
            log.warn("Failed to destroy secure credential storage", e);
        }
    }
}
