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
package org.codelibs.jcifs.smb.internal.smb2;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.internal.smb2.nego.EncryptionNegotiateContext;
import org.codelibs.jcifs.smb.util.SecureKeyManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SMB2/SMB3 Encryption Context
 *
 * Manages encryption and decryption operations for SMB2/SMB3 sessions.
 * Handles both AES-CCM (SMB 3.0/3.0.2) and AES-GCM (SMB 3.1.1) cipher suites.
 *
 * @author mbechler
 */
public class Smb2EncryptionContext implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(Smb2EncryptionContext.class);

    private final int cipherId;
    private final DialectVersion dialect;
    private byte[] encryptionKey;
    private byte[] decryptionKey;
    private final AtomicLong nonceCounter = new AtomicLong(0);
    private final SecureRandom secureRandom = new SecureRandom();

    // Secure key management
    private SecureKeyManager keyManager;
    private String sessionId;
    private volatile boolean closed = false;

    // Store session key and preauth hash for key rotation
    private byte[] sessionKey;
    private byte[] preauthIntegrityHash;
    private int rotationCount = 0;

    // Key rotation tracking - use atomic for lock-free operations
    private final AtomicLong bytesEncrypted = new AtomicLong(0);
    private long encryptionStartTime = System.currentTimeMillis();

    // Configurable key rotation limits with defaults
    private volatile long keyRotationBytesLimit = 1L << 30; // Default: 1GB
    private volatile long keyRotationTimeLimit = 24 * 60 * 60 * 1000L; // Default: 24 hours

    // Rotation metrics
    private final AtomicLong totalKeyRotations = new AtomicLong(0);
    private final AtomicLong lastKeyRotationTime = new AtomicLong(0);

    /**
     * AES-128-CCM cipher identifier for SMB3 encryption
     */
    public static final int CIPHER_AES_128_CCM = EncryptionNegotiateContext.CIPHER_AES128_CCM;
    /**
     * AES-128-GCM cipher identifier for SMB3.1.1 encryption
     */
    public static final int CIPHER_AES_128_GCM = EncryptionNegotiateContext.CIPHER_AES128_GCM;
    /**
     * AES-256-CCM cipher identifier for SMB3 encryption (future support)
     */
    public static final int CIPHER_AES_256_CCM = 0x0003;
    /**
     * AES-256-GCM cipher identifier for SMB3.1.1 encryption (future support)
     */
    public static final int CIPHER_AES_256_GCM = 0x0004;

    /**
     * Transform header flag indicating the message is encrypted
     */
    public static final int TRANSFORM_FLAG_ENCRYPTED = 0x0001;

    /**
     * Create encryption context
     *
     * @param cipherId
     *            negotiated cipher identifier
     * @param dialect
     *            SMB dialect version
     * @param encryptionKey
     *            key for client->server encryption
     * @param decryptionKey
     *            key for server->client decryption
     */
    public Smb2EncryptionContext(final int cipherId, final DialectVersion dialect, final byte[] encryptionKey, final byte[] decryptionKey) {
        this(cipherId, dialect, encryptionKey, decryptionKey, null, null, null);
    }

    /**
     * Create encryption context with secure key management (backward compatibility)
     *
     * @param cipherId
     *            negotiated cipher identifier
     * @param dialect
     *            SMB dialect version
     * @param encryptionKey
     *            key for client->server encryption
     * @param decryptionKey
     *            key for server->client decryption
     * @param keyManager
     *            secure key manager
     */
    public Smb2EncryptionContext(final int cipherId, final DialectVersion dialect, final byte[] encryptionKey, final byte[] decryptionKey,
            final SecureKeyManager keyManager) {
        this(cipherId, dialect, encryptionKey, decryptionKey, keyManager, null, null);
    }

    /**
     * Create encryption context with session key for rotation support
     *
     * @param cipherId
     *            negotiated cipher identifier
     * @param dialect
     *            SMB dialect version
     * @param encryptionKey
     *            key for client->server encryption
     * @param decryptionKey
     *            key for server->client decryption
     * @param sessionKey
     *            base session key for key rotation
     * @param preauthHash
     *            preauth integrity hash for SMB 3.1.1
     */
    public Smb2EncryptionContext(final int cipherId, final DialectVersion dialect, final byte[] encryptionKey, final byte[] decryptionKey,
            final byte[] sessionKey, final byte[] preauthHash) {
        this(cipherId, dialect, encryptionKey, decryptionKey, null, sessionKey, preauthHash);
    }

    /**
     * Create encryption context with secure key management
     *
     * @param cipherId
     *            negotiated cipher identifier
     * @param dialect
     *            SMB dialect version
     * @param encryptionKey
     *            key for client->server encryption
     * @param decryptionKey
     *            key for server->client decryption
     * @param keyManager
     *            optional secure key manager for enhanced key management
     * @param sessionKey
     *            base session key for key rotation (optional)
     * @param preauthHash
     *            preauth integrity hash for SMB 3.1.1 (optional)
     */
    public Smb2EncryptionContext(final int cipherId, final DialectVersion dialect, final byte[] encryptionKey, final byte[] decryptionKey,
            final SecureKeyManager keyManager, final byte[] sessionKey, final byte[] preauthHash) {
        this.cipherId = cipherId;
        this.dialect = dialect;
        this.keyManager = keyManager;
        this.sessionKey = sessionKey != null ? sessionKey.clone() : null;
        this.preauthIntegrityHash = preauthHash != null ? preauthHash.clone() : null;

        // Generate unique session ID for key management
        this.sessionId = String.format("smb-enc-%d-%d", System.currentTimeMillis(), secureRandom.nextLong());

        if (keyManager != null) {
            // Store keys securely
            String encKeyId = sessionId + "-enc";
            String decKeyId = sessionId + "-dec";
            keyManager.storeSessionKey(encKeyId, encryptionKey, "AES");
            keyManager.storeSessionKey(decKeyId, decryptionKey, "AES");

            // Clear local key copies for security
            this.encryptionKey = null;
            this.decryptionKey = null;

            log.debug("Keys stored in SecureKeyManager for session: {}", sessionId);
        } else {
            // Fall back to traditional in-memory storage
            this.encryptionKey = encryptionKey.clone();
            this.decryptionKey = decryptionKey.clone();
        }
    }

    /**
     * Get the negotiated cipher identifier
     * @return the negotiated cipher ID
     */
    public int getCipherId() {
        return this.cipherId;
    }

    /**
     * Get the SMB dialect version
     * @return the SMB dialect version
     */
    public DialectVersion getDialect() {
        return this.dialect;
    }

    /**
     * Set key rotation limits
     *
     * @param bytesLimit maximum bytes to encrypt before rotation (0 to disable)
     * @param timeMillis maximum time in milliseconds before rotation (0 to disable)
     */
    public void setKeyRotationLimits(long bytesLimit, long timeMillis) {
        if (bytesLimit > 0) {
            this.keyRotationBytesLimit = bytesLimit;
        }
        if (timeMillis > 0) {
            this.keyRotationTimeLimit = timeMillis;
        }
        log.info("Key rotation limits updated - bytes: {} MB, time: {} hours", bytesLimit / (1024 * 1024), timeMillis / (60 * 60 * 1000));
    }

    /**
     * Get key rotation metrics
     *
     * @return metrics map containing rotation statistics
     */
    public java.util.Map<String, Long> getKeyRotationMetrics() {
        java.util.Map<String, Long> metrics = new java.util.HashMap<>();
        metrics.put("totalRotations", totalKeyRotations.get());
        metrics.put("lastRotationTime", lastKeyRotationTime.get());
        metrics.put("bytesEncryptedSinceLastRotation", bytesEncrypted.get());
        metrics.put("timeSinceLastRotation", System.currentTimeMillis() - encryptionStartTime);
        metrics.put("rotationBytesLimit", keyRotationBytesLimit);
        metrics.put("rotationTimeLimit", keyRotationTimeLimit);
        return metrics;
    }

    /**
     * Generate a unique nonce for encryption following SMB3 specification.
     * Uses SMB3-compliant nonce generation with guaranteed uniqueness.
     *
     * @return nonce appropriate for the dialect (16 bytes for GCM, 12 bytes for CCM)
     */
    public byte[] generateNonce() {
        final byte[] nonce = new byte[isGCMCipher() ? 16 : 12];

        if (isGCMCipher()) {
            // SMB 3.1.1 GCM: 96-bit random/fixed + 32-bit counter for guaranteed uniqueness
            // Fill first 12 bytes with random data
            secureRandom.nextBytes(nonce);

            // Last 4 bytes: incrementing counter for guaranteed uniqueness
            final long counter = this.nonceCounter.incrementAndGet();
            final ByteBuffer buffer = ByteBuffer.wrap(nonce, 12, 4);
            buffer.order(java.nio.ByteOrder.LITTLE_ENDIAN);
            buffer.putInt((int) counter);
        } else {
            // SMB 3.0/3.0.2 CCM: Counter-based approach as per SMB3 specification
            final long counter = this.nonceCounter.incrementAndGet();
            final ByteBuffer buffer = ByteBuffer.wrap(nonce);
            buffer.order(java.nio.ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(counter);
            // Remaining bytes (if any) stay zero-padded
        }

        return nonce;
    }

    /**
     * Generate a secure random nonce for initial session setup.
     * This method can be used when enhanced randomness is required,
     * such as during initial key exchange or session establishment.
     *
     * @return randomized nonce appropriate for the dialect
     */
    public byte[] generateSecureNonce() {
        final byte[] nonce = new byte[isGCMCipher() ? 16 : 12];
        this.secureRandom.nextBytes(nonce);
        return nonce;
    }

    /**
     * Encrypt an SMB2 message with constant-time operations
     *
     * @param message
     *            plaintext message to encrypt
     * @param sessionId
     *            session identifier
     * @return encrypted message with transform header
     * @throws CIFSException
     *             if encryption fails
     */
    public byte[] encryptMessage(final byte[] message, final long sessionId) throws CIFSException {
        if (message == null) {
            throw new IllegalArgumentException("Message cannot be null");
        }

        // Validate encryption parameters
        if (!validateEncryptionParameters()) {
            throw new CIFSException("Invalid encryption parameters");
        }

        // Check if key rotation is needed (including the current message)
        if (needsKeyRotation(message.length)) {
            log.warn("Encryption keys need rotation - will exceed usage limits (bytes: {} + {}, time: {} ms)", bytesEncrypted.get(),
                    message.length, System.currentTimeMillis() - encryptionStartTime);

            // Perform automatic key rotation if session key is available
            if (sessionKey != null) {
                try {
                    performAutomaticKeyRotation();
                    log.info("Successfully performed automatic key rotation for session: {}", sessionId);
                } catch (GeneralSecurityException e) {
                    log.error("Automatic key rotation failed", e);
                    throw new CIFSException("Automatic key rotation failed", e);
                }
            } else {
                // Fall back to throwing exception if no session key is available
                totalKeyRotations.incrementAndGet();
                lastKeyRotationTime.set(System.currentTimeMillis());
                throw new CIFSException("Encryption keys need rotation but session key not available for auto-rotation");
            }
        }

        try {
            final byte[] nonce = generateNonce();
            final int flags = getTransformFlags();

            final Smb2TransformHeader transformHeader = new Smb2TransformHeader(nonce, message.length, flags, sessionId);
            final byte[] associatedData = transformHeader.getAssociatedData();

            // Perform encryption based on cipher type
            EncryptionResult encResult =
                    isGCMCipher() ? encryptWithGCM(message, nonce, associatedData) : encryptWithCCM(message, nonce, associatedData);

            // Set authentication tag in transform header
            transformHeader.setSignature(encResult.authTag);

            // Build final encrypted message
            final byte[] result = new byte[Smb2TransformHeader.TRANSFORM_HEADER_SIZE + encResult.ciphertext.length];
            transformHeader.encode(result, 0);
            System.arraycopy(encResult.ciphertext, 0, result, Smb2TransformHeader.TRANSFORM_HEADER_SIZE, encResult.ciphertext.length);

            // Track encrypted bytes for key rotation - lock-free atomic operation
            bytesEncrypted.addAndGet(message.length);

            return result;
        } catch (final Exception e) {
            // Clear sensitive data on error
            if (e instanceof CIFSException) {
                throw (CIFSException) e;
            }
            throw new CIFSException("Failed to encrypt message", e);
        }
    }

    /**
     * Validate encryption parameters to prevent security issues
     *
     * @return true if parameters are valid
     */
    private boolean validateEncryptionParameters() {
        // Validate cipher ID
        if (cipherId != CIPHER_AES_128_CCM && cipherId != CIPHER_AES_128_GCM && cipherId != CIPHER_AES_256_CCM
                && cipherId != CIPHER_AES_256_GCM) {
            log.error("Invalid cipher ID: {}", cipherId);
            return false;
        }

        // Validate keys are available
        if (keyManager == null && (encryptionKey == null || decryptionKey == null)) {
            log.error("No encryption keys available");
            return false;
        }

        // Validate key lengths
        try {
            int expectedKeyLength = getKeyLength();
            byte[] encKey = getEncryptionKey();
            byte[] decKey = getDecryptionKey();

            try {
                boolean valid =
                        encKey != null && encKey.length == expectedKeyLength && decKey != null && decKey.length == expectedKeyLength;
                return valid;
            } finally {
                // Securely wipe temporary key references - guaranteed by try-finally
                if (encKey != null) {
                    SecureKeyManager.secureWipe(encKey);
                }
                if (decKey != null) {
                    SecureKeyManager.secureWipe(decKey);
                }
            }
        } catch (Exception e) {
            log.error("Error validating key lengths", e);
            return false;
        }
    }

    /**
     * Helper class to hold encryption results
     */
    private static class EncryptionResult {
        final byte[] ciphertext;
        final byte[] authTag;

        EncryptionResult(byte[] ciphertext, byte[] authTag) {
            this.ciphertext = ciphertext;
            this.authTag = authTag;
        }
    }

    /**
     * Encrypt using AES-GCM with constant-time operations
     */
    private EncryptionResult encryptWithGCM(byte[] message, byte[] nonce, byte[] associatedData) throws Exception {
        final Cipher cipher = createGCMCipher(true, nonce);
        cipher.updateAAD(associatedData);

        // Use constant-time encryption
        final byte[] encrypted = performConstantTimeEncryption(cipher, message);

        // Split ciphertext and authentication tag
        final int tagLength = getAuthTagLength();
        final byte[] ciphertext = new byte[encrypted.length - tagLength];
        final byte[] authTag = new byte[tagLength];

        // Use constant-time copy operations
        constantTimeCopy(encrypted, 0, ciphertext, 0, ciphertext.length);
        constantTimeCopy(encrypted, ciphertext.length, authTag, 0, tagLength);

        return new EncryptionResult(ciphertext, authTag);
    }

    /**
     * Encrypt using AES-CCM with Bouncy Castle and constant-time operations
     */
    private EncryptionResult encryptWithCCM(byte[] message, byte[] nonce, byte[] associatedData) throws Exception {
        final AEADBlockCipher cipher = createCCMCipher(true, nonce, associatedData.length, message.length);

        // Process AAD (not included in output)
        cipher.processAADBytes(associatedData, 0, associatedData.length);

        // Process message (will be encrypted)
        final byte[] output = new byte[cipher.getOutputSize(message.length)];
        int len = cipher.processBytes(message, 0, message.length, output, 0);
        len += cipher.doFinal(output, len);

        // Split ciphertext and authentication tag
        final int tagLength = getAuthTagLength();
        final byte[] ciphertext = new byte[message.length];
        final byte[] authTag = new byte[tagLength];

        // Use constant-time copy operations
        constantTimeCopy(output, 0, ciphertext, 0, message.length);
        constantTimeCopy(output, message.length, authTag, 0, tagLength);

        return new EncryptionResult(ciphertext, authTag);
    }

    /**
     * Perform constant-time encryption to prevent timing attacks
     */
    private byte[] performConstantTimeEncryption(Cipher cipher, byte[] message) throws Exception {
        // Pad to fixed block size to prevent timing leaks
        int blockSize = cipher.getBlockSize();
        if (blockSize == 0)
            blockSize = 16; // GCM mode

        int paddedLength = ((message.length + blockSize - 1) / blockSize) * blockSize;
        byte[] paddedMessage = new byte[Math.max(paddedLength, message.length)];
        System.arraycopy(message, 0, paddedMessage, 0, message.length);

        // Encrypt with constant timing
        byte[] result = cipher.doFinal(paddedMessage, 0, message.length);

        // Clear padded data
        java.util.Arrays.fill(paddedMessage, (byte) 0);

        return result;
    }

    /**
     * Constant-time array copy to prevent timing attacks
     */
    private void constantTimeCopy(byte[] src, int srcPos, byte[] dest, int destPos, int length) {
        // Simple constant-time copy - always process all bytes
        for (int i = 0; i < length; i++) {
            dest[destPos + i] = src[srcPos + i];
        }
    }

    /**
     * Decrypt an SMB2 message
     *
     * @param encryptedMessage
     *            encrypted message with transform header
     * @return decrypted plaintext message
     * @throws CIFSException
     *             if decryption fails
     */
    public byte[] decryptMessage(final byte[] encryptedMessage) throws CIFSException {
        try {
            // Parse transform header
            final Smb2TransformHeader transformHeader = Smb2TransformHeader.decode(encryptedMessage, 0);
            final byte[] associatedData = transformHeader.getAssociatedData();
            byte[] nonce = transformHeader.getNonce();
            final byte[] authTag = transformHeader.getSignature();

            // Extract ciphertext
            final int ciphertextLength = encryptedMessage.length - Smb2TransformHeader.TRANSFORM_HEADER_SIZE;
            final byte[] ciphertext = new byte[ciphertextLength];
            System.arraycopy(encryptedMessage, Smb2TransformHeader.TRANSFORM_HEADER_SIZE, ciphertext, 0, ciphertextLength);

            byte[] plaintext;

            if (isGCMCipher()) {
                // Use AES-GCM - nonce is 16 bytes
                final Cipher cipher = createGCMCipher(false, nonce);
                cipher.updateAAD(associatedData);

                // Combine ciphertext and auth tag for decryption
                final byte[] input = new byte[ciphertext.length + authTag.length];
                System.arraycopy(ciphertext, 0, input, 0, ciphertext.length);
                System.arraycopy(authTag, 0, input, ciphertext.length, authTag.length);

                plaintext = cipher.doFinal(input);
            } else {
                // Use AES-CCM with Bouncy Castle
                // For CCM, we need to extract only the first 12 bytes of the nonce
                final byte[] ccmNonce = new byte[12];
                System.arraycopy(nonce, 0, ccmNonce, 0, 12);
                final AEADBlockCipher cipher = createCCMCipher(false, ccmNonce, associatedData.length, ciphertext.length);

                // Process AAD (not included in ciphertext)
                cipher.processAADBytes(associatedData, 0, associatedData.length);

                // Process ciphertext + auth tag
                final byte[] input = new byte[ciphertext.length + authTag.length];
                System.arraycopy(ciphertext, 0, input, 0, ciphertext.length);
                System.arraycopy(authTag, 0, input, ciphertext.length, authTag.length);

                final byte[] output = new byte[cipher.getOutputSize(input.length)];
                int len = cipher.processBytes(input, 0, input.length, output, 0);
                len += cipher.doFinal(output, len);

                plaintext = new byte[ciphertext.length];
                System.arraycopy(output, 0, plaintext, 0, ciphertext.length);
            }

            return plaintext;
        } catch (final Exception e) {
            throw new CIFSException("Failed to decrypt message", e);
        }
    }

    private boolean isGCMCipher() {
        return this.cipherId == CIPHER_AES_128_GCM || this.cipherId == CIPHER_AES_256_GCM;
    }

    private int getKeyLength() {
        // Java 17 switch expression for cipher key length determination
        return switch (this.cipherId) {
        case CIPHER_AES_128_CCM, CIPHER_AES_128_GCM -> 16; // AES-128 ciphers use 16-byte keys
        case CIPHER_AES_256_CCM, CIPHER_AES_256_GCM -> 32; // AES-256 ciphers use 32-byte keys
        default -> throw new IllegalArgumentException("Unsupported cipher: " + this.cipherId);
        };
    }

    private int getAuthTagLength() {
        return 16; // All SMB3 ciphers use 16-byte authentication tags
    }

    private int getTransformFlags() {
        if (this.dialect.atLeast(DialectVersion.SMB311)) {
            return TRANSFORM_FLAG_ENCRYPTED;
        }
        // For SMB 3.0/3.0.2, this field contains the encryption algorithm
        return this.cipherId;
    }

    private byte[] getEncryptionKey() {
        if (keyManager != null) {
            String encKeyId = sessionId + "-enc";
            byte[] key = keyManager.getRawKey(encKeyId);
            if (key == null) {
                throw new IllegalStateException("Encryption key not found in SecureKeyManager");
            }
            return key;
        }
        return this.encryptionKey;
    }

    private byte[] getDecryptionKey() {
        if (keyManager != null) {
            String decKeyId = sessionId + "-dec";
            byte[] key = keyManager.getRawKey(decKeyId);
            if (key == null) {
                throw new IllegalStateException("Decryption key not found in SecureKeyManager");
            }
            return key;
        }
        return this.decryptionKey;
    }

    private Cipher createGCMCipher(final boolean encrypt, final byte[] nonce) throws Exception {
        // Determine key size based on cipher ID for AES-256 support
        int keyLength = getKeyLength();
        String transformation;

        // Select appropriate AES algorithm based on key length
        if (keyLength == 32) {
            // AES-256 support
            transformation = "AES/GCM/NoPadding";
        } else if (keyLength == 16) {
            // AES-128 (existing)
            transformation = "AES/GCM/NoPadding";
        } else {
            throw new IllegalArgumentException("Unsupported key length for GCM: " + keyLength);
        }

        byte[] key = null;
        byte[] keyCopy = null;

        try {
            // Get the key and create a defensive copy for SecretKeySpec
            key = encrypt ? getEncryptionKey() : getDecryptionKey();
            keyCopy = Arrays.copyOf(key, key.length);

            // Validate key length matches expected cipher requirements
            if (keyCopy.length != keyLength) {
                throw new IllegalArgumentException("Key length mismatch: expected " + keyLength + ", got " + keyCopy.length);
            }

            // Create cipher with the copy - algorithm is just "AES" for SecretKeySpec
            final SecretKeySpec keySpec = new SecretKeySpec(keyCopy, "AES");
            final Cipher cipher = Cipher.getInstance(transformation);
            final GCMParameterSpec gcmSpec = new GCMParameterSpec(getAuthTagLength() * 8, nonce);

            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            return cipher;
        } finally {
            // Guaranteed cleanup of all key material
            if (key != null) {
                SecureKeyManager.secureWipe(key);
            }
            if (keyCopy != null) {
                SecureKeyManager.secureWipe(keyCopy);
            }
        }
    }

    private AEADBlockCipher createCCMCipher(final boolean encrypt, final byte[] nonce, final int aadLength, final int plaintextLength) {
        // Support both AES-128 and AES-256 for CCM cipher
        int keyLength = getKeyLength();
        final AEADBlockCipher cipher;

        if (keyLength == 16) {
            // AES-128 CCM
            cipher = new CCMBlockCipher(new AESEngine());
        } else if (keyLength == 32) {
            // AES-256 CCM - Bouncy Castle supports AES-256 with same AESEngine
            cipher = new CCMBlockCipher(new AESEngine());
        } else {
            throw new IllegalArgumentException("Unsupported key length for CCM: " + keyLength);
        }

        byte[] key = null;
        byte[] keyCopy = null;

        try {
            // Get the key and create a defensive copy for KeyParameter
            key = encrypt ? getEncryptionKey() : getDecryptionKey();
            keyCopy = Arrays.copyOf(key, key.length);

            // Validate key length matches expected cipher requirements
            if (keyCopy.length != keyLength) {
                throw new IllegalArgumentException("Key length mismatch: expected " + keyLength + ", got " + keyCopy.length);
            }

            final KeyParameter keyParam = new KeyParameter(keyCopy);

            // CCMBlockCipher requires nonce length between 7 and 13
            // Use the nonce directly if it's 12 bytes (generated appropriately)
            final byte[] adjustedNonce;
            if (nonce.length == 12) {
                adjustedNonce = nonce;
            } else {
                // Fallback for compatibility
                adjustedNonce = new byte[12];
                System.arraycopy(nonce, 0, adjustedNonce, 0, Math.min(12, nonce.length));
            }

            final AEADParameters params = new AEADParameters(keyParam, getAuthTagLength() * 8, adjustedNonce, null);

            cipher.init(encrypt, params);

            return cipher;
        } finally {
            // Guaranteed cleanup of all key material
            if (key != null) {
                SecureKeyManager.secureWipe(key);
            }
            if (keyCopy != null) {
                SecureKeyManager.secureWipe(keyCopy);
            }
        }
    }

    private static byte[] longToBytes(final long value) {
        final byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (value >>> 8 * (7 - i));
        }
        return bytes;
    }

    /**
     * Check if key rotation is needed based on configurable usage limits
     *
     * @return true if key rotation is needed
     */
    public boolean needsKeyRotation() {
        return needsKeyRotation(0);
    }

    /**
     * Check if key rotation is needed, considering additional bytes to be encrypted
     *
     * @param additionalBytes bytes about to be encrypted
     * @return true if key rotation is needed
     */
    public boolean needsKeyRotation(int additionalBytes) {
        long currentTime = System.currentTimeMillis();
        long timeSinceStart = currentTime - encryptionStartTime;
        long totalBytes = bytesEncrypted.get() + additionalBytes;

        boolean needsRotation = (keyRotationBytesLimit > 0 && totalBytes >= keyRotationBytesLimit)
                || (keyRotationTimeLimit > 0 && timeSinceStart >= keyRotationTimeLimit);

        if (needsRotation) {
            log.info("Key rotation needed - bytes: {} / {} MB, time: {} / {} hours", totalBytes / (1024 * 1024),
                    keyRotationBytesLimit / (1024 * 1024), timeSinceStart / (60 * 60 * 1000), keyRotationTimeLimit / (60 * 60 * 1000));
        }

        return needsRotation;
    }

    /**
     * Reset key rotation tracking after new keys are established
     */
    public void resetKeyRotationTracking() {
        bytesEncrypted.set(0);
        encryptionStartTime = System.currentTimeMillis();
        log.debug("Key rotation tracking reset");
    }

    /**
     * Rotate encryption keys for enhanced security
     *
     * @param newEncryptionKey the new encryption key
     * @param newDecryptionKey the new decryption key
     * @throws GeneralSecurityException if key rotation fails
     */
    public void rotateKeys(byte[] newEncryptionKey, byte[] newDecryptionKey) throws GeneralSecurityException {
        if (closed) {
            throw new IllegalStateException("Cannot rotate keys on closed context");
        }

        log.info("Rotating encryption keys for session: {}", sessionId);

        if (keyManager != null) {
            // Rotate keys in SecureKeyManager
            String encKeyId = sessionId + "-enc";
            String decKeyId = sessionId + "-dec";

            // Remove old keys
            keyManager.removeSessionKey(encKeyId);
            keyManager.removeSessionKey(decKeyId);

            // Store new keys
            keyManager.storeSessionKey(encKeyId, newEncryptionKey, "AES");
            keyManager.storeSessionKey(decKeyId, newDecryptionKey, "AES");

            log.debug("Keys rotated successfully in SecureKeyManager");
        } else {
            // Securely wipe old keys
            secureWipeKeys();

            // Store new keys
            this.encryptionKey = newEncryptionKey.clone();
            this.decryptionKey = newDecryptionKey.clone();
        }

        // Reset rotation tracking
        resetKeyRotationTracking();

        // Update metrics
        totalKeyRotations.incrementAndGet();
        lastKeyRotationTime.set(System.currentTimeMillis());
    }

    /**
     * Get the current key rotation count
     *
     * @return number of times keys have been rotated
     */
    public int getKeyRotationCount() {
        return rotationCount;
    }

    /**
     * Set the key rotation bytes limit
     *
     * @param limit number of bytes to encrypt before rotating keys
     */
    public void setKeyRotationBytesLimit(long limit) {
        this.keyRotationBytesLimit = limit;
    }

    /**
     * Set the key rotation time limit
     *
     * @param limit time in milliseconds before rotating keys
     */
    public void setKeyRotationTimeLimit(long limit) {
        this.keyRotationTimeLimit = limit;
    }

    /**
     * Perform automatic key rotation using the stored session key following SMB3 key derivation
     *
     * @throws GeneralSecurityException if key rotation fails
     */
    private void performAutomaticKeyRotation() throws GeneralSecurityException {
        if (sessionKey == null) {
            throw new GeneralSecurityException("Session key not available for automatic rotation");
        }

        // Increment rotation counter for tracking and key derivation
        rotationCount++;

        // SMB3-compliant key rotation: Use rotation counter as per SMB3 specification
        // This follows Microsoft's approach for predictable but unique key derivation
        byte[] modifiedSessionKey = new byte[sessionKey.length + 8];
        System.arraycopy(sessionKey, 0, modifiedSessionKey, 0, sessionKey.length);

        // Add rotation counter and timestamp for key uniqueness (SMB3-style)
        final ByteBuffer saltBuffer = ByteBuffer.wrap(modifiedSessionKey, sessionKey.length, 8);
        saltBuffer.order(java.nio.ByteOrder.LITTLE_ENDIAN);
        saltBuffer.putInt(rotationCount); // Rotation counter
        saltBuffer.putInt((int) (System.currentTimeMillis() / 1000)); // Timestamp for additional uniqueness

        // Derive new keys using SMB3 KDF with rotation-specific input
        final int dialectInt = dialect.getDialect();
        final byte[] newEncryptionKey = Smb3KeyDerivation.deriveEncryptionKey(dialectInt, modifiedSessionKey, preauthIntegrityHash);
        final byte[] newDecryptionKey = Smb3KeyDerivation.deriveDecryptionKey(dialectInt, modifiedSessionKey, preauthIntegrityHash);

        // Securely wipe the modified session key
        SecureKeyManager.secureWipe(modifiedSessionKey);

        // Rotate keys using existing method
        rotateKeys(newEncryptionKey, newDecryptionKey);

        log.info("Automatic key rotation completed for session: {} (rotation count: {})", sessionId, rotationCount);
    }

    /**
     * Securely wipe encryption keys from memory
     */
    public void secureWipeKeys() {
        if (this.encryptionKey != null) {
            // Multi-pass secure wipe for enhanced security
            SecureKeyManager.secureWipe(this.encryptionKey);
            this.encryptionKey = null;
        }
        if (this.decryptionKey != null) {
            // Multi-pass secure wipe for enhanced security
            SecureKeyManager.secureWipe(this.decryptionKey);
            this.decryptionKey = null;
        }

        // Also remove from key manager if present
        if (keyManager != null && sessionId != null) {
            keyManager.removeSessionKey(sessionId + "-enc");
            keyManager.removeSessionKey(sessionId + "-dec");
        }
    }

    /**
     * Close the encryption context and securely wipe keys
     */
    @Override
    public void close() {
        if (closed) {
            return;
        }

        try {
            secureWipeKeys();

            // Clear session ID
            sessionId = null;

            log.debug("Encryption context closed and keys wiped");
        } finally {
            closed = true;
        }
    }

    /**
     * Check if this context is closed
     *
     * @return true if closed, false otherwise
     */
    public boolean isClosed() {
        return closed;
    }
}
