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
package jcifs.internal.smb2;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import jcifs.CIFSException;
import jcifs.DialectVersion;
import jcifs.internal.smb2.nego.EncryptionNegotiateContext;

/**
 * SMB2/SMB3 Encryption Context
 *
 * Manages encryption and decryption operations for SMB2/SMB3 sessions.
 * Handles both AES-CCM (SMB 3.0/3.0.2) and AES-GCM (SMB 3.1.1) cipher suites.
 *
 * @author mbechler
 */
public class Smb2EncryptionContext {

    private final int cipherId;
    private final DialectVersion dialect;
    private final byte[] encryptionKey;
    private final byte[] decryptionKey;
    private final AtomicLong nonceCounter = new AtomicLong(0);
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * AES-128-CCM cipher identifier for SMB3 encryption
     */
    public static final int CIPHER_AES_128_CCM = EncryptionNegotiateContext.CIPHER_AES128_CCM;
    /**
     * AES-128-GCM cipher identifier for SMB3.1.1 encryption
     */
    public static final int CIPHER_AES_128_GCM = EncryptionNegotiateContext.CIPHER_AES128_GCM;
    // Note: AES-256 variants are not currently defined in the negotiate context

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
        this.cipherId = cipherId;
        this.dialect = dialect;
        this.encryptionKey = encryptionKey.clone();
        this.decryptionKey = decryptionKey.clone();
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
     * Generate a unique nonce for encryption
     *
     * @return 16-byte nonce
     */
    public byte[] generateNonce() {
        final byte[] nonce = new byte[16];

        // Use combination of counter and random data for uniqueness
        final long counter = this.nonceCounter.incrementAndGet();
        System.arraycopy(longToBytes(counter), 0, nonce, 0, 8);

        // Fill remaining 8 bytes with random data
        final byte[] randomBytes = new byte[8];
        this.secureRandom.nextBytes(randomBytes);
        System.arraycopy(randomBytes, 0, nonce, 8, 8);

        return nonce;
    }

    /**
     * Encrypt an SMB2 message
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
        try {
            final byte[] nonce = generateNonce();
            final int flags = getTransformFlags();

            final Smb2TransformHeader transformHeader = new Smb2TransformHeader(nonce, message.length, flags, sessionId);
            final byte[] associatedData = transformHeader.getAssociatedData();

            byte[] ciphertext;
            byte[] authTag;

            if (isGCMCipher()) {
                // Use AES-GCM
                final Cipher cipher = createGCMCipher(true, nonce);
                cipher.updateAAD(associatedData);
                final byte[] encrypted = cipher.doFinal(message);

                // Split ciphertext and authentication tag
                final int tagLength = getAuthTagLength();
                ciphertext = new byte[encrypted.length - tagLength];
                authTag = new byte[tagLength];
                System.arraycopy(encrypted, 0, ciphertext, 0, ciphertext.length);
                System.arraycopy(encrypted, ciphertext.length, authTag, 0, tagLength);
            } else {
                // Use AES-CCM with Bouncy Castle
                final AEADBlockCipher cipher = createCCMCipher(true, nonce, associatedData.length, message.length);

                final byte[] input = new byte[associatedData.length + message.length];
                System.arraycopy(associatedData, 0, input, 0, associatedData.length);
                System.arraycopy(message, 0, input, associatedData.length, message.length);

                final byte[] output = new byte[cipher.getOutputSize(input.length)];
                int len = cipher.processBytes(input, 0, input.length, output, 0);
                len += cipher.doFinal(output, len);

                // Split ciphertext and authentication tag
                final int tagLength = getAuthTagLength();
                ciphertext = new byte[message.length];
                authTag = new byte[tagLength];
                System.arraycopy(output, associatedData.length, ciphertext, 0, message.length);
                System.arraycopy(output, output.length - tagLength, authTag, 0, tagLength);
            }

            // Set authentication tag in transform header
            transformHeader.setSignature(authTag);

            // Build final encrypted message
            final byte[] result = new byte[Smb2TransformHeader.TRANSFORM_HEADER_SIZE + ciphertext.length];
            transformHeader.encode(result, 0);
            System.arraycopy(ciphertext, 0, result, Smb2TransformHeader.TRANSFORM_HEADER_SIZE, ciphertext.length);

            return result;
        } catch (final Exception e) {
            throw new CIFSException("Failed to encrypt message", e);
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
            final byte[] nonce = transformHeader.getNonce();
            final byte[] authTag = transformHeader.getSignature();

            // Extract ciphertext
            final int ciphertextLength = encryptedMessage.length - Smb2TransformHeader.TRANSFORM_HEADER_SIZE;
            final byte[] ciphertext = new byte[ciphertextLength];
            System.arraycopy(encryptedMessage, Smb2TransformHeader.TRANSFORM_HEADER_SIZE, ciphertext, 0, ciphertextLength);

            byte[] plaintext;

            if (isGCMCipher()) {
                // Use AES-GCM
                final Cipher cipher = createGCMCipher(false, nonce);
                cipher.updateAAD(associatedData);

                // Combine ciphertext and auth tag for decryption
                final byte[] input = new byte[ciphertext.length + authTag.length];
                System.arraycopy(ciphertext, 0, input, 0, ciphertext.length);
                System.arraycopy(authTag, 0, input, ciphertext.length, authTag.length);

                plaintext = cipher.doFinal(input);
            } else {
                // Use AES-CCM with Bouncy Castle
                final AEADBlockCipher cipher = createCCMCipher(false, nonce, associatedData.length, ciphertext.length);

                final byte[] input = new byte[associatedData.length + ciphertext.length + authTag.length];
                System.arraycopy(associatedData, 0, input, 0, associatedData.length);
                System.arraycopy(ciphertext, 0, input, associatedData.length, ciphertext.length);
                System.arraycopy(authTag, 0, input, associatedData.length + ciphertext.length, authTag.length);

                final byte[] output = new byte[cipher.getOutputSize(input.length)];
                int len = cipher.processBytes(input, 0, input.length, output, 0);
                len += cipher.doFinal(output, len);

                plaintext = new byte[ciphertext.length];
                System.arraycopy(output, associatedData.length, plaintext, 0, ciphertext.length);
            }

            return plaintext;
        } catch (final Exception e) {
            throw new CIFSException("Failed to decrypt message", e);
        }
    }

    private boolean isGCMCipher() {
        return this.cipherId == CIPHER_AES_128_GCM;
    }

    private int getKeyLength() {
        // Currently only AES-128 is supported
        if (this.cipherId == CIPHER_AES_128_CCM || this.cipherId == CIPHER_AES_128_GCM) {
            return 16;
        }
        throw new IllegalArgumentException("Unsupported cipher: " + this.cipherId);
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

    private Cipher createGCMCipher(final boolean encrypt, final byte[] nonce) throws Exception {
        final String algorithm = "AES";
        final SecretKeySpec keySpec = new SecretKeySpec(encrypt ? this.encryptionKey : this.decryptionKey, algorithm);

        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final GCMParameterSpec gcmSpec = new GCMParameterSpec(getAuthTagLength() * 8, nonce);
        cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        return cipher;
    }

    private AEADBlockCipher createCCMCipher(final boolean encrypt, final byte[] nonce, final int aadLength, final int plaintextLength) {
        final AEADBlockCipher cipher = new CCMBlockCipher(new AESEngine());

        final KeyParameter keyParam = new KeyParameter(encrypt ? this.encryptionKey : this.decryptionKey);
        // CCMBlockCipher requires nonce length between 7 and 13
        final byte[] adjustedNonce = new byte[13];
        System.arraycopy(nonce, 0, adjustedNonce, 0, Math.min(13, nonce.length));

        final AEADParameters params = new AEADParameters(keyParam, getAuthTagLength() * 8, adjustedNonce, null);

        cipher.init(encrypt, params);

        return cipher;
    }

    private static byte[] longToBytes(final long value) {
        final byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (value >>> 8 * (7 - i));
        }
        return bytes;
    }
}
