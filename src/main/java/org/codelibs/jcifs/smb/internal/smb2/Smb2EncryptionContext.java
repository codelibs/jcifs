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

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.internal.smb2.nego.EncryptionNegotiateContext;

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
     * Random prefix that separates this context's nonce space from any other context that might share a key. The
     * trailing counter guarantees uniqueness within this context.
     */
    private final byte[] noncePrefix;

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
        this.noncePrefix = new byte[Math.max(0, getNonceLength() - Long.BYTES)];
        this.secureRandom.nextBytes(this.noncePrefix);
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
     * @return a nonce of the cipher's nonce length (see {@link #getNonceLength()})
     */
    public byte[] generateNonce() {
        final byte[] nonce = new byte[getNonceLength()];
        System.arraycopy(this.noncePrefix, 0, nonce, 0, this.noncePrefix.length);

        // Big-endian counter in the trailing 8 bytes. MS-SMB2 2.2.41 requires that a nonce is never reused for a
        // given key; a 64-bit counter cannot wrap within the lifetime of a session.
        long counter = this.nonceCounter.incrementAndGet();
        for (int i = nonce.length - 1; i >= this.noncePrefix.length; i--) {
            nonce[i] = (byte) counter;
            counter >>>= 8;
        }
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
        final byte[] result = new byte[Smb2TransformHeader.TRANSFORM_HEADER_SIZE + message.length];
        encryptMessage(message, 0, message.length, sessionId, result, 0);
        return result;
    }

    /**
     * Encrypt an SMB2 message into a caller-supplied buffer.
     *
     * <p>
     * Lets the caller reserve room in front of the transform header, so that the NetBIOS session header and the
     * wrapped message can be written to the socket as a single buffer.
     * </p>
     *
     * @param src
     *            buffer holding the plaintext message
     * @param srcOff
     *            offset of the plaintext within {@code src}
     * @param srcLen
     *            length of the plaintext
     * @param sessionId
     *            session identifier
     * @param dst
     *            destination buffer, which must hold {@link Smb2TransformHeader#TRANSFORM_HEADER_SIZE} +
     *            {@code srcLen} bytes from {@code dstOff}
     * @param dstOff
     *            offset to write the transform header at
     * @return the number of bytes written at {@code dstOff}
     * @throws CIFSException
     *             if encryption fails
     */
    public int encryptMessage(final byte[] src, final int srcOff, final int srcLen, final long sessionId, final byte[] dst,
            final int dstOff) throws CIFSException {
        try {
            final byte[] nonce = generateNonce();

            // The transform header carries a 16-byte nonce field; everything beyond the cipher's nonce length must
            // be zero (MS-SMB2 2.2.41).
            final byte[] nonceField = new byte[16];
            System.arraycopy(nonce, 0, nonceField, 0, nonce.length);

            final Smb2TransformHeader transformHeader = new Smb2TransformHeader(nonceField, srcLen, getTransformFlags(), sessionId);

            // Encode the header first, then authenticate the bytes that actually go on the wire rather than a
            // reconstruction of the parsed fields. The signature lies before the authenticated region, so it can
            // be filled in afterwards.
            transformHeader.encode(dst, dstOff);
            final byte[] associatedData =
                    Arrays.copyOfRange(dst, dstOff + Smb2TransformHeader.AAD_OFFSET, dstOff + Smb2TransformHeader.TRANSFORM_HEADER_SIZE);

            final AEADBlockCipher cipher = createCipher(true, nonce, associatedData);
            final byte[] output = new byte[cipher.getOutputSize(srcLen)];
            int len = cipher.processBytes(src, srcOff, srcLen, output, 0);
            len += cipher.doFinal(output, len);

            final int tagLength = getAuthTagLength();
            final int ciphertextLength = len - tagLength;
            System.arraycopy(output, ciphertextLength, dst, dstOff + Smb2TransformHeader.SIGNATURE_OFFSET, tagLength);
            System.arraycopy(output, 0, dst, dstOff + Smb2TransformHeader.TRANSFORM_HEADER_SIZE, ciphertextLength);

            return Smb2TransformHeader.TRANSFORM_HEADER_SIZE + ciphertextLength;
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
            if (encryptedMessage.length < Smb2TransformHeader.TRANSFORM_HEADER_SIZE) {
                throw new CIFSException("Transform message shorter than its header");
            }

            final Smb2TransformHeader transformHeader = Smb2TransformHeader.decode(encryptedMessage, 0);
            checkTransformFlags(transformHeader.getFlags());
            final byte[] authTag = transformHeader.getSignature();

            // Authenticate the bytes exactly as received rather than re-encoding the parsed fields.
            final byte[] associatedData =
                    Arrays.copyOfRange(encryptedMessage, Smb2TransformHeader.AAD_OFFSET, Smb2TransformHeader.TRANSFORM_HEADER_SIZE);

            // Only the leading bytes of the 16-byte nonce field are significant for the negotiated cipher.
            final byte[] nonce = new byte[getNonceLength()];
            System.arraycopy(transformHeader.getNonce(), 0, nonce, 0, nonce.length);

            final int ciphertextLength = encryptedMessage.length - Smb2TransformHeader.TRANSFORM_HEADER_SIZE;
            final byte[] input = new byte[ciphertextLength + authTag.length];
            System.arraycopy(encryptedMessage, Smb2TransformHeader.TRANSFORM_HEADER_SIZE, input, 0, ciphertextLength);
            System.arraycopy(authTag, 0, input, ciphertextLength, authTag.length);

            final AEADBlockCipher cipher = createCipher(false, nonce, associatedData);
            final byte[] output = new byte[cipher.getOutputSize(input.length)];
            int len = cipher.processBytes(input, 0, input.length, output, 0);
            len += cipher.doFinal(output, len);

            // MS-SMB2 3.2.5.1.1: the header has to agree with what came out of the cipher. The AEAD tag only
            // proves the field is authentic, not that the server filled it in consistently.
            final int originalMessageSize = transformHeader.getOriginalMessageSize();
            if (originalMessageSize != len) {
                throw new CIFSException(
                        "Transform header declares " + originalMessageSize + " plaintext bytes but " + len + " were decrypted");
            }

            return output;
        } catch (final CIFSException e) {
            throw e;
        } catch (final Exception e) {
            throw new CIFSException("Failed to decrypt message", e);
        }
    }

    private boolean isGCMCipher() {
        return this.cipherId == CIPHER_AES_128_GCM;
    }

    private int getAuthTagLength() {
        return 16; // All SMB3 ciphers use 16-byte authentication tags
    }

    /**
     * Rejects a transform header whose Flags/EncryptionAlgorithm field does not describe the message this context
     * is able to decrypt (MS-SMB2 2.2.41, 3.2.5.1.1).
     */
    private void checkTransformFlags(final int flags) throws CIFSException {
        final int expected = getTransformFlags();
        if (flags != expected) {
            throw new CIFSException(String.format("Unexpected transform header flags 0x%04x, expected 0x%04x", flags, expected));
        }
    }

    private int getTransformFlags() {
        if (this.dialect.atLeast(DialectVersion.SMB311)) {
            return TRANSFORM_FLAG_ENCRYPTED;
        }
        // For SMB 3.0/3.0.2, this field contains the encryption algorithm
        return this.cipherId;
    }

    /**
     * Nonce length in bytes for the negotiated cipher.
     *
     * <p>
     * MS-SMB2 2.2.41: AES-CCM uses an 11-byte nonce and AES-GCM a 12-byte nonce, both carried in a 16-byte field
     * whose remaining bytes are zero.
     * </p>
     *
     * @return the significant nonce length
     */
    public int getNonceLength() {
        return isGCMCipher() ? 12 : 11;
    }

    private AEADBlockCipher createCipher(final boolean forEncryption, final byte[] nonce, final byte[] associatedData) {
        final AEADBlockCipher cipher =
                isGCMCipher() ? GCMBlockCipher.newInstance(AESEngine.newInstance()) : CCMBlockCipher.newInstance(AESEngine.newInstance());
        final KeyParameter keyParam = new KeyParameter(forEncryption ? this.encryptionKey : this.decryptionKey);
        cipher.init(forEncryption, new AEADParameters(keyParam, getAuthTagLength() * 8, nonce, associatedData));
        return cipher;
    }

}
