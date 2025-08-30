/*
 * © 2017 AgNO3 Gmbh & Co. KG
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

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.concurrent.locks.ReentrantLock;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.internal.CommonServerMessageBlock;
import jcifs.internal.SMBSigningDigest;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Crypto;

/**
 * SMB2/SMB3 message signing digest implementation.
 *
 * This class handles cryptographic signing of SMB2/SMB3 messages to ensure
 * message integrity and authenticity. It supports different signing algorithms
 * used in various SMB2/SMB3 dialect versions.
 *
 * @author mbechler
 */
public class Smb2SigningDigest implements SMBSigningDigest, AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(Smb2SigningDigest.class);

    /**
     *
     */
    private static final int SIGNATURE_OFFSET = 48;
    private static final int SIGNATURE_LENGTH = 16;
    private final Mac digest;
    private final ReentrantLock signingLock = new ReentrantLock();
    private byte[] signingKey;
    private final String algorithmName;
    private final java.security.Provider provider;
    private volatile boolean closed = false;

    /**
     * Constructs a SMB2 signing digest with the specified session key and dialect
     *
     * @param sessionKey
     *            the session key for signing
     * @param dialect
     *            the SMB2 dialect version
     * @param preauthIntegrityHash
     *            the pre-authentication integrity hash (for SMB 3.1.1)
     * @throws GeneralSecurityException
     *             if the signing algorithm cannot be initialized
     *
     */
    public Smb2SigningDigest(final byte[] sessionKey, final int dialect, final byte[] preauthIntegrityHash)
            throws GeneralSecurityException {
        switch (dialect) {
        case Smb2Constants.SMB2_DIALECT_0202:
        case Smb2Constants.SMB2_DIALECT_0210:
            this.algorithmName = "HmacSHA256";
            this.provider = null;
            this.signingKey = sessionKey.clone();
            break;
        case Smb2Constants.SMB2_DIALECT_0300:
        case Smb2Constants.SMB2_DIALECT_0302:
            this.signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, new byte[0] /* unimplemented */);
            this.algorithmName = "AESCMAC";
            this.provider = Crypto.getProvider();
            break;
        case Smb2Constants.SMB2_DIALECT_0311:
            if (preauthIntegrityHash == null) {
                throw new IllegalArgumentException("Missing preauthIntegrityHash for SMB 3.1.1");
            }
            this.signingKey = Smb3KeyDerivation.deriveSigningKey(dialect, sessionKey, preauthIntegrityHash);
            this.algorithmName = "AESCMAC";
            this.provider = Crypto.getProvider();
            break;
        default:
            throw new IllegalArgumentException("Unknown dialect");
        }

        // Initialize the digest once to validate configuration
        this.digest = createMacInstance();
    }

    /**
     * Create a new Mac instance for thread-safe operations
     * @return initialized Mac instance
     * @throws GeneralSecurityException if Mac cannot be created
     */
    private Mac createMacInstance() throws GeneralSecurityException {
        if (this.closed) {
            throw new IllegalStateException("SigningDigest is closed");
        }
        if (this.signingKey == null) {
            throw new IllegalStateException("Signing key has been wiped");
        }
        Mac m;
        if (this.provider != null) {
            m = Mac.getInstance(this.algorithmName, this.provider);
        } else {
            m = Mac.getInstance(this.algorithmName);
        }
        m.init(new SecretKeySpec(this.signingKey, "HMAC"));
        return m;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SMBSigningDigest#sign(byte[], int, int, jcifs.internal.CommonServerMessageBlock,
     *      jcifs.internal.CommonServerMessageBlock)
     */
    @Override
    public void sign(final byte[] data, final int offset, final int length, final CommonServerMessageBlock request,
            final CommonServerMessageBlock response) {
        // Validate input parameters
        if (data == null) {
            throw new IllegalArgumentException("Data buffer cannot be null");
        }
        if (offset < 0 || length < 0) {
            throw new IllegalArgumentException("Offset and length must be non-negative");
        }
        if (offset + length > data.length) {
            throw new IllegalArgumentException("Offset + length exceeds data buffer size");
        }
        if (offset + SIGNATURE_OFFSET + SIGNATURE_LENGTH > data.length) {
            throw new IllegalArgumentException("Signature field exceeds data buffer size");
        }

        // Use fine-grained locking for better concurrency
        this.signingLock.lock();
        try {
            if (this.closed) {
                throw new IllegalStateException("SigningDigest is closed");
            }

            // zero out signature field
            final int index = offset + SIGNATURE_OFFSET;
            for (int i = 0; i < SIGNATURE_LENGTH; i++) {
                data[index + i] = 0;
            }

            // set signed flag
            final int oldFlags = SMBUtil.readInt4(data, offset + 16);
            final int flags = oldFlags | ServerMessageBlock2.SMB2_FLAGS_SIGNED;
            SMBUtil.writeInt4(flags, data, offset + 16);

            // Create new Mac instance for thread safety without blocking other operations
            Mac mac;
            try {
                mac = createMacInstance();
            } catch (GeneralSecurityException e) {
                log.error("Failed to create Mac instance for signing", e);
                throw new RuntimeException("Failed to create Mac instance", e);
            }

            mac.update(data, offset, length);
            final byte[] sig = mac.doFinal();
            System.arraycopy(sig, 0, data, offset + SIGNATURE_OFFSET, SIGNATURE_LENGTH);
        } finally {
            this.signingLock.unlock();
        }
    }

    /**
     *
     * {@inheritDoc}
     *
     * @see jcifs.internal.SMBSigningDigest#verify(byte[], int, int, int, jcifs.internal.CommonServerMessageBlock)
     */
    @Override
    public boolean verify(final byte[] data, final int offset, final int length, final int extraPad, final CommonServerMessageBlock msg) {
        // Validate input parameters
        if (data == null) {
            log.error("Data buffer is null in verify");
            return false;
        }
        if (offset < 0 || length < 0) {
            log.error("Invalid offset or length in verify: offset={}, length={}", offset, length);
            return false;
        }
        if (offset + length > data.length) {
            log.error("Offset + length exceeds data buffer size in verify");
            return false;
        }
        if (offset + SIGNATURE_OFFSET + SIGNATURE_LENGTH > data.length) {
            log.error("Signature field exceeds data buffer size in verify");
            return false;
        }

        final int flags = SMBUtil.readInt4(data, offset + 16);
        if ((flags & ServerMessageBlock2.SMB2_FLAGS_SIGNED) == 0) {
            log.error("The server did not sign a message we expected to be signed");
            return true;
        }

        final byte[] sig = new byte[SIGNATURE_LENGTH];
        System.arraycopy(data, offset + SIGNATURE_OFFSET, sig, 0, SIGNATURE_LENGTH);

        // Use fine-grained locking for verification
        this.signingLock.lock();
        try {
            if (this.closed) {
                throw new IllegalStateException("SigningDigest is closed");
            }

            final int index = offset + SIGNATURE_OFFSET;
            for (int i = 0; i < SIGNATURE_LENGTH; i++) {
                data[index + i] = 0;
            }

            // Create new Mac instance for thread safety
            Mac mac;
            try {
                mac = createMacInstance();
            } catch (GeneralSecurityException e) {
                log.error("Failed to create Mac instance for verification", e);
                return false;
            }

            mac.update(data, offset, length);
            final byte[] cmp = new byte[SIGNATURE_LENGTH];
            System.arraycopy(mac.doFinal(), 0, cmp, 0, SIGNATURE_LENGTH);

            // Use constant-time comparison to prevent timing attacks
            if (!MessageDigest.isEqual(sig, cmp)) {
                return false; // Signature verification failed
            }
            return true; // Signature verification succeeded
        } finally {
            this.signingLock.unlock();
        }
    }

    /**
     * Securely wipe signing key from memory
     */
    public void secureWipeKey() {
        this.signingLock.lock();
        try {
            if (this.signingKey != null) {
                java.util.Arrays.fill(this.signingKey, (byte) 0);
                this.signingKey = null;
            }
            this.closed = true;
        } finally {
            this.signingLock.unlock();
        }
    }

    /**
     * Close the signing digest and securely wipe keys
     */
    @Override
    public void close() {
        secureWipeKey();
    }

}
