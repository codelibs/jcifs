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
package org.codelibs.jcifs.smb;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.codelibs.jcifs.smb.internal.smb2.nego.PreauthIntegrityNegotiateContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Enhanced Pre-Authentication Integrity Service for SMB 3.1.1.
 *
 * Provides comprehensive pre-authentication integrity protection against
 * downgrade attacks by maintaining cryptographic hash chains of all
 * negotiation and session setup messages.
 */
public class PreauthIntegrityService {

    private static final Logger log = LoggerFactory.getLogger(PreauthIntegrityService.class);

    /**
     * SHA-512 hash algorithm identifier for preauth integrity
     */
    public static final int HASH_ALGO_SHA512 = PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512;

    // Default configuration
    private static final int DEFAULT_HASH_ALGORITHM = HASH_ALGO_SHA512;
    private static final int SALT_SIZE = 32; // 32 bytes as per SMB 3.1.1 spec
    private static final int HASH_SIZE_SHA512 = 64; // SHA-512 produces 64-byte hashes

    // Session-specific preauth integrity contexts
    private final ConcurrentMap<String, PreauthIntegrityContext> sessionContexts = new ConcurrentHashMap<>();

    // Security configuration
    private final SecureRandom secureRandom;
    private final int selectedHashAlgorithm;
    private final boolean enforceIntegrity;

    /**
     * Context for maintaining preauth integrity state per session.
     */
    public static class PreauthIntegrityContext {
        private final byte[] salt;
        private final int hashAlgorithm;
        private volatile byte[] currentHash;
        private volatile boolean isValid;
        private final Object hashLock = new Object();

        /**
         * Creates a new preauth integrity context
         * @param salt the salt value for the context
         * @param hashAlgorithm the hash algorithm to use
         */
        public PreauthIntegrityContext(byte[] salt, int hashAlgorithm) {
            this.salt = salt != null ? salt.clone() : new byte[0];
            this.hashAlgorithm = hashAlgorithm;
            this.currentHash = new byte[HASH_SIZE_SHA512]; // Initialize with zeros
            this.isValid = true;
        }

        /**
         * Gets the salt value for this context
         * @return a copy of the salt bytes
         */
        public byte[] getSalt() {
            return salt.clone();
        }

        /**
         * Gets the hash algorithm identifier
         * @return the hash algorithm constant
         */
        public int getHashAlgorithm() {
            return hashAlgorithm;
        }

        /**
         * Gets the current hash value
         * @return a copy of the current hash bytes
         */
        public byte[] getCurrentHash() {
            synchronized (hashLock) {
                return currentHash.clone();
            }
        }

        /**
         * Updates the current hash value
         * @param newHash the new hash bytes to set
         */
        public void updateHash(byte[] newHash) {
            synchronized (hashLock) {
                if (newHash != null && newHash.length == currentHash.length) {
                    this.currentHash = newHash.clone();
                }
            }
        }

        /**
         * Checks if this context is still valid
         * @return true if the context is valid, false otherwise
         */
        public boolean isValid() {
            return isValid;
        }

        /**
         * Invalidates this context and clears sensitive data
         */
        public void invalidate() {
            this.isValid = false;
            // Clear sensitive data
            synchronized (hashLock) {
                Arrays.fill(currentHash, (byte) 0);
            }
        }
    }

    /**
     * Constructs a PreauthIntegrityService with default configuration.
     */
    public PreauthIntegrityService() {
        this(new SecureRandom(), DEFAULT_HASH_ALGORITHM, true);
    }

    /**
     * Constructs a PreauthIntegrityService with specified configuration.
     *
     * @param secureRandom the secure random generator
     * @param hashAlgorithm the hash algorithm to use
     * @param enforceIntegrity whether to enforce integrity checks
     */
    public PreauthIntegrityService(SecureRandom secureRandom, int hashAlgorithm, boolean enforceIntegrity) {
        this.secureRandom = secureRandom != null ? secureRandom : new SecureRandom();
        this.selectedHashAlgorithm = hashAlgorithm;
        this.enforceIntegrity = enforceIntegrity;
    }

    /**
     * Generates a new preauth salt for SMB 3.1.1 negotiation.
     *
     * @return a cryptographically secure random salt
     */
    public byte[] generatePreauthSalt() {
        byte[] salt = new byte[SALT_SIZE];
        secureRandom.nextBytes(salt);
        log.debug("Generated new preauth salt of {} bytes", salt.length);
        return salt;
    }

    /**
     * Initializes preauth integrity context for a new session.
     *
     * @param sessionId the session identifier
     * @param salt the preauth salt from negotiation
     * @param hashAlgorithm the selected hash algorithm
     * @return the created context
     * @throws CIFSException if initialization fails
     */
    public PreauthIntegrityContext initializeSession(String sessionId, byte[] salt, int hashAlgorithm) throws CIFSException {
        if (sessionId == null || sessionId.isEmpty()) {
            throw new CIFSException("Session ID cannot be null or empty");
        }
        if (salt == null || salt.length < 16) {
            throw new CIFSException("Invalid preauth salt: minimum 16 bytes required");
        }
        if (!isHashAlgorithmSupported(hashAlgorithm)) {
            throw new CIFSException("Unsupported hash algorithm: " + hashAlgorithm);
        }

        PreauthIntegrityContext context = new PreauthIntegrityContext(salt, hashAlgorithm);
        sessionContexts.put(sessionId, context);

        log.debug("Initialized preauth integrity context for session {}", sessionId);
        return context;
    }

    /**
     * Updates the preauth integrity hash with a new message.
     *
     * @param sessionId the session identifier
     * @param messageData the message data to include in hash
     * @throws CIFSException if update fails
     */
    public void updatePreauthHash(String sessionId, byte[] messageData) throws CIFSException {
        PreauthIntegrityContext context = sessionContexts.get(sessionId);
        if (context == null) {
            if (enforceIntegrity) {
                throw new CIFSException("No preauth integrity context found for session: " + sessionId);
            }
            log.warn("No preauth integrity context for session {}, skipping update", sessionId);
            return;
        }

        if (!context.isValid()) {
            throw new CIFSException("Preauth integrity context is invalid for session: " + sessionId);
        }

        try {
            byte[] newHash = calculateHash(context.getCurrentHash(), messageData, context.getHashAlgorithm());
            context.updateHash(newHash);

            log.debug("Updated preauth hash for session {} with {} bytes of data", sessionId, messageData.length);
        } catch (Exception e) {
            context.invalidate();
            throw new CIFSException("Failed to update preauth integrity hash for session " + sessionId, e);
        }
    }

    /**
     * Validates the preauth integrity for completed negotiation.
     *
     * @param sessionId the session identifier
     * @param expectedHash the expected final hash
     * @return true if validation passes
     * @throws CIFSException if validation fails
     */
    public boolean validatePreauthIntegrity(String sessionId, byte[] expectedHash) throws CIFSException {
        PreauthIntegrityContext context = sessionContexts.get(sessionId);
        if (context == null) {
            if (enforceIntegrity) {
                throw new CIFSException("No preauth integrity context found for session: " + sessionId);
            }
            log.warn("No preauth integrity context for session {}, skipping validation", sessionId);
            return false;
        }

        if (!context.isValid()) {
            throw new CIFSException("Preauth integrity context is invalid for session: " + sessionId);
        }

        byte[] actualHash = context.getCurrentHash();
        boolean isValid = MessageDigest.isEqual(actualHash, expectedHash);

        if (isValid) {
            log.debug("Preauth integrity validation passed for session {}", sessionId);
        } else {
            log.error("Preauth integrity validation FAILED for session {}", sessionId);
            context.invalidate();
            if (enforceIntegrity) {
                throw new CIFSException("Preauth integrity validation failed - possible downgrade attack detected");
            }
        }

        return isValid;
    }

    /**
     * Gets the current preauth hash for a session.
     *
     * @param sessionId the session identifier
     * @return the current hash, or null if no context exists
     */
    public byte[] getCurrentPreauthHash(String sessionId) {
        PreauthIntegrityContext context = sessionContexts.get(sessionId);
        return context != null ? context.getCurrentHash() : null;
    }

    /**
     * Finalizes and removes the preauth integrity context for a session.
     *
     * @param sessionId the session identifier
     */
    public void finalizeSession(String sessionId) {
        PreauthIntegrityContext context = sessionContexts.remove(sessionId);
        if (context != null) {
            context.invalidate();
            log.debug("Finalized preauth integrity context for session {}", sessionId);
        }
    }

    /**
     * Checks if a hash algorithm is supported.
     *
     * @param hashAlgorithm the algorithm to check
     * @return true if supported
     */
    public boolean isHashAlgorithmSupported(int hashAlgorithm) {
        return hashAlgorithm == HASH_ALGO_SHA512; // Currently only SHA-512 is supported
    }

    /**
     * Gets the list of supported hash algorithms.
     *
     * @return array of supported algorithms
     */
    public int[] getSupportedHashAlgorithms() {
        return new int[] { HASH_ALGO_SHA512 };
    }

    /**
     * Gets the selected hash algorithm.
     *
     * @return the hash algorithm
     */
    public int getSelectedHashAlgorithm() {
        return selectedHashAlgorithm;
    }

    /**
     * Calculates hash according to SMB 3.1.1 preauth integrity specification.
     *
     * @param previousHash the previous hash in the chain
     * @param messageData the message data to hash
     * @param hashAlgorithm the hash algorithm to use
     * @return the new hash
     * @throws CIFSException if hash calculation fails
     */
    private byte[] calculateHash(byte[] previousHash, byte[] messageData, int hashAlgorithm) throws CIFSException {
        try {
            MessageDigest digest;
            switch (hashAlgorithm) {
            case HASH_ALGO_SHA512:
                digest = MessageDigest.getInstance("SHA-512");
                break;
            default:
                throw new CIFSException("Unsupported hash algorithm: " + hashAlgorithm);
            }

            // SMB 3.1.1 spec: Hash = Hash(PreviousHash || Message)
            digest.update(previousHash);
            digest.update(messageData);

            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new CIFSException("Hash algorithm not available: " + hashAlgorithm, e);
        }
    }

    /**
     * Gets the name of a hash algorithm.
     *
     * @param algorithm the algorithm constant
     * @return the algorithm name
     */
    public static String getHashAlgorithmName(int algorithm) {
        switch (algorithm) {
        case HASH_ALGO_SHA512:
            return "SHA-512";
        default:
            return "Unknown(0x" + Integer.toHexString(algorithm) + ")";
        }
    }

    /**
     * Clears all session contexts (for cleanup).
     */
    public void cleanup() {
        for (PreauthIntegrityContext context : sessionContexts.values()) {
            context.invalidate();
        }
        sessionContexts.clear();
        log.debug("Cleaned up all preauth integrity contexts");
    }
}
