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
package org.codelibs.jcifs.smb.util;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Secure key management for SMB encryption.
 * Provides centralized management of encryption keys with secure storage and cleanup.
 *
 * Features:
 * - Secure key storage with optional KeyStore integration
 * - Automatic key cleanup on close
 * - Thread-safe key management
 * - Key derivation utilities
 * - Memory wiping capabilities
 */
public class SecureKeyManager implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(SecureKeyManager.class);

    private final Map<String, SecretKey> sessionKeys = new ConcurrentHashMap<>();
    private final Map<String, byte[]> rawKeys = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();
    private KeyStore keyStore;
    private char[] keyStorePassword;
    private volatile boolean closed = false;

    /**
     * Create a secure key manager without KeyStore
     */
    public SecureKeyManager() {
        this.keyStore = null;
        this.keyStorePassword = null;
    }

    /**
     * Create a secure key manager with KeyStore support
     *
     * @param keyStore the KeyStore to use for key storage
     * @param keyStorePassword password for the KeyStore
     */
    public SecureKeyManager(KeyStore keyStore, char[] keyStorePassword) {
        this.keyStore = keyStore;
        this.keyStorePassword = keyStorePassword != null ? keyStorePassword.clone() : null;
    }

    /**
     * Store a session key
     *
     * @param sessionId unique session identifier
     * @param key the secret key to store
     * @param algorithm the key algorithm (e.g., "AES")
     */
    public void storeSessionKey(String sessionId, byte[] key, String algorithm) {
        checkNotClosed();

        if (key == null || sessionId == null) {
            throw new IllegalArgumentException("Session ID and key must not be null");
        }

        // Clone the key to prevent external modification
        byte[] keyClone = key.clone();
        SecretKey secretKey = new SecretKeySpec(keyClone, algorithm);

        // Store in memory
        sessionKeys.put(sessionId, secretKey);
        rawKeys.put(sessionId, keyClone);

        // Track creation time for rotation (only for non-archived keys)
        if (!sessionId.contains(".v")) {
            keyCreationTimes.put(sessionId, System.currentTimeMillis());
            keyVersions.putIfAbsent(sessionId, 0);
        }

        // Optionally store in KeyStore
        if (keyStore != null) {
            try {
                KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(secretKey);
                KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(keyStorePassword);
                keyStore.setEntry("smb.session." + sessionId, keyEntry, protection);
            } catch (Exception e) {
                log.warn("Failed to store key in KeyStore: {}", e.getMessage());
            }
        }

        log.debug("Stored session key for session: {}", sessionId);
    }

    /**
     * Retrieve a session key
     *
     * @param sessionId unique session identifier
     * @return the secret key, or null if not found
     */
    public SecretKey getSessionKey(String sessionId) {
        checkNotClosed();

        SecretKey key = sessionKeys.get(sessionId);

        // Try to load from KeyStore if not in memory
        if (key == null && keyStore != null) {
            try {
                KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(keyStorePassword);
                KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry("smb.session." + sessionId, protection);
                if (entry != null) {
                    key = entry.getSecretKey();
                    sessionKeys.put(sessionId, key);
                }
            } catch (Exception e) {
                log.debug("Failed to load key from KeyStore: {}", e.getMessage());
            }
        }

        return key;
    }

    /**
     * Get raw key bytes
     *
     * @param sessionId unique session identifier
     * @return raw key bytes, or null if not found
     */
    public byte[] getRawKey(String sessionId) {
        checkNotClosed();

        byte[] key = rawKeys.get(sessionId);
        if (key != null) {
            return key.clone(); // Return a copy to prevent modification
        }

        // Try to get from SecretKey if available
        SecretKey secretKey = getSessionKey(sessionId);
        if (secretKey != null) {
            return secretKey.getEncoded();
        }

        return null;
    }

    /**
     * Remove and securely wipe a session key
     *
     * @param sessionId unique session identifier
     */
    public void removeSessionKey(String sessionId) {
        checkNotClosed();

        // Remove from memory maps
        SecretKey secretKey = sessionKeys.remove(sessionId);
        byte[] rawKey = rawKeys.remove(sessionId);

        // Wipe the raw key bytes
        if (rawKey != null) {
            Arrays.fill(rawKey, (byte) 0);
        }

        // Destroy the SecretKey if possible
        if (secretKey instanceof Destroyable) {
            try {
                ((Destroyable) secretKey).destroy();
            } catch (DestroyFailedException e) {
                log.warn("Failed to destroy SecretKey: {}", e.getMessage());
            }
        }

        // Remove from KeyStore
        if (keyStore != null) {
            try {
                keyStore.deleteEntry("smb.session." + sessionId);
            } catch (Exception e) {
                log.debug("Failed to remove key from KeyStore: {}", e.getMessage());
            }
        }

        log.debug("Removed and wiped session key for session: {}", sessionId);
    }

    /**
     * Derive a new key from an existing key
     *
     * @param baseKey the base key
     * @param label key derivation label
     * @param context key derivation context
     * @param length desired key length in bytes
     * @return derived key
     * @throws GeneralSecurityException if key derivation fails
     */
    public byte[] deriveKey(byte[] baseKey, String label, byte[] context, int length) throws GeneralSecurityException {
        checkNotClosed();

        // Simple KDF implementation (should be replaced with proper KDF like HKDF)
        // This is a placeholder - real implementation should use proper KDF
        byte[] derived = new byte[length];

        // Combine inputs
        byte[] labelBytes = label.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] input = new byte[baseKey.length + labelBytes.length + (context != null ? context.length : 0)];

        int pos = 0;
        System.arraycopy(baseKey, 0, input, pos, baseKey.length);
        pos += baseKey.length;
        System.arraycopy(labelBytes, 0, input, pos, labelBytes.length);
        pos += labelBytes.length;
        if (context != null) {
            System.arraycopy(context, 0, input, pos, context.length);
        }

        // Use SHA-256 for derivation (placeholder)
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input);
            System.arraycopy(hash, 0, derived, 0, Math.min(length, hash.length));

            // If we need more bytes, hash again with counter
            int counter = 1;
            while (derived.length > hash.length * counter) {
                md.update(input);
                md.update((byte) counter);
                hash = md.digest();
                int copyLen = Math.min(length - (hash.length * counter), hash.length);
                System.arraycopy(hash, 0, derived, hash.length * counter, copyLen);
                counter++;
            }
        } finally {
            // Wipe input
            Arrays.fill(input, (byte) 0);
        }

        return derived;
    }

    /**
     * Generate a random key
     *
     * @param length key length in bytes
     * @return random key bytes
     */
    public byte[] generateRandomKey(int length) {
        checkNotClosed();

        byte[] key = new byte[length];
        secureRandom.nextBytes(key);
        return key;
    }

    /**
     * Clear all stored keys
     */
    public void clearAllKeys() {
        checkNotClosed();

        log.info("Clearing all stored keys");

        // Wipe all raw keys
        for (Map.Entry<String, byte[]> entry : rawKeys.entrySet()) {
            Arrays.fill(entry.getValue(), (byte) 0);
        }
        rawKeys.clear();

        // Destroy all secret keys
        for (Map.Entry<String, SecretKey> entry : sessionKeys.entrySet()) {
            SecretKey key = entry.getValue();
            if (key instanceof Destroyable) {
                try {
                    ((Destroyable) key).destroy();
                } catch (DestroyFailedException e) {
                    log.warn("Failed to destroy key for session {}: {}", entry.getKey(), e.getMessage());
                }
            }
        }
        sessionKeys.clear();

        // Clear KeyStore entries
        if (keyStore != null) {
            try {
                java.util.Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (alias.startsWith("smb.session.")) {
                        keyStore.deleteEntry(alias);
                    }
                }
            } catch (Exception e) {
                log.warn("Failed to clear KeyStore entries: {}", e.getMessage());
            }
        }
    }

    /**
     * Get the number of stored keys
     *
     * @return number of keys in memory
     */
    public int getKeyCount() {
        return sessionKeys.size();
    }

    /**
     * Check if a session key exists
     *
     * @param sessionId session identifier
     * @return true if key exists
     */
    public boolean hasSessionKey(String sessionId) {
        checkNotClosed();
        return sessionKeys.containsKey(sessionId) || (keyStore != null && keyStoreContainsKey(sessionId));
    }

    private boolean keyStoreContainsKey(String sessionId) {
        try {
            return keyStore.containsAlias("smb.session." + sessionId);
        } catch (Exception e) {
            return false;
        }
    }

    private void checkNotClosed() {
        if (closed) {
            throw new IllegalStateException("SecureKeyManager is closed");
        }
    }

    // Key rotation configuration
    private long keyRotationIntervalMillis = 3600000L; // 1 hour default
    private final Map<String, Long> keyCreationTimes = new ConcurrentHashMap<>();
    private final Map<String, Integer> keyVersions = new ConcurrentHashMap<>();
    private final java.util.concurrent.ScheduledExecutorService rotationScheduler =
            java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "SecureKeyManager-Rotation");
                t.setDaemon(true);
                return t;
            });
    private java.util.concurrent.ScheduledFuture<?> rotationTask;

    /**
     * Configure key rotation interval
     *
     * @param intervalMillis rotation interval in milliseconds
     */
    public void configureKeyRotation(long intervalMillis) {
        this.keyRotationIntervalMillis = intervalMillis;

        // Cancel existing rotation task if any
        if (rotationTask != null) {
            rotationTask.cancel(false);
        }

        // Schedule new rotation task
        if (intervalMillis > 0) {
            rotationTask = rotationScheduler.scheduleWithFixedDelay(this::rotateExpiredKeys, intervalMillis, intervalMillis,
                    java.util.concurrent.TimeUnit.MILLISECONDS);
            log.info("Key rotation configured with interval: {} ms", intervalMillis);
        }
    }

    /**
     * Rotate a specific session key
     *
     * @param sessionId the session ID
     * @return the new key version number
     * @throws GeneralSecurityException if rotation fails
     */
    public int rotateSessionKey(String sessionId) throws GeneralSecurityException {
        checkNotClosed();

        if (!sessionKeys.containsKey(sessionId)) {
            throw new IllegalArgumentException("Session key not found: " + sessionId);
        }

        // Get current key
        byte[] currentKey = getRawKey(sessionId);
        if (currentKey == null) {
            throw new IllegalStateException("Unable to retrieve current key for rotation");
        }

        try {
            // Generate new key version
            int currentVersion = keyVersions.getOrDefault(sessionId, 0);
            int newVersion = currentVersion + 1;

            // Derive new key from current key
            String rotationLabel = String.format("KeyRotation-v%d", newVersion);
            byte[] newKey = deriveKey(currentKey, rotationLabel, String.valueOf(System.currentTimeMillis()).getBytes(), currentKey.length);

            // Archive old key (keep last version for rollback)
            String archiveId = sessionId + ".v" + currentVersion;
            storeSessionKeyInternal(archiveId, currentKey, "AES");

            // Store new key
            storeSessionKeyInternal(sessionId, newKey, "AES");
            keyVersions.put(sessionId, newVersion);
            keyCreationTimes.put(sessionId, System.currentTimeMillis());

            log.info("Rotated key for session {} from version {} to {}", sessionId, currentVersion, newVersion);

            // Securely wipe the old key copy
            secureWipe(currentKey);
            secureWipe(newKey);

            return newVersion;

        } catch (Exception e) {
            log.error("Failed to rotate key for session: {}", sessionId, e);
            throw new GeneralSecurityException("Key rotation failed", e);
        }
    }

    /**
     * Internal method to store key without updating rotation metadata
     */
    private void storeSessionKeyInternal(String sessionId, byte[] key, String algorithm) {
        if (key == null || sessionId == null) {
            throw new IllegalArgumentException("Session ID and key must not be null");
        }

        // Clone the key to prevent external modification
        byte[] keyClone = key.clone();
        SecretKey secretKey = new SecretKeySpec(keyClone, algorithm);

        // Store in memory
        sessionKeys.put(sessionId, secretKey);
        rawKeys.put(sessionId, keyClone);

        // Optionally store in KeyStore
        if (keyStore != null) {
            try {
                KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(secretKey);
                KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(keyStorePassword);
                keyStore.setEntry("smb.session." + sessionId, keyEntry, protection);
            } catch (Exception e) {
                log.warn("Failed to store key in KeyStore: {}", e.getMessage());
            }
        }
    }

    /**
     * Rotate all expired keys based on configured interval
     */
    private void rotateExpiredKeys() {
        if (closed) {
            return;
        }

        long now = System.currentTimeMillis();
        java.util.List<String> sessionsToRotate = new java.util.ArrayList<>();

        // Find expired keys
        for (Map.Entry<String, Long> entry : keyCreationTimes.entrySet()) {
            String sessionId = entry.getKey();
            Long creationTime = entry.getValue();

            if (creationTime != null && (now - creationTime) > keyRotationIntervalMillis) {
                // Skip archived keys (those with version suffix)
                if (!sessionId.contains(".v")) {
                    sessionsToRotate.add(sessionId);
                }
            }
        }

        // Rotate expired keys
        for (String sessionId : sessionsToRotate) {
            try {
                rotateSessionKey(sessionId);
            } catch (Exception e) {
                log.warn("Failed to auto-rotate key for session: {}", sessionId, e);
            }
        }

        if (!sessionsToRotate.isEmpty()) {
            log.info("Auto-rotated {} expired keys", sessionsToRotate.size());
        }
    }

    /**
     * Get the current version of a session key
     *
     * @param sessionId the session ID
     * @return the key version, or 0 if not versioned
     */
    public int getKeyVersion(String sessionId) {
        return keyVersions.getOrDefault(sessionId, 0);
    }

    /**
     * Get key age in milliseconds
     *
     * @param sessionId the session ID
     * @return age in milliseconds, or -1 if unknown
     */
    public long getKeyAge(String sessionId) {
        Long creationTime = keyCreationTimes.get(sessionId);
        if (creationTime == null) {
            return -1;
        }
        return System.currentTimeMillis() - creationTime;
    }

    /**
     * Force rotation of all active keys
     *
     * @return number of keys rotated
     */
    public int forceRotateAllKeys() {
        checkNotClosed();

        int rotated = 0;
        java.util.List<String> sessionIds = new java.util.ArrayList<>(sessionKeys.keySet());

        for (String sessionId : sessionIds) {
            // Skip archived keys
            if (!sessionId.contains(".v")) {
                try {
                    rotateSessionKey(sessionId);
                    rotated++;
                } catch (Exception e) {
                    log.warn("Failed to rotate key for session: {}", sessionId, e);
                }
            }
        }

        log.info("Force rotated {} keys", rotated);
        return rotated;
    }

    /**
     * Clean up old archived key versions
     *
     * @param keepVersions number of versions to keep (minimum 1)
     */
    public void cleanupArchivedKeys(int keepVersions) {
        checkNotClosed();

        if (keepVersions < 1) {
            keepVersions = 1;
        }

        Map<String, java.util.List<String>> sessionArchives = new HashMap<>();

        // Group archived keys by session
        for (String key : sessionKeys.keySet()) {
            if (key.contains(".v")) {
                String baseSession = key.substring(0, key.indexOf(".v"));
                sessionArchives.computeIfAbsent(baseSession, k -> new java.util.ArrayList<>()).add(key);
            }
        }

        // Remove old versions
        int removed = 0;
        for (Map.Entry<String, java.util.List<String>> entry : sessionArchives.entrySet()) {
            java.util.List<String> archives = entry.getValue();

            // Sort by version number
            archives.sort((a, b) -> {
                int versionA = extractVersion(a);
                int versionB = extractVersion(b);
                return Integer.compare(versionB, versionA); // Descending order
            });

            // Keep only the specified number of versions
            for (int i = keepVersions; i < archives.size(); i++) {
                removeSessionKey(archives.get(i));
                removed++;
            }
        }

        if (removed > 0) {
            log.info("Cleaned up {} archived key versions", removed);
        }
    }

    private int extractVersion(String archivedKey) {
        try {
            String versionStr = archivedKey.substring(archivedKey.indexOf(".v") + 2);
            return Integer.parseInt(versionStr);
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Close the key manager and securely wipe all keys
     */
    @Override
    public void close() {
        if (closed) {
            return;
        }

        log.info("Closing SecureKeyManager and wiping all keys");

        try {
            // Cancel rotation task
            if (rotationTask != null) {
                rotationTask.cancel(false);
                rotationTask = null;
            }

            // Shutdown rotation scheduler
            rotationScheduler.shutdownNow();

            clearAllKeys();
        } finally {
            // Wipe KeyStore password
            if (keyStorePassword != null) {
                Arrays.fill(keyStorePassword, '\0');
                keyStorePassword = null;
            }

            keyStore = null;
            closed = true;
        }
    }

    /**
     * Static utility to securely wipe a byte array
     *
     * @param array the array to wipe
     */
    public static void secureWipe(byte[] array) {
        if (array != null) {
            Arrays.fill(array, (byte) 0);
            // Additional passes with different patterns for enhanced security
            Arrays.fill(array, (byte) 0xFF);
            Arrays.fill(array, (byte) 0xAA);
            Arrays.fill(array, (byte) 0x55);
            Arrays.fill(array, (byte) 0);
        }
    }
}
