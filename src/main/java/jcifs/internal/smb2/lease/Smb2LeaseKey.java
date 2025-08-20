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
package jcifs.internal.smb2.lease;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * SMB2 Lease Key
 *
 * Represents a 16-byte lease key used to identify leases in SMB2/SMB3
 * MS-SMB2 2.2.13.2.8
 */
public class Smb2LeaseKey {

    private final byte[] key;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int LEASE_KEY_SIZE = 16;

    /**
     * Create a new random lease key
     */
    public Smb2LeaseKey() {
        this.key = new byte[LEASE_KEY_SIZE];
        RANDOM.nextBytes(this.key);
    }

    /**
     * Create a lease key from existing bytes
     *
     * @param key 16-byte array
     * @throws IllegalArgumentException if key is not 16 bytes
     */
    public Smb2LeaseKey(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("Lease key cannot be null");
        }
        if (key.length != LEASE_KEY_SIZE) {
            throw new IllegalArgumentException("Lease key must be 16 bytes, got " + key.length);
        }
        this.key = Arrays.copyOf(key, LEASE_KEY_SIZE);
    }

    /**
     * Get the lease key bytes
     *
     * @return copy of the 16-byte lease key
     */
    public byte[] getKey() {
        return Arrays.copyOf(key, LEASE_KEY_SIZE);
    }

    /**
     * Write the lease key to a buffer
     *
     * @param dst destination buffer
     * @param dstIndex starting index in destination buffer
     */
    public void encode(byte[] dst, int dstIndex) {
        System.arraycopy(key, 0, dst, dstIndex, LEASE_KEY_SIZE);
    }

    /**
     * Check if this is a zero key (all bytes are zero)
     *
     * @return true if all bytes are zero
     */
    public boolean isZero() {
        for (byte b : key) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        Smb2LeaseKey other = (Smb2LeaseKey) obj;
        return Arrays.equals(key, other.key);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("LeaseKey[");
        for (int i = 0; i < key.length; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(String.format("%02X", key[i] & 0xFF));
        }
        sb.append(']');
        return sb.toString();
    }
}