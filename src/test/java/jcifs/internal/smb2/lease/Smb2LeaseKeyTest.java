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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Smb2LeaseKey Tests")
class Smb2LeaseKeyTest {

    @Test
    @DisplayName("Should generate random lease key with correct size")
    void testRandomLeaseKeyGeneration() {
        Smb2LeaseKey key = new Smb2LeaseKey();

        assertNotNull(key.getKey());
        assertEquals(16, key.getKey().length);
        assertFalse(key.isZero());
    }

    @Test
    @DisplayName("Should create lease key from byte array")
    void testLeaseKeyFromBytes() {
        byte[] testBytes = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };

        Smb2LeaseKey key = new Smb2LeaseKey(testBytes);

        assertArrayEquals(testBytes, key.getKey());
        assertFalse(key.isZero());
    }

    @Test
    @DisplayName("Should create zero lease key")
    void testZeroLeaseKey() {
        byte[] zeroBytes = new byte[16];
        Arrays.fill(zeroBytes, (byte) 0);

        Smb2LeaseKey key = new Smb2LeaseKey(zeroBytes);

        assertTrue(key.isZero());
        assertArrayEquals(zeroBytes, key.getKey());
    }

    @Test
    @DisplayName("Should reject null key")
    void testNullKey() {
        assertThrows(IllegalArgumentException.class, () -> new Smb2LeaseKey(null));
    }

    @Test
    @DisplayName("Should reject wrong size key")
    void testWrongSizeKey() {
        assertThrows(IllegalArgumentException.class, () -> new Smb2LeaseKey(new byte[15]));
        assertThrows(IllegalArgumentException.class, () -> new Smb2LeaseKey(new byte[17]));
        assertThrows(IllegalArgumentException.class, () -> new Smb2LeaseKey(new byte[0]));
    }

    @Test
    @DisplayName("Should encode lease key to buffer")
    void testEncode() {
        byte[] testBytes = new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB,
                (byte) 0xCC, (byte) 0xDD, (byte) 0xEE, (byte) 0xFF, 0x00 };

        Smb2LeaseKey key = new Smb2LeaseKey(testBytes);
        byte[] buffer = new byte[20];

        key.encode(buffer, 2);

        for (int i = 0; i < 16; i++) {
            assertEquals(testBytes[i], buffer[i + 2]);
        }
    }

    @Test
    @DisplayName("Should implement equals correctly")
    void testEquals() {
        byte[] testBytes1 = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        byte[] testBytes2 = Arrays.copyOf(testBytes1, 16);
        byte[] testBytes3 = new byte[] { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };

        Smb2LeaseKey key1 = new Smb2LeaseKey(testBytes1);
        Smb2LeaseKey key2 = new Smb2LeaseKey(testBytes2);
        Smb2LeaseKey key3 = new Smb2LeaseKey(testBytes3);

        assertEquals(key1, key2);
        assertNotEquals(key1, key3);
        assertNotEquals(key1, null);
        assertNotEquals(key1, "not a lease key");
        assertEquals(key1, key1); // reflexive
    }

    @Test
    @DisplayName("Should implement hashCode correctly")
    void testHashCode() {
        byte[] testBytes1 = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        byte[] testBytes2 = Arrays.copyOf(testBytes1, 16);

        Smb2LeaseKey key1 = new Smb2LeaseKey(testBytes1);
        Smb2LeaseKey key2 = new Smb2LeaseKey(testBytes2);

        assertEquals(key1.hashCode(), key2.hashCode());
    }

    @Test
    @DisplayName("Should generate different random keys")
    void testRandomKeyUniqueness() {
        Smb2LeaseKey key1 = new Smb2LeaseKey();
        Smb2LeaseKey key2 = new Smb2LeaseKey();

        assertNotEquals(key1, key2);
        assertFalse(Arrays.equals(key1.getKey(), key2.getKey()));
    }

    @Test
    @DisplayName("Should return defensive copy of key")
    void testDefensiveCopy() {
        byte[] originalBytes =
                new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };

        Smb2LeaseKey key = new Smb2LeaseKey(originalBytes);
        byte[] retrievedKey = key.getKey();

        // Modify the retrieved key
        retrievedKey[0] = (byte) 0xFF;

        // Original key should remain unchanged
        assertEquals(0x01, key.getKey()[0]);
    }

    @Test
    @DisplayName("Should create readable string representation")
    void testToString() {
        byte[] testBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

        Smb2LeaseKey key = new Smb2LeaseKey(testBytes);
        String str = key.toString();

        assertTrue(str.startsWith("LeaseKey["));
        assertTrue(str.endsWith("]"));
        assertTrue(str.contains("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"));
    }
}