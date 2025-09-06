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
package org.codelibs.jcifs.smb.internal.smb2.create;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.codelibs.jcifs.smb.internal.smb2.lease.Smb2LeaseKey;
import org.codelibs.jcifs.smb.internal.smb2.lease.Smb2LeaseState;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("LeaseV1CreateContextRequest Tests")
class LeaseV1CreateContextRequestTest {

    private LeaseV1CreateContextRequest leaseContext;
    private Smb2LeaseKey testKey;
    private int testState;

    @BeforeEach
    void setUp() {
        byte[] keyBytes = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        testKey = new Smb2LeaseKey(keyBytes);
        testState = Smb2LeaseState.SMB2_LEASE_READ_WRITE;
        leaseContext = new LeaseV1CreateContextRequest(testKey, testState);
    }

    @Test
    @DisplayName("Should have correct context name")
    void testContextName() {
        assertArrayEquals("RqLs".getBytes(), leaseContext.getName());
        assertEquals("RqLs", LeaseV1CreateContextRequest.CONTEXT_NAME);
    }

    @Test
    @DisplayName("Should initialize with default values")
    void testDefaultConstructor() {
        LeaseV1CreateContextRequest defaultContext = new LeaseV1CreateContextRequest();

        assertNotNull(defaultContext.getLeaseKey());
        assertEquals(0, defaultContext.getLeaseState());
        assertEquals(0, defaultContext.getLeaseFlags());
    }

    @Test
    @DisplayName("Should initialize with provided values")
    void testParameterizedConstructor() {
        assertEquals(testKey, leaseContext.getLeaseKey());
        assertEquals(testState, leaseContext.getLeaseState());
        assertEquals(0, leaseContext.getLeaseFlags());
    }

    @Test
    @DisplayName("Should calculate correct size")
    void testSize() {
        int expectedSize = 16 + 4 + 4 + 32; // header + name + padding + data
        assertEquals(expectedSize, leaseContext.size());
    }

    @Test
    @DisplayName("Should set and get lease key")
    void testLeaseKeyAccessors() {
        byte[] newKeyBytes = new byte[] { (byte) 0xFF, (byte) 0xFE, (byte) 0xFD, (byte) 0xFC, (byte) 0xFB, (byte) 0xFA, (byte) 0xF9,
                (byte) 0xF8, (byte) 0xF7, (byte) 0xF6, (byte) 0xF5, (byte) 0xF4, (byte) 0xF3, (byte) 0xF2, (byte) 0xF1, (byte) 0xF0 };
        Smb2LeaseKey newKey = new Smb2LeaseKey(newKeyBytes);

        leaseContext.setLeaseKey(newKey);
        assertEquals(newKey, leaseContext.getLeaseKey());
    }

    @Test
    @DisplayName("Should set and get lease state")
    void testLeaseStateAccessors() {
        int newState = Smb2LeaseState.SMB2_LEASE_FULL;

        leaseContext.setLeaseState(newState);
        assertEquals(newState, leaseContext.getLeaseState());
    }

    @Test
    @DisplayName("Should set and get lease flags")
    void testLeaseFlagsAccessors() {
        int newFlags = 0x12345678;

        leaseContext.setLeaseFlags(newFlags);
        assertEquals(newFlags, leaseContext.getLeaseFlags());
    }

    @Test
    @DisplayName("Should encode context correctly")
    void testEncode() {
        byte[] buffer = new byte[leaseContext.size()];
        int encoded = leaseContext.encode(buffer, 0);

        assertEquals(leaseContext.size(), encoded);

        // Verify context header structure according to MS-SMB2
        // Next field (4 bytes) - should be 0 for last/single context
        assertEquals(0, SMBUtil.readInt4(buffer, 0));

        // NameOffset field (2 bytes) - should be 16 (after header)
        assertEquals(16, SMBUtil.readInt2(buffer, 4));

        // NameLength field (2 bytes) - should be 4 for "RqLs"
        assertEquals(4, SMBUtil.readInt2(buffer, 6));

        // Reserved field (2 bytes) - should be 0
        assertEquals(0, SMBUtil.readInt2(buffer, 8));

        // DataOffset field (2 bytes) - should be 24 (16 header + 4 name + 4 padding)
        assertEquals(24, SMBUtil.readInt2(buffer, 10));

        // DataLength field (4 bytes) - should be 32 (lease V1 structure size)
        assertEquals(32, SMBUtil.readInt4(buffer, 12));

        // Verify context name is encoded at offset 16
        byte[] nameBytes = new byte[4];
        System.arraycopy(buffer, 16, nameBytes, 0, 4);
        assertArrayEquals("RqLs".getBytes(), nameBytes);

        // Verify lease key is encoded at offset 24 (after header + name + padding)
        byte[] encodedKey = new byte[16];
        System.arraycopy(buffer, 24, encodedKey, 0, 16);
        assertArrayEquals(testKey.getKey(), encodedKey);

        // Verify lease state at offset 40 (24 + 16 for key)
        assertEquals(testState, SMBUtil.readInt4(buffer, 40));

        // Verify lease flags at offset 44 (40 + 4 for state)
        assertEquals(0, SMBUtil.readInt4(buffer, 44));

        // Verify lease duration at offset 48 (44 + 4 for flags) - should be 0 (reserved)
        assertEquals(0, SMBUtil.readInt8(buffer, 48));
    }
}
