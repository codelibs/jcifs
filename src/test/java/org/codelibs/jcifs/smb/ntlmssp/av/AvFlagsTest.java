package org.codelibs.jcifs.smb.ntlmssp.av;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

public class AvFlagsTest {

    /**
     * Test constructor with raw bytes.
     */
    @Test
    void testAvFlagsByteArrayConstructor() {
        // Test with a positive integer
        byte[] rawBytes = new byte[] { 0x01, 0x02, 0x03, 0x04 }; // Represents 0x04030201 (little-endian)
        AvFlags avFlags = new AvFlags(rawBytes);
        assertNotNull(avFlags, "AvFlags object should not be null");
        assertEquals(0x04030201, avFlags.getFlags(), "Flags should match the raw bytes (little-endian)");

        // Test with zero
        byte[] zeroBytes = new byte[] { 0x00, 0x00, 0x00, 0x00 };
        AvFlags zeroAvFlags = new AvFlags(zeroBytes);
        assertNotNull(zeroAvFlags, "AvFlags object should not be null for zero bytes");
        assertEquals(0, zeroAvFlags.getFlags(), "Flags should be 0 for zero bytes");

        // Test with negative integer (two's complement)
        byte[] negativeBytes = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF }; // Represents -1
        AvFlags negativeAvFlags = new AvFlags(negativeBytes);
        assertNotNull(negativeAvFlags, "AvFlags object should not be null for negative bytes");
        assertEquals(-1, negativeAvFlags.getFlags(), "Flags should be -1 for all FF bytes");
    }

    /**
     * Test constructor with integer flags.
     */
    @Test
    void testAvFlagsIntConstructor() {
        // Test with a positive integer
        int flags = 0x12345678;
        AvFlags avFlags = new AvFlags(flags);
        assertNotNull(avFlags, "AvFlags object should not be null");
        assertEquals(flags, avFlags.getFlags(), "Flags should match the input integer");

        // Test with zero
        int zeroFlags = 0;
        AvFlags zeroAvFlags = new AvFlags(zeroFlags);
        assertNotNull(zeroAvFlags, "AvFlags object should not be null for zero flags");
        assertEquals(zeroFlags, zeroAvFlags.getFlags(), "Flags should be 0 for zero input");

        // Test with maximum integer value
        int maxFlags = Integer.MAX_VALUE;
        AvFlags maxAvFlags = new AvFlags(maxFlags);
        assertNotNull(maxAvFlags, "AvFlags object should not be null for max flags");
        assertEquals(maxFlags, maxAvFlags.getFlags(), "Flags should match Integer.MAX_VALUE");

        // Test with minimum integer value
        int minFlags = Integer.MIN_VALUE;
        AvFlags minAvFlags = new AvFlags(minFlags);
        assertNotNull(minAvFlags, "AvFlags object should not be null for min flags");
        assertEquals(minFlags, minAvFlags.getFlags(), "Flags should match Integer.MIN_VALUE");

        // Test with a negative integer
        int negativeFlags = -12345;
        AvFlags negAvFlags = new AvFlags(negativeFlags);
        assertNotNull(negAvFlags, "AvFlags object should not be null for negative flags");
        assertEquals(negativeFlags, negAvFlags.getFlags(), "Flags should match the negative input integer");
    }

    /**
     * Test getFlags method.
     * This is implicitly tested by the constructors, but an explicit test ensures its direct functionality.
     */
    @Test
    void testGetFlags() {
        int expectedFlags = 0xAABBCCDD;
        AvFlags avFlags = new AvFlags(expectedFlags);
        assertEquals(expectedFlags, avFlags.getFlags(), "getFlags should return the correct integer value");
    }
}
