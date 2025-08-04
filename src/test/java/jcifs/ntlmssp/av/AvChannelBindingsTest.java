package jcifs.ntlmssp.av;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class AvChannelBindingsTest {

    /**
     * Test that the constructor correctly initializes with a valid channel binding hash.
     */
    @Test
    void testConstructorWithValidHash() {
        byte[] testHash = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        AvChannelBindings avChannelBindings = new AvChannelBindings(testHash);

        assertEquals(AvPair.MsvAvChannelBindings, avChannelBindings.getType(), "Type should be MsvAvChannelBindings");
        assertArrayEquals(testHash, avChannelBindings.getRaw(), "Value should match the provided hash");
    }

    /**
     * Test that the constructor handles a null channel binding hash.
     */
    @Test
    void testConstructorWithNullHash() {
        AvChannelBindings avChannelBindings = new AvChannelBindings(null);

        assertEquals(AvPair.MsvAvChannelBindings, avChannelBindings.getType(), "Type should be MsvAvChannelBindings");
        assertNull(avChannelBindings.getRaw(), "Value should be null when null hash is provided");
    }

    /**
     * Test that the constructor handles an empty channel binding hash.
     */
    @Test
    void testConstructorWithEmptyHash() {
        byte[] emptyHash = new byte[0];
        AvChannelBindings avChannelBindings = new AvChannelBindings(emptyHash);

        assertEquals(AvPair.MsvAvChannelBindings, avChannelBindings.getType(), "Type should be MsvAvChannelBindings");
        assertArrayEquals(emptyHash, avChannelBindings.getRaw(), "Value should be an empty array when empty hash is provided");
    }

    /**
     * Test that the constructor creates a defensive copy of the input byte array.
     */
    @Test
    void testConstructorDefensiveCopy() {
        byte[] originalHash = { 0x01, 0x02, 0x03 };
        AvChannelBindings avChannelBindings = new AvChannelBindings(originalHash);

        // Modify the original array after passing it to the constructor
        originalHash[0] = 0x00;

        // Ensure the value in AvChannelBindings is not affected
        assertNotEquals(0x00, avChannelBindings.getRaw()[0],
                "Value should be a defensive copy and not reflect changes to original array");
        assertEquals(0x01, avChannelBindings.getRaw()[0], "Value should retain its original content");
    }
}
