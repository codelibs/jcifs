package jcifs.ntlmssp.av;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class AvPairTest {

    @Test
    void testConstructorAndGetters() {
        // Test with a valid type and raw data
        int type = AvPair.MsvAvTimestamp;
        byte[] raw = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        AvPair avPair = new AvPair(type, raw);

        assertEquals(type, avPair.getType(), "Type should match the constructor argument.");
        assertArrayEquals(raw, avPair.getRaw(), "Raw data should match the constructor argument.");

        // Test with another type and empty raw data
        int type2 = AvPair.MsvAvEOL;
        byte[] raw2 = new byte[] {};
        AvPair avPair2 = new AvPair(type2, raw2);

        assertEquals(type2, avPair2.getType(), "Type should match the constructor argument for empty raw data.");
        assertArrayEquals(raw2, avPair2.getRaw(), "Raw data should match the constructor argument for empty raw data.");

        // Test with null raw data
        int type3 = AvPair.MsvAvFlags;
        byte[] raw3 = null;
        AvPair avPair3 = new AvPair(type3, raw3);

        assertEquals(type3, avPair3.getType(), "Type should match the constructor argument for null raw data.");
        assertNull(avPair3.getRaw(), "Raw data should be null if constructor argument was null.");
    }

    @Test
    void testConstants() {
        assertEquals(0x0, AvPair.MsvAvEOL, "MsvAvEOL constant should be 0x0.");
        assertEquals(0x6, AvPair.MsvAvFlags, "MsvAvFlags constant should be 0x6.");
        assertEquals(0x7, AvPair.MsvAvTimestamp, "MsvAvTimestamp constant should be 0x7.");
        assertEquals(0x08, AvPair.MsvAvSingleHost, "MsvAvSingleHost constant should be 0x08.");
        assertEquals(0x09, AvPair.MsvAvTargetName, "MsvAvTargetName constant should be 0x09.");
        assertEquals(0x0A, AvPair.MsvAvChannelBindings, "MsvAvChannelBindings constant should be 0x0A.");
    }

    @Test
    void testRawDataImmutability() {
        int type = AvPair.MsvAvTimestamp;
        byte[] raw = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        AvPair avPair = new AvPair(type, raw);

        // Modify the original raw array
        raw[0] = 0x05;

        // Ensure the AvPair's internal raw array is not affected (defensive copy not made)
        // This test assumes that the AvPair constructor does NOT make a defensive copy of the raw array.
        // If a defensive copy were made, this test would fail, and the behavior would be more robust.
        // Given the current implementation, direct modification of the passed array affects the AvPair.
        // If this is not desired, a defensive copy should be added in the AvPair constructor.
        assertEquals(0x05, avPair.getRaw()[0],
                "Modifying original raw array should affect AvPair's raw data if no defensive copy is made.");
    }
}
