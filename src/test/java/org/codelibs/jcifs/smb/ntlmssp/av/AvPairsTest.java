package org.codelibs.jcifs.smb.ntlmssp.av;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class AvPairsTest {

    private byte[] createAvPairData(int avId, byte[] data) {
        byte[] result = new byte[4 + data.length];
        SMBUtil.writeInt2(avId, result, 0);
        SMBUtil.writeInt2(data.length, result, 2);
        System.arraycopy(data, 0, result, 4, data.length);
        return result;
    }

    private byte[] createEolData() {
        byte[] result = new byte[4];
        SMBUtil.writeInt2(AvPair.MsvAvEOL, result, 0);
        SMBUtil.writeInt2(0, result, 2);
        return result;
    }

    /**
     * Test decode with valid single AvPair followed by EOL
     */
    @Test
    @DisplayName("Decode single AvPair with EOL")
    void testDecodeSinglePair() throws CIFSException {
        // Create test data: AvFlags with value 0x12345678 + EOL
        byte[] flagData = new byte[4];
        SMBUtil.writeInt4(0x12345678, flagData, 0);
        byte[] avPairData = createAvPairData(AvPair.MsvAvFlags, flagData);
        byte[] eolData = createEolData();

        byte[] fullData = new byte[avPairData.length + eolData.length];
        System.arraycopy(avPairData, 0, fullData, 0, avPairData.length);
        System.arraycopy(eolData, 0, fullData, avPairData.length, eolData.length);

        List<AvPair> pairs = AvPairs.decode(fullData);

        assertNotNull(pairs, "Decoded pairs should not be null");
        assertEquals(1, pairs.size(), "Should have decoded one pair");

        AvPair pair = pairs.get(0);
        assertEquals(AvPair.MsvAvFlags, pair.getType(), "Pair type should be MsvAvFlags");
        assertTrue(pair instanceof AvFlags, "Should be decoded as AvFlags");
        assertEquals(0x12345678, ((AvFlags) pair).getFlags(), "Flags value should match");
    }

    /**
     * Test decode with multiple AvPairs
     */
    @Test
    @DisplayName("Decode multiple AvPairs with EOL")
    void testDecodeMultiplePairs() throws CIFSException {
        // Create multiple AvPairs
        byte[] flagData = new byte[4];
        SMBUtil.writeInt4(0xAABBCCDD, flagData, 0);
        byte[] avFlagsData = createAvPairData(AvPair.MsvAvFlags, flagData);

        byte[] timestampData = new byte[8];
        SMBUtil.writeInt8(0x0123456789ABCDEFL, timestampData, 0);
        byte[] avTimestampData = createAvPairData(AvPair.MsvAvTimestamp, timestampData);

        byte[] targetNameData = "TEST".getBytes();
        byte[] avTargetNameData = createAvPairData(AvPair.MsvAvTargetName, targetNameData);

        byte[] eolData = createEolData();

        // Combine all data
        int totalLength = avFlagsData.length + avTimestampData.length + avTargetNameData.length + eolData.length;
        byte[] fullData = new byte[totalLength];
        int pos = 0;
        System.arraycopy(avFlagsData, 0, fullData, pos, avFlagsData.length);
        pos += avFlagsData.length;
        System.arraycopy(avTimestampData, 0, fullData, pos, avTimestampData.length);
        pos += avTimestampData.length;
        System.arraycopy(avTargetNameData, 0, fullData, pos, avTargetNameData.length);
        pos += avTargetNameData.length;
        System.arraycopy(eolData, 0, fullData, pos, eolData.length);

        List<AvPair> pairs = AvPairs.decode(fullData);

        assertNotNull(pairs, "Decoded pairs should not be null");
        assertEquals(3, pairs.size(), "Should have decoded three pairs");

        // Check first pair (AvFlags)
        assertEquals(AvPair.MsvAvFlags, pairs.get(0).getType(), "First pair should be MsvAvFlags");
        assertTrue(pairs.get(0) instanceof AvFlags, "First pair should be AvFlags instance");

        // Check second pair (AvTimestamp)
        assertEquals(AvPair.MsvAvTimestamp, pairs.get(1).getType(), "Second pair should be MsvAvTimestamp");
        assertTrue(pairs.get(1) instanceof AvTimestamp, "Second pair should be AvTimestamp instance");

        // Check third pair (AvTargetName)
        assertEquals(AvPair.MsvAvTargetName, pairs.get(2).getType(), "Third pair should be MsvAvTargetName");
        assertTrue(pairs.get(2) instanceof AvTargetName, "Third pair should be AvTargetName instance");
    }

    /**
     * Test decode with only EOL
     */
    @Test
    @DisplayName("Decode empty list with only EOL")
    void testDecodeEmptyList() throws CIFSException {
        byte[] eolData = createEolData();
        List<AvPair> pairs = AvPairs.decode(eolData);

        assertNotNull(pairs, "Decoded pairs should not be null");
        assertEquals(0, pairs.size(), "Should have no pairs");
    }

    /**
     * Test decode with missing EOL
     */
    @Test
    @DisplayName("Decode should throw exception when EOL is missing")
    void testDecodeMissingEOL() {
        byte[] flagData = new byte[4];
        SMBUtil.writeInt4(0x12345678, flagData, 0);
        byte[] avPairData = createAvPairData(AvPair.MsvAvFlags, flagData);

        CIFSException exception = assertThrows(CIFSException.class, () -> {
            AvPairs.decode(avPairData);
        });

        assertEquals("Missing AvEOL", exception.getMessage(), "Should throw exception with correct message");
    }

    /**
     * Test decode with invalid EOL (non-zero length)
     */
    @Test
    @DisplayName("Decode should throw exception for invalid EOL length")
    void testDecodeInvalidEOL() {
        byte[] invalidEolData = new byte[6];
        SMBUtil.writeInt2(AvPair.MsvAvEOL, invalidEolData, 0);
        SMBUtil.writeInt2(2, invalidEolData, 2); // Invalid: EOL should have length 0

        CIFSException exception = assertThrows(CIFSException.class, () -> {
            AvPairs.decode(invalidEolData);
        });

        assertEquals("Invalid avLen for AvEOL", exception.getMessage(), "Should throw exception for invalid EOL");
    }

    /**
     * Test decode with truncated data
     */
    @Test
    @DisplayName("Decode should handle truncated data")
    void testDecodeTruncatedData() {
        byte[] truncatedData = new byte[3]; // Less than 4 bytes

        CIFSException exception = assertThrows(CIFSException.class, () -> {
            AvPairs.decode(truncatedData);
        });

        assertEquals("Missing AvEOL", exception.getMessage(), "Should throw exception for truncated data");
    }

    /**
     * Test decode with unknown AvPair type
     */
    @Test
    @DisplayName("Decode unknown AvPair type as generic AvPair")
    void testDecodeUnknownType() throws CIFSException {
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        int unknownType = 0xFF;
        byte[] avPairData = createAvPairData(unknownType, data);
        byte[] eolData = createEolData();

        byte[] fullData = new byte[avPairData.length + eolData.length];
        System.arraycopy(avPairData, 0, fullData, 0, avPairData.length);
        System.arraycopy(eolData, 0, fullData, avPairData.length, eolData.length);

        List<AvPair> pairs = AvPairs.decode(fullData);

        assertNotNull(pairs, "Decoded pairs should not be null");
        assertEquals(1, pairs.size(), "Should have decoded one pair");

        AvPair pair = pairs.get(0);
        assertEquals(unknownType, pair.getType(), "Pair type should match unknown type");
        assertFalse(pair instanceof AvFlags, "Should not be decoded as specific type");
        assertFalse(pair instanceof AvTimestamp, "Should not be decoded as specific type");
    }

    /**
     * Test contains method with null list
     */
    @Test
    @DisplayName("Contains should return false for null list")
    void testContainsNullList() {
        assertFalse(AvPairs.contains(null, AvPair.MsvAvFlags), "Should return false for null list");
    }

    /**
     * Test contains method with empty list
     */
    @Test
    @DisplayName("Contains should return false for empty list")
    void testContainsEmptyList() {
        List<AvPair> emptyList = new ArrayList<>();
        assertFalse(AvPairs.contains(emptyList, AvPair.MsvAvFlags), "Should return false for empty list");
    }

    /**
     * Test contains method with existing type
     */
    @Test
    @DisplayName("Contains should return true when type exists")
    void testContainsExistingType() {
        List<AvPair> pairs = new LinkedList<>();
        pairs.add(new AvFlags(0x12345678));
        pairs.add(new AvTimestamp(new byte[8]));

        assertTrue(AvPairs.contains(pairs, AvPair.MsvAvFlags), "Should find MsvAvFlags");
        assertTrue(AvPairs.contains(pairs, AvPair.MsvAvTimestamp), "Should find MsvAvTimestamp");
        assertFalse(AvPairs.contains(pairs, AvPair.MsvAvTargetName), "Should not find MsvAvTargetName");
    }

    /**
     * Test get method with existing type
     */
    @Test
    @DisplayName("Get should return first occurrence of type")
    void testGetExistingType() {
        List<AvPair> pairs = new LinkedList<>();
        AvFlags flags1 = new AvFlags(0x11111111);
        AvFlags flags2 = new AvFlags(0x22222222);
        pairs.add(flags1);
        pairs.add(new AvTimestamp(new byte[8]));
        pairs.add(flags2);

        AvPair result = AvPairs.get(pairs, AvPair.MsvAvFlags);
        assertNotNull(result, "Should find the pair");
        assertEquals(flags1, result, "Should return first occurrence");
    }

    /**
     * Test get method with non-existing type
     */
    @Test
    @DisplayName("Get should return null for non-existing type")
    void testGetNonExistingType() {
        List<AvPair> pairs = new LinkedList<>();
        pairs.add(new AvFlags(0x12345678));

        AvPair result = AvPairs.get(pairs, AvPair.MsvAvTargetName);
        assertNull(result, "Should return null for non-existing type");
    }

    /**
     * Test get method with empty list
     */
    @Test
    @DisplayName("Get should return null for empty list")
    void testGetEmptyList() {
        List<AvPair> pairs = new LinkedList<>();

        AvPair result = AvPairs.get(pairs, AvPair.MsvAvFlags);
        assertNull(result, "Should return null for empty list");
    }

    /**
     * Test remove method
     */
    @Test
    @DisplayName("Remove should delete all occurrences of type")
    void testRemove() {
        List<AvPair> pairs = new LinkedList<>();
        AvFlags flags1 = new AvFlags(0x11111111);
        AvFlags flags2 = new AvFlags(0x22222222);
        AvTimestamp timestamp = new AvTimestamp(new byte[8]);
        pairs.add(flags1);
        pairs.add(timestamp);
        pairs.add(flags2);

        assertEquals(3, pairs.size(), "Should start with 3 pairs");

        AvPairs.remove(pairs, AvPair.MsvAvFlags);

        assertEquals(1, pairs.size(), "Should have 1 pair after removal");
        assertFalse(AvPairs.contains(pairs, AvPair.MsvAvFlags), "Should not contain MsvAvFlags");
        assertTrue(AvPairs.contains(pairs, AvPair.MsvAvTimestamp), "Should still contain MsvAvTimestamp");
    }

    /**
     * Test remove method with non-existing type
     */
    @Test
    @DisplayName("Remove should handle non-existing type gracefully")
    void testRemoveNonExisting() {
        List<AvPair> pairs = new LinkedList<>();
        AvTimestamp timestamp = new AvTimestamp(new byte[8]);
        pairs.add(timestamp);

        assertEquals(1, pairs.size(), "Should start with 1 pair");

        AvPairs.remove(pairs, AvPair.MsvAvFlags);

        assertEquals(1, pairs.size(), "Should still have 1 pair");
        assertTrue(AvPairs.contains(pairs, AvPair.MsvAvTimestamp), "Should still contain MsvAvTimestamp");
    }

    /**
     * Test replace method
     */
    @Test
    @DisplayName("Replace should remove old and add new")
    void testReplace() {
        List<AvPair> pairs = new LinkedList<>();
        AvFlags oldFlags1 = new AvFlags(0x11111111);
        AvFlags oldFlags2 = new AvFlags(0x22222222);
        AvTimestamp timestamp = new AvTimestamp(new byte[8]);
        pairs.add(oldFlags1);
        pairs.add(timestamp);
        pairs.add(oldFlags2);

        AvFlags newFlags = new AvFlags(0x33333333);
        AvPairs.replace(pairs, newFlags);

        assertEquals(2, pairs.size(), "Should have 2 pairs after replace");
        assertTrue(AvPairs.contains(pairs, AvPair.MsvAvFlags), "Should contain MsvAvFlags");
        assertTrue(AvPairs.contains(pairs, AvPair.MsvAvTimestamp), "Should still contain MsvAvTimestamp");

        AvPair result = AvPairs.get(pairs, AvPair.MsvAvFlags);
        assertEquals(newFlags, result, "Should have the new flags instance");
    }

    /**
     * Test replace method when type doesn't exist
     */
    @Test
    @DisplayName("Replace should add new when type doesn't exist")
    void testReplaceNonExisting() {
        List<AvPair> pairs = new LinkedList<>();
        AvTimestamp timestamp = new AvTimestamp(new byte[8]);
        pairs.add(timestamp);

        AvFlags newFlags = new AvFlags(0x33333333);
        AvPairs.replace(pairs, newFlags);

        assertEquals(2, pairs.size(), "Should have 2 pairs after replace");
        assertTrue(AvPairs.contains(pairs, AvPair.MsvAvFlags), "Should contain MsvAvFlags");
        assertTrue(AvPairs.contains(pairs, AvPair.MsvAvTimestamp), "Should contain MsvAvTimestamp");
    }

    /**
     * Test encode with single pair
     */
    @Test
    @DisplayName("Encode single AvPair with EOL")
    void testEncodeSinglePair() {
        List<AvPair> pairs = new LinkedList<>();
        AvFlags flags = new AvFlags(0x12345678);
        pairs.add(flags);

        byte[] encoded = AvPairs.encode(pairs);

        assertNotNull(encoded, "Encoded data should not be null");
        assertEquals(12, encoded.length, "Should be 4 (header) + 4 (data) + 4 (EOL)");

        // Check AvFlags header
        assertEquals(AvPair.MsvAvFlags, SMBUtil.readInt2(encoded, 0), "First pair type should be MsvAvFlags");
        assertEquals(4, SMBUtil.readInt2(encoded, 2), "First pair length should be 4");

        // Check AvFlags data
        assertEquals(0x12345678, SMBUtil.readInt4(encoded, 4), "Flags value should match");

        // Check EOL
        assertEquals(AvPair.MsvAvEOL, SMBUtil.readInt2(encoded, 8), "Should end with EOL");
        assertEquals(0, SMBUtil.readInt2(encoded, 10), "EOL length should be 0");
    }

    /**
     * Test encode with multiple pairs
     */
    @Test
    @DisplayName("Encode multiple AvPairs with EOL")
    void testEncodeMultiplePairs() {
        List<AvPair> pairs = new LinkedList<>();
        pairs.add(new AvFlags(0xAABBCCDD));
        pairs.add(new AvTimestamp(new byte[8]));
        pairs.add(new AvTargetName("TEST".getBytes()));

        byte[] encoded = AvPairs.encode(pairs);

        assertNotNull(encoded, "Encoded data should not be null");

        int expectedLength = 4 + 4 + // AvFlags header + data
                4 + 8 + // AvTimestamp header + data
                4 + 4 + // AvTargetName header + data
                4; // EOL
        assertEquals(expectedLength, encoded.length, "Encoded length should match expected");

        // Verify EOL at the end
        int eolPos = encoded.length - 4;
        assertEquals(AvPair.MsvAvEOL, SMBUtil.readInt2(encoded, eolPos), "Should end with EOL");
        assertEquals(0, SMBUtil.readInt2(encoded, eolPos + 2), "EOL length should be 0");
    }

    /**
     * Test encode with empty list
     */
    @Test
    @DisplayName("Encode empty list should produce only EOL")
    void testEncodeEmptyList() {
        List<AvPair> pairs = new LinkedList<>();

        byte[] encoded = AvPairs.encode(pairs);

        assertNotNull(encoded, "Encoded data should not be null");
        assertEquals(4, encoded.length, "Should only have EOL (4 bytes)");
        assertEquals(AvPair.MsvAvEOL, SMBUtil.readInt2(encoded, 0), "Should be EOL");
        assertEquals(0, SMBUtil.readInt2(encoded, 2), "EOL length should be 0");
    }

    /**
     * Test round-trip encoding and decoding
     */
    @Test
    @DisplayName("Round-trip encode and decode should preserve data")
    void testRoundTrip() throws CIFSException {
        List<AvPair> originalPairs = new LinkedList<>();
        originalPairs.add(new AvFlags(0x12345678));
        originalPairs.add(new AvTimestamp(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }));
        originalPairs.add(new AvTargetName("TESTNAME".getBytes()));
        originalPairs.add(new AvSingleHost(new byte[] { 0x11, 0x22, 0x33, 0x44 }));
        originalPairs.add(new AvChannelBindings(new byte[] { 0x55, 0x66 }));

        byte[] encoded = AvPairs.encode(originalPairs);
        List<AvPair> decodedPairs = AvPairs.decode(encoded);

        assertEquals(originalPairs.size(), decodedPairs.size(), "Should have same number of pairs");

        for (int i = 0; i < originalPairs.size(); i++) {
            AvPair original = originalPairs.get(i);
            AvPair decoded = decodedPairs.get(i);

            assertEquals(original.getType(), decoded.getType(), "Type should match at index " + i);
            assertTrue(Arrays.equals(original.getRaw(), decoded.getRaw()), "Raw data should match at index " + i);
        }
    }

    /**
     * Test decode with AvSingleHost type
     */
    @Test
    @DisplayName("Decode should create AvSingleHost instance")
    void testDecodeAvSingleHost() throws CIFSException {
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        byte[] avPairData = createAvPairData(AvPair.MsvAvSingleHost, data);
        byte[] eolData = createEolData();

        byte[] fullData = new byte[avPairData.length + eolData.length];
        System.arraycopy(avPairData, 0, fullData, 0, avPairData.length);
        System.arraycopy(eolData, 0, fullData, avPairData.length, eolData.length);

        List<AvPair> pairs = AvPairs.decode(fullData);

        assertEquals(1, pairs.size(), "Should have one pair");
        assertTrue(pairs.get(0) instanceof AvSingleHost, "Should be AvSingleHost instance");
    }

    /**
     * Test decode with AvChannelBindings type
     */
    @Test
    @DisplayName("Decode should create AvChannelBindings instance")
    void testDecodeAvChannelBindings() throws CIFSException {
        byte[] data = new byte[] { (byte) 0xAA, (byte) 0xBB };
        byte[] avPairData = createAvPairData(AvPair.MsvAvChannelBindings, data);
        byte[] eolData = createEolData();

        byte[] fullData = new byte[avPairData.length + eolData.length];
        System.arraycopy(avPairData, 0, fullData, 0, avPairData.length);
        System.arraycopy(eolData, 0, fullData, avPairData.length, eolData.length);

        List<AvPair> pairs = AvPairs.decode(fullData);

        assertEquals(1, pairs.size(), "Should have one pair");
        assertTrue(pairs.get(0) instanceof AvChannelBindings, "Should be AvChannelBindings instance");
    }

    /**
     * Test edge case with maximum data size
     */
    @Test
    @DisplayName("Handle large data size")
    void testLargeDataSize() throws CIFSException {
        // Create a large data array
        byte[] largeData = new byte[1024];
        Arrays.fill(largeData, (byte) 0xFF);

        byte[] avPairData = createAvPairData(0x99, largeData);
        byte[] eolData = createEolData();

        byte[] fullData = new byte[avPairData.length + eolData.length];
        System.arraycopy(avPairData, 0, fullData, 0, avPairData.length);
        System.arraycopy(eolData, 0, fullData, avPairData.length, eolData.length);

        List<AvPair> pairs = AvPairs.decode(fullData);

        assertEquals(1, pairs.size(), "Should have one pair");
        assertEquals(0x99, pairs.get(0).getType(), "Type should match");
        assertEquals(largeData.length, pairs.get(0).getRaw().length, "Data length should match");
    }

    /**
     * Test with data that has exact boundary conditions
     */
    @Test
    @DisplayName("Handle exact boundary data size")
    void testExactBoundarySize() throws CIFSException {
        // Test with data that ends exactly at the position where EOL should be checked
        byte[] data = new byte[0];
        byte[] avPairData = createAvPairData(AvPair.MsvAvTargetName, data);
        byte[] eolData = createEolData();

        byte[] fullData = new byte[avPairData.length + eolData.length];
        System.arraycopy(avPairData, 0, fullData, 0, avPairData.length);
        System.arraycopy(eolData, 0, fullData, avPairData.length, eolData.length);

        List<AvPair> pairs = AvPairs.decode(fullData);

        assertEquals(1, pairs.size(), "Should have one pair");
        assertEquals(0, pairs.get(0).getRaw().length, "Should have empty data");
    }
}