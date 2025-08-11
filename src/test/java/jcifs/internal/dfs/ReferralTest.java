package jcifs.internal.dfs;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jcifs.RuntimeCIFSException;
import jcifs.internal.smb1.trans2.Trans2GetDfsReferralResponse;

/**
 * Test class for Referral
 */
public class ReferralTest {

    private Referral referral;
    private byte[] testBuffer;

    @BeforeEach
    public void setUp() {
        referral = new Referral();
        testBuffer = new byte[512];
    }

    // Version 3 Referral Tests

    @Test
    public void testDecodeVersion3WithoutNameList() {
        // Prepare test data
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        // Header
        bb.putShort((short) 3);     // version
        bb.putShort((short) 100);   // size (large enough for all strings)
        bb.putShort((short) 1);     // serverType
        bb.putShort((short) 0);     // rflags (no name list)
        bb.putShort((short) 5);     // proximity
        bb.putShort((short) 300);   // ttl
        bb.putShort((short) 22);    // pathOffset (relative to start of referral)
        bb.putShort((short) 54);    // altPathOffset
        bb.putShort((short) 76);    // nodeOffset
        
        // Path string at offset 22 (relative to start of referral at position 0)
        bb.position(22);
        String path = "\\\\server\\share";
        bb.put(path.getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);
        
        // Alt path string at offset 54
        bb.position(54);
        String altPath = "\\\\alt\\path";
        bb.put(altPath.getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);
        
        // Node string at offset 76
        bb.position(76);
        String node = "NODE01";
        bb.put(node.getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);

        // Decode
        int decodedSize = referral.decode(testBuffer, 0, testBuffer.length);

        // Verify
        assertEquals(100, decodedSize);
        assertEquals(3, referral.getVersion());
        assertEquals(100, referral.getSize());
        assertEquals(1, referral.getServerType());
        assertEquals(0, referral.getRFlags());
        assertEquals(5, referral.getProximity());
        assertEquals(300, referral.getTtl());
        assertEquals(path, referral.getRpath());
        assertEquals(altPath, referral.getAltPath());
        assertEquals(node, referral.getNode());
        assertNull(referral.getSpecialName());
        assertArrayEquals(new String[0], referral.getExpandedNames());
    }

    @Test
    public void testDecodeVersion3WithNameList() {
        // Prepare test data
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        // Header
        bb.putShort((short) 3);     // version
        bb.putShort((short) 100);   // size (must be large enough for all data)
        bb.putShort((short) 2);     // serverType
        bb.putShort((short) Trans2GetDfsReferralResponse.FLAGS_NAME_LIST_REFERRAL); // rflags with name list
        bb.putShort((short) 10);    // proximity
        bb.putShort((short) 600);   // ttl
        bb.putShort((short) 22);    // specialNameOffset
        bb.putShort((short) 3);     // numExpanded
        bb.putShort((short) 44);    // expandedNameOffset
        
        // Special name at offset 22
        bb.position(22);
        String specialName = "SPECIAL";
        bb.put(specialName.getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);
        
        // Expanded names at offset 44
        bb.position(44);
        String[] expandedNames = {"NAME1", "NAME2", "NAME3"};
        for (String name : expandedNames) {
            bb.put(name.getBytes(StandardCharsets.UTF_16LE));
            bb.putShort((short) 0);
        }

        // Decode
        int decodedSize = referral.decode(testBuffer, 0, testBuffer.length);

        // Verify
        assertEquals(100, decodedSize);
        assertEquals(3, referral.getVersion());
        assertEquals(100, referral.getSize());
        assertEquals(2, referral.getServerType());
        assertEquals(Trans2GetDfsReferralResponse.FLAGS_NAME_LIST_REFERRAL, referral.getRFlags());
        assertEquals(10, referral.getProximity());
        assertEquals(600, referral.getTtl());
        assertEquals(specialName, referral.getSpecialName());
        assertArrayEquals(expandedNames, referral.getExpandedNames());
        assertNull(referral.getRpath());
        assertNull(referral.getAltPath());
        assertNull(referral.getNode());
    }

    @Test
    public void testVersion3WithZeroOffsets() {
        // Prepare test data with zero offsets
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        bb.putShort((short) 3);     // version
        bb.putShort((short) 34);    // size
        bb.putShort((short) 1);     // serverType
        bb.putShort((short) 0);     // rflags
        bb.putShort((short) 5);     // proximity
        bb.putShort((short) 300);   // ttl
        bb.putShort((short) 0);     // pathOffset (zero)
        bb.putShort((short) 0);     // altPathOffset (zero)
        bb.putShort((short) 0);     // nodeOffset (zero)

        // Decode
        int decodedSize = referral.decode(testBuffer, 0, testBuffer.length);

        // Verify all paths are null when offsets are zero
        assertEquals(34, decodedSize);
        assertNull(referral.getRpath());
        assertNull(referral.getAltPath());
        assertNull(referral.getNode());
    }

    @Test
    public void testVersion3WithEmptyExpandedNames() {
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        bb.putShort((short) 3);     // version
        bb.putShort((short) 34);    // size
        bb.putShort((short) 2);     // serverType
        bb.putShort((short) Trans2GetDfsReferralResponse.FLAGS_NAME_LIST_REFERRAL);
        bb.putShort((short) 10);    // proximity
        bb.putShort((short) 600);   // ttl
        bb.putShort((short) 0);     // specialNameOffset (zero)
        bb.putShort((short) 0);     // numExpanded (zero)
        bb.putShort((short) 0);     // expandedNameOffset (zero)

        // Decode
        int decodedSize = referral.decode(testBuffer, 0, testBuffer.length);

        // Verify
        assertEquals(34, decodedSize);
        assertNull(referral.getSpecialName());
        assertArrayEquals(new String[0], referral.getExpandedNames());
    }

    // Version 1 Referral Tests

    @Test
    public void testDecodeVersion1() {
        // Prepare test data
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        bb.putShort((short) 1);     // version
        bb.putShort((short) 24);    // size
        bb.putShort((short) 1);     // serverType
        bb.putShort((short) 0);     // rflags
        
        // Node string immediately follows header
        String node = "\\\\SERVER\\SHARE";
        bb.put(node.getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);

        // Decode
        int decodedSize = referral.decode(testBuffer, 0, testBuffer.length);

        // Verify
        assertEquals(24, decodedSize);
        assertEquals(1, referral.getVersion());
        assertEquals(24, referral.getSize());
        assertEquals(1, referral.getServerType());
        assertEquals(0, referral.getRFlags());
        assertEquals(node, referral.getNode());
        
        // Version 1 doesn't have these fields
        assertEquals(0, referral.getProximity());
        assertEquals(0, referral.getTtl());
        assertNull(referral.getRpath());
        assertNull(referral.getAltPath());
        assertNull(referral.getSpecialName());
    }

    // Unsupported Version Tests

    @Test
    public void testUnsupportedVersions() {
        int[] versions = {0, 2, 4, 5, 100, 65535};
        for (int version : versions) {
            ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
            bb.putShort((short) version);
            bb.putShort((short) 24);
            bb.putShort((short) 1);
            bb.putShort((short) 0);

            Referral ref = new Referral();
            RuntimeCIFSException exception = assertThrows(RuntimeCIFSException.class, 
                () -> ref.decode(testBuffer, 0, testBuffer.length),
                "Should have thrown exception for version " + version);
            
            assertTrue(exception.getMessage().contains("Version " + version + " referral not supported"),
                "Exception message should contain version");
            assertTrue(exception.getMessage().contains("jcifs at samba dot org"),
                "Exception message should contain contact info");
        }
    }

    // String Reading Tests

    @Test
    public void testOddBufferIndexAlignment() {
        // Create buffer with odd starting position
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        // Start at position 1 (odd)
        bb.position(1);
        bb.putShort((short) 3);     // version
        bb.putShort((short) 34);    // size
        bb.putShort((short) 1);     // serverType
        bb.putShort((short) 0);     // rflags
        bb.putShort((short) 5);     // proximity
        bb.putShort((short) 300);   // ttl
        bb.putShort((short) 23);    // pathOffset (22 + 1 for odd start)
        bb.putShort((short) 0);     // altPathOffset
        bb.putShort((short) 0);     // nodeOffset
        
        // Path string at offset 23 (which should be aligned to 24)
        bb.position(24); // Aligned position
        String path = "\\\\test";
        bb.put(path.getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);

        // Decode from position 1
        int decodedSize = referral.decode(testBuffer, 1, testBuffer.length - 1);

        // Verify
        assertEquals(34, decodedSize);
        assertEquals(path, referral.getRpath());
    }

    @Test
    public void testUnicodeStringHandling() {
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        bb.putShort((short) 3);     // version
        bb.putShort((short) 100);   // size (larger to accommodate unicode strings)
        bb.putShort((short) 1);     // serverType
        bb.putShort((short) 0);     // rflags
        bb.putShort((short) 5);     // proximity
        bb.putShort((short) 300);   // ttl
        bb.putShort((short) 22);    // pathOffset
        bb.putShort((short) 0);     // altPathOffset
        bb.putShort((short) 0);     // nodeOffset
        
        // Unicode string with special characters
        bb.position(22);
        String path = "\\\\пример\\分享\\例え";
        bb.put(path.getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);

        // Decode
        int decodedSize = referral.decode(testBuffer, 0, testBuffer.length);

        // Verify
        assertEquals(path, referral.getRpath());
    }

    // Debug Test
    
    @Test 
    public void testSimpleVersion3() {
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        // Write the header
        bb.putShort((short) 3);     // version
        bb.putShort((short) 100);   // size
        bb.putShort((short) 1);     // serverType
        bb.putShort((short) 0);     // rflags
        bb.putShort((short) 5);     // proximity
        bb.putShort((short) 300);   // ttl
        bb.putShort((short) 22);    // pathOffset
        bb.putShort((short) 0);     // altPathOffset (0 = null)
        bb.putShort((short) 0);     // nodeOffset (0 = null)
        
        // Write path string at offset 22
        bb.position(22);
        String expectedPath = "\\\\test";
        bb.put(expectedPath.getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);  // null terminator
        
        // Decode
        referral.decode(testBuffer, 0, testBuffer.length);
        
        // Check
        assertEquals(3, referral.getVersion());
        assertEquals(100, referral.getSize());
        assertEquals(expectedPath, referral.getRpath());
        assertNull(referral.getAltPath());
        assertNull(referral.getNode());
    }

    // Getter Tests

    @Test
    public void testGetters() {
        // Setup a complete referral
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        bb.putShort((short) 3);
        bb.putShort((short) 100);
        bb.putShort((short) 7);
        bb.putShort((short) 1);     // rflags without name list flag
        bb.putShort((short) 20);
        bb.putShort((short) 3600);
        bb.putShort((short) 22);
        bb.putShort((short) 38);
        bb.putShort((short) 52);
        
        bb.position(22);
        bb.put("\\\\path".getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);
        
        bb.position(38);
        bb.put("\\\\alt".getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);
        
        bb.position(52);
        bb.put("NODE".getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);
        
        referral.decode(testBuffer, 0, testBuffer.length);
        
        assertEquals(3, referral.getVersion());
        assertEquals(100, referral.getSize());
        assertEquals(7, referral.getServerType());
        assertEquals(1, referral.getRFlags());
        assertEquals(20, referral.getProximity());
        assertEquals(3600, referral.getTtl());
        assertEquals("\\\\path", referral.getRpath());
        assertEquals("\\\\alt", referral.getAltPath());
        assertEquals("NODE", referral.getNode());
    }

    // ToString Tests

    @Test
    public void testToString() {
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        bb.putShort((short) 3);
        bb.putShort((short) 200);   // increased size
        bb.putShort((short) 1);
        bb.putShort((short) 0);     // rflags without name list flag  
        bb.putShort((short) 10);
        bb.putShort((short) 600);
        bb.putShort((short) 22);    // pathOffset
        bb.putShort((short) 60);    // altPathOffset - with proper spacing
        bb.putShort((short) 90);    // nodeOffset - with proper spacing
        
        bb.position(22);
        bb.put("\\\\server\\\\share".getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);
        
        bb.position(60);  // Properly spaced
        bb.put("\\\\alt\\\\path".getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);
        
        bb.position(90);  // Properly spaced
        bb.put("NODE01".getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);
        
        referral.decode(testBuffer, 0, testBuffer.length);
        
        // First verify the referral was parsed correctly
        assertNotNull(referral.getRpath());
        assertNotNull(referral.getAltPath());
        assertNotNull(referral.getNode());
        assertEquals("\\\\server\\\\share", referral.getRpath());
        assertEquals("\\\\alt\\\\path", referral.getAltPath());
        assertEquals("NODE01", referral.getNode());
        
        String result = referral.toString();
        
        assertTrue(result.contains("Referral["));
        assertTrue(result.contains("version=3"));
        assertTrue(result.contains("size=200"));  // updated size
        assertTrue(result.contains("serverType=1"));
        assertTrue(result.contains("flags=0"));
        assertTrue(result.contains("proximity=10"));
        assertTrue(result.contains("ttl=600"));
        // Check that paths and node are present
        assertTrue(result.contains("path="));
        assertTrue(result.contains("altPath="));
        assertTrue(result.contains("node="));
        assertTrue(result.endsWith("]"));
    }

    @Test
    public void testToStringWithNulls() {
        // Create minimal referral
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        bb.putShort((short) 1);
        bb.putShort((short) 24);
        bb.putShort((short) 0);
        bb.putShort((short) 0);
        bb.put("NODE".getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);
        
        referral.decode(testBuffer, 0, testBuffer.length);
        
        String result = referral.toString();
        
        assertTrue(result.contains("path=null"));
        assertTrue(result.contains("altPath=null"));
        assertTrue(result.contains("node=NODE"));
    }

    // Edge Cases and Boundary Tests

    @Test
    public void testMaximumValues() {
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        bb.putShort((short) 3);
        bb.putShort((short) 65535);  // max unsigned short
        bb.putShort((short) 65535);
        bb.putShort((short) 65535);
        bb.putShort((short) 65535);
        bb.putShort((short) 65535);
        bb.putShort((short) 0);
        bb.putShort((short) 0);
        bb.putShort((short) 0);
        
        int decodedSize = referral.decode(testBuffer, 0, testBuffer.length);
        
        assertEquals(65535, decodedSize);
        assertEquals(65535, referral.getSize());
        assertEquals(65535, referral.getServerType());
        assertEquals(65535, referral.getRFlags());
        assertEquals(65535, referral.getProximity());
        assertEquals(65535, referral.getTtl());
    }

    @Test
    public void testEmptyStrings() {
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        bb.putShort((short) 3);
        bb.putShort((short) 34);
        bb.putShort((short) 1);
        bb.putShort((short) 0);
        bb.putShort((short) 5);
        bb.putShort((short) 300);
        bb.putShort((short) 22);
        bb.putShort((short) 24);
        bb.putShort((short) 26);
        
        // Empty strings (just null terminators)
        bb.position(22);
        bb.putShort((short) 0);
        bb.position(24);
        bb.putShort((short) 0);
        bb.position(26);
        bb.putShort((short) 0);
        
        referral.decode(testBuffer, 0, testBuffer.length);
        
        assertEquals("", referral.getRpath());
        assertEquals("", referral.getAltPath());
        assertEquals("", referral.getNode());
    }

    @Test
    public void testVariousFieldValues() {
        int[][] testCases = {
            {0, 0, 0},
            {100, 200, 300},
            {32767, 32767, 32767},
            {65535, 65535, 65535}
        };
        
        for (int[] testCase : testCases) {
            int serverType = testCase[0];
            int proximity = testCase[1];
            int ttl = testCase[2];
            
            ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
            
            bb.putShort((short) 3);
            bb.putShort((short) 34);
            bb.putShort((short) serverType);
            bb.putShort((short) 0);
            bb.putShort((short) proximity);
            bb.putShort((short) ttl);
            bb.putShort((short) 0);
            bb.putShort((short) 0);
            bb.putShort((short) 0);
            
            Referral ref = new Referral();
            ref.decode(testBuffer, 0, testBuffer.length);
            
            assertEquals(serverType, ref.getServerType());
            assertEquals(proximity, ref.getProximity());
            assertEquals(ttl, ref.getTtl());
        }
    }

    // Buffer Offset Tests

    @Test
    public void testDecodeFromNonZeroIndex() {
        int offset = 100;
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        bb.position(offset);
        bb.putShort((short) 1);
        bb.putShort((short) 24);
        bb.putShort((short) 1);
        bb.putShort((short) 0);
        bb.put("TEST".getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);
        
        int decodedSize = referral.decode(testBuffer, offset, testBuffer.length - offset);
        
        assertEquals(24, decodedSize);
        assertEquals(1, referral.getVersion());
        assertEquals("TEST", referral.getNode());
    }

    @Test
    public void testDifferentBufferLengths() {
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        bb.putShort((short) 1);
        bb.putShort((short) 24);
        bb.putShort((short) 1);
        bb.putShort((short) 0);
        bb.put("NODE".getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);
        
        // Decode with exact length
        int decodedSize = referral.decode(testBuffer, 0, 24);
        assertEquals(24, decodedSize);
        
        // Decode with excess length
        Referral referral2 = new Referral();
        decodedSize = referral2.decode(testBuffer, 0, 512);
        assertEquals(24, decodedSize);
    }

    // Multiple Expanded Names Tests

    @Test
    public void testSingleExpandedName() {
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        bb.putShort((short) 3);
        bb.putShort((short) 100);
        bb.putShort((short) 2);
        bb.putShort((short) Trans2GetDfsReferralResponse.FLAGS_NAME_LIST_REFERRAL);
        bb.putShort((short) 10);
        bb.putShort((short) 600);
        bb.putShort((short) 0);     // no special name
        bb.putShort((short) 1);     // one expanded name
        bb.putShort((short) 22);    // expandedNameOffset
        
        bb.position(22);
        bb.put("SINGLE".getBytes(StandardCharsets.UTF_16LE));
        bb.putShort((short) 0);
        
        referral.decode(testBuffer, 0, testBuffer.length);
        
        String[] expanded = referral.getExpandedNames();
        assertEquals(1, expanded.length);
        assertEquals("SINGLE", expanded[0]);
    }

    @Test
    public void testManyExpandedNames() {
        ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
        
        bb.putShort((short) 3);
        bb.putShort((short) 150);   // larger size for multiple names
        bb.putShort((short) 2);
        bb.putShort((short) Trans2GetDfsReferralResponse.FLAGS_NAME_LIST_REFERRAL);
        bb.putShort((short) 10);
        bb.putShort((short) 600);
        bb.putShort((short) 0);
        bb.putShort((short) 5);     // five expanded names
        bb.putShort((short) 22);
        
        bb.position(22);
        String[] expectedNames = {"NAME1", "NAME2", "NAME3", "NAME4", "NAME5"};
        for (String name : expectedNames) {
            bb.put(name.getBytes(StandardCharsets.UTF_16LE));
            bb.putShort((short) 0);
        }
        
        referral.decode(testBuffer, 0, testBuffer.length);
        
        assertArrayEquals(expectedNames, referral.getExpandedNames());
    }
}
