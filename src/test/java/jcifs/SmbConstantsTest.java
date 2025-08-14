package jcifs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for SmbConstants interface constants
 */
@DisplayName("SmbConstants Tests")
class SmbConstantsTest extends BaseTest {

    @Test
    @DisplayName("Should define default connection constants")
    void testDefaultConstants() {
        assertEquals(445, SmbConstants.DEFAULT_PORT);
        assertEquals(10, SmbConstants.DEFAULT_MAX_MPX_COUNT);
        assertEquals(30000, SmbConstants.DEFAULT_RESPONSE_TIMEOUT);
        assertEquals(35000, SmbConstants.DEFAULT_SO_TIMEOUT);
        assertEquals(0xFFFF, SmbConstants.DEFAULT_RCV_BUF_SIZE);
        assertEquals(0xFFFF, SmbConstants.DEFAULT_SND_BUF_SIZE);
        assertEquals(1024, SmbConstants.DEFAULT_NOTIFY_BUF_SIZE);
        assertEquals(250, SmbConstants.DEFAULT_SSN_LIMIT);
        assertEquals(35000, SmbConstants.DEFAULT_CONN_TIMEOUT);
    }

    @Test
    @DisplayName("Should define SMB flags constants")
    void testSmbFlags() {
        assertEquals(0x00, SmbConstants.FLAGS_NONE);
        assertEquals(0x01, SmbConstants.FLAGS_LOCK_AND_READ_WRITE_AND_UNLOCK);
        assertEquals(0x02, SmbConstants.FLAGS_RECEIVE_BUFFER_POSTED);
        assertEquals(0x08, SmbConstants.FLAGS_PATH_NAMES_CASELESS);
        assertEquals(0x10, SmbConstants.FLAGS_PATH_NAMES_CANONICALIZED);
        assertEquals(0x20, SmbConstants.FLAGS_OPLOCK_REQUESTED_OR_GRANTED);
        assertEquals(0x40, SmbConstants.FLAGS_NOTIFY_OF_MODIFY_ACTION);
        assertEquals(0x80, SmbConstants.FLAGS_RESPONSE);
    }

    @Test
    @DisplayName("Should define SMB flags2 constants")
    void testSmbFlags2() {
        assertEquals(0x0000, SmbConstants.FLAGS2_NONE);
        assertEquals(0x0001, SmbConstants.FLAGS2_LONG_FILENAMES);
        assertEquals(0x0002, SmbConstants.FLAGS2_EXTENDED_ATTRIBUTES);
        assertEquals(0x0004, SmbConstants.FLAGS2_SECURITY_SIGNATURES);
        assertEquals(0x0010, SmbConstants.FLAGS2_SECURITY_REQUIRE_SIGNATURES);
        assertEquals(0x0800, SmbConstants.FLAGS2_EXTENDED_SECURITY_NEGOTIATION);
        assertEquals(0x1000, SmbConstants.FLAGS2_RESOLVE_PATHS_IN_DFS);
        assertEquals(0x2000, SmbConstants.FLAGS2_PERMIT_READ_IF_EXECUTE_PERM);
        assertEquals(0x4000, SmbConstants.FLAGS2_STATUS32);
        assertEquals(0x8000, SmbConstants.FLAGS2_UNICODE);
    }

    @Test
    @DisplayName("Should define capability constants")
    void testCapabilityConstants() {
        assertEquals(0x0000, SmbConstants.CAP_NONE);
        assertEquals(0x0001, SmbConstants.CAP_RAW_MODE);
        assertEquals(0x0002, SmbConstants.CAP_MPX_MODE);
        assertEquals(0x0004, SmbConstants.CAP_UNICODE);
        assertEquals(0x0008, SmbConstants.CAP_LARGE_FILES);
        assertEquals(0x0010, SmbConstants.CAP_NT_SMBS);
        assertEquals(0x0020, SmbConstants.CAP_RPC_REMOTE_APIS);
        assertEquals(0x0040, SmbConstants.CAP_STATUS32);
        assertEquals(0x0080, SmbConstants.CAP_LEVEL_II_OPLOCKS);
        assertEquals(0x0100, SmbConstants.CAP_LOCK_AND_READ);
        assertEquals(0x0200, SmbConstants.CAP_NT_FIND);
        assertEquals(0x1000, SmbConstants.CAP_DFS);
        assertEquals(0x4000, SmbConstants.CAP_LARGE_READX);
        assertEquals(0x8000, SmbConstants.CAP_LARGE_WRITEX);
        assertEquals(0x80000000, SmbConstants.CAP_EXTENDED_SECURITY);
    }

    @Test
    @DisplayName("Should define file attribute constants")
    void testFileAttributes() {
        assertEquals(0x01, SmbConstants.ATTR_READONLY);
        assertEquals(0x02, SmbConstants.ATTR_HIDDEN);
        assertEquals(0x04, SmbConstants.ATTR_SYSTEM);
        assertEquals(0x08, SmbConstants.ATTR_VOLUME);
        assertEquals(0x10, SmbConstants.ATTR_DIRECTORY);
        assertEquals(0x20, SmbConstants.ATTR_ARCHIVE);
        assertEquals(0x800, SmbConstants.ATTR_COMPRESSED);
        assertEquals(0x080, SmbConstants.ATTR_NORMAL);
        assertEquals(0x100, SmbConstants.ATTR_TEMPORARY);
    }

    @Test
    @DisplayName("Should define access mask constants")
    void testAccessMaskConstants() {
        assertEquals(0x00000001, SmbConstants.FILE_READ_DATA);
        assertEquals(0x00000002, SmbConstants.FILE_WRITE_DATA);
        assertEquals(0x00000004, SmbConstants.FILE_APPEND_DATA);
        assertEquals(0x00000008, SmbConstants.FILE_READ_EA);
        assertEquals(0x00000010, SmbConstants.FILE_WRITE_EA);
        assertEquals(0x00000020, SmbConstants.FILE_EXECUTE);
        assertEquals(0x00000040, SmbConstants.FILE_DELETE);
        assertEquals(0x00000080, SmbConstants.FILE_READ_ATTRIBUTES);
        assertEquals(0x00000100, SmbConstants.FILE_WRITE_ATTRIBUTES);
        assertEquals(0x00010000, SmbConstants.DELETE);
        assertEquals(0x00020000, SmbConstants.READ_CONTROL);
        assertEquals(0x00040000, SmbConstants.WRITE_DAC);
        assertEquals(0x00080000, SmbConstants.WRITE_OWNER);
        assertEquals(0x00100000, SmbConstants.SYNCHRONIZE);
        assertEquals(0x10000000, SmbConstants.GENERIC_ALL);
        assertEquals(0x20000000, SmbConstants.GENERIC_EXECUTE);
        assertEquals(0x40000000, SmbConstants.GENERIC_WRITE);
        assertEquals(0x80000000, SmbConstants.GENERIC_READ);
    }

    @Test
    @DisplayName("Should define share access constants")
    void testShareAccessConstants() {
        assertEquals(0x00, SmbConstants.FILE_NO_SHARE);
        assertEquals(0x01, SmbConstants.FILE_SHARE_READ);
        assertEquals(0x02, SmbConstants.FILE_SHARE_WRITE);
        assertEquals(0x04, SmbConstants.FILE_SHARE_DELETE);
        assertEquals(SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE | SmbConstants.FILE_SHARE_DELETE,
                SmbConstants.DEFAULT_SHARING);
    }

    @Test
    @DisplayName("Should define SMB resource type constants")
    void testResourceTypeConstants() {
        assertEquals(0x01, SmbConstants.TYPE_FILESYSTEM);
        assertEquals(0x02, SmbConstants.TYPE_WORKGROUP);
        assertEquals(0x04, SmbConstants.TYPE_SERVER);
        assertEquals(0x08, SmbConstants.TYPE_SHARE);
        assertEquals(0x10, SmbConstants.TYPE_NAMED_PIPE);
        assertEquals(0x20, SmbConstants.TYPE_PRINTER);
        assertEquals(0x40, SmbConstants.TYPE_COMM);
    }

    @Test
    @DisplayName("Should define open flags constants")
    void testOpenFlagsConstants() {
        assertEquals(0x01, SmbConstants.O_RDONLY);
        assertEquals(0x02, SmbConstants.O_WRONLY);
        assertEquals(0x03, SmbConstants.O_RDWR);
        assertEquals(0x04, SmbConstants.O_APPEND);
        assertEquals(0x0010, SmbConstants.O_CREAT);
        assertEquals(0x0020, SmbConstants.O_EXCL);
        assertEquals(0x0040, SmbConstants.O_TRUNC);
    }

    @Test
    @DisplayName("Should define copy/move flags constants")
    void testCopyMoveFlags() {
        assertEquals(0x0001, SmbConstants.FLAGS_TARGET_MUST_BE_FILE);
        assertEquals(0x0002, SmbConstants.FLAGS_TARGET_MUST_BE_DIRECTORY);
        assertEquals(0x0004, SmbConstants.FLAGS_COPY_TARGET_MODE_ASCII);
        assertEquals(0x0008, SmbConstants.FLAGS_COPY_SOURCE_MODE_ASCII);
        assertEquals(0x0010, SmbConstants.FLAGS_VERIFY_ALL_WRITES);
        assertEquals(0x0020, SmbConstants.FLAGS_TREE_COPY);
    }

    @Test
    @DisplayName("Should define protocol specific constants")
    void testProtocolConstants() {
        assertEquals(0x0000, SmbConstants.OPEN_FUNCTION_FAIL_IF_EXISTS);
        assertEquals(0x0020, SmbConstants.OPEN_FUNCTION_OVERWRITE_IF_EXISTS);
        assertEquals(0x00, SmbConstants.SECURITY_SHARE);
        assertEquals(0x01, SmbConstants.SECURITY_USER);
        assertEquals(4, SmbConstants.CMD_OFFSET);
        assertEquals(5, SmbConstants.ERROR_CODE_OFFSET);
        assertEquals(9, SmbConstants.FLAGS_OFFSET);
        assertEquals(14, SmbConstants.SIGNATURE_OFFSET);
        assertEquals(24, SmbConstants.TID_OFFSET);
        assertEquals(32, SmbConstants.SMB1_HEADER_LENGTH);
    }

    @Test
    @DisplayName("Should define time and encoding constants")
    void testTimeAndEncodingConstants() {
        assertEquals(11644473600000L, SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601);
        assertEquals("Cp850", SmbConstants.DEFAULT_OEM_ENCODING);
        assertEquals(-1, SmbConstants.FOREVER);
    }

    @Test
    @DisplayName("Should validate flag combinations work correctly")
    void testFlagCombinations() {
        // Test that flags can be combined with bitwise OR
        int combinedShareAccess = SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE;
        assertEquals(0x03, combinedShareAccess);

        int allShareAccess = SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE | SmbConstants.FILE_SHARE_DELETE;
        assertEquals(SmbConstants.DEFAULT_SHARING, allShareAccess);

        // Test attribute combinations
        int readOnlyHidden = SmbConstants.ATTR_READONLY | SmbConstants.ATTR_HIDDEN;
        assertEquals(0x03, readOnlyHidden);
    }

    @Test
    @DisplayName("Should validate access mask combinations")
    void testAccessMaskCombinations() {
        // Test common access combinations
        int readWriteAccess = SmbConstants.FILE_READ_DATA | SmbConstants.FILE_WRITE_DATA;
        assertEquals(0x03, readWriteAccess);

        int fullFileAccess =
                SmbConstants.FILE_READ_DATA | SmbConstants.FILE_WRITE_DATA | SmbConstants.FILE_APPEND_DATA | SmbConstants.FILE_DELETE;
        assertEquals(0x47, fullFileAccess);
    }

    @Test
    @DisplayName("Should validate constants are immutable interface values")
    void testConstantNature() {
        // SmbConstants is an interface with static final fields
        // Verify constants maintain their values
        assertEquals(445, SmbConstants.DEFAULT_PORT);

        // Test that the constant values are as expected for protocol compliance
        assertTrue(SmbConstants.DEFAULT_PORT > 0);
        assertTrue(SmbConstants.DEFAULT_RESPONSE_TIMEOUT > 0);
        assertTrue(SmbConstants.DEFAULT_SO_TIMEOUT >= SmbConstants.DEFAULT_RESPONSE_TIMEOUT);
    }

    @Test
    @DisplayName("Should have distinct bit patterns for flags")
    void testDistinctBitPatterns() {
        // Verify file attributes have distinct bit patterns
        int[] attributes = { SmbConstants.ATTR_READONLY, SmbConstants.ATTR_HIDDEN, SmbConstants.ATTR_SYSTEM, SmbConstants.ATTR_VOLUME,
                SmbConstants.ATTR_DIRECTORY, SmbConstants.ATTR_ARCHIVE };

        for (int i = 0; i < attributes.length; i++) {
            for (int j = i + 1; j < attributes.length; j++) {
                assertNotEquals(attributes[i], attributes[j], "Attributes should have distinct values");
                assertEquals(0, attributes[i] & attributes[j], "Attributes should not overlap in bit patterns");
            }
        }
    }

    @Test
    @DisplayName("Should have resource types with power-of-2 values")
    void testResourceTypeBitPatterns() {
        // Resource types should be powers of 2 for bit flag usage
        int[] types = { SmbConstants.TYPE_FILESYSTEM, SmbConstants.TYPE_WORKGROUP, SmbConstants.TYPE_SERVER, SmbConstants.TYPE_SHARE,
                SmbConstants.TYPE_NAMED_PIPE, SmbConstants.TYPE_PRINTER, SmbConstants.TYPE_COMM };

        for (int type : types) {
            // Check if it's a power of 2 (has exactly one bit set)
            assertTrue(type > 0 && (type & (type - 1)) == 0, "Resource type " + type + " should be a power of 2");
        }
    }
}