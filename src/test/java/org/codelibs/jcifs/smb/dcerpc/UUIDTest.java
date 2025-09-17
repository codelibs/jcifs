package org.codelibs.jcifs.smb.dcerpc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayName("UUID Tests")
class UUIDTest {

    // Test data for a valid UUID string
    private static final String VALID_UUID_STRING = "00112233-4455-6677-8899-AABBCCDDEEFF";
    private static final String VALID_UUID_STRING_LOWERCASE = "00112233-4455-6677-8899-aabbccddeeff";

    // Corresponding values for the valid UUID string
    private static final int TIME_LOW = 0x00112233;
    private static final short TIME_MID = (short) 0x4455;
    private static final short TIME_HI_AND_VERSION = (short) 0x6677;
    private static final byte CLOCK_SEQ_HI_AND_RESERVED = (byte) 0x88;
    private static final byte CLOCK_SEQ_LOW = (byte) 0x99;
    private static final byte[] NODE = { (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE, (byte) 0xFF };

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Constructor with rpc.uuid_t should copy all fields correctly")
        void testConstructorWithRpcUuidT() {
            // Arrange
            rpc.uuid_t rpcUuid = new rpc.uuid_t();
            rpcUuid.time_low = TIME_LOW;
            rpcUuid.time_mid = TIME_MID;
            rpcUuid.time_hi_and_version = TIME_HI_AND_VERSION;
            rpcUuid.clock_seq_hi_and_reserved = CLOCK_SEQ_HI_AND_RESERVED;
            rpcUuid.clock_seq_low = CLOCK_SEQ_LOW;
            rpcUuid.node = NODE;

            // Act
            UUID uuid = new UUID(rpcUuid);

            // Assert
            assertEquals(TIME_LOW, uuid.time_low, "time_low should match");
            assertEquals(TIME_MID, uuid.time_mid, "time_mid should match");
            assertEquals(TIME_HI_AND_VERSION, uuid.time_hi_and_version, "time_hi_and_version should match");
            assertEquals(CLOCK_SEQ_HI_AND_RESERVED, uuid.clock_seq_hi_and_reserved, "clock_seq_hi_and_reserved should match");
            assertEquals(CLOCK_SEQ_LOW, uuid.clock_seq_low, "clock_seq_low should match");
            assertArrayEquals(NODE, uuid.node, "node array should match");
        }

        @Test
        @DisplayName("Constructor with valid uppercase UUID string should parse correctly")
        void testConstructorWithString() {
            // Act
            UUID uuid = new UUID(VALID_UUID_STRING);

            // Assert
            assertEquals(TIME_LOW, uuid.time_low, "time_low should be parsed correctly");
            assertEquals(TIME_MID, uuid.time_mid, "time_mid should be parsed correctly");
            assertEquals(TIME_HI_AND_VERSION, uuid.time_hi_and_version, "time_hi_and_version should be parsed correctly");
            assertEquals(CLOCK_SEQ_HI_AND_RESERVED, uuid.clock_seq_hi_and_reserved, "clock_seq_hi_and_reserved should be parsed correctly");
            assertEquals(CLOCK_SEQ_LOW, uuid.clock_seq_low, "clock_seq_low should be parsed correctly");
            assertArrayEquals(NODE, uuid.node, "node array should be parsed correctly");
        }

        @Test
        @DisplayName("Constructor with valid lowercase UUID string should parse correctly")
        void testConstructorWithStringLowercase() {
            // Act
            UUID uuid = new UUID(VALID_UUID_STRING_LOWERCASE);

            // Assert
            assertEquals(TIME_LOW, uuid.time_low, "time_low should be parsed correctly with lowercase hex");
            assertEquals(TIME_MID, uuid.time_mid, "time_mid should be parsed correctly with lowercase hex");
            assertEquals(TIME_HI_AND_VERSION, uuid.time_hi_and_version,
                    "time_hi_and_version should be parsed correctly with lowercase hex");
            assertEquals(CLOCK_SEQ_HI_AND_RESERVED, uuid.clock_seq_hi_and_reserved,
                    "clock_seq_hi_and_reserved should be parsed correctly with lowercase hex");
            assertEquals(CLOCK_SEQ_LOW, uuid.clock_seq_low, "clock_seq_low should be parsed correctly with lowercase hex");
            assertArrayEquals(NODE, uuid.node, "node array should be parsed correctly with lowercase hex");
        }

        @Test
        @DisplayName("Constructor with UUID string containing invalid character should throw IllegalArgumentException")
        void testConstructorWithStringInvalidCharacter() {
            // Arrange
            String invalidUuid = "00112233-4455-6677-8899-AABBCCDDEXX"; // 'X' is invalid

            // Act & Assert
            assertThrows(IllegalArgumentException.class, () -> new UUID(invalidUuid),
                    "Should throw IllegalArgumentException for invalid character in UUID string");
        }

        @Test
        @DisplayName("Constructor with UUID string containing non-hex character should throw IllegalArgumentException")
        void testConstructorWithStringNonHexCharacter() {
            // Arrange
            String invalidUuid = "00112233-4455-6677-8899-AABBCCDDEEGG"; // 'G' is invalid

            // Act & Assert
            assertThrows(IllegalArgumentException.class, () -> new UUID(invalidUuid),
                    "Should throw IllegalArgumentException for non-hex character in UUID string");
        }

        @Test
        @DisplayName("Constructor with too short UUID string should parse available data")
        void testConstructorWithStringTooShort() {
            // Arrange - UUID string missing last two characters
            String shortUuid = "00112233-4455-6677-8899-AABBCCDDEE";

            // Act
            UUID uuid = new UUID(shortUuid);

            // Assert - The implementation parses what's available without validation
            assertEquals(TIME_LOW, uuid.time_low, "time_low should be parsed correctly");
            assertEquals(TIME_MID, uuid.time_mid, "time_mid should be parsed correctly");
            assertEquals(TIME_HI_AND_VERSION, uuid.time_hi_and_version, "time_hi_and_version should be parsed correctly");
            assertEquals(CLOCK_SEQ_HI_AND_RESERVED, uuid.clock_seq_hi_and_reserved, "clock_seq_hi_and_reserved should be parsed correctly");
            assertEquals(CLOCK_SEQ_LOW, uuid.clock_seq_low, "clock_seq_low should be parsed correctly");
            // Node array will be partially filled
            assertEquals((byte) 0xAA, uuid.node[0]);
            assertEquals((byte) 0xBB, uuid.node[1]);
            assertEquals((byte) 0xCC, uuid.node[2]);
            assertEquals((byte) 0xDD, uuid.node[3]);
            assertEquals((byte) 0xEE, uuid.node[4]);
            assertEquals((byte) 0x00, uuid.node[5]); // Missing data defaults to 0
        }

        @Test
        @DisplayName("Constructor with empty node array in rpc.uuid_t should handle gracefully")
        void testConstructorWithEmptyNode() {
            // Arrange
            rpc.uuid_t rpcUuid = new rpc.uuid_t();
            rpcUuid.time_low = TIME_LOW;
            rpcUuid.time_mid = TIME_MID;
            rpcUuid.time_hi_and_version = TIME_HI_AND_VERSION;
            rpcUuid.clock_seq_hi_and_reserved = CLOCK_SEQ_HI_AND_RESERVED;
            rpcUuid.clock_seq_low = CLOCK_SEQ_LOW;
            rpcUuid.node = new byte[6]; // Empty node array

            // Act
            UUID uuid = new UUID(rpcUuid);

            // Assert
            assertNotNull(uuid.node);
            assertEquals(6, uuid.node.length);
            assertArrayEquals(new byte[6], uuid.node, "Empty node array should be copied");
        }
    }

    @Nested
    @DisplayName("toString() Tests")
    class ToStringTests {

        @Test
        @DisplayName("toString() should return correctly formatted UUID string")
        void testToString() {
            // Arrange
            rpc.uuid_t rpcUuid = new rpc.uuid_t();
            rpcUuid.time_low = TIME_LOW;
            rpcUuid.time_mid = TIME_MID;
            rpcUuid.time_hi_and_version = TIME_HI_AND_VERSION;
            rpcUuid.clock_seq_hi_and_reserved = CLOCK_SEQ_HI_AND_RESERVED;
            rpcUuid.clock_seq_low = CLOCK_SEQ_LOW;
            rpcUuid.node = NODE;

            UUID uuid = new UUID(rpcUuid);

            // Act
            String result = uuid.toString();

            // Assert
            assertEquals(VALID_UUID_STRING, result.toUpperCase(), "toString() should return the correct UUID string in uppercase");
        }

        @Test
        @DisplayName("toString() should work correctly for UUID created from string")
        void testToStringFromConstructorWithString() {
            // Arrange
            UUID uuid = new UUID(VALID_UUID_STRING);

            // Act
            String result = uuid.toString();

            // Assert
            assertEquals(VALID_UUID_STRING, result.toUpperCase(),
                    "toString() should return the correct UUID string for string-constructed UUID");
        }

        @Test
        @DisplayName("toString() should return uppercase for UUID created from lowercase string")
        void testToStringFromConstructorWithStringLowercase() {
            // Arrange
            UUID uuid = new UUID(VALID_UUID_STRING_LOWERCASE);

            // Act
            String result = uuid.toString();

            // Assert
            assertEquals(VALID_UUID_STRING, result.toUpperCase(),
                    "toString() should return the correct UUID string in uppercase for lowercase input");
        }

        @Test
        @DisplayName("toString() should handle zero UUID correctly")
        void testToStringZeroUuid() {
            // Arrange
            rpc.uuid_t rpcUuid = new rpc.uuid_t();
            rpcUuid.time_low = 0;
            rpcUuid.time_mid = 0;
            rpcUuid.time_hi_and_version = 0;
            rpcUuid.clock_seq_hi_and_reserved = 0;
            rpcUuid.clock_seq_low = 0;
            rpcUuid.node = new byte[6];

            UUID uuid = new UUID(rpcUuid);

            // Act
            String result = uuid.toString();

            // Assert
            assertEquals("00000000-0000-0000-0000-000000000000", result, "toString() should correctly format zero UUID");
        }

        @Test
        @DisplayName("toString() should handle maximum values correctly")
        void testToStringMaxValues() {
            // Arrange
            rpc.uuid_t rpcUuid = new rpc.uuid_t();
            rpcUuid.time_low = 0xFFFFFFFF;
            rpcUuid.time_mid = (short) 0xFFFF;
            rpcUuid.time_hi_and_version = (short) 0xFFFF;
            rpcUuid.clock_seq_hi_and_reserved = (byte) 0xFF;
            rpcUuid.clock_seq_low = (byte) 0xFF;
            rpcUuid.node = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };

            UUID uuid = new UUID(rpcUuid);

            // Act
            String result = uuid.toString();

            // Assert
            assertEquals("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", result, "toString() should correctly format maximum value UUID");
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("UUID with mixed case should parse correctly")
        void testMixedCaseUuid() {
            // Arrange
            String mixedCaseUuid = "00112233-4455-6677-8899-AaBbCcDdEeFf";

            // Act
            UUID uuid = new UUID(mixedCaseUuid);

            // Assert
            assertEquals(TIME_LOW, uuid.time_low);
            assertEquals(TIME_MID, uuid.time_mid);
            assertEquals(TIME_HI_AND_VERSION, uuid.time_hi_and_version);
            assertEquals(CLOCK_SEQ_HI_AND_RESERVED, uuid.clock_seq_hi_and_reserved);
            assertEquals(CLOCK_SEQ_LOW, uuid.clock_seq_low);
            assertArrayEquals(NODE, uuid.node);
        }

        @Test
        @DisplayName("UUID string with extra characters after valid UUID should parse correctly")
        void testUuidWithExtraCharacters() {
            // Arrange
            String uuidWithExtra = VALID_UUID_STRING + "EXTRA";

            // Act
            UUID uuid = new UUID(uuidWithExtra);

            // Assert - The implementation only reads what it needs
            assertEquals(TIME_LOW, uuid.time_low);
            assertEquals(TIME_MID, uuid.time_mid);
            assertEquals(TIME_HI_AND_VERSION, uuid.time_hi_and_version);
            assertEquals(CLOCK_SEQ_HI_AND_RESERVED, uuid.clock_seq_hi_and_reserved);
            assertEquals(CLOCK_SEQ_LOW, uuid.clock_seq_low);
            assertArrayEquals(NODE, uuid.node);
        }

        @Test
        @DisplayName("Constructor should handle special boundary values")
        void testBoundaryValues() {
            // Arrange
            String boundaryUuid = "80000000-8000-8000-8080-808080808080";

            // Act
            UUID uuid = new UUID(boundaryUuid);

            // Assert
            assertEquals(0x80000000, uuid.time_low);
            assertEquals((short) 0x8000, uuid.time_mid);
            assertEquals((short) 0x8000, uuid.time_hi_and_version);
            assertEquals((byte) 0x80, uuid.clock_seq_hi_and_reserved);
            assertEquals((byte) 0x80, uuid.clock_seq_low);
            assertArrayEquals(new byte[] { (byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80 }, uuid.node);
        }
    }
}