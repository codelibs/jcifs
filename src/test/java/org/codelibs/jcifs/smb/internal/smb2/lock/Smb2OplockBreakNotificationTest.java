package org.codelibs.jcifs.smb.internal.smb2.lock;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.stream.Stream;

import org.codelibs.jcifs.smb.BaseTest;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Response;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Hexdump;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Test class for Smb2OplockBreakNotification functionality
 */
@DisplayName("Smb2OplockBreakNotification Tests")
class Smb2OplockBreakNotificationTest extends BaseTest {

    private Configuration mockConfig;
    private Smb2OplockBreakNotification notification;

    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
        notification = new Smb2OplockBreakNotification(mockConfig);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create notification with configuration")
        void testConstructorWithConfiguration() {
            Smb2OplockBreakNotification testNotification = new Smb2OplockBreakNotification(mockConfig);
            assertNotNull(testNotification);
            // Verify it extends ServerMessageBlock2Response
            assertTrue(testNotification instanceof ServerMessageBlock2Response);
        }
    }

    @Nested
    @DisplayName("ReadBytesWireFormat Tests")
    class ReadBytesWireFormatTests {

        @Test
        @DisplayName("Should read valid oplock break notification from buffer")
        void testReadValidOplockBreakNotification() throws Exception {
            // Create a valid buffer with structure size 24
            byte[] buffer = new byte[64];
            int bufferIndex = 0;

            // Write structure size (24)
            SMBUtil.writeInt2(24, buffer, bufferIndex);

            // Write oplock level at offset 2
            byte expectedOplockLevel = (byte) 0x02; // SMB2_OPLOCK_LEVEL_II
            buffer[bufferIndex + 2] = expectedOplockLevel;

            // Write reserved field (4 bytes at offset 4)
            bufferIndex += 4;

            // Write Reserved2 (4 bytes)
            bufferIndex += 4;

            // Write file ID (16 bytes)
            byte[] expectedFileId = createTestData(16);
            System.arraycopy(expectedFileId, 0, buffer, bufferIndex, 16);

            // Read the buffer
            int bytesRead = notification.readBytesWireFormat(buffer, 0);

            // Verify the bytes read
            assertEquals(24, bytesRead);

            // Verify the fields were set correctly using reflection
            Field oplockLevelField = Smb2OplockBreakNotification.class.getDeclaredField("oplockLevel");
            oplockLevelField.setAccessible(true);
            assertEquals(expectedOplockLevel, oplockLevelField.get(notification));

            Field fileIdField = Smb2OplockBreakNotification.class.getDeclaredField("fileId");
            fileIdField.setAccessible(true);
            assertArrayEquals(expectedFileId, (byte[]) fileIdField.get(notification));
        }

        @Test
        @DisplayName("Should throw exception for invalid structure size")
        void testReadInvalidStructureSize() {
            // Create buffer with invalid structure size
            byte[] buffer = new byte[64];
            SMBUtil.writeInt2(23, buffer, 0); // Invalid size (should be 24)

            SMBProtocolDecodingException exception =
                    assertThrows(SMBProtocolDecodingException.class, () -> notification.readBytesWireFormat(buffer, 0));

            assertEquals("Expected structureSize = 24", exception.getMessage());
        }

        @ParameterizedTest
        @DisplayName("Should read different oplock levels correctly")
        @ValueSource(bytes = { 0x00, 0x01, 0x02, 0x08, (byte) 0xFF })
        void testReadDifferentOplockLevels(byte oplockLevel) throws Exception {
            byte[] buffer = createValidOplockBreakBuffer(oplockLevel, createTestData(16));

            int bytesRead = notification.readBytesWireFormat(buffer, 0);
            assertEquals(24, bytesRead);

            Field oplockLevelField = Smb2OplockBreakNotification.class.getDeclaredField("oplockLevel");
            oplockLevelField.setAccessible(true);
            assertEquals(oplockLevel, oplockLevelField.get(notification));
        }

        @Test
        @DisplayName("Should handle buffer with offset correctly")
        void testReadWithBufferOffset() throws Exception {
            int offset = 10;
            byte[] buffer = new byte[64];
            byte[] fileId = createTestData(16);
            byte oplockLevel = 0x02;

            // Fill some random data before offset
            Arrays.fill(buffer, 0, offset, (byte) 0xAB);

            // Write valid data at offset
            SMBUtil.writeInt2(24, buffer, offset);
            buffer[offset + 2] = oplockLevel;
            System.arraycopy(fileId, 0, buffer, offset + 8, 16);

            int bytesRead = notification.readBytesWireFormat(buffer, offset);
            assertEquals(24, bytesRead);

            Field fileIdField = Smb2OplockBreakNotification.class.getDeclaredField("fileId");
            fileIdField.setAccessible(true);
            assertArrayEquals(fileId, (byte[]) fileIdField.get(notification));
        }

        @Test
        @DisplayName("Should read file ID correctly with various patterns")
        void testReadFileIdPatterns() throws Exception {
            // Test with all zeros
            byte[] zeroFileId = new byte[16];
            testFileIdReading(zeroFileId);

            // Test with all ones
            byte[] onesFileId = new byte[16];
            Arrays.fill(onesFileId, (byte) 0xFF);
            testFileIdReading(onesFileId);

            // Test with pattern
            byte[] patternFileId = createTestData(16);
            testFileIdReading(patternFileId);
        }

        private void testFileIdReading(byte[] expectedFileId) throws Exception {
            Smb2OplockBreakNotification testNotification = new Smb2OplockBreakNotification(mockConfig);
            byte[] buffer = createValidOplockBreakBuffer((byte) 0x01, expectedFileId);

            testNotification.readBytesWireFormat(buffer, 0);

            Field fileIdField = Smb2OplockBreakNotification.class.getDeclaredField("fileId");
            fileIdField.setAccessible(true);
            assertArrayEquals(expectedFileId, (byte[]) fileIdField.get(testNotification));
        }

        private byte[] createValidOplockBreakBuffer(byte oplockLevel, byte[] fileId) {
            byte[] buffer = new byte[64];
            SMBUtil.writeInt2(24, buffer, 0);
            buffer[2] = oplockLevel;
            System.arraycopy(fileId, 0, buffer, 8, 16);
            return buffer;
        }
    }

    @Nested
    @DisplayName("WriteBytesWireFormat Tests")
    class WriteBytesWireFormatTests {

        @Test
        @DisplayName("Should always return 0 for write operation")
        void testWriteBytesWireFormat() {
            byte[] buffer = new byte[64];
            int result = notification.writeBytesWireFormat(buffer, 0);
            assertEquals(0, result);

            // Test with different offsets
            result = notification.writeBytesWireFormat(buffer, 10);
            assertEquals(0, result);

            result = notification.writeBytesWireFormat(buffer, 50);
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should not modify buffer during write")
        void testWriteDoesNotModifyBuffer() {
            byte[] buffer = new byte[64];
            Arrays.fill(buffer, (byte) 0xAA);
            byte[] originalBuffer = buffer.clone();

            notification.writeBytesWireFormat(buffer, 0);

            assertArrayEquals(originalBuffer, buffer);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should generate correct string representation")
        void testToString() throws Exception {
            // Set up notification with known values
            byte oplockLevel = 0x02;
            byte[] fileId = new byte[16];
            Arrays.fill(fileId, 0, 8, (byte) 0xAB);
            Arrays.fill(fileId, 8, 16, (byte) 0xCD);

            // Use reflection to set private fields
            Field oplockLevelField = Smb2OplockBreakNotification.class.getDeclaredField("oplockLevel");
            oplockLevelField.setAccessible(true);
            oplockLevelField.set(notification, oplockLevel);

            Field fileIdField = Smb2OplockBreakNotification.class.getDeclaredField("fileId");
            fileIdField.setAccessible(true);
            fileIdField.set(notification, fileId);

            String result = notification.toString();

            // Note: There's a typo in the original code - "Opblock" instead of "Oplock"
            assertTrue(result.startsWith("Smb2OpblockBreakNotification["));
            assertTrue(result.contains("oplockLevel=" + oplockLevel));
            assertTrue(result.contains("fileId=" + Hexdump.toHexString(fileId)));
            assertTrue(result.endsWith("]"));
        }

        @Test
        @DisplayName("Should handle null fileId in toString")
        void testToStringWithNullFileId() throws Exception {
            // Set oplockLevel but leave fileId as null
            Field oplockLevelField = Smb2OplockBreakNotification.class.getDeclaredField("oplockLevel");
            oplockLevelField.setAccessible(true);
            oplockLevelField.set(notification, (byte) 0x01);

            // The implementation calls Hexdump.toHexString which throws NPE on null
            // This test verifies the actual behavior
            assertThrows(NullPointerException.class, () -> notification.toString());
        }

        @ParameterizedTest
        @DisplayName("Should format different oplock levels correctly")
        @CsvSource({ "0, 0", "1, 1", "2, 2", "8, 8", "255, -1" // byte 255 is -1 when printed as signed
        })
        void testToStringWithDifferentOplockLevels(int inputValue, String expectedDisplay) throws Exception {
            byte oplockLevel = (byte) inputValue;

            Field oplockLevelField = Smb2OplockBreakNotification.class.getDeclaredField("oplockLevel");
            oplockLevelField.setAccessible(true);
            oplockLevelField.set(notification, oplockLevel);

            Field fileIdField = Smb2OplockBreakNotification.class.getDeclaredField("fileId");
            fileIdField.setAccessible(true);
            fileIdField.set(notification, new byte[16]);

            String result = notification.toString();
            assertTrue(result.contains("oplockLevel=" + oplockLevel));
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle minimum valid buffer size")
        void testMinimumBufferSize() throws Exception {
            byte[] buffer = new byte[24]; // Exact size needed
            SMBUtil.writeInt2(24, buffer, 0);
            buffer[2] = 0x01;

            int bytesRead = notification.readBytesWireFormat(buffer, 0);
            assertEquals(24, bytesRead);
        }

        @Test
        @DisplayName("Should handle buffer with extra data")
        void testBufferWithExtraData() throws Exception {
            byte[] buffer = new byte[100];
            Arrays.fill(buffer, (byte) 0xFF); // Fill with non-zero values

            // Write valid notification data
            SMBUtil.writeInt2(24, buffer, 0);
            buffer[2] = 0x02;
            byte[] fileId = createTestData(16);
            System.arraycopy(fileId, 0, buffer, 8, 16);

            int bytesRead = notification.readBytesWireFormat(buffer, 0);
            assertEquals(24, bytesRead);

            // Verify only the necessary bytes were read
            Field fileIdField = Smb2OplockBreakNotification.class.getDeclaredField("fileId");
            fileIdField.setAccessible(true);
            assertArrayEquals(fileId, (byte[]) fileIdField.get(notification));
        }

        @Test
        @DisplayName("Should correctly parse reserved fields")
        void testReservedFieldsAreSkipped() throws Exception {
            byte[] buffer = new byte[64];

            // Structure with specific values in reserved fields
            SMBUtil.writeInt2(24, buffer, 0);
            buffer[2] = 0x01; // Oplock level
            buffer[3] = (byte) 0xAA; // Reserved byte

            // Reserved2 field (4 bytes at offset 4)
            buffer[4] = (byte) 0xBB;
            buffer[5] = (byte) 0xCC;
            buffer[6] = (byte) 0xDD;
            buffer[7] = (byte) 0xEE;

            byte[] fileId = createTestData(16);
            System.arraycopy(fileId, 0, buffer, 8, 16);

            int bytesRead = notification.readBytesWireFormat(buffer, 0);
            assertEquals(24, bytesRead);

            // Verify that reserved fields were properly skipped
            Field oplockLevelField = Smb2OplockBreakNotification.class.getDeclaredField("oplockLevel");
            oplockLevelField.setAccessible(true);
            assertEquals((byte) 0x01, oplockLevelField.get(notification));

            Field fileIdField = Smb2OplockBreakNotification.class.getDeclaredField("fileId");
            fileIdField.setAccessible(true);
            assertArrayEquals(fileId, (byte[]) fileIdField.get(notification));
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle multiple consecutive reads")
        void testMultipleConsecutiveReads() throws Exception {
            // First read
            byte[] buffer1 = createValidOplockBreakBuffer((byte) 0x01, createTestData(16));
            notification.readBytesWireFormat(buffer1, 0);

            // Second read with different values
            byte[] fileId2 = new byte[16];
            Arrays.fill(fileId2, (byte) 0x99);
            byte[] buffer2 = createValidOplockBreakBuffer((byte) 0x08, fileId2);
            notification.readBytesWireFormat(buffer2, 0);

            // Verify second read overwrote first read values
            Field oplockLevelField = Smb2OplockBreakNotification.class.getDeclaredField("oplockLevel");
            oplockLevelField.setAccessible(true);
            assertEquals((byte) 0x08, oplockLevelField.get(notification));

            Field fileIdField = Smb2OplockBreakNotification.class.getDeclaredField("fileId");
            fileIdField.setAccessible(true);
            assertArrayEquals(fileId2, (byte[]) fileIdField.get(notification));
        }

        @Test
        @DisplayName("Should maintain state after successful read")
        void testStateMaintenanceAfterRead() throws Exception {
            byte oplockLevel = 0x02;
            byte[] fileId = createTestData(16);
            byte[] buffer = createValidOplockBreakBuffer(oplockLevel, fileId);

            notification.readBytesWireFormat(buffer, 0);

            // Verify state is maintained through multiple toString calls
            String firstToString = notification.toString();
            String secondToString = notification.toString();
            assertEquals(firstToString, secondToString);

            // Verify state is maintained after write operation
            notification.writeBytesWireFormat(new byte[64], 0);
            String thirdToString = notification.toString();
            assertEquals(firstToString, thirdToString);
        }

        private byte[] createValidOplockBreakBuffer(byte oplockLevel, byte[] fileId) {
            byte[] buffer = new byte[64];
            SMBUtil.writeInt2(24, buffer, 0);
            buffer[2] = oplockLevel;
            System.arraycopy(fileId, 0, buffer, 8, 16);
            return buffer;
        }
    }

    @Nested
    @DisplayName("Oplock Level Constants Tests")
    class OplockLevelTests {

        @ParameterizedTest
        @DisplayName("Should handle standard oplock levels")
        @MethodSource("provideOplockLevels")
        void testStandardOplockLevels(byte oplockLevel, String description) throws Exception {
            byte[] buffer = new byte[64];
            SMBUtil.writeInt2(24, buffer, 0);
            buffer[2] = oplockLevel;
            byte[] fileId = createTestData(16);
            System.arraycopy(fileId, 0, buffer, 8, 16);

            int bytesRead = notification.readBytesWireFormat(buffer, 0);
            assertEquals(24, bytesRead);

            Field oplockLevelField = Smb2OplockBreakNotification.class.getDeclaredField("oplockLevel");
            oplockLevelField.setAccessible(true);
            assertEquals(oplockLevel, oplockLevelField.get(notification));

            // Log the test for clarity
            logger.debug("Tested oplock level: {} ({})", oplockLevel, description);
        }

        private static Stream<Arguments> provideOplockLevels() {
            return Stream.of(Arguments.of((byte) 0x00, "SMB2_OPLOCK_LEVEL_NONE"), Arguments.of((byte) 0x01, "SMB2_OPLOCK_LEVEL_II"),
                    Arguments.of((byte) 0x08, "SMB2_OPLOCK_LEVEL_EXCLUSIVE"), Arguments.of((byte) 0x09, "SMB2_OPLOCK_LEVEL_BATCH"),
                    Arguments.of((byte) 0xFF, "SMB2_OPLOCK_LEVEL_LEASE"));
        }
    }
}
