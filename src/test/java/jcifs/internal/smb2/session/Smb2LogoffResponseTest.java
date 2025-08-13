package jcifs.internal.smb2.session;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

@ExtendWith(MockitoExtension.class)
class Smb2LogoffResponseTest {

    // Helper to create an instance with a mocked Configuration
    private Smb2LogoffResponse newResponse() {
        Configuration cfg = Mockito.mock(Configuration.class);
        return new Smb2LogoffResponse(cfg);
    }

    @Test
    @DisplayName("Constructor accepts a Configuration and creates instance")
    void constructor_happyPath() {
        // Arrange
        Configuration cfg = Mockito.mock(Configuration.class);

        // Act
        Smb2LogoffResponse resp = new Smb2LogoffResponse(cfg);

        // Assert
        assertNotNull(resp, "Response instance should be created");
    }

    @Nested
    @DisplayName("writeBytesWireFormat")
    class WriteBytesWireFormat {

        @ParameterizedTest
        @ValueSource(ints = { -10, -1, 0, 1, 42 })
        @DisplayName("Returns 0 regardless of dst and index")
        void returnsZero_forVariousIndexes(int index) {
            // Arrange
            Smb2LogoffResponse resp = newResponse();
            byte[] buffer = new byte[8];
            byte[] original = buffer.clone();

            // Act
            int written = resp.writeBytesWireFormat(buffer, index);

            // Assert
            assertEquals(0, written, "Should report 0 bytes written");
            assertArrayEquals(original, buffer, "Buffer must remain unchanged");
        }

        @Test
        @DisplayName("Handles null destination without throwing and returns 0")
        void allowsNullBuffer() {
            // Arrange
            Smb2LogoffResponse resp = newResponse();

            // Act & Assert
            assertEquals(0, resp.writeBytesWireFormat(null, 0), "Should return 0 even with null buffer");
        }
    }

    @Nested
    @DisplayName("readBytesWireFormat")
    class ReadBytesWireFormat {

        @ParameterizedTest
        @ValueSource(ints = { 0, 1, 5, 10 })
        @DisplayName("Reads structure size 4 and returns 4 for various start indexes")
        void returnsFour_whenStructureSizeIsFour(int start) throws Exception {
            // Arrange: build a buffer that has the little-endian value 4 at 'start'
            int len = start + 2; // need at least two bytes from start
            byte[] buffer = new byte[len + 3];
            SMBUtil.writeInt2(4, buffer, start);
            Smb2LogoffResponse resp = newResponse();

            // Act
            int read = resp.readBytesWireFormat(buffer, start);

            // Assert
            assertEquals(4, read, "Should return the fixed structure size (4)");
        }

        @ParameterizedTest
        @ValueSource(ints = { 0, 1, 7 })
        @DisplayName("Throws when structure size is not 4")
        void throws_whenStructureSizeIsNotFour(int size) {
            // Arrange
            byte[] buffer = new byte[2];
            SMBUtil.writeInt2(size, buffer, 0);
            Smb2LogoffResponse resp = newResponse();

            // Act
            SMBProtocolDecodingException ex = assertThrows(
                SMBProtocolDecodingException.class,
                () -> resp.readBytesWireFormat(buffer, 0),
                "Should throw when structure size != 4"
            );

            // Assert: message is meaningful
            assertEquals("Structure size is not 4", ex.getMessage());
        }

        @Test
        @DisplayName("Null buffer leads to NullPointerException from readInt2")
        void nullBuffer_throwsNPE() {
            // Arrange
            Smb2LogoffResponse resp = newResponse();

            // Act & Assert
            assertThrows(NullPointerException.class, () -> resp.readBytesWireFormat(null, 0));
        }

        @Test
        @DisplayName("Insufficient buffer causes ArrayIndexOutOfBoundsException")
        void shortBuffer_throwsAIOOBE() {
            // Arrange: length 1 means readInt2 will access index 1 and fail
            byte[] buffer = new byte[1];
            Smb2LogoffResponse resp = newResponse();

            // Act & Assert
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> resp.readBytesWireFormat(buffer, 0));
        }
    }
}

