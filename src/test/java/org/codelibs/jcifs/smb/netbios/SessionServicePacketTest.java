package org.codelibs.jcifs.smb.netbios;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class SessionServicePacketTest {

    private TestSessionServicePacket packet;

    @Mock
    private InputStream mockInputStream;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        packet = new TestSessionServicePacket();
    }

    // Tests for static methods

    @Test
    @DisplayName("writeInt2 should correctly write 16-bit integer")
    void testWriteInt2() {
        byte[] dst = new byte[4];
        SessionServicePacket.writeInt2(0x1234, dst, 0);

        assertEquals((byte) 0x12, dst[0]);
        assertEquals((byte) 0x34, dst[1]);
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 255, 256, 32767, 65535 })
    @DisplayName("writeInt2 should handle various values")
    void testWriteInt2Various(int value) {
        byte[] dst = new byte[4];
        SessionServicePacket.writeInt2(value, dst, 0);

        assertEquals((byte) ((value >> 8) & 0xFF), dst[0]);
        assertEquals((byte) (value & 0xFF), dst[1]);
    }

    @Test
    @DisplayName("writeInt2 with offset should write at correct position")
    void testWriteInt2WithOffset() {
        byte[] dst = new byte[10];
        dst[2] = (byte) 0xFF; // Mark position
        dst[3] = (byte) 0xFF;

        SessionServicePacket.writeInt2(0xABCD, dst, 4);

        assertEquals((byte) 0xFF, dst[2]); // Should be unchanged
        assertEquals((byte) 0xFF, dst[3]); // Should be unchanged
        assertEquals((byte) 0xAB, dst[4]);
        assertEquals((byte) 0xCD, dst[5]);
    }

    @Test
    @DisplayName("writeInt4 should correctly write 32-bit integer")
    void testWriteInt4() {
        byte[] dst = new byte[8];
        SessionServicePacket.writeInt4(0x12345678, dst, 0);

        assertEquals((byte) 0x12, dst[0]);
        assertEquals((byte) 0x34, dst[1]);
        assertEquals((byte) 0x56, dst[2]);
        assertEquals((byte) 0x78, dst[3]);
    }

    @ParameterizedTest
    @MethodSource("provideInt4TestValues")
    @DisplayName("writeInt4 should handle various values")
    void testWriteInt4Various(int value) {
        byte[] dst = new byte[4];
        SessionServicePacket.writeInt4(value, dst, 0);

        assertEquals((byte) ((value >> 24) & 0xFF), dst[0]);
        assertEquals((byte) ((value >> 16) & 0xFF), dst[1]);
        assertEquals((byte) ((value >> 8) & 0xFF), dst[2]);
        assertEquals((byte) (value & 0xFF), dst[3]);
    }

    private static Stream<Arguments> provideInt4TestValues() {
        return Stream.of(Arguments.of(0), Arguments.of(1), Arguments.of(255), Arguments.of(256), Arguments.of(65535), Arguments.of(65536),
                Arguments.of(0x7FFFFFFF), Arguments.of(0xFFFFFFFF));
    }

    @Test
    @DisplayName("readInt2 should correctly read 16-bit integer")
    void testReadInt2() {
        byte[] src = { (byte) 0x12, (byte) 0x34, (byte) 0x56 };
        int result = SessionServicePacket.readInt2(src, 0);

        assertEquals(0x1234, result);
    }

    @Test
    @DisplayName("readInt2 with offset should read from correct position")
    void testReadInt2WithOffset() {
        byte[] src = { (byte) 0xFF, (byte) 0xFF, (byte) 0xAB, (byte) 0xCD };
        int result = SessionServicePacket.readInt2(src, 2);

        assertEquals(0xABCD, result);
    }

    @Test
    @DisplayName("readInt4 should correctly read 32-bit integer")
    void testReadInt4() {
        byte[] src = { (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78 };
        int result = SessionServicePacket.readInt4(src, 0);

        assertEquals(0x12345678, result);
    }

    @Test
    @DisplayName("readInt4 with negative bytes should handle correctly")
    void testReadInt4WithNegativeBytes() {
        byte[] src = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
        int result = SessionServicePacket.readInt4(src, 0);

        assertEquals(-1, result);
    }

    @Test
    @DisplayName("readLength should extract length from packet header")
    void testReadLength() {
        byte[] src = { (byte) 0x00, (byte) 0x01, (byte) 0x23, (byte) 0x45 };
        int length = SessionServicePacket.readLength(src, 0);

        // Bit 0 of byte 1 is MSB, followed by bytes 2 and 3
        assertEquals(0x012345, length);
    }

    @Test
    @DisplayName("readLength should handle maximum length")
    void testReadLengthMaximum() {
        byte[] src = { (byte) 0x00, (byte) 0x01, (byte) 0xFF, (byte) 0xFF };
        int length = SessionServicePacket.readLength(src, 0);

        assertEquals(0x01FFFF, length);
    }

    @Test
    @DisplayName("readLength should handle zero length")
    void testReadLengthZero() {
        byte[] src = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
        int length = SessionServicePacket.readLength(src, 0);

        assertEquals(0, length);
    }

    @Test
    @DisplayName("readn should read complete data when available")
    void testReadnComplete() throws IOException {
        byte[] buffer = new byte[10];
        byte[] data = { 1, 2, 3, 4, 5 };
        ByteArrayInputStream bais = new ByteArrayInputStream(data);

        int bytesRead = SessionServicePacket.readn(bais, buffer, 0, 5);

        assertEquals(5, bytesRead);
        for (int i = 0; i < 5; i++) {
            assertEquals(data[i], buffer[i]);
        }
    }

    @Test
    @DisplayName("readn should handle partial reads")
    void testReadnPartial() throws IOException {
        byte[] buffer = new byte[10];
        byte[] data = { 1, 2, 3 };
        ByteArrayInputStream bais = new ByteArrayInputStream(data);

        int bytesRead = SessionServicePacket.readn(bais, buffer, 0, 5);

        assertEquals(3, bytesRead); // Only 3 bytes available
    }

    @Test
    @DisplayName("readn should handle EOF correctly")
    void testReadnEOF() throws IOException {
        byte[] buffer = new byte[10];
        ByteArrayInputStream bais = new ByteArrayInputStream(new byte[0]);

        int bytesRead = SessionServicePacket.readn(bais, buffer, 0, 5);

        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("readn should handle multiple read calls")
    void testReadnMultipleCalls() throws IOException {
        when(mockInputStream.read(any(byte[].class), anyInt(), anyInt())).thenReturn(2) // First read returns 2 bytes
                .thenReturn(2) // Second read returns 2 bytes
                .thenReturn(1); // Third read returns 1 byte

        byte[] buffer = new byte[10];
        int bytesRead = SessionServicePacket.readn(mockInputStream, buffer, 0, 5);

        assertEquals(5, bytesRead);
        verify(mockInputStream, times(3)).read(any(byte[].class), anyInt(), anyInt());
    }

    @Test
    @DisplayName("readPacketType should read header and return packet type")
    void testReadPacketType() throws IOException {
        byte[] headerData = { (byte) 0x81, (byte) 0x00, (byte) 0x00, (byte) 0x44 };
        ByteArrayInputStream bais = new ByteArrayInputStream(headerData);
        byte[] buffer = new byte[10];

        int type = SessionServicePacket.readPacketType(bais, buffer, 0);

        assertEquals(0x81, type);
        assertEquals((byte) 0x81, buffer[0]);
    }

    @Test
    @DisplayName("readPacketType should throw IOException on EOF")
    void testReadPacketTypeEOF() {
        ByteArrayInputStream bais = new ByteArrayInputStream(new byte[0]);
        byte[] buffer = new byte[10];

        IOException exception = assertThrows(IOException.class, () -> {
            SessionServicePacket.readPacketType(bais, buffer, 0);
        });

        assertEquals("unexpected EOF reading netbios session header", exception.getMessage());
    }

    @Test
    @DisplayName("readPacketType should throw IOException on incomplete header")
    void testReadPacketTypeIncompleteHeader() {
        byte[] headerData = { (byte) 0x81, (byte) 0x00 }; // Only 2 bytes instead of 4
        ByteArrayInputStream bais = new ByteArrayInputStream(headerData);
        byte[] buffer = new byte[10];

        IOException exception = assertThrows(IOException.class, () -> {
            SessionServicePacket.readPacketType(bais, buffer, 0);
        });

        assertEquals("unexpected EOF reading netbios session header", exception.getMessage());
    }

    @Test
    @DisplayName("readPacketType with special stream returning -1 should return -1")
    void testReadPacketTypeSpecialStream() throws IOException {
        // Create a mock stream that returns exactly -1 on first read (special case)
        when(mockInputStream.read(any(byte[].class), anyInt(), anyInt())).thenReturn(-1); // Immediate EOF

        byte[] buffer = new byte[10];

        // The readn method will return 0 when stream returns -1
        // So this should still throw IOException, not return -1
        IOException exception = assertThrows(IOException.class, () -> {
            SessionServicePacket.readPacketType(mockInputStream, buffer, 0);
        });

        assertEquals("unexpected EOF reading netbios session header", exception.getMessage());
    }

    // Tests for instance methods

    @Test
    @DisplayName("writeWireFormat should write header and trailer")
    void testWriteWireFormat() {
        packet.type = SessionServicePacket.SESSION_MESSAGE;
        packet.trailerLength = 10; // Mock trailer will write 10 bytes

        byte[] dst = new byte[50];
        int totalWritten = packet.writeWireFormat(dst, 0);

        assertEquals(14, totalWritten); // 4 header + 10 trailer
        assertEquals((byte) SessionServicePacket.SESSION_MESSAGE, dst[0]);
    }

    @Test
    @DisplayName("writeWireFormat should handle large lengths correctly")
    void testWriteWireFormatLargeLength() {
        packet.type = SessionServicePacket.SESSION_MESSAGE;
        packet.trailerLength = 0x10000; // Length requiring extended bit

        byte[] dst = new byte[100];
        packet.writeWireFormat(dst, 0);

        assertEquals((byte) 0x01, dst[1]); // Extended length bit should be set
    }

    @Test
    @DisplayName("readWireFormat should read header and trailer")
    void testReadWireFormat() throws IOException {
        byte[] data = new byte[50];
        data[0] = (byte) 0x85; // SESSION_KEEP_ALIVE
        data[1] = 0x00;
        data[2] = 0x00;
        data[3] = 0x0A; // Length = 10

        ByteArrayInputStream bais = new ByteArrayInputStream(data);

        int totalRead = packet.readWireFormat(bais, data, 0);

        assertEquals(14, totalRead); // 4 header + 10 trailer
        assertEquals(0x85, packet.type);
        assertEquals(10, packet.length);
    }

    @Test
    @DisplayName("writeHeaderWireFormat should write correct header")
    void testWriteHeaderWireFormat() {
        packet.type = SessionServicePacket.SESSION_REQUEST;
        packet.length = 0x1234;

        byte[] dst = new byte[10];
        int written = packet.writeHeaderWireFormat(dst, 0);

        assertEquals(4, written);
        assertEquals((byte) SessionServicePacket.SESSION_REQUEST, dst[0]);
        assertEquals((byte) 0x00, dst[1]); // No extended bit
        assertEquals((byte) 0x12, dst[2]);
        assertEquals((byte) 0x34, dst[3]);
    }

    @Test
    @DisplayName("writeHeaderWireFormat should set extended bit for large length")
    void testWriteHeaderWireFormatExtendedLength() {
        packet.type = SessionServicePacket.SESSION_MESSAGE;
        packet.length = 0x10000;

        byte[] dst = new byte[10];
        packet.writeHeaderWireFormat(dst, 0);

        assertEquals((byte) 0x01, dst[1]); // Extended bit set
    }

    @Test
    @DisplayName("readHeaderWireFormat should parse header correctly")
    void testReadHeaderWireFormat() {
        byte[] buffer = { (byte) 0x82, (byte) 0x00, (byte) 0x00, (byte) 0x20 };
        ByteArrayInputStream bais = new ByteArrayInputStream(buffer);

        int read = packet.readHeaderWireFormat(bais, buffer, 0);

        assertEquals(4, read);
        assertEquals(0x82, packet.type);
        assertEquals(0x20, packet.length);
    }

    @Test
    @DisplayName("readHeaderWireFormat should handle extended length")
    void testReadHeaderWireFormatExtendedLength() {
        byte[] buffer = { (byte) 0x00, (byte) 0x01, (byte) 0xFF, (byte) 0xFF };
        ByteArrayInputStream bais = new ByteArrayInputStream(buffer);

        packet.readHeaderWireFormat(bais, buffer, 0);

        assertEquals(0x1FFFF, packet.length);
    }

    // Test for constants
    @Test
    @DisplayName("Constants should have expected values")
    void testConstants() {
        assertEquals(0x00, SessionServicePacket.SESSION_MESSAGE);
        assertEquals(0x81, SessionServicePacket.SESSION_REQUEST);
        assertEquals(0x82, SessionServicePacket.POSITIVE_SESSION_RESPONSE);
        assertEquals(0x83, SessionServicePacket.NEGATIVE_SESSION_RESPONSE);
        assertEquals(0x84, SessionServicePacket.SESSION_RETARGET_RESPONSE);
        assertEquals(0x85, SessionServicePacket.SESSION_KEEP_ALIVE);
        assertEquals(0x0001FFFF, SessionServicePacket.MAX_MESSAGE_SIZE);
        assertEquals(4, SessionServicePacket.HEADER_LENGTH);
    }

    @ParameterizedTest
    @MethodSource("provideRoundTripTestData")
    @DisplayName("Write and read operations should be symmetric")
    void testWriteReadSymmetry(int value, boolean isInt2) {
        byte[] buffer = new byte[10];

        if (isInt2) {
            SessionServicePacket.writeInt2(value, buffer, 0);
            int result = SessionServicePacket.readInt2(buffer, 0);
            assertEquals(value & 0xFFFF, result);
        } else {
            SessionServicePacket.writeInt4(value, buffer, 0);
            int result = SessionServicePacket.readInt4(buffer, 0);
            assertEquals(value, result);
        }
    }

    private static Stream<Arguments> provideRoundTripTestData() {
        return Stream.of(Arguments.of(0, true), Arguments.of(0xFFFF, true), Arguments.of(0x8000, true), Arguments.of(0, false),
                Arguments.of(0xFFFFFFFF, false), Arguments.of(0x80000000, false), Arguments.of(Integer.MAX_VALUE, false),
                Arguments.of(Integer.MIN_VALUE, false));
    }

    // Concrete implementation for testing abstract class
    private static class TestSessionServicePacket extends SessionServicePacket {
        int trailerLength = 10; // Default trailer length for testing
        int trailerBytesRead = 0;

        @Override
        int writeTrailerWireFormat(byte[] dst, int dstIndex) {
            // Simple mock implementation
            for (int i = 0; i < trailerLength && dstIndex + i < dst.length; i++) {
                dst[dstIndex + i] = (byte) i;
            }
            return trailerLength;
        }

        @Override
        int readTrailerWireFormat(InputStream in, byte[] buffer, int bufferIndex) throws IOException {
            // Simple mock implementation
            byte[] temp = new byte[length];
            int read = in.read(temp, 0, length);
            if (read < length) {
                throw new IOException("Incomplete trailer data");
            }
            trailerBytesRead = read;
            return read;
        }
    }
}