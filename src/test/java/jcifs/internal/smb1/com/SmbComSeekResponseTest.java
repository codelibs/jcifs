package jcifs.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;

/**
 * Unit tests for {@link SmbComSeekResponse}.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SmbComSeekResponse tests")
class SmbComSeekResponseTest {

    @Mock
    private Configuration mockConfig;

    private SmbComSeekResponse response;

    @BeforeEach
    void setUp() {
        // Setup mock configuration to avoid NPE
        when(mockConfig.getPid()).thenReturn(12345);
        response = new SmbComSeekResponse(mockConfig);
    }

    /* ------------------------------------------------------------------ */
    /* 1. Construction and basic getters                                    */
    /* ------------------------------------------------------------------ */

    @Test
    @DisplayName("Construct with a valid configuration - should not throw")
    void testConstructionWithValidConfiguration() {
        assertDoesNotThrow(() -> new SmbComSeekResponse(mockConfig));
    }

    @Test
    @DisplayName("getOffset before any read - should return zero")
    void testOffsetInitiallyZero() {
        assertEquals(0L, response.getOffset(), "Offset should be initialized to 0");
    }

    /* ------------------------------------------------------------------ */
    /* 2. Parameter word reading - happy path & edge cases                */
    /* ------------------------------------------------------------------ */

    /**
     * Provides test cases for {@link SmbComSeekResponse#readParameterWordsWireFormat(byte[], int)}.
     * @return a stream of {@link Arguments} objects containing an integer
     *         value and the corresponding little-endian byte array.
     */
    static java.util.stream.Stream<Arguments> int32Provider() {
        return java.util.stream.Stream.of(Arguments.of(0x00000000, new byte[] { 0x00, 0x00, 0x00, 0x00 }),
                Arguments.of(0x12345678, new byte[] { 0x78, 0x56, 0x34, 0x12 }),
                Arguments.of(0xFFFFFFFF, new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF }),
                Arguments.of(0x7FFFFFFF, new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x7F }));
    }

    @ParameterizedTest
    @MethodSource("int32Provider")
    @DisplayName("readParameterWordsWireFormat correctly decodes 32-bit offset")
    void testReadParameterWords(int expectedInt, byte[] bytes) {
        // The implementation reads via SMBUtil.readInt4 which returns an int
        // When assigned to a long field, it gets sign-extended
        int readLen = response.readParameterWordsWireFormat(bytes, 0);
        long expectedOffset = expectedInt; // Sign extension happens here for negative values
        assertEquals(expectedOffset, response.getOffset(), "Offset should match decoded value");
        assertEquals(4, readLen, "Byte count returned should be 4");
    }

    @Test
    @DisplayName("readParameterWordsWireFormat with a too-short buffer - throws exception")
    void testReadParameterWordsWithShortBuffer() {
        byte[] buffer = new byte[] { 0x00, 0x01, 0x02 }; // only three bytes
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> response.readParameterWordsWireFormat(buffer, 0));
    }

    @Test
    @DisplayName("readParameterWordsWireFormat with null buffer - throws NullPointerException")
    void testReadParameterWordsWithNullBuffer() {
        assertThrows(NullPointerException.class, () -> response.readParameterWordsWireFormat(null, 0));
    }

    @Test
    @DisplayName("readParameterWordsWireFormat with offset beyond buffer - throws exception")
    void testReadParameterWordsWithOffsetBeyondBuffer() {
        byte[] buffer = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> response.readParameterWordsWireFormat(buffer, 2) // Only 3 bytes available from offset 2
        );
    }

    @Test
    @DisplayName("readParameterWordsWireFormat with valid offset - correctly reads data")
    void testReadParameterWordsWithValidOffset() {
        byte[] buffer = new byte[] { 0x00, 0x00, // padding
                0x78, 0x56, 0x34, 0x12, // little-endian 0x12345678
                0x00, 0x00 // padding
        };
        int readLen = response.readParameterWordsWireFormat(buffer, 2);
        assertEquals(0x12345678L, response.getOffset(), "Offset should match decoded value");
        assertEquals(4, readLen, "Byte count returned should be 4");
    }

    /* ------------------------------------------------------------------ */
    /* 3. Writing methods - trivial behaviour                           */
    /* ------------------------------------------------------------------ */

    @Test
    @DisplayName("writeParameterWordsWireFormat returns zero bytes written")
    void testWriteParameterWordsWireFormat() {
        byte[] buf = new byte[10];
        assertEquals(0, response.writeParameterWordsWireFormat(buf, 0), "Should write 0 bytes");
    }

    @Test
    @DisplayName("writeParameterWordsWireFormat with null buffer - returns zero")
    void testWriteParameterWordsWireFormatNullBuffer() {
        assertEquals(0, response.writeParameterWordsWireFormat(null, 0), "Should write 0 bytes");
    }

    @Test
    @DisplayName("writeBytesWireFormat returns zero bytes written")
    void testWriteBytesWireFormat() {
        byte[] buf = new byte[10];
        assertEquals(0, response.writeBytesWireFormat(buf, 0), "Should write 0 bytes");
    }

    @Test
    @DisplayName("writeBytesWireFormat with null buffer - returns zero")
    void testWriteBytesWireFormatNullBuffer() {
        assertEquals(0, response.writeBytesWireFormat(null, 0), "Should write 0 bytes");
    }

    @Test
    @DisplayName("readBytesWireFormat returns zero bytes read")
    void testReadBytesWireFormat() throws SMBProtocolDecodingException {
        byte[] buffer = new byte[10];
        assertEquals(0, response.readBytesWireFormat(buffer, 0), "Should read 0 bytes");
    }

    @Test
    @DisplayName("readBytesWireFormat with null buffer - returns zero")
    void testReadBytesWireFormatNullBuffer() throws SMBProtocolDecodingException {
        assertEquals(0, response.readBytesWireFormat(null, 0), "Should read 0 bytes");
    }

    /* ------------------------------------------------------------------ */
    /* 4. State verification after operations                             */
    /* ------------------------------------------------------------------ */

    @Test
    @DisplayName("Multiple reads update offset correctly")
    void testMultipleReadsUpdateOffset() {
        byte[] buffer1 = new byte[] { 0x10, 0x00, 0x00, 0x00 }; // 16
        byte[] buffer2 = new byte[] { 0x20, 0x00, 0x00, 0x00 }; // 32

        response.readParameterWordsWireFormat(buffer1, 0);
        assertEquals(16L, response.getOffset(), "First read should set offset to 16");

        response.readParameterWordsWireFormat(buffer2, 0);
        assertEquals(32L, response.getOffset(), "Second read should update offset to 32");
    }

    @Test
    @DisplayName("getOffset returns same value on multiple calls")
    void testGetOffsetConsistency() {
        byte[] buffer = new byte[] { 0x42, 0x00, 0x00, 0x00 }; // 66
        response.readParameterWordsWireFormat(buffer, 0);

        long firstCall = response.getOffset();
        long secondCall = response.getOffset();
        long thirdCall = response.getOffset();

        assertEquals(66L, firstCall, "First call should return 66");
        assertEquals(66L, secondCall, "Second call should return 66");
        assertEquals(66L, thirdCall, "Third call should return 66");
    }
}