/* Test class for jcifs.smb1.dcerpc.ndr.NdrShort */
package jcifs.smb1.dcerpc.ndr;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import jcifs.smb1.util.Encdec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link NdrShort}.  The tests cover construction,
 * encoding and decoding logic, masking behaviour, alignment handling and
 * interaction with {@link NdrBuffer}.  All public behaviour is exercised.
 */
@ExtendWith(MockitoExtension.class)
class NdrShortTest {

    /**
     * A small reusable buffer for encode/decode tests.
     */
    private byte[] raw;
    private NdrBuffer buf;

    @BeforeEach
    void setUp() {
        // 10 bytes is more than enough for the 2-byte short
        raw = new byte[10];
        buf = new NdrBuffer(raw, 0);
    }

    /**
     * Validate that the constructor masks the supplied value to its
     * lowest 8 bits (NdrShort incorrectly masks to 8 bits even though it's a short).
     */
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 255, -1, 256, 65535})
    void constructorMasksValue(int input) {
        NdrShort ns = new NdrShort(input);
        // NdrShort masks to 0xFF (8 bits) in its constructor
        int expected = input & 0xFF;
        assertEquals(expected, ns.value,
                     "value should be masked to 0xFF before storing");
    }

    /**
     * Round-trip encode/decode for a selection of representative values.
     */
    @ParameterizedTest
    @ValueSource(ints = {0, 42, 255, -1, 128})
    void encodeDecodeRoundTrip(int original) throws Exception {
        // The constructor masks to 0xFF (8 bits)
        int expected = original & 0xFF;
        NdrShort ns = new NdrShort(original);
        buf.reset();
        ns.encode(buf); // should not throw
        
        // After encoding, check how many bytes were used
        int bytesUsed = buf.getIndex();
        // Should be 2 bytes for the short value (alignment may add padding)
        assertTrue(bytesUsed >= 2, "Should use at least 2 bytes for short");
        
        // Reset index to read back
        buf.reset();
        NdrShort decoded = new NdrShort(0); // placeholder value
        decoded.decode(buf);
        assertEquals(expected, decoded.value,
                     "decoded value should match original after masking");
    }

    /**
     * Verify that encode writes the correct little-endian sequence
     * to the buffer and that alignment is respected.
     */
    @Test
    void encodeWritesCorrectBytesAndAlignment() throws NdrException {
        NdrShort ns = new NdrShort(0xABCD); // value & 0xFF => 0xCD
        buf.reset();
        int startIndex = buf.getIndex();
        ns.encode(buf);
        
        // Find where the actual data starts (after alignment)
        int alignmentBytes = 0;
        if (startIndex % 2 != 0) {
            alignmentBytes = 1; // Need 1 byte of padding for 2-byte alignment
        }
        
        // The value 0xCD should be encoded as a 16-bit value (0x00CD) in little-endian
        byte[] bufferData = buf.getBuffer();
        assertEquals((byte) 0xCD, bufferData[startIndex + alignmentBytes],
                     "Least significant byte should be first");
        assertEquals((byte) 0x00, bufferData[startIndex + alignmentBytes + 1],
                     "Most significant byte should be second");
    }

    /**
     * When given a buffer with sufficient length, decode performs
     * the inverse of encode.
     */
    @Test
    void decodeFromEncodedBuffer() throws NdrException {
        NdrShort ns = new NdrShort(123); // masked value 123 (already fits in 8 bits)
        buf.reset();
        ns.encode(buf);
        
        // Reset buffer to start for decoding
        buf.reset();
        
        // Prepare a new object to decode into
        NdrShort decoded = new NdrShort(0);
        decoded.decode(buf);
        assertEquals(123, decoded.value, "decoded value should equal original");
    }

    /**
     * Verify that encode invokes NdrBuffer.enc_ndr_short via a mocked
     * (spied) buffer.
     */
    @Test
    void encodeWithSpiedBufferCallsEncMethod() throws NdrException {
        NdrShort ns = new NdrShort(42);
        NdrBuffer spy = spy(new NdrBuffer(new byte[10], 0));
        ns.encode(spy);
        // NdrShort passes its value (already masked to 0xFF) to enc_ndr_short
        verify(spy).enc_ndr_short(42);
    }

    /**
     * Verify that decode invokes NdrBuffer.dec_ndr_short.
     */
    @Test
    void decodeWithSpiedBufferCallsDecMethod() throws NdrException {
        NdrShort ns = new NdrShort(0); // value will be overwritten
        // Pre-populate buffer with the encoding of a short value
        NdrBuffer prepare = new NdrBuffer(new byte[10], 0);
        prepare.enc_ndr_short(0x34); // Encode value 0x34
        prepare.reset(); // Reset to beginning for decoding
        
        NdrBuffer spy = spy(prepare);
        ns.decode(spy);
        verify(spy).dec_ndr_short();
    }
}

