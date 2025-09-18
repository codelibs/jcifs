package org.codelibs.jcifs.smb1.dcerpc.ndr;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link NdrHyper}.
 * <p>
 * The class only contains an encode/decode pair that delegates to
 * {@link NdrBuffer#enc_ndr_hyper(long)} and {@link NdrBuffer#dec_ndr_hyper()}.
 * The tests verify that:
 * <ul>
 *   <li>encoding and decoding round‑trip correctly handle typical, zero,
 *       and extreme {@code long} values.</li>
 *   <li>encode/decode methods interact correctly with a mocked
 *       {@link NdrBuffer} so that the correct method is called with
 *       the correct argument.</li>
 *   <li>passing {@code null} throws {@link NullPointerException}.
 * </ul>
 *
 * The buffer is created with enough capacity for a 64‑bit value.
 */
@ExtendWith(MockitoExtension.class)
public class NdrHyperTest {

    /**
     * Tests a simple round‑trip encode → decode retains the original value.
     */
    @Test
    @DisplayName("Basic round‑trip for a fixed value")
    public void shouldEncodeAndDecodeRoundTrip() throws NdrException {
        final long original = 0x1122334455667788L;
        NdrHyper hyper = new NdrHyper(original);
        // Create buffer with extra space for alignment
        NdrBuffer buf = new NdrBuffer(new byte[16], 0);
        hyper.encode(buf);
        // Reset buffer position for decoding
        buf.reset();
        NdrHyper decoded = new NdrHyper(0);
        decoded.decode(buf);
        assertEquals(original, decoded.value, "Decoded value should match encoded value");
    }

    /**
     * Parameterised test for a selection of edge and typical values.
     */
    @ParameterizedTest(name = "Encode and decode {0}")
    @ValueSource(longs = { 0L, 1L, -1L, Long.MAX_VALUE, Long.MIN_VALUE })
    public void shouldEncodeAndDecodeVariousValues(long val) throws NdrException {
        NdrHyper hyper = new NdrHyper(val);
        // Create buffer with extra space for alignment
        NdrBuffer buf = new NdrBuffer(new byte[16], 0);
        hyper.encode(buf);
        // Reset buffer position for decoding
        buf.reset();
        NdrHyper decoded = new NdrHyper(0);
        decoded.decode(buf);
        assertEquals(val, decoded.value, "Decoded value should match encoded value for " + Long.toHexString(val));
    }

    /**
     * Ensure encode throws NPE when passed a null buffer.
     */
    @Test
    @DisplayName("Encode with null buffer throws NullPointerException")
    public void shouldThrowNullPointerExceptionForEncodeWithNullBuffer() throws NdrException {
        NdrHyper hyper = new NdrHyper(5L);
        assertThrows(NullPointerException.class, () -> hyper.encode(null));
    }

    /**
     * Ensure decode throws NPE when passed a null buffer.
     */
    @Test
    @DisplayName("Decode with null buffer throws NullPointerException")
    public void shouldThrowNullPointerExceptionForDecodeWithNullBuffer() throws NdrException {
        NdrHyper hyper = new NdrHyper(0L);
        assertThrows(NullPointerException.class, () -> hyper.decode(null));
    }

    /**
     * Verify that the encode method forwards the value to NdrBuffer.
     */
    @Test
    @DisplayName("Encode should call NdrBuffer.enc_ndr_hyper with correct value")
    public void shouldCallEncodeHyperWithCorrectValue() throws NdrException {
        NdrBuffer buf = mock(NdrBuffer.class);
        NdrHyper hyper = new NdrHyper(12345L);
        hyper.encode(buf);
        verify(buf, times(1)).enc_ndr_hyper(12345L);
    }

    /**
     * Verify that the decode method updates the value field from NdrBuffer.
     */
    @Test
    @DisplayName("Decode should set value from NdrBuffer.dec_ndr_hyper")
    public void shouldSetValueFromDecodeHyper() throws NdrException {
        NdrBuffer buf = mock(NdrBuffer.class);
        when(buf.dec_ndr_hyper()).thenReturn(0xdeadbeefcafebabeL);
        NdrHyper hyper = new NdrHyper(0L);
        hyper.decode(buf);
        assertEquals(0xdeadbeefcafebabeL, hyper.value);
    }
}
