package org.codelibs.jcifs.smb.dcerpc.ndr;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class NdrSmallTest {

    @Mock
    private NdrBuffer mockNdrBuffer;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testConstructor_validValue() {
        // Test with a value within the byte range
        NdrSmall ndrSmall = new NdrSmall(123);
        assertEquals(123, ndrSmall.value, "Value should be initialized correctly for valid input.");
    }

    @Test
    void testConstructor_maxValue() {
        // Test with the maximum byte value
        NdrSmall ndrSmall = new NdrSmall(255);
        assertEquals(255, ndrSmall.value, "Value should be initialized correctly for max byte value.");
    }

    @Test
    void testConstructor_zeroValue() {
        // Test with zero value
        NdrSmall ndrSmall = new NdrSmall(0);
        assertEquals(0, ndrSmall.value, "Value should be initialized correctly for zero.");
    }

    @Test
    void testConstructor_negativeValue() {
        // Test with a negative value, expecting it to be masked to a positive byte
        NdrSmall ndrSmall = new NdrSmall(-1); // -1 & 0xFF = 255
        assertEquals(255, ndrSmall.value, "Negative value should be masked to its unsigned byte equivalent.");
    }

    @Test
    void testConstructor_overflowValue() {
        // Test with a value exceeding byte range, expecting it to be masked
        NdrSmall ndrSmall = new NdrSmall(256); // 256 & 0xFF = 0
        assertEquals(0, ndrSmall.value, "Value exceeding byte range should be masked.");

        ndrSmall = new NdrSmall(511); // 511 & 0xFF = 255
        assertEquals(255, ndrSmall.value, "Value exceeding byte range should be masked correctly.");
    }

    @Test
    void testEncode() throws NdrException {
        // Create an NdrSmall object with a specific value
        NdrSmall ndrSmall = new NdrSmall(100);

        // Call the encode method
        ndrSmall.encode(mockNdrBuffer);

        // Verify that enc_ndr_small was called with the correct value
        verify(mockNdrBuffer, times(1)).enc_ndr_small(100);
        verifyNoMoreInteractions(mockNdrBuffer);
    }

    @Test
    void testDecode() throws NdrException {
        // Define the value that dec_ndr_small should return
        int decodedValue = 200;
        when(mockNdrBuffer.dec_ndr_small()).thenReturn(decodedValue);

        // Create an NdrSmall object (initial value doesn't matter for decode)
        NdrSmall ndrSmall = new NdrSmall(0);

        // Call the decode method
        ndrSmall.decode(mockNdrBuffer);

        // Verify that dec_ndr_small was called
        verify(mockNdrBuffer, times(1)).dec_ndr_small();
        // Verify that the value field was updated correctly
        assertEquals(decodedValue, ndrSmall.value, "Value should be updated after decoding.");
        verifyNoMoreInteractions(mockNdrBuffer);
    }
}
