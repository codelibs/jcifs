package jcifs.dcerpc.ndr;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class NdrLongTest {

    @Mock
    private NdrBuffer mockNdrBuffer;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void constructor_shouldInitializeValueCorrectly() {
        // Test case 1: Positive value
        int positiveValue = 12345;
        NdrLong ndrLongPositive = new NdrLong(positiveValue);
        assertEquals(positiveValue, ndrLongPositive.value, "Constructor should correctly initialize with a positive value.");

        // Test case 2: Negative value
        int negativeValue = -54321;
        NdrLong ndrLongNegative = new NdrLong(negativeValue);
        assertEquals(negativeValue, ndrLongNegative.value, "Constructor should correctly initialize with a negative value.");

        // Test case 3: Zero value
        int zeroValue = 0;
        NdrLong ndrLongZero = new NdrLong(zeroValue);
        assertEquals(zeroValue, ndrLongZero.value, "Constructor should correctly initialize with zero.");

        // Test case 4: Max int value
        int maxIntValue = Integer.MAX_VALUE;
        NdrLong ndrLongMax = new NdrLong(maxIntValue);
        assertEquals(maxIntValue, ndrLongMax.value, "Constructor should correctly initialize with Integer.MAX_VALUE.");

        // Test case 5: Min int value
        int minIntValue = Integer.MIN_VALUE;
        NdrLong ndrLongMin = new NdrLong(minIntValue);
        assertEquals(minIntValue, ndrLongMin.value, "Constructor should correctly initialize with Integer.MIN_VALUE.");
    }

    @Test
    void encode_shouldCallEncNdrLongWithCorrectValue() throws NdrException {
        int testValue = 98765;
        NdrLong ndrLong = new NdrLong(testValue);

        // Call the encode method
        ndrLong.encode(mockNdrBuffer);

        // Verify that enc_ndr_long was called exactly once with the correct value
        verify(mockNdrBuffer, times(1)).enc_ndr_long(testValue);
        // Verify that no other interactions occurred with the mock buffer
        verifyNoMoreInteractions(mockNdrBuffer);
    }

    @Test
    void decode_shouldCallDecNdrLongAndAssignValue() throws NdrException {
        int decodedValue = 54321;
        // Configure the mock to return a specific value when dec_ndr_long is called
        when(mockNdrBuffer.dec_ndr_long()).thenReturn(decodedValue);

        NdrLong ndrLong = new NdrLong(0); // Initialize with a dummy value

        // Call the decode method
        ndrLong.decode(mockNdrBuffer);

        // Verify that dec_ndr_long was called exactly once
        verify(mockNdrBuffer, times(1)).dec_ndr_long();
        // Verify that the value field was updated correctly
        assertEquals(decodedValue, ndrLong.value, "Decode should correctly assign the value returned by dec_ndr_long.");
        // Verify that no other interactions occurred with the mock buffer
        verifyNoMoreInteractions(mockNdrBuffer);
    }
}
