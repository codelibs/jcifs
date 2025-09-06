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

class NdrHyperTest {

    @Mock
    private NdrBuffer mockNdrBuffer;

    @BeforeEach
    void setUp() {
        // Initialize mocks before each test
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testConstructorAndGetValue() {
        // Test that the constructor correctly initializes the value
        long expectedValue = 123456789012345L;
        NdrHyper ndrHyper = new NdrHyper(expectedValue);
        assertEquals(expectedValue, ndrHyper.value, "Constructor should set the correct value.");
    }

    @Test
    void testEncode() throws NdrException {
        // Test the encode method
        long testValue = 987654321098765L;
        NdrHyper ndrHyper = new NdrHyper(testValue);

        // Call the encode method with the mocked NdrBuffer
        ndrHyper.encode(mockNdrBuffer);

        // Verify that enc_ndr_hyper was called exactly once with the correct value
        verify(mockNdrBuffer, times(1)).enc_ndr_hyper(testValue);
        verifyNoMoreInteractions(mockNdrBuffer);
    }

    @Test
    void testDecode() throws NdrException {
        // Test the decode method
        long decodedValue = 112233445566778L;
        NdrHyper ndrHyper = new NdrHyper(0); // Initialize with a dummy value

        // Configure the mock NdrBuffer to return a specific value when dec_ndr_hyper is called
        when(mockNdrBuffer.dec_ndr_hyper()).thenReturn(decodedValue);

        // Call the decode method with the mocked NdrBuffer
        ndrHyper.decode(mockNdrBuffer);

        // Verify that dec_ndr_hyper was called exactly once
        verify(mockNdrBuffer, times(1)).dec_ndr_hyper();
        verifyNoMoreInteractions(mockNdrBuffer);

        // Verify that the NdrHyper object's value was updated correctly
        assertEquals(decodedValue, ndrHyper.value, "Decode should update the value correctly.");
    }
}
