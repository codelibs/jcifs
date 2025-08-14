package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import jcifs.DfsReferralData;

/**
 * Tests for the DfsReferral class.
 */
class DfsReferralTest {

    /**
     * Test the constructor and the getData method.
     */
    @Test
    void testConstructorAndGetData() {
        // Create a mock DfsReferralData object
        DfsReferralData mockData = mock(DfsReferralData.class);

        // Create a DfsReferral instance with the mock data
        DfsReferral dfsReferral = new DfsReferral(mockData);

        // Verify that getData() returns the same mock data object
        assertEquals(mockData, dfsReferral.getData(), "getData() should return the DfsReferralData object passed to the constructor.");
    }

    /**
     * Test the toString method.
     */
    @Test
    void testToString() {
        // Create a mock DfsReferralData object
        DfsReferralData mockData = mock(DfsReferralData.class);
        String expectedToString = "Mock DfsReferralData";

        // Define the behavior of the mock's toString() method
        when(mockData.toString()).thenReturn(expectedToString);

        // Create a DfsReferral instance with the mock data
        DfsReferral dfsReferral = new DfsReferral(mockData);

        // Verify that toString() returns the expected string from the mock data object
        assertEquals(expectedToString, dfsReferral.toString(),
                "toString() should return the result of the wrapped DfsReferralData's toString() method.");
    }
}
