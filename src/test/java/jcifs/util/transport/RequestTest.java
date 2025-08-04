package jcifs.util.transport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class RequestTest {

    @Mock
    private Request mockRequest;

    @BeforeEach
    void setUp() {
        // Initialize mocks before each test
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testGetCreditCost() {
        // Test case for getCreditCost method
        int expectedCreditCost = 10;
        when(mockRequest.getCreditCost()).thenReturn(expectedCreditCost);

        int actualCreditCost = mockRequest.getCreditCost();

        assertEquals(expectedCreditCost, actualCreditCost, "Credit cost should match the mocked value.");
        verify(mockRequest, times(1)).getCreditCost(); // Verify method was called once
    }

    @Test
    void testSetRequestCredits() {
        // Test case for setRequestCredits method
        int credits = 5;
        mockRequest.setRequestCredits(credits);

        // Verify that setRequestCredits was called with the correct argument
        verify(mockRequest, times(1)).setRequestCredits(credits);
    }

    @Test
    void testIsCancelTrue() {
        // Test case for isCancel method when it returns true
        when(mockRequest.isCancel()).thenReturn(true);

        assertTrue(mockRequest.isCancel(), "isCancel should return true when mocked to do so.");
        verify(mockRequest, times(1)).isCancel();
    }

    @Test
    void testIsCancelFalse() {
        // Test case for isCancel method when it returns false
        when(mockRequest.isCancel()).thenReturn(false);

        assertFalse(mockRequest.isCancel(), "isCancel should return false when mocked to do so.");
        verify(mockRequest, times(1)).isCancel();
    }

    @Test
    void testGetNext() {
        // Test case for getNext method
        Request nextRequest = mock(Request.class); // Mock a chained request
        when(mockRequest.getNext()).thenReturn(nextRequest);

        Request actualNextRequest = mockRequest.getNext();

        assertEquals(nextRequest, actualNextRequest, "Next request should match the mocked object.");
        verify(mockRequest, times(1)).getNext();
    }

    @Test
    void testGetNextNull() {
        // Test case for getNext method when it returns null (no chained request)
        when(mockRequest.getNext()).thenReturn(null);

        assertNull(mockRequest.getNext(), "Next request should be null when mocked to do so.");
        verify(mockRequest, times(1)).getNext();
    }

    @Test
    void testGetResponse() {
        // Test case for getResponse method
        Response mockResponse = mock(Response.class); // Mock a response object
        when(mockRequest.getResponse()).thenReturn(mockResponse);

        Response actualResponse = mockRequest.getResponse();

        assertEquals(mockResponse, actualResponse, "Response should match the mocked object.");
        verify(mockRequest, times(1)).getResponse();
    }

    @Test
    void testGetResponseNull() {
        // Test case for getResponse method when it returns null (no response yet)
        when(mockRequest.getResponse()).thenReturn(null);

        assertNull(mockRequest.getResponse(), "Response should be null when mocked to do so.");
        verify(mockRequest, times(1)).getResponse();
    }
}
