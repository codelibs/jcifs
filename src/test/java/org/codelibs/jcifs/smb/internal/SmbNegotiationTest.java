package org.codelibs.jcifs.smb.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Test class for SmbNegotiation
 */
class SmbNegotiationTest {

    @Mock
    private SmbNegotiationRequest mockRequest;

    @Mock
    private SmbNegotiationResponse mockResponse;

    private byte[] testRequestBuffer;
    private byte[] testResponseBuffer;
    private SmbNegotiation negotiation;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testRequestBuffer = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        testResponseBuffer = new byte[] { 0x05, 0x06, 0x07, 0x08 };
        negotiation = new SmbNegotiation(mockRequest, mockResponse, testRequestBuffer, testResponseBuffer);
    }

    @Test
    @DisplayName("Constructor should properly initialize all fields")
    void testConstructor() {
        // Verify all fields are properly initialized
        assertNotNull(negotiation);
        assertSame(mockRequest, negotiation.getRequest());
        assertSame(mockResponse, negotiation.getResponse());
        assertSame(testRequestBuffer, negotiation.getRequestRaw());
        assertSame(testResponseBuffer, negotiation.getResponseRaw());
    }

    @Test
    @DisplayName("Constructor with null request should work")
    void testConstructorWithNullRequest() {
        // Test that null request is handled properly
        SmbNegotiation negotiationWithNullRequest = new SmbNegotiation(null, mockResponse, testRequestBuffer, testResponseBuffer);

        assertNull(negotiationWithNullRequest.getRequest());
        assertSame(mockResponse, negotiationWithNullRequest.getResponse());
        assertSame(testRequestBuffer, negotiationWithNullRequest.getRequestRaw());
        assertSame(testResponseBuffer, negotiationWithNullRequest.getResponseRaw());
    }

    @Test
    @DisplayName("Constructor with null response should work")
    void testConstructorWithNullResponse() {
        // Test that null response is handled properly
        SmbNegotiation negotiationWithNullResponse = new SmbNegotiation(mockRequest, null, testRequestBuffer, testResponseBuffer);

        assertSame(mockRequest, negotiationWithNullResponse.getRequest());
        assertNull(negotiationWithNullResponse.getResponse());
        assertSame(testRequestBuffer, negotiationWithNullResponse.getRequestRaw());
        assertSame(testResponseBuffer, negotiationWithNullResponse.getResponseRaw());
    }

    @Test
    @DisplayName("Constructor with null buffers should work")
    void testConstructorWithNullBuffers() {
        // Test that null buffers are handled properly
        SmbNegotiation negotiationWithNullBuffers = new SmbNegotiation(mockRequest, mockResponse, null, null);

        assertSame(mockRequest, negotiationWithNullBuffers.getRequest());
        assertSame(mockResponse, negotiationWithNullBuffers.getResponse());
        assertNull(negotiationWithNullBuffers.getRequestRaw());
        assertNull(negotiationWithNullBuffers.getResponseRaw());
    }

    @Test
    @DisplayName("Constructor with all null parameters should work")
    void testConstructorWithAllNullParameters() {
        // Test that all null parameters are handled properly
        SmbNegotiation negotiationAllNull = new SmbNegotiation(null, null, null, null);

        assertNull(negotiationAllNull.getRequest());
        assertNull(negotiationAllNull.getResponse());
        assertNull(negotiationAllNull.getRequestRaw());
        assertNull(negotiationAllNull.getResponseRaw());
    }

    @Test
    @DisplayName("getRequest should return the same request instance")
    void testGetRequest() {
        // Verify getRequest returns the exact same instance
        SmbNegotiationRequest request = negotiation.getRequest();
        assertSame(mockRequest, request);

        // Verify multiple calls return the same instance
        assertSame(request, negotiation.getRequest());
    }

    @Test
    @DisplayName("getResponse should return the same response instance")
    void testGetResponse() {
        // Verify getResponse returns the exact same instance
        SmbNegotiationResponse response = negotiation.getResponse();
        assertSame(mockResponse, response);

        // Verify multiple calls return the same instance
        assertSame(response, negotiation.getResponse());
    }

    @Test
    @DisplayName("getRequestRaw should return the same request buffer")
    void testGetRequestRaw() {
        // Verify getRequestRaw returns the exact same array instance
        byte[] requestBuffer = negotiation.getRequestRaw();
        assertSame(testRequestBuffer, requestBuffer);

        // Verify multiple calls return the same instance
        assertSame(requestBuffer, negotiation.getRequestRaw());

        // Verify content is correct
        assertArrayEquals(new byte[] { 0x01, 0x02, 0x03, 0x04 }, requestBuffer);
    }

    @Test
    @DisplayName("getResponseRaw should return the same response buffer")
    void testGetResponseRaw() {
        // Verify getResponseRaw returns the exact same array instance
        byte[] responseBuffer = negotiation.getResponseRaw();
        assertSame(testResponseBuffer, responseBuffer);

        // Verify multiple calls return the same instance
        assertSame(responseBuffer, negotiation.getResponseRaw());

        // Verify content is correct
        assertArrayEquals(new byte[] { 0x05, 0x06, 0x07, 0x08 }, responseBuffer);
    }

    @Test
    @DisplayName("Test with empty buffers")
    void testWithEmptyBuffers() {
        // Test with empty byte arrays
        byte[] emptyRequestBuffer = new byte[0];
        byte[] emptyResponseBuffer = new byte[0];

        SmbNegotiation negotiationWithEmptyBuffers = new SmbNegotiation(mockRequest, mockResponse, emptyRequestBuffer, emptyResponseBuffer);

        assertSame(mockRequest, negotiationWithEmptyBuffers.getRequest());
        assertSame(mockResponse, negotiationWithEmptyBuffers.getResponse());
        assertSame(emptyRequestBuffer, negotiationWithEmptyBuffers.getRequestRaw());
        assertSame(emptyResponseBuffer, negotiationWithEmptyBuffers.getResponseRaw());
        assertEquals(0, negotiationWithEmptyBuffers.getRequestRaw().length);
        assertEquals(0, negotiationWithEmptyBuffers.getResponseRaw().length);
    }

    @Test
    @DisplayName("Test with large buffers")
    void testWithLargeBuffers() {
        // Test with large byte arrays
        byte[] largeRequestBuffer = new byte[1024];
        byte[] largeResponseBuffer = new byte[2048];

        // Fill with some test data
        for (int i = 0; i < largeRequestBuffer.length; i++) {
            largeRequestBuffer[i] = (byte) (i % 256);
        }
        for (int i = 0; i < largeResponseBuffer.length; i++) {
            largeResponseBuffer[i] = (byte) ((i * 2) % 256);
        }

        SmbNegotiation negotiationWithLargeBuffers = new SmbNegotiation(mockRequest, mockResponse, largeRequestBuffer, largeResponseBuffer);

        assertSame(largeRequestBuffer, negotiationWithLargeBuffers.getRequestRaw());
        assertSame(largeResponseBuffer, negotiationWithLargeBuffers.getResponseRaw());
        assertEquals(1024, negotiationWithLargeBuffers.getRequestRaw().length);
        assertEquals(2048, negotiationWithLargeBuffers.getResponseRaw().length);
    }

    @Test
    @DisplayName("Fields should be immutable after construction")
    void testImmutability() {
        // Get references to the objects
        SmbNegotiationRequest originalRequest = negotiation.getRequest();
        SmbNegotiationResponse originalResponse = negotiation.getResponse();
        byte[] originalRequestBuffer = negotiation.getRequestRaw();
        byte[] originalResponseBuffer = negotiation.getResponseRaw();

        // Verify fields remain unchanged on subsequent calls
        assertSame(originalRequest, negotiation.getRequest());
        assertSame(originalResponse, negotiation.getResponse());
        assertSame(originalRequestBuffer, negotiation.getRequestRaw());
        assertSame(originalResponseBuffer, negotiation.getResponseRaw());
    }

    @Test
    @DisplayName("Test buffer modifications are reflected")
    void testBufferModifications() {
        // Since the class returns the same array reference, modifications will be reflected
        byte[] requestBuffer = negotiation.getRequestRaw();
        byte[] responseBuffer = negotiation.getResponseRaw();

        // Modify the buffers
        requestBuffer[0] = (byte) 0xFF;
        responseBuffer[0] = (byte) 0xEE;

        // Verify modifications are reflected
        assertEquals((byte) 0xFF, negotiation.getRequestRaw()[0]);
        assertEquals((byte) 0xEE, negotiation.getResponseRaw()[0]);
    }

    @Test
    @DisplayName("Test with different buffer sizes")
    void testWithDifferentBufferSizes() {
        // Test with buffers of different sizes
        byte[] smallBuffer = new byte[] { 0x01 };
        byte[] mediumBuffer = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };

        SmbNegotiation negotiationDifferentSizes = new SmbNegotiation(mockRequest, mockResponse, smallBuffer, mediumBuffer);

        assertEquals(1, negotiationDifferentSizes.getRequestRaw().length);
        assertEquals(5, negotiationDifferentSizes.getResponseRaw().length);
    }

    @Test
    @DisplayName("Test multiple instances do not interfere")
    void testMultipleInstances() {
        // Create another instance with different data
        SmbNegotiationRequest anotherRequest = mock(SmbNegotiationRequest.class);
        SmbNegotiationResponse anotherResponse = mock(SmbNegotiationResponse.class);
        byte[] anotherRequestBuffer = new byte[] { 0x10, 0x20 };
        byte[] anotherResponseBuffer = new byte[] { 0x30, 0x40 };

        SmbNegotiation anotherNegotiation =
                new SmbNegotiation(anotherRequest, anotherResponse, anotherRequestBuffer, anotherResponseBuffer);

        // Verify the instances are independent
        assertNotSame(negotiation.getRequest(), anotherNegotiation.getRequest());
        assertNotSame(negotiation.getResponse(), anotherNegotiation.getResponse());
        assertNotSame(negotiation.getRequestRaw(), anotherNegotiation.getRequestRaw());
        assertNotSame(negotiation.getResponseRaw(), anotherNegotiation.getResponseRaw());

        // Verify original instance is unchanged
        assertSame(mockRequest, negotiation.getRequest());
        assertSame(mockResponse, negotiation.getResponse());
        assertArrayEquals(new byte[] { 0x01, 0x02, 0x03, 0x04 }, negotiation.getRequestRaw());
        assertArrayEquals(new byte[] { 0x05, 0x06, 0x07, 0x08 }, negotiation.getResponseRaw());
    }
}
