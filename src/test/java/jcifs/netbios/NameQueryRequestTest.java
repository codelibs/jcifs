package jcifs.netbios;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;

class NameQueryRequestTest {

    @Mock
    private Configuration mockConfig;
    @Mock
    private Name mockName;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testConstructor() {
        // Test that the constructor correctly initializes questionName and questionType
        NameQueryRequest request = new NameQueryRequest(mockConfig, mockName);

        assertNotNull(request);
        assertEquals(mockName, request.questionName);
        assertEquals(NameServicePacket.NB, request.questionType);
    }

    @Test
    void testWriteBodyWireFormat() {
        // Test that writeBodyWireFormat calls writeQuestionSectionWireFormat
        NameQueryRequest request = spy(new NameQueryRequest(mockConfig, mockName));
        byte[] dst = new byte[100];
        int dstIndex = 0;

        // Mock the superclass method to control its behavior
        doReturn(10).when((NameServicePacket) request).writeQuestionSectionWireFormat(any(byte[].class), anyInt());

        int result = request.writeBodyWireFormat(dst, dstIndex);

        // Verify that writeQuestionSectionWireFormat was called
        verify((NameServicePacket) request, times(1)).writeQuestionSectionWireFormat(dst, dstIndex);
        assertEquals(10, result);
    }

    @Test
    void testReadBodyWireFormat() {
        // Test that readBodyWireFormat calls readQuestionSectionWireFormat
        NameQueryRequest request = spy(new NameQueryRequest(mockConfig, mockName));
        byte[] src = new byte[100];
        int srcIndex = 0;

        // Mock the superclass method to control its behavior
        doReturn(15).when((NameServicePacket) request).readQuestionSectionWireFormat(any(byte[].class), anyInt());

        int result = request.readBodyWireFormat(src, srcIndex);

        // Verify that readQuestionSectionWireFormat was called
        verify((NameServicePacket) request, times(1)).readQuestionSectionWireFormat(src, srcIndex);
        assertEquals(15, result);
    }

    @Test
    void testWriteRDataWireFormat() {
        // Test that writeRDataWireFormat always returns 0
        NameQueryRequest request = new NameQueryRequest(mockConfig, mockName);
        byte[] dst = new byte[100];
        int dstIndex = 0;

        int result = request.writeRDataWireFormat(dst, dstIndex);

        assertEquals(0, result);
    }

    @Test
    void testReadRDataWireFormat() {
        // Test that readRDataWireFormat always returns 0
        NameQueryRequest request = new NameQueryRequest(mockConfig, mockName);
        byte[] src = new byte[100];
        int srcIndex = 0;

        int result = request.readRDataWireFormat(src, srcIndex);

        assertEquals(0, result);
    }

    @Test
    void testToString() {
        // Test the toString method's output format
        NameQueryRequest request = new NameQueryRequest(mockConfig, mockName);
        String expectedStringPrefix = "NameQueryRequest[";
        String actualString = request.toString();

        assertTrue(actualString.startsWith(expectedStringPrefix));
        assertTrue(actualString.endsWith("]"));
        // Further verification could involve mocking super.toString() if needed
    }
}
