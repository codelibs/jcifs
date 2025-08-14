package jcifs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import jcifs.internal.SMBProtocolDecodingException;

/**
 * Test class for Decodable interface functionality
 */
@DisplayName("Decodable Interface Tests")
class DecodableTest extends BaseTest {

    @Mock
    private Decodable mockDecodable;

    @Test
    @DisplayName("Should define decode method")
    void testDecodeMethod() throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[10];
        int bufferIndex = 0;
        int len = 10;
        when(mockDecodable.decode(buffer, bufferIndex, len)).thenReturn(10);

        // When
        int decodedLength = mockDecodable.decode(buffer, bufferIndex, len);

        // Then
        assertEquals(10, decodedLength);
        verify(mockDecodable).decode(buffer, bufferIndex, len);
    }
}
