package org.codelibs.jcifs.smb.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.Configuration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for {@link SmbComSetInformationResponse}.
 *
 * Tests focus on the wire format methods which all return 0,
 * and the toString method implementation.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SmbComSetInformationResponse tests")
public class SmbComSetInformationResponseTest {

    @Mock
    private Configuration mockConfig;

    private SmbComSetInformationResponse response;

    @BeforeEach
    void setUp() {
        // Setup mock configuration to avoid NPE
        when(mockConfig.getPid()).thenReturn(12345);

        response = new SmbComSetInformationResponse(mockConfig);
    }

    @Test
    @DisplayName("Constructor accepts valid config")
    void constructorValid() {
        assertDoesNotThrow(() -> new SmbComSetInformationResponse(mockConfig));
    }

    @Nested
    @DisplayName("writeParameterWordsWireFormat tests")
    class WriteParameterWords {

        @Test
        @DisplayName("Returns 0 with null array")
        void nullArray() {
            assertEquals(0, response.writeParameterWordsWireFormat(null, 0));
        }

        @ParameterizedTest
        @ValueSource(ints = { 0, 5, 9 })
        @DisplayName("Returns 0 with valid array and various indices")
        void nonNullArray(int index) {
            byte[] arr = new byte[10];
            assertEquals(0, response.writeParameterWordsWireFormat(arr, index));
        }
    }

    @Nested
    @DisplayName("writeBytesWireFormat tests")
    class WriteBytes {

        @Test
        @DisplayName("Returns 0 with null array")
        void nullArray() {
            assertEquals(0, response.writeBytesWireFormat(null, 0));
        }

        @ParameterizedTest
        @ValueSource(ints = { 0, 7 })
        @DisplayName("Returns 0 with valid array and various indices")
        void nonNullArray(int idx) {
            byte[] arr = new byte[10];
            assertEquals(0, response.writeBytesWireFormat(arr, idx));
        }
    }

    @Nested
    @DisplayName("readParameterWordsWireFormat tests")
    class ReadParameterWords {

        @Test
        @DisplayName("Returns 0 with null array")
        void nullArray() {
            assertEquals(0, response.readParameterWordsWireFormat(null, 0));
        }

        @ParameterizedTest
        @ValueSource(ints = { 1, 6 })
        @DisplayName("Returns 0 with valid array and various indices")
        void normalArray(int idx) {
            byte[] arr = new byte[15];
            assertEquals(0, response.readParameterWordsWireFormat(arr, idx));
        }
    }

    @Nested
    @DisplayName("readBytesWireFormat tests")
    class ReadBytes {

        @Test
        @DisplayName("Returns 0 with null array")
        void nullArray() {
            assertEquals(0, response.readBytesWireFormat(null, 0));
        }

        @ParameterizedTest
        @ValueSource(ints = { 2, 9 })
        @DisplayName("Returns 0 with valid array and various indices")
        void normalArray(int idx) {
            byte[] arr = new byte[12];
            assertEquals(0, response.readBytesWireFormat(arr, idx));
        }
    }

    @Test
    @DisplayName("toString contains class name and delegates to superclass")
    void toStringMatches() {
        String s = response.toString();
        assertNotNull(s);
        assertTrue(s.startsWith("SmbComSetInformationResponse["));
        assertTrue(s.endsWith("]"));
        // Verify it contains superclass toString content
        assertTrue(s.length() > "SmbComSetInformationResponse[]".length());
    }
}
