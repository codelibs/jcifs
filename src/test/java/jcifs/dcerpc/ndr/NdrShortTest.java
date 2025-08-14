package jcifs.dcerpc.ndr;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Comprehensive test suite for NdrShort class
 * Tests construction, encoding, decoding, and edge cases
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("NdrShort Test Suite")
class NdrShortTest {

    @Mock
    private NdrBuffer mockBuffer;

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @ParameterizedTest
        @DisplayName("Should mask input values with 0xFF correctly")
        @ValueSource(ints = { 0, 1, 127, 128, 255, 256, -1, -128, -255, -256, 32767, -32768, 65535, 65536 })
        void testConstructorMasking(int inputValue) {
            // Given: An input value
            // When: Creating NdrShort with that value
            NdrShort ndrShort = new NdrShort(inputValue);

            // Then: Value should be masked with 0xFF (lower 8 bits)
            assertEquals(inputValue & 0xFF, ndrShort.value, "Constructor should mask value with 0xFF");
        }

        @Test
        @DisplayName("Should handle zero value correctly")
        void testConstructorZero() {
            // Given/When: Creating NdrShort with zero
            NdrShort ndrShort = new NdrShort(0);

            // Then: Value should be zero
            assertEquals(0, ndrShort.value);
        }

        @Test
        @DisplayName("Should handle maximum byte value correctly")
        void testConstructorMaxByte() {
            // Given/When: Creating NdrShort with max byte value
            NdrShort ndrShort = new NdrShort(255);

            // Then: Value should be 255
            assertEquals(255, ndrShort.value);
        }

        @Test
        @DisplayName("Should handle overflow correctly")
        void testConstructorOverflow() {
            // Given/When: Creating NdrShort with value > 255
            NdrShort ndrShort = new NdrShort(300);

            // Then: Value should be masked (300 & 0xFF = 44)
            assertEquals(44, ndrShort.value);
        }
    }

    @Nested
    @DisplayName("Encoding Tests")
    class EncodingTests {

        @Test
        @DisplayName("Should encode value correctly")
        void testEncode() throws NdrException {
            // Given: NdrShort with test value
            int testValue = 123;
            NdrShort ndrShort = new NdrShort(testValue);

            // When: Encoding the value
            ndrShort.encode(mockBuffer);

            // Then: Should call enc_ndr_short with masked value
            verify(mockBuffer).enc_ndr_short(testValue & 0xFF);
            verifyNoMoreInteractions(mockBuffer);
        }

        @Test
        @DisplayName("Should encode zero correctly")
        void testEncodeZero() throws NdrException {
            // Given: NdrShort with zero value
            NdrShort ndrShort = new NdrShort(0);

            // When: Encoding the value
            ndrShort.encode(mockBuffer);

            // Then: Should call enc_ndr_short with zero
            verify(mockBuffer).enc_ndr_short(0);
            verifyNoMoreInteractions(mockBuffer);
        }

        @Test
        @DisplayName("Should encode maximum byte value correctly")
        void testEncodeMaxValue() throws NdrException {
            // Given: NdrShort with max byte value
            NdrShort ndrShort = new NdrShort(255);

            // When: Encoding the value
            ndrShort.encode(mockBuffer);

            // Then: Should call enc_ndr_short with 255
            verify(mockBuffer).enc_ndr_short(255);
            verifyNoMoreInteractions(mockBuffer);
        }

        @Test
        @DisplayName("Should encode masked overflow value correctly")
        void testEncodeMaskedValue() throws NdrException {
            // Given: NdrShort with overflow value that gets masked
            int inputValue = 300; // 300 & 0xFF = 44
            NdrShort ndrShort = new NdrShort(inputValue);

            // When: Encoding the value
            ndrShort.encode(mockBuffer);

            // Then: Should call enc_ndr_short with masked value
            verify(mockBuffer).enc_ndr_short(44);
            verifyNoMoreInteractions(mockBuffer);
        }
    }

    @Nested
    @DisplayName("Decoding Tests")
    class DecodingTests {

        @Test
        @DisplayName("Should decode value correctly")
        void testDecode() throws NdrException {
            // Given: NdrShort and mock returning specific value
            int decodedValue = 200;
            NdrShort ndrShort = new NdrShort(0);
            when(mockBuffer.dec_ndr_short()).thenReturn(decodedValue);

            // When: Decoding the value
            ndrShort.decode(mockBuffer);

            // Then: Should call dec_ndr_short and set value correctly
            verify(mockBuffer).dec_ndr_short();
            verifyNoMoreInteractions(mockBuffer);
            assertEquals(decodedValue, ndrShort.value);
        }

        @Test
        @DisplayName("Should decode zero correctly")
        void testDecodeZero() throws NdrException {
            // Given: NdrShort and mock returning zero
            NdrShort ndrShort = new NdrShort(100); // Initial value should be overwritten
            when(mockBuffer.dec_ndr_short()).thenReturn(0);

            // When: Decoding the value
            ndrShort.decode(mockBuffer);

            // Then: Should update value to zero
            verify(mockBuffer).dec_ndr_short();
            assertEquals(0, ndrShort.value);
        }

        @Test
        @DisplayName("Should decode negative value correctly")
        void testDecodeNegativeValue() throws NdrException {
            // Given: NdrShort and mock returning negative value
            int negativeValue = -1;
            NdrShort ndrShort = new NdrShort(0);
            when(mockBuffer.dec_ndr_short()).thenReturn(negativeValue);

            // When: Decoding the value
            ndrShort.decode(mockBuffer);

            // Then: Should set the negative value directly (no masking on decode)
            verify(mockBuffer).dec_ndr_short();
            assertEquals(negativeValue, ndrShort.value);
        }

        @Test
        @DisplayName("Should decode large value correctly")
        void testDecodeLargeValue() throws NdrException {
            // Given: NdrShort and mock returning large value
            int largeValue = 65535;
            NdrShort ndrShort = new NdrShort(0);
            when(mockBuffer.dec_ndr_short()).thenReturn(largeValue);

            // When: Decoding the value
            ndrShort.decode(mockBuffer);

            // Then: Should set the large value directly (no masking on decode)
            verify(mockBuffer).dec_ndr_short();
            assertEquals(largeValue, ndrShort.value);
        }
    }

    @Nested
    @DisplayName("Round-trip Tests")
    class RoundTripTests {

        @Test
        @DisplayName("Should handle encode-decode round-trip correctly")
        void testEncodeDecodeRoundTrip() throws NdrException {
            // Given: Original value that fits in byte range
            int originalValue = 150;
            NdrShort ndrShort1 = new NdrShort(originalValue);

            // Create separate mocks for encoding and decoding to simulate real buffer
            NdrBuffer encodeBuffer = mock(NdrBuffer.class);
            NdrBuffer decodeBuffer = mock(NdrBuffer.class);
            when(decodeBuffer.dec_ndr_short()).thenReturn(originalValue);

            // When: Encoding then decoding
            ndrShort1.encode(encodeBuffer);

            NdrShort ndrShort2 = new NdrShort(0);
            ndrShort2.decode(decodeBuffer);

            // Then: Values should match
            verify(encodeBuffer).enc_ndr_short(originalValue);
            verify(decodeBuffer).dec_ndr_short();
            assertEquals(ndrShort1.value, ndrShort2.value);
        }

        @Test
        @DisplayName("Should handle masked value round-trip correctly")
        void testMaskedValueRoundTrip() throws NdrException {
            // Given: Original value that gets masked
            int originalValue = 300; // Will be masked to 44
            int maskedValue = originalValue & 0xFF; // 44
            NdrShort ndrShort1 = new NdrShort(originalValue);

            NdrBuffer encodeBuffer = mock(NdrBuffer.class);
            NdrBuffer decodeBuffer = mock(NdrBuffer.class);
            when(decodeBuffer.dec_ndr_short()).thenReturn(maskedValue);

            // When: Encoding then decoding
            ndrShort1.encode(encodeBuffer);

            NdrShort ndrShort2 = new NdrShort(0);
            ndrShort2.decode(decodeBuffer);

            // Then: Should maintain masked value consistency
            verify(encodeBuffer).enc_ndr_short(maskedValue);
            verify(decodeBuffer).dec_ndr_short();
            assertEquals(maskedValue, ndrShort1.value);
            assertEquals(maskedValue, ndrShort2.value);
        }
    }

    @Nested
    @DisplayName("Edge Cases and Error Handling")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle multiple operations correctly")
        void testMultipleOperations() throws NdrException {
            // Given: NdrShort that will be used multiple times
            NdrShort ndrShort = new NdrShort(50);
            NdrBuffer buffer1 = mock(NdrBuffer.class);
            NdrBuffer buffer2 = mock(NdrBuffer.class);
            when(buffer2.dec_ndr_short()).thenReturn(75);

            // When: Performing multiple operations
            ndrShort.encode(buffer1);
            ndrShort.decode(buffer2);

            // Then: Should handle both operations correctly
            verify(buffer1).enc_ndr_short(50);
            verify(buffer2).dec_ndr_short();
            assertEquals(75, ndrShort.value);
        }

        @Test
        @DisplayName("Should handle boundary values correctly")
        void testBoundaryValues() {
            // Test various boundary values
            assertEquals(0, new NdrShort(0).value);
            assertEquals(255, new NdrShort(255).value);
            assertEquals(0, new NdrShort(256).value); // 256 & 0xFF = 0
            assertEquals(255, new NdrShort(-1).value); // -1 & 0xFF = 255
            assertEquals(128, new NdrShort(-128).value); // -128 & 0xFF = 128
        }

        @Test
        @DisplayName("Should maintain value consistency after multiple constructions")
        void testValueConsistency() {
            // Given: Same input value
            int inputValue = 1000;
            int expectedMasked = inputValue & 0xFF; // 232

            // When: Creating multiple NdrShort instances
            NdrShort ndrShort1 = new NdrShort(inputValue);
            NdrShort ndrShort2 = new NdrShort(inputValue);

            // Then: All should have same masked value
            assertEquals(expectedMasked, ndrShort1.value);
            assertEquals(expectedMasked, ndrShort2.value);
            assertEquals(ndrShort1.value, ndrShort2.value);
        }
    }
}
