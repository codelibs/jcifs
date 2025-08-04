package jcifs.dcerpc.ndr;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;

/**
 * Tests for the NdrObject abstract class.
 * This test uses a concrete implementation to verify the abstract contract.
 */
@ExtendWith(MockitoExtension.class)
class NdrObjectTest {

    @Mock
    private NdrBuffer mockBuffer;

    private ConcreteNdrObject ndrObject;

    // A concrete implementation of NdrObject for testing purposes.
    private static class ConcreteNdrObject extends NdrObject {
        private boolean throwOnEncode = false;
        private boolean throwOnDecode = false;

        @Override
        public void encode(NdrBuffer dst) throws NdrException {
            if (throwOnEncode) {
                throw new NdrException("Failed to encode");
            }
            // Simulate some encoding activity on the buffer
            dst.enc_ndr_long(123);
        }

        @Override
        public void decode(NdrBuffer src) throws NdrException {
            if (throwOnDecode) {
                throw new NdrException("Failed to decode");
            }
            // Simulate some decoding activity on the buffer
            src.dec_ndr_long();
        }

        public void setThrowOnEncode(boolean throwOnEncode) {
            this.throwOnEncode = throwOnEncode;
        }

        public void setThrowOnDecode(boolean throwOnDecode) {
            this.throwOnDecode = throwOnDecode;
        }
    }

    @BeforeEach
    void setUp() {
        ndrObject = new ConcreteNdrObject();
    }

    /**
     * Test case for the encode method.
     * Verifies that the encode method of a concrete implementation is called
     * and interacts with the NdrBuffer as expected.
     * @throws NdrException if encoding fails.
     */
    @Test
    void testEncode() throws NdrException {
        // When
        ndrObject.encode(mockBuffer);

        // Then
        // Verify that our mock buffer had the expected method called.
        verify(mockBuffer).enc_ndr_long(123);
    }

    /**
     * Test case for the decode method.
     * Verifies that the decode method of a concrete implementation is called
     * and interacts with the NdrBuffer as expected.
     * @throws NdrException if decoding fails.
     */
    @Test
    void testDecode() throws NdrException {
        // When
        ndrObject.decode(mockBuffer);

        // Then
        // Verify that our mock buffer had the expected method called.
        verify(mockBuffer).dec_ndr_long();
    }

    /**
     * Test case for the encode method when it throws an NdrException.
     * Verifies that the exception is correctly propagated.
     */
    @Test
    void testEncodeThrowsNdrException() {
        // Given
        ndrObject.setThrowOnEncode(true);

        // When & Then
        assertThrows(NdrException.class, () -> {
            ndrObject.encode(mockBuffer);
        });
    }

    /**
     * Test case for the decode method when it throws an NdrException.
     * Verifies that the exception is correctly propagated.
     */
    @Test
    void testDecodeThrowsNdrException() {
        // Given
        ndrObject.setThrowOnDecode(true);

        // When & Then
        assertThrows(NdrException.class, () -> {
            ndrObject.decode(mockBuffer);
        });
    }
}
