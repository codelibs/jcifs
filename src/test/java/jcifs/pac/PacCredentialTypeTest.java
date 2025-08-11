package jcifs.pac;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import jcifs.pac.PACDecodingException;

/**
 * Tests for the {@link PacCredentialType} class.
 */
class PacCredentialTypeTest {

    /**
     * Tests the constructor with a valid byte array.
     */
    @Test
    void testConstructorWithValidData() {
        // A byte array with a length less than 32 should be considered valid.
        byte[] validData = new byte[31];
        assertDoesNotThrow(() -> new PacCredentialType(validData));
    }

    /**
     * Tests the constructor with a null byte array, which should throw an exception.
     */
    @Test
    void testConstructorWithNullData() {
        // A null byte array should cause a PACDecodingException.
        PACDecodingException exception = assertThrows(PACDecodingException.class, () -> new PacCredentialType(null));
        assertEquals("Invalid PAC credential type", exception.getMessage());
    }

    /**
     * Tests the constructor with a byte array that is too large.
     */
    @Test
    void testConstructorWithDataTooLarge() {
        // A byte array with a length of 32 should be considered too large.
        byte[] largeData = new byte[32];
        PACDecodingException exception = assertThrows(PACDecodingException.class, () -> new PacCredentialType(largeData));
        assertEquals("Invalid PAC credential type", exception.getMessage());
    }

    /**
     * Tests the constructor with a byte array that is larger than the minimal buffer size.
     */
    @Test
    void testConstructorWithDataMuchLarger() {
        // A byte array with a length greater than 32 should also be considered too large.
        byte[] veryLargeData = new byte[100];
        PACDecodingException exception = assertThrows(PACDecodingException.class, () -> new PacCredentialType(veryLargeData));
        assertEquals("Invalid PAC credential type", exception.getMessage());
    }

    /**
     * Tests the isCredentialTypeCorrect method with a valid byte array.
     *
     * @throws PACDecodingException if the PAC decoding fails.
     */
    @Test
    void testIsCredentialTypeCorrectWithValidData() throws PACDecodingException {
        // A byte array with a length less than 32 should be correct.
        byte[] validData = new byte[31];
        PacCredentialType pacCredentialType = new PacCredentialType(validData);
        assertTrue(pacCredentialType.isCredentialTypeCorrect());
    }

    /**
     * Tests the isCredentialTypeCorrect method with a null byte array.
     * This test is indirect as the constructor would throw an exception.
     * We can't instantiate the class with null, so we can't directly test this method's behavior with null.
     * However, the constructor logic `!isCredentialTypeCorrect()` covers this.
     * If `new PacCredentialType(null)` throws, it implies `isCredentialTypeCorrect()` returned false for null.
     */
    @Test
    void testIsCredentialTypeCorrectWithNullData() {
        // The constructor check `if (!isCredentialTypeCorrect())` handles the null case.
        // We verify that the constructor throws an exception, which indirectly tests the desired logic.
        assertThrows(PACDecodingException.class, () -> new PacCredentialType(null));
    }

    /**
     * Tests the isCredentialTypeCorrect method with a byte array of exact minimal buffer size.
     * This test is also indirect.
     */
    @Test
    void testIsCredentialTypeCorrectWithExactSizeData() {
        // The constructor check `if (!isCredentialTypeCorrect())` handles this case.
        // We verify that the constructor throws an exception.
        byte[] exactSizeData = new byte[32];
        assertThrows(PACDecodingException.class, () -> new PacCredentialType(exactSizeData));
    }
}
