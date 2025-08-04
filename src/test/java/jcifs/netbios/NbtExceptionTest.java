package jcifs.netbios;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import jcifs.CIFSException;

class NbtExceptionTest {

    /**
     * Test the constructor of NbtException.
     * It should correctly set errorClass and errorCode, and the message should be derived from getErrorString.
     */
    @Test
    @DisplayName("NbtException constructor should correctly set error class, error code, and message")
    void testConstructor() {
        int errorClass = NbtException.ERR_NAM_SRVC;
        int errorCode = NbtException.FMT_ERR;
        NbtException exception = new NbtException(errorClass, errorCode);

        assertEquals(errorClass, exception.errorClass, "Error class should match the constructor argument");
        assertEquals(errorCode, exception.errorCode, "Error code should match the constructor argument");
        assertEquals(NbtException.getErrorString(errorClass, errorCode), exception.getMessage(),
                "Exception message should match getErrorString output");
        assertTrue(exception instanceof CIFSException, "NbtException should be an instance of CIFSException");
    }

    /**
     * Test the getErrorString method with various error classes and codes to ensure all branches are covered.
     */
    @ParameterizedTest
    @MethodSource("provideErrorClassAndCodeForGetErrorString")
    @DisplayName("getErrorString should return correct messages for all defined error classes and codes")
    void testGetErrorString(int errorClass, int errorCode, String expectedMessage) {
        assertEquals(expectedMessage, NbtException.getErrorString(errorClass, errorCode),
                "The error string should match the expected message for given error class and code");
    }

    /**
     * Provides arguments for the testGetErrorString parameterized test.
     * Covers all defined error classes and codes, including default cases.
     */
    private static Stream<Arguments> provideErrorClassAndCodeForGetErrorString() {
        return Stream.of(
                // SUCCESS
                Arguments.of(NbtException.SUCCESS, 0, "SUCCESS"),

                // ERR_NAM_SRVC
                Arguments.of(NbtException.ERR_NAM_SRVC, NbtException.FMT_ERR, "ERR_NAM_SRVC/FMT_ERR: Format Error"),
                Arguments.of(NbtException.ERR_NAM_SRVC, 99, "ERR_NAM_SRVC/Unknown error code: 99"), // Default case for name service

                // ERR_SSN_SRVC
                Arguments.of(NbtException.ERR_SSN_SRVC, NbtException.CONNECTION_REFUSED, "ERR_SSN_SRVC/Connection refused"),
                Arguments.of(NbtException.ERR_SSN_SRVC, NbtException.NOT_LISTENING_CALLED, "ERR_SSN_SRVC/Not listening on called name"),
                Arguments.of(NbtException.ERR_SSN_SRVC, NbtException.NOT_LISTENING_CALLING, "ERR_SSN_SRVC/Not listening for calling name"),
                Arguments.of(NbtException.ERR_SSN_SRVC, NbtException.CALLED_NOT_PRESENT, "ERR_SSN_SRVC/Called name not present"),
                Arguments.of(NbtException.ERR_SSN_SRVC, NbtException.NO_RESOURCES,
                        "ERR_SSN_SRVC/Called name present, but insufficient resources"),
                Arguments.of(NbtException.ERR_SSN_SRVC, NbtException.UNSPECIFIED, "ERR_SSN_SRVC/Unspecified error"),
                Arguments.of(NbtException.ERR_SSN_SRVC, 99, "ERR_SSN_SRVC/Unknown error code: 99"), // Default case for session service

                // Default error class
                Arguments.of(999, 0, "unknown error class: 999"));
    }

    /**
     * Test the toString method to ensure it returns the expected string format.
     */
    @Test
    @DisplayName("toString should return a correctly formatted string")
    void testToString() {
        int errorClass = NbtException.ERR_SSN_SRVC;
        int errorCode = NbtException.CONNECTION_REFUSED;
        NbtException exception = new NbtException(errorClass, errorCode);

        String expectedToString = "errorClass=" + errorClass + ",errorCode=" + errorCode + ",errorString="
                + NbtException.getErrorString(errorClass, errorCode);

        assertEquals(expectedToString, exception.toString(), "toString output should match the expected format");
    }

    /**
     * Test that NbtException can be caught as a CIFSException.
     */
    @Test
    @DisplayName("NbtException should be catchable as CIFSException")
    void testCatchableAsCIFSException() {
        try {
            throw new NbtException(NbtException.ERR_NAM_SRVC, NbtException.FMT_ERR);
        } catch (CIFSException e) {
            assertTrue(e instanceof NbtException, "Caught exception should be an instance of NbtException");
            assertEquals(NbtException.ERR_NAM_SRVC, ((NbtException) e).errorClass);
            assertEquals(NbtException.FMT_ERR, ((NbtException) e).errorCode);
        } catch (Exception e) {
            fail("Should have caught CIFSException, but caught " + e.getClass().getSimpleName());
        }
    }
}
