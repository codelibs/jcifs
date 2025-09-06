package org.codelibs.jcifs.smb.dcerpc.ndr;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

class NdrExceptionTest {

    /**
     * Test the constructor with a message.
     * Ensures that the exception is created with the correct message.
     */
    @Test
    void testConstructorWithMessage() {
        String testMessage = "This is a test message for NdrException.";
        NdrException exception = new NdrException(testMessage);
        assertEquals(testMessage, exception.getMessage(), "The exception message should match the input message.");
    }

    /**
     * Test the NO_NULL_REF static field.
     * Ensures that the static field holds the expected string value.
     */
    @Test
    void testNoNullRefConstant() {
        assertNotNull(NdrException.NO_NULL_REF, "NO_NULL_REF constant should not be null.");
        assertEquals("ref pointer cannot be null", NdrException.NO_NULL_REF, "NO_NULL_REF constant should have the expected value.");
    }

    /**
     * Test the INVALID_CONFORMANCE static field.
     * Ensures that the static field holds the expected string value.
     */
    @Test
    void testInvalidConformanceConstant() {
        assertNotNull(NdrException.INVALID_CONFORMANCE, "INVALID_CONFORMANCE constant should not be null.");
        assertEquals("invalid array conformance", NdrException.INVALID_CONFORMANCE,
                "INVALID_CONFORMANCE constant should have the expected value.");
    }
}
