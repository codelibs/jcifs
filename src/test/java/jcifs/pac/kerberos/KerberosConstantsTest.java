package jcifs.pac.kerberos;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;


/**
 * Tests for the KerberosConstants interface.
 */
class KerberosConstantsTest {

    /**
     * This test primarily exists to ensure the constants interface can be loaded
     * and to provide a basic check of its values.
     * Since it's an interface with only static final fields, there is no complex logic to test.
     */
    @Test
    void testConstants() {
        // A simple assertion to verify that some of the constants have the expected values.
        // This confirms that the class is on the classpath and its fields are accessible.
        assertEquals("1.2.840.113554.1.2.2", KerberosConstants.KERBEROS_OID, "KERBEROS_OID should have the correct value.");
        assertEquals("5", KerberosConstants.KERBEROS_VERSION, "KERBEROS_VERSION should have the correct value.");
        assertEquals(23, KerberosConstants.RC4_ENC_TYPE, "RC4_ENC_TYPE should have the correct value.");
        assertEquals("HmacMD5", KerberosConstants.HMAC_ALGORITHM, "HMAC_ALGORITHM should have the correct value.");
    }
}
