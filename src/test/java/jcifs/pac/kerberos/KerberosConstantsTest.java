/*
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
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
