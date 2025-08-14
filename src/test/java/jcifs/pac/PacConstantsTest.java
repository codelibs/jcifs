package jcifs.pac;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * Tests for the PacConstants interface.
 * This test class verifies that the constant values defined in PacConstants are correct.
 */
class PacConstantsTest {

    /**
     * Tests that the constant values in the PacConstants interface match their expected values.
     * This prevents accidental modification of these critical constants.
     */
    @Test
    void testConstantValues() {
        // Verify the PAC version
        assertEquals(0, PacConstants.PAC_VERSION, "PAC_VERSION should be 0");

        // Verify PAC buffer types
        assertEquals(1, PacConstants.LOGON_INFO, "LOGON_INFO should be 1");
        assertEquals(2, PacConstants.CREDENTIAL_TYPE, "CREDENTIAL_TYPE should be 2");
        assertEquals(6, PacConstants.SERVER_CHECKSUM, "SERVER_CHECKSUM should be 6");
        assertEquals(7, PacConstants.PRIVSVR_CHECKSUM, "PRIVSVR_CHECKSUM should be 7");
        assertEquals(0xA, PacConstants.CLIENT_NAME_TYPE, "CLIENT_NAME_TYPE should be 0xA");
        assertEquals(0xB, PacConstants.CONSTRAINT_DELEGATIION_TYPE, "CONSTRAINT_DELEGATIION_TYPE should be 0xB");
        assertEquals(0xC, PacConstants.CLIENT_UPN_TYPE, "CLIENT_UPN_TYPE should be 0xC");
        assertEquals(0xD, PacConstants.CLIENT_CLAIMS_TYPE, "CLIENT_CLAIMS_TYPE should be 0xD");
        assertEquals(0xE, PacConstants.DEVICE_INFO_TYPE, "DEVICE_INFO_TYPE should be 0xE");
        assertEquals(0xF, PacConstants.DEVICE_CLAIMS_TYPE, "DEVICE_CLAIMS_TYPE should be 0xF");

        // Verify PAC logon info constants
        assertEquals(0x20, PacConstants.LOGON_EXTRA_SIDS, "LOGON_EXTRA_SIDS should be 0x20");
        assertEquals(0x200, PacConstants.LOGON_RESOURCE_GROUPS, "LOGON_RESOURCE_GROUPS should be 0x200");

        // Verify cryptographic constants
        assertEquals(17, PacConstants.MD5_KRB_SALT, "MD5_KRB_SALT should be 17");
        assertEquals(64, PacConstants.MD5_BLOCK_LENGTH, "MD5_BLOCK_LENGTH should be 64");
    }
}
