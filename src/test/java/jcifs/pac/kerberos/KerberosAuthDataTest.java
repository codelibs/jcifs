package jcifs.pac.kerberos;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import javax.security.auth.kerberos.KerberosKey;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.pac.PACDecodingException;

/**
 * Tests for the {@link KerberosAuthData} class.
 */
@ExtendWith(MockitoExtension.class)
class KerberosAuthDataTest {

    @Mock
    private Map<Integer, KerberosKey> mockKeys;

    /**
     * Test parsing with an unknown auth type.
     * Expects an empty list of authorizations.
     * @throws PACDecodingException should not be thrown
     */
    @Test
    void testParseUnknownAuthType() throws PACDecodingException {
        // GIVEN an unknown auth type
        int unknownAuthType = -1;
        byte[] emptyToken = new byte[0];

        // WHEN parsing the auth data
        List<KerberosAuthData> result = KerberosAuthData.parse(unknownAuthType, emptyToken, mockKeys);

        // THEN the result should be an empty list
        assertNotNull(result, "The result should not be null.");
        assertTrue(result.isEmpty(), "The result should be empty for unknown auth types.");
    }

    /**
     * Test parsing of {@link KerberosConstants#AUTH_DATA_PAC} with an invalid token.
     * Expects a {@link PACDecodingException} to be thrown.
     */
    @Test
    void testParseAuthDataPacWithInvalidToken() {
        // GIVEN an invalid token for AUTH_DATA_PAC
        byte[] invalidToken = "invalid-pac-token".getBytes();

        // WHEN parsing the auth data
        // THEN a PACDecodingException should be thrown
        assertThrows(PACDecodingException.class, () -> {
            KerberosAuthData.parse(KerberosConstants.AUTH_DATA_PAC, invalidToken, mockKeys);
        }, "Parsing an invalid PAC token should throw a PACDecodingException.");
    }

    /**
     * Test parsing of {@link KerberosConstants#AUTH_DATA_RELEVANT} with an invalid token.
     * Expects a {@link PACDecodingException} to be thrown.
     */
    @Test
    void testParseAuthDataRelevantWithInvalidToken() {
        // GIVEN an invalid token for AUTH_DATA_RELEVANT
        byte[] invalidToken = "invalid-relevant-auth-data-token".getBytes();

        // WHEN parsing the auth data
        // THEN a PACDecodingException should be thrown
        assertThrows(PACDecodingException.class, () -> {
            KerberosAuthData.parse(KerberosConstants.AUTH_DATA_RELEVANT, invalidToken, mockKeys);
        }, "Parsing invalid relevant auth data should throw a PACDecodingException.");
    }
}
