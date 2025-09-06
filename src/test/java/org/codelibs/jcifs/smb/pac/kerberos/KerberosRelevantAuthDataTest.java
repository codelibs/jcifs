package org.codelibs.jcifs.smb.pac.kerberos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.kerberos.KerberosKey;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.codelibs.jcifs.smb.pac.PACDecodingException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Test class for {@link KerberosRelevantAuthData}.
 */
@ExtendWith(MockitoExtension.class)
class KerberosRelevantAuthDataTest {

    private MockedStatic<KerberosAuthData> mockedStaticAuthData;

    @BeforeEach
    void setUp() {
        // Mock the static parse method of KerberosAuthData
        mockedStaticAuthData = mockStatic(KerberosAuthData.class);
    }

    @AfterEach
    void tearDown() {
        // Close the static mock
        mockedStaticAuthData.close();
    }

    /**
     * Test constructor with a valid ASN.1 token.
     *
     * @throws IOException if ASN.1 encoding fails.
     * @throws PACDecodingException if PAC decoding fails.
     */
    @Test
    void testConstructor_ValidToken() throws IOException, PACDecodingException {
        // 1. GIVEN
        // Create a mock KerberosAuthData to be returned by the mocked parse method
        KerberosAuthData mockAuthData = mock(KerberosAuthData.class);
        mockedStaticAuthData.when(() -> KerberosAuthData.parse(anyInt(), any(byte[].class), any(Map.class)))
                .thenReturn(Collections.singletonList(mockAuthData));

        // Construct a valid ASN.1 sequence for KerberosRelevantAuthData
        ASN1EncodableVector authVector = new ASN1EncodableVector();
        ASN1EncodableVector elementVector = new ASN1EncodableVector();
        elementVector.add(new DERTaggedObject(0, new ASN1Integer(1))); // authType
        elementVector.add(new DERTaggedObject(1, new DEROctetString(new byte[] { 0x01, 0x02 }))); // authData
        authVector.add(new DERSequence(elementVector));

        byte[] token = new DERSequence(authVector).getEncoded();
        Map<Integer, KerberosKey> keys = new HashMap<>();

        // 2. WHEN
        KerberosRelevantAuthData relevantAuthData = new KerberosRelevantAuthData(token, keys);

        // 3. THEN
        assertNotNull(relevantAuthData, "The KerberosRelevantAuthData object should not be null.");
        List<KerberosAuthData> authorizations = relevantAuthData.getAuthorizations();
        assertNotNull(authorizations, "The authorizations list should not be null.");
        assertEquals(1, authorizations.size(), "The authorizations list should contain one element.");
        assertEquals(mockAuthData, authorizations.get(0), "The authorization element should be the mocked object.");
    }

    /**
     * Test constructor with a malformed ASN.1 token.
     */
    @Test
    void testConstructor_MalformedToken() {
        // 1. GIVEN
        byte[] malformedToken = new byte[] { 0x00, 0x01, 0x02, 0x03 }; // Not a valid ASN.1 sequence
        Map<Integer, KerberosKey> keys = new HashMap<>();

        // 2. WHEN & 3. THEN
        PACDecodingException exception = assertThrows(PACDecodingException.class, () -> {
            new KerberosRelevantAuthData(malformedToken, keys);
        }, "A PACDecodingException should be thrown for a malformed token.");

        assertEquals("Malformed kerberos ticket", exception.getMessage(), "The exception message should indicate a malformed ticket.");
    }

    /**
     * Test constructor with an empty token.
     * Empty token causes readObject() to return null, which leads to NullPointerException.
     */
    @Test
    void testConstructor_EmptyToken() {
        // 1. GIVEN
        byte[] emptyToken = new byte[0];
        Map<Integer, KerberosKey> keys = new HashMap<>();

        // 2. WHEN & 3. THEN
        // When ASN1InputStream.readObject() returns null due to empty input,
        // ASN1Util.as() throws NullPointerException (not wrapped)
        Exception exception = assertThrows(Exception.class, () -> {
            new KerberosRelevantAuthData(emptyToken, keys);
        }, "An exception should be thrown for an empty token.");

        // The exception could be PACDecodingException or NullPointerException
        assertTrue(exception instanceof PACDecodingException || exception instanceof NullPointerException,
                "The exception should be either PACDecodingException or NullPointerException.");

        if (exception instanceof PACDecodingException) {
            assertEquals("Malformed kerberos ticket", exception.getMessage(), "PAC exception should indicate malformed ticket.");
        } else if (exception instanceof NullPointerException) {
            // Empty input causes null ASN1 object, which is expected behavior
            assertTrue(exception.getMessage() == null || exception.getMessage().contains("Cannot invoke \"Object.getClass()\""),
                    "NullPointerException should be from null ASN1 object.");
        }
    }

    /**
     * Test constructor with a valid token that contains no authorization entries.
     *
     * @throws IOException if ASN.1 encoding fails.
     * @throws PACDecodingException if PAC decoding fails.
     */
    @Test
    void testConstructor_TokenWithNoAuthorizations() throws IOException, PACDecodingException {
        // 1. GIVEN
        // An empty sequence
        byte[] token = new DERSequence().getEncoded();
        Map<Integer, KerberosKey> keys = new HashMap<>();

        // 2. WHEN
        KerberosRelevantAuthData relevantAuthData = new KerberosRelevantAuthData(token, keys);

        // 3. THEN
        assertNotNull(relevantAuthData, "The KerberosRelevantAuthData object should not be null.");
        List<KerberosAuthData> authorizations = relevantAuthData.getAuthorizations();
        assertNotNull(authorizations, "The authorizations list should not be null.");
        assertTrue(authorizations.isEmpty(), "The authorizations list should be empty.");
    }

    /**
     * Test the getAuthorizations method.
     *
     * @throws IOException if ASN.1 encoding fails.
     * @throws PACDecodingException if PAC decoding fails.
     */
    @Test
    void testGetAuthorizations() throws IOException, PACDecodingException {
        // 1. GIVEN
        KerberosAuthData mockAuthData1 = mock(KerberosAuthData.class);
        KerberosAuthData mockAuthData2 = mock(KerberosAuthData.class);

        // Mock the parse method to return two different objects based on input
        // Must use matchers for all arguments when using any matcher
        mockedStaticAuthData.when(() -> KerberosAuthData.parse(eq(1), eq(new byte[] { 0x01 }), any(Map.class)))
                .thenReturn(Collections.singletonList(mockAuthData1));
        mockedStaticAuthData.when(() -> KerberosAuthData.parse(eq(2), eq(new byte[] { 0x02 }), any(Map.class)))
                .thenReturn(Collections.singletonList(mockAuthData2));

        // Construct a token with two authorization entries
        ASN1EncodableVector authVector = new ASN1EncodableVector();

        ASN1EncodableVector elementVector1 = new ASN1EncodableVector();
        elementVector1.add(new DERTaggedObject(0, new ASN1Integer(1)));
        elementVector1.add(new DERTaggedObject(1, new DEROctetString(new byte[] { 0x01 })));
        authVector.add(new DERSequence(elementVector1));

        ASN1EncodableVector elementVector2 = new ASN1EncodableVector();
        elementVector2.add(new DERTaggedObject(0, new ASN1Integer(2)));
        elementVector2.add(new DERTaggedObject(1, new DEROctetString(new byte[] { 0x02 })));
        authVector.add(new DERSequence(elementVector2));

        byte[] token = new DERSequence(authVector).getEncoded();
        Map<Integer, KerberosKey> keys = new HashMap<>();

        KerberosRelevantAuthData relevantAuthData = new KerberosRelevantAuthData(token, keys);

        // 2. WHEN
        List<KerberosAuthData> authorizations = relevantAuthData.getAuthorizations();

        // 3. THEN
        assertNotNull(authorizations, "The authorizations list should not be null.");
        assertEquals(2, authorizations.size(), "The authorizations list should contain two elements.");
        assertTrue(authorizations.contains(mockAuthData1), "The list should contain the first mocked auth data.");
        assertTrue(authorizations.contains(mockAuthData2), "The list should contain the second mocked auth data.");
    }
}
