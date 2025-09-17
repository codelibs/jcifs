package org.codelibs.jcifs.smb.pac.kerberos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

import javax.security.auth.kerberos.KerberosKey;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.codelibs.jcifs.smb.pac.PACDecodingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for the KerberosTicket class.
 */
@ExtendWith(MockitoExtension.class)
class KerberosTicketTest {

    @Mock
    private KerberosKey kerberosKey;

    private KerberosKey[] keys;

    private static final String SERVER_REALM = "EXAMPLE.COM";
    private static final String SERVER_PRINCIPAL_NAME = "krbtgt/EXAMPLE.COM";
    private static final String USER_PRINCIPAL_NAME = "user@EXAMPLE.COM";
    private static final String USER_REALM = "EXAMPLE.COM";
    private static final int ENCRYPTION_TYPE = 23; // aes128-cts-hmac-sha1-96
    private static final byte[] ENCRYPTED_DATA = "encrypted-data".getBytes();

    @BeforeEach
    void setUp() {
        keys = new KerberosKey[] { kerberosKey };
    }

    /**
     * Creates a byte array representing a Kerberos ticket for testing purposes.
     * @param version Kerberos version
     * @param realm Server realm
     * @param principalName Server principal name
     * @param encType Encryption type
     * @param encryptedData Encrypted data
     * @param unknownTag Optional unknown tag number to test error handling
     * @return A byte array representing the ticket
     * @throws IOException on encoding error
     */
    private byte[] createTestTicketBytes(Number version, String realm, String principalName, int encType, byte[] encryptedData,
            Integer unknownTag) throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(true, 0, new ASN1Integer(version.longValue())));
        v.add(new DERTaggedObject(true, 1, new DERGeneralString(realm)));

        ASN1EncodableVector principalNameVector = new ASN1EncodableVector();
        for (String part : principalName.split("/")) {
            principalNameVector.add(new DERGeneralString(part));
        }
        ASN1EncodableVector principalVector = new ASN1EncodableVector();
        principalVector.add(new DERTaggedObject(true, 0, new ASN1Integer(1))); // name-type
        principalVector.add(new DERTaggedObject(true, 1, new DERSequence(principalNameVector)));
        v.add(new DERTaggedObject(true, 2, new DERSequence(principalVector)));

        ASN1EncodableVector encPart = new ASN1EncodableVector();
        encPart.add(new DERTaggedObject(true, 0, new ASN1Integer(encType)));
        // Add kvno (key version number) field that is optional but expected when accessing index 2
        encPart.add(new DERTaggedObject(true, 1, new ASN1Integer(1))); // kvno
        encPart.add(new DERTaggedObject(true, 2, new DEROctetString(encryptedData)));
        v.add(new DERTaggedObject(true, 3, new DERSequence(encPart)));

        if (unknownTag != null) {
            v.add(new DERTaggedObject(true, unknownTag, new DERGeneralString("unknown")));
        }

        return new DERSequence(v).getEncoded();
    }

    /**
     * Creates a byte array representing the decrypted data part of a Kerberos ticket.
     * @param userName User principal name
     * @param userRealm User realm
     * @return A byte array representing the decrypted data
     * @throws IOException on encoding error
     */
    private byte[] createDecryptedDataBytes(String userName, String userRealm) throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();

        // crealm (field 2)
        v.add(new DERTaggedObject(true, 2, new DERGeneralString(userRealm)));

        // cname (field 3)
        ASN1EncodableVector principalNameVector = new ASN1EncodableVector();
        principalNameVector.add(new DERGeneralString(userName));
        ASN1EncodableVector principalVector = new ASN1EncodableVector();
        principalVector.add(new DERTaggedObject(true, 0, new ASN1Integer(1))); // name-type
        principalVector.add(new DERTaggedObject(true, 1, new DERSequence(principalNameVector)));
        v.add(new DERTaggedObject(true, 3, new DERSequence(principalVector)));

        // Wrap in APPLICATION tag as expected by KerberosEncData
        DERSequence seq = new DERSequence(v);
        return new DERTaggedObject(false, BERTags.APPLICATION, 3, seq).getEncoded();
    }

    @Test
    void testConstructorWithEmptyToken() {
        // Test that PACDecodingException is thrown for an empty token
        byte[] emptyToken = new byte[0];
        PACDecodingException e = assertThrows(PACDecodingException.class, () -> new KerberosTicket(emptyToken, (byte) 0, keys));
        assertEquals("Empty kerberos ticket", e.getMessage());
    }

    @Test
    void testConstructorWithMalformedToken() {
        // Test that PACDecodingException is thrown for a malformed token
        byte[] malformedToken = new byte[] { 0x01, 0x02, 0x03 };
        PACDecodingException e = assertThrows(PACDecodingException.class, () -> new KerberosTicket(malformedToken, (byte) 0, keys));
        assertTrue(e.getMessage().startsWith("Malformed kerberos ticket"));
    }

    @Test
    void testConstructorWithInvalidVersion() throws IOException {
        // Test with an invalid Kerberos version
        byte[] invalidVersionToken = createTestTicketBytes(99, SERVER_REALM, SERVER_PRINCIPAL_NAME, ENCRYPTION_TYPE, ENCRYPTED_DATA, null);
        PACDecodingException e = assertThrows(PACDecodingException.class, () -> new KerberosTicket(invalidVersionToken, (byte) 0, keys));
        assertTrue(e.getMessage().startsWith("Invalid kerberos version"));
    }

    @Test
    void testConstructorWithBigIntegerVersion() throws IOException {
        // Test with a BigInteger Kerberos version
        byte[] validToken = createTestTicketBytes(new BigInteger(KerberosConstants.KERBEROS_VERSION), SERVER_REALM, SERVER_PRINCIPAL_NAME,
                ENCRYPTION_TYPE, ENCRYPTED_DATA, null);
        // This should not throw an exception if decryption is mocked
        try (MockedStatic<KerberosEncData> mockedEncData = Mockito.mockStatic(KerberosEncData.class)) {
            byte[] decryptedData = createDecryptedDataBytes(USER_PRINCIPAL_NAME, USER_REALM);
            mockedEncData.when(() -> KerberosEncData.decrypt(ENCRYPTED_DATA, kerberosKey, ENCRYPTION_TYPE)).thenReturn(decryptedData);
            when(kerberosKey.getKeyType()).thenReturn(ENCRYPTION_TYPE);

            KerberosTicket ticket = new KerberosTicket(validToken, (byte) 0, keys);
            assertNotNull(ticket);
        }
    }

    @Test
    void testConstructorWithKeyNotFound() throws IOException {
        // Test when no suitable Kerberos key is found
        byte[] token = createTestTicketBytes(new BigInteger(KerberosConstants.KERBEROS_VERSION), SERVER_REALM, SERVER_PRINCIPAL_NAME,
                ENCRYPTION_TYPE, ENCRYPTED_DATA, null);
        when(kerberosKey.getKeyType()).thenReturn(99); // Different key type

        PACDecodingException e = assertThrows(PACDecodingException.class, () -> new KerberosTicket(token, (byte) 0, keys));
        assertEquals("Kerberos key not found for eType " + ENCRYPTION_TYPE, e.getMessage());
    }

    @Test
    void testConstructorWithDecryptionFailure() throws IOException, GeneralSecurityException {
        // Test when decryption fails
        byte[] token = createTestTicketBytes(new BigInteger(KerberosConstants.KERBEROS_VERSION), SERVER_REALM, SERVER_PRINCIPAL_NAME,
                ENCRYPTION_TYPE, ENCRYPTED_DATA, null);
        when(kerberosKey.getKeyType()).thenReturn(ENCRYPTION_TYPE);

        try (MockedStatic<KerberosEncData> mockedEncData = Mockito.mockStatic(KerberosEncData.class)) {
            mockedEncData.when(() -> KerberosEncData.decrypt(ENCRYPTED_DATA, kerberosKey, ENCRYPTION_TYPE))
                    .thenThrow(new GeneralSecurityException("Decryption error"));

            PACDecodingException e = assertThrows(PACDecodingException.class, () -> new KerberosTicket(token, (byte) 0, keys));
            assertTrue(e.getMessage().startsWith("Decryption failed"));
        }
    }

    @Test
    void testConstructorWithUnrecognizedField() throws IOException, GeneralSecurityException {
        // Test with an unrecognized field in the ticket
        // Note: In the actual implementation, field 99 would come after mandatory fields,
        // so decryption happens first. We test with a mocked successful decryption.
        byte[] token = createTestTicketBytes(new BigInteger(KerberosConstants.KERBEROS_VERSION), SERVER_REALM, SERVER_PRINCIPAL_NAME,
                ENCRYPTION_TYPE, ENCRYPTED_DATA, 99);
        byte[] decryptedData = createDecryptedDataBytes(USER_PRINCIPAL_NAME, USER_REALM);

        when(kerberosKey.getKeyType()).thenReturn(ENCRYPTION_TYPE);

        try (MockedStatic<KerberosEncData> mockedEncData = Mockito.mockStatic(KerberosEncData.class)) {
            mockedEncData.when(() -> KerberosEncData.decrypt(ENCRYPTED_DATA, kerberosKey, ENCRYPTION_TYPE)).thenReturn(decryptedData);

            PACDecodingException e = assertThrows(PACDecodingException.class, () -> new KerberosTicket(token, (byte) 0, keys));
            assertEquals("Unrecognized field 99", e.getMessage());
        }
    }

    @Test
    void testConstructorAndGettersWithValidTicket() throws IOException, GeneralSecurityException, PACDecodingException {
        // Test successful instantiation and getter methods with a valid ticket
        byte[] validToken = createTestTicketBytes(new BigInteger(KerberosConstants.KERBEROS_VERSION), SERVER_REALM, SERVER_PRINCIPAL_NAME,
                ENCRYPTION_TYPE, ENCRYPTED_DATA, null);
        byte[] decryptedData = createDecryptedDataBytes(USER_PRINCIPAL_NAME, USER_REALM);

        when(kerberosKey.getKeyType()).thenReturn(ENCRYPTION_TYPE);

        try (MockedStatic<KerberosEncData> mockedEncData = Mockito.mockStatic(KerberosEncData.class)) {
            mockedEncData.when(() -> KerberosEncData.decrypt(ENCRYPTED_DATA, kerberosKey, ENCRYPTION_TYPE)).thenReturn(decryptedData);

            // When
            KerberosTicket ticket = new KerberosTicket(validToken, (byte) 0, keys);

            // Then
            assertNotNull(ticket);
            assertEquals(SERVER_REALM, ticket.getServerRealm());
            assertEquals(SERVER_PRINCIPAL_NAME, ticket.getServerPrincipalName());
            assertNotNull(ticket.getEncData());

            // Also test getters that delegate to KerberosEncData
            assertEquals(USER_PRINCIPAL_NAME, ticket.getUserPrincipalName());
            assertEquals(USER_REALM, ticket.getUserRealm());
        }
    }

    // Note: Testing the code path where keys are null and retrieved from
    // KerberosCredentials requires mocking the constructor of KerberosCredentials,
    // which is not possible with standard Mockito. A tool like PowerMock would be needed.
}