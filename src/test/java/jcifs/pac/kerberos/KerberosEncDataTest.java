package jcifs.pac.kerberos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.kerberos.KerberosKey;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.junit.jupiter.api.Test;

import jcifs.pac.PACDecodingException;

/**
 * Tests for KerberosEncData.
 */
class KerberosEncDataTest {

    /**
     * Test constructor with a valid token.
     *
     * @throws IOException if an I/O error occurs
     * @throws PACDecodingException if a PAC decoding error occurs
     * @throws UnknownHostException if the IP address is not found
     */
    @Test
    void testConstructor() throws IOException, PACDecodingException, UnknownHostException {
        // Build a sample Kerberos EncData structure
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new DERTaggedObject(2, new DERGeneralString("TEST.REALM")));

        ASN1EncodableVector principalVector = new ASN1EncodableVector();
        principalVector.add(new DERTaggedObject(0, new ASN1Integer(1))); // name-type
        ASN1EncodableVector nameVector = new ASN1EncodableVector();
        nameVector.add(new DERGeneralString("testuser"));
        principalVector.add(new DERTaggedObject(1, new DERSequence(nameVector)));
        vector.add(new DERTaggedObject(3, new DERSequence(principalVector)));

        ASN1EncodableVector addressesVector = new ASN1EncodableVector();
        ASN1EncodableVector addressVector = new ASN1EncodableVector();
        addressVector.add(new ASN1Integer(KerberosConstants.AF_INTERNET));
        addressVector.add(new DEROctetString(InetAddress.getByName("127.0.0.1").getAddress()));
        addressesVector.add(new DERSequence(addressVector));
        vector.add(new DERTaggedObject(9, new DERSequence(addressesVector)));

        ASN1EncodableVector authDataVector = new ASN1EncodableVector();
        ASN1EncodableVector authElementVector = new ASN1EncodableVector();
        // Use an auth type that doesn't require complex parsing (e.g., 999 - unknown type)
        authElementVector.add(new DERTaggedObject(0, new ASN1Integer(999))); // ad-type
        authElementVector.add(new DERTaggedObject(1, new DEROctetString(new byte[] { 1, 2, 3, 4 })));
        authDataVector.add(new DERSequence(authElementVector));
        vector.add(new DERTaggedObject(10, new DERSequence(authDataVector)));

        DERSequence sequence = new DERSequence(vector);
        byte[] encoded = new DERTaggedObject(false, BERTags.APPLICATION, 1, sequence).getEncoded();

        KerberosEncData encData = new KerberosEncData(encoded, Collections.emptyMap());

        assertEquals("TEST.REALM", encData.getUserRealm());
        assertEquals("testuser", encData.getUserPrincipalName());
        assertNotNull(encData.getUserAddresses());
        assertEquals(1, encData.getUserAddresses().size());
        assertEquals(InetAddress.getByName("127.0.0.1"), encData.getUserAddresses().get(0));
        assertNotNull(encData.getUserAuthorizations());
        // Assuming KerberosAuthData.parse is tested elsewhere and might return empty for this test case
        assertTrue(encData.getUserAuthorizations().isEmpty());
    }

    /**
     * Test constructor with a malformed token.
     */
    @Test
    void testConstructorMalformed() {
        byte[] malformedToken = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        assertThrows(PACDecodingException.class, () -> new KerberosEncData(malformedToken, Collections.emptyMap()));
    }

    /**
     * Test constructor with an unknown field.
     *
     * @throws IOException if an I/O error occurs
     */
    @Test
    void testConstructorUnknownField() throws IOException {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new DERTaggedObject(99, new DERGeneralString("unknown")));
        DERSequence sequence = new DERSequence(vector);
        byte[] encoded = new DERTaggedObject(false, BERTags.APPLICATION, 1, sequence).getEncoded();

        assertThrows(PACDecodingException.class, () -> new KerberosEncData(encoded, Collections.emptyMap()));
    }

    /**
     * Test decrypt with RC4 encryption.
     *
     * @throws GeneralSecurityException if a security error occurs
     */
    @Test
    void testDecryptRc4() throws GeneralSecurityException {
        // This is a simplified test and does not use real encrypted data from Kerberos
        // It mainly tests the decryption logic path
        Key key = new KerberosKey(null, new byte[16], KerberosConstants.RC4_ENC_TYPE, 0);
        byte[] data = new byte[32]; // Dummy data
        // The test will likely fail with "Checksum failed" as the data is not properly encrypted
        // but it proves the decryption path is taken.
        assertThrows(GeneralSecurityException.class, () -> KerberosEncData.decrypt(data, key, KerberosConstants.RC4_ENC_TYPE));
    }

    /**
     * Test decrypt with DES encryption.
     *
     * @throws GeneralSecurityException if a security error occurs
     * @throws NoSuchAlgorithmException if the algorithm is not available
     */
    @Test
    void testDecryptDes() throws GeneralSecurityException, NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56);
        SecretKey secretKey = keyGen.generateKey();
        Key key = new KerberosKey(null, secretKey.getEncoded(), KerberosConstants.DES_ENC_TYPE, 0);
        byte[] data = new byte[32]; // Dummy data, must be multiple of 8
        byte[] decrypted = KerberosEncData.decrypt(data, key, KerberosConstants.DES_ENC_TYPE);
        assertNotNull(decrypted);
        // With dummy data, we can't verify the content, just that it decrypts without error
        // and returns a result of the expected size.
        assertEquals(data.length - 24, decrypted.length);
    }

    /**
     * Test decrypt with an unsupported encryption type.
     */
    @Test
    void testDecryptUnsupportedType() {
        Key key = new KerberosKey(null, new byte[16], 99, 0);
        byte[] data = new byte[16];
        Exception exception = assertThrows(GeneralSecurityException.class, () -> KerberosEncData.decrypt(data, key, 99));
        assertEquals("Unsupported encryption type 99", exception.getMessage());
    }

    /**
     * Test getters with null values.
     *
     * @throws IOException if an I/O error occurs
     * @throws PACDecodingException if a PAC decoding error occurs
     */
    @Test
    void testGettersWithNull() throws IOException, PACDecodingException {
        // Build a token with no optional fields
        ASN1EncodableVector vector = new ASN1EncodableVector();
        DERSequence sequence = new DERSequence(vector);
        byte[] encoded = new DERTaggedObject(false, BERTags.APPLICATION, 1, sequence).getEncoded();

        KerberosEncData encData = new KerberosEncData(encoded, Collections.emptyMap());

        assertEquals(null, encData.getUserRealm());
        assertEquals(null, encData.getUserPrincipalName());
        assertEquals(null, encData.getUserAddresses());
        assertEquals(null, encData.getUserAuthorizations());
    }
}
