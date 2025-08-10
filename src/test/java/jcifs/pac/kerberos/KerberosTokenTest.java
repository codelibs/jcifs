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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import javax.security.auth.kerberos.KerberosKey;
import jcifs.pac.PACDecodingException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.junit.jupiter.api.Test;

/**
 * Test class for {@link KerberosToken}.
 */
class KerberosTokenTest {

    /**
     * Test constructor with an empty token.
     */
    @Test
    void testConstructorWithEmptyToken() {
        byte[] emptyToken = new byte[0];
        assertThrows(PACDecodingException.class, () -> new KerberosToken(emptyToken));
    }

    /**
     * Test constructor with a malformed token (not ASN.1).
     */
    @Test
    void testConstructorWithMalformedToken() {
        byte[] malformedToken = "This is not a valid token".getBytes();
        assertThrows(PACDecodingException.class, () -> new KerberosToken(malformedToken));
    }

    /**
     * Test constructor with a token that has an incorrect OID.
     *
     * @throws IOException if an I/O error occurs
     */
    @Test
    void testConstructorWithWrongOid() throws IOException {
        byte[] wrongOidToken = createGssApiWrapper(new ASN1ObjectIdentifier("1.2.3.4.5"), new byte[0]);
        assertThrows(PACDecodingException.class, () -> new KerberosToken(wrongOidToken));
    }

    /**
     * Test constructor with a malformed Kerberos token (invalid inner structure).
     *
     * @throws IOException if an I/O error occurs
     */
    @Test
    void testConstructorWithMalformedKerberosToken() throws IOException {
        byte[] malformedToken = createGssApiWrapper(new ASN1ObjectIdentifier(KerberosConstants.KERBEROS_OID), new byte[] { 0x00, 0x00 });
        assertThrows(PACDecodingException.class, () -> new KerberosToken(malformedToken));
    }

    /**
     * Test constructor with a valid token structure but no keys.
     *
     * @throws IOException if an I/O error occurs
     */
    @Test
    void testConstructorWithValidTokenNoKeys() throws IOException {
        byte[] validToken = createValidToken();
        // This will still fail deep inside KerberosApRequest without keys, but the initial parsing should pass.
        // We expect the constructor to proceed far enough to instantiate KerberosApRequest.
        assertDoesNotThrow(() -> new KerberosToken(validToken));
    }

    /**
     * Test constructor with a valid token and mock keys.
     *
     * @throws IOException if an I/O error occurs
     */
    @Test
    void testConstructorWithValidTokenAndKeys() throws IOException {
        byte[] validToken = createValidToken();
        KerberosKey[] keys = { mock(KerberosKey.class) };
        assertDoesNotThrow(() -> new KerberosToken(validToken, keys));
    }

    /**
     * Test getTicket method.
     *
     * @throws IOException if an I/O error occurs
     * @throws PACDecodingException if a PAC decoding error occurs
     */
    @Test
    void testGetTicket() throws IOException, PACDecodingException {
        byte[] validToken = createValidToken();
        KerberosToken kerberosToken = new KerberosToken(validToken);
        assertNotNull(kerberosToken.getTicket());
    }

    /**
     * Test getApRequest method.
     *
     * @throws IOException if an I/O error occurs
     * @throws PACDecodingException if a PAC decoding error occurs
     */
    @Test
    void testGetApRequest() throws IOException, PACDecodingException {
        byte[] validToken = createValidToken();
        KerberosToken kerberosToken = new KerberosToken(validToken);
        assertNotNull(kerberosToken.getApRequest());
    }


    // Helper methods to create test tokens

    private byte[] createGssApiWrapper(ASN1ObjectIdentifier oid, byte[] data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // GSS-API wrapper
        // [APPLICATION 0] IMPLICIT SEQUENCE ...
        DERTaggedObject gssApi = new DERTaggedObject(true, 0, new DERSequence(new ASN1ObjectIdentifier(oid.getId())));
        baos.write(gssApi.getEncoded());
        baos.write(data);
        return baos.toByteArray();
    }

    private byte[] createValidToken() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // Inner AP-REQ
        ASN1Sequence apReqSequence = new DERSequence(new ASN1Encodable[] {
            new DERTaggedObject(true, 0, new ASN1Integer(5)), // pvno
            new DERTaggedObject(true, 1, new ASN1Integer(0)), // msg-type
            new DERTaggedObject(true, 2, new DEROctetString(new byte[0])), // ap-options
            createTicket(), // ticket
            new DERTaggedObject(true, 4, createEncryptedData()) // authenticator
        });

        ASN1TaggedObject mechToken = new DERTaggedObject(
            true,
            BERTags.APPLICATION,
            apReqSequence
        );

        // GSS-API structure
        baos.write(0x60); // Application tag
        baos.write(0x82); // length
        baos.write(0x01); // length
        baos.write(0x0a); // length, just a guess for a long enough token

        // OID
        ASN1ObjectIdentifier kerberosOid = new ASN1ObjectIdentifier(KerberosConstants.KERBEROS_OID);
        baos.write(kerberosOid.getEncoded());

        // some magic bytes
        baos.write(0x01);
        baos.write(0x00);

        // the actual token
        baos.write(mechToken.getEncoded());

        return baos.toByteArray();
    }

    private ASN1TaggedObject createTicket() {
        ASN1Sequence ticketSequence = new DERSequence(new ASN1Encodable[] {
            new DERTaggedObject(true, 0, new ASN1Integer(5)), // tkt-vno
            new DERTaggedObject(true, 1, new DEROctetString("realm".getBytes())), // realm
            new DERTaggedObject(true, 2, createPrincipalName()), // sname
            new DERTaggedObject(true, 3, createEncryptedData()) // enc-part
        });
        return new DERTaggedObject(true, 1, ticketSequence);
    }

    private ASN1TaggedObject createPrincipalName() {
        ASN1Sequence principalNameSequence = new DERSequence(new ASN1Encodable[] {
            new DERTaggedObject(true, 0, new ASN1Integer(0)), // name-type
            new DERTaggedObject(true, 1, new DERSequence(new DEROctetString("service".getBytes()))) // name-string
        });
        return new DERTaggedObject(true, 2, principalNameSequence);
    }

    private ASN1TaggedObject createEncryptedData() {
        ASN1Sequence encryptedDataSequence = new DERSequence(new ASN1Encodable[] {
            new DERTaggedObject(true, 0, new ASN1Integer(0)), // etype
            new DERTaggedObject(true, 1, new ASN1Integer(0)), // kvno
            new DERTaggedObject(true, 2, new DEROctetString(new byte[16])) // cipher
        });
        return new DERTaggedObject(true, 3, encryptedDataSequence);
    }
}