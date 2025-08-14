package jcifs.pac.kerberos;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.junit.jupiter.api.Test;

import jcifs.pac.PACDecodingException;

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
     * Test constructor with missing APPLICATION tag in the token.
     *
     * @throws IOException if an I/O error occurs
     */
    @Test
    void testConstructorWithMissingApplicationTag() throws IOException {
        // Create inner content with OID and magic bytes but wrong tag after
        ByteArrayOutputStream innerContent = new ByteArrayOutputStream();
        ASN1ObjectIdentifier kerberosOid = new ASN1ObjectIdentifier(KerberosConstants.KERBEROS_OID);
        innerContent.write(kerberosOid.getEncoded());
        innerContent.write(0x01); // magic byte 1
        innerContent.write(0x00); // magic byte 2

        // Add a sequence instead of APPLICATION tagged object
        DERSequence wrongTag = new DERSequence(new ASN1Encodable[] { new ASN1Integer(5) });
        innerContent.write(wrongTag.getEncoded());

        byte[] content = innerContent.toByteArray();

        // Create GSS-API wrapper
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(0x60); // APPLICATION 0
        baos.write(content.length);
        baos.write(content);

        byte[] token = baos.toByteArray();
        assertThrows(PACDecodingException.class, () -> new KerberosToken(token));
    }

    /**
     * Test constructor with APPLICATION tag but wrong tag class.
     *
     * @throws IOException if an I/O error occurs
     */
    @Test
    void testConstructorWithWrongTagClass() throws IOException {
        // Create AP-REQ structure
        ASN1Sequence apReqSequence = new DERSequence(new ASN1Encodable[] { new DERTaggedObject(true, 0, new ASN1Integer(5)), // pvno
                new DERTaggedObject(true, 1, new ASN1Integer(14)), // msg-type
        });

        // Create CONTEXT tagged object instead of APPLICATION
        DERTaggedObject contextTag = new DERTaggedObject(false, 14, apReqSequence);

        // Build inner content with OID and magic bytes
        ByteArrayOutputStream innerContent = new ByteArrayOutputStream();
        ASN1ObjectIdentifier kerberosOid = new ASN1ObjectIdentifier(KerberosConstants.KERBEROS_OID);
        innerContent.write(kerberosOid.getEncoded());
        innerContent.write(0x01); // magic byte 1
        innerContent.write(0x00); // magic byte 2
        innerContent.write(contextTag.getEncoded());

        byte[] content = innerContent.toByteArray();

        // Create GSS-API wrapper
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(0x60); // APPLICATION 0
        baos.write(content.length);
        baos.write(content);

        byte[] token = baos.toByteArray();
        assertThrows(PACDecodingException.class, () -> new KerberosToken(token));
    }

    /**
     * Test constructor with APPLICATION tag but non-sequence content.
     *
     * @throws IOException if an I/O error occurs
     */
    @Test
    void testConstructorWithNonSequenceContent() throws IOException {
        // Create APPLICATION tagged object with non-sequence content
        DERTaggedObject appTag = new DERTaggedObject(false, BERTags.APPLICATION | 14, new ASN1Integer(5));

        // Build inner content with OID and magic bytes
        ByteArrayOutputStream innerContent = new ByteArrayOutputStream();
        ASN1ObjectIdentifier kerberosOid = new ASN1ObjectIdentifier(KerberosConstants.KERBEROS_OID);
        innerContent.write(kerberosOid.getEncoded());
        innerContent.write(0x01); // magic byte 1
        innerContent.write(0x00); // magic byte 2
        innerContent.write(appTag.getEncoded());

        byte[] content = innerContent.toByteArray();

        // Create GSS-API wrapper
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(0x60); // APPLICATION 0
        baos.write(content.length);
        baos.write(content);

        byte[] token = baos.toByteArray();
        assertThrows(PACDecodingException.class, () -> new KerberosToken(token));
    }

    // Helper methods to create test tokens

    private byte[] createGssApiWrapper(ASN1ObjectIdentifier oid, byte[] data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // Build the inner content
        ByteArrayOutputStream innerContent = new ByteArrayOutputStream();
        innerContent.write(oid.getEncoded());
        innerContent.write(data);

        byte[] content = innerContent.toByteArray();

        // Create GSS-API APPLICATION 0 tag
        baos.write(0x60); // APPLICATION 0

        // Write length
        if (content.length < 128) {
            baos.write(content.length);
        } else if (content.length < 256) {
            baos.write(0x81); // length of length = 1
            baos.write(content.length);
        } else {
            baos.write(0x82); // length of length = 2
            baos.write((content.length >> 8) & 0xFF);
            baos.write(content.length & 0xFF);
        }

        baos.write(content);
        return baos.toByteArray();
    }
}
