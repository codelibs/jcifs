package jcifs.pac.kerberos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import javax.security.auth.kerberos.KerberosKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.pac.PACDecodingException;

class KerberosApRequestTest {

    // Helper: build a minimal, valid-looking ASN.1 AP-REQ sequence with tags 0/1/2
    private ASN1Sequence buildMinimalApReqSeq(byte apOptions) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        // pvno [0] INTEGER 5
        v.add(new DERTaggedObject(true, 0, new ASN1Integer(Integer.parseInt(KerberosConstants.KERBEROS_VERSION))));
        // msg-type [1] INTEGER 14 (AP-REQ)
        v.add(new DERTaggedObject(true, 1, new ASN1Integer(Integer.parseInt(KerberosConstants.KERBEROS_AP_REQ))));
        // ap-options [2] BIT STRING
        v.add(new DERTaggedObject(true, 2, new DERBitString(new byte[] { apOptions }))); // first byte read by impl
        return new DERSequence(v);
    }

    @Test
    @DisplayName("byte[] ctor: empty token throws PACDecodingException with clear message")
    void byteArrayConstructor_emptyToken_throws() {
        // Arrange
        byte[] empty = new byte[0];

        // Act + Assert
        PACDecodingException ex = assertThrows(PACDecodingException.class, () -> new KerberosApRequest(empty, new KerberosKey[0]));
        assertTrue(ex.getMessage().contains("Empty kerberos ApReq"));
    }

    @Test
    @DisplayName("byte[] ctor: malformed DER is wrapped as PACDecodingException (IOException path)")
    void byteArrayConstructor_malformedDER_throwsWrapped() {
        // Arrange: Truncated SEQUENCE (0x30 len=2 but only 1 byte of content)
        byte[] malformed = new byte[] { 0x30, 0x02, 0x01 };

        // Act + Assert
        PACDecodingException ex = assertThrows(PACDecodingException.class, () -> new KerberosApRequest(malformed, null));
        assertTrue(ex.getMessage().contains("Malformed Kerberos Ticket"));
    }

    @Test
    @DisplayName("byte[] ctor: top-level non-SEQUENCE triggers PACDecodingException (type mismatch)")
    void byteArrayConstructor_topLevelNotSequence_throws() throws Exception {
        // Arrange: Encoded INTEGER instead of SEQUENCE
        byte[] notASequence = new ASN1Integer(42).getEncoded();

        // Act + Assert
        assertThrows(PACDecodingException.class, () -> new KerberosApRequest(notASequence, null));
    }

    @Test
    @DisplayName("seq ctor: valid minimal sequence sets apOptions and leaves ticket null")
    void sequenceConstructor_minimal_valid_setsApOptions_noTicket() throws Exception {
        // Arrange
        byte ap = (byte) 0x7A;
        ASN1Sequence seq = buildMinimalApReqSeq(ap);

        // Act
        KerberosApRequest req = new KerberosApRequest(seq, null);

        // Assert
        assertEquals(ap, req.getApOptions(), "apOptions should reflect BIT STRING's first byte");
        assertNull(req.getTicket(), "ticket should be null when tag 3 is absent");
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 4, 6, 99 })
    @DisplayName("seq ctor: invalid pvno values throw")
    void sequenceConstructor_invalidVersion_throws(int badPvno) throws Exception {
        // Arrange: Build sequence with invalid version and otherwise valid tags
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(true, 0, new ASN1Integer(badPvno))); // wrong pvno
        v.add(new DERTaggedObject(true, 1, new ASN1Integer(Integer.parseInt(KerberosConstants.KERBEROS_AP_REQ))));
        v.add(new DERTaggedObject(true, 2, new DERBitString(new byte[] { 0x00 })));
        ASN1Sequence seq = new DERSequence(v);

        // Act + Assert
        PACDecodingException ex = assertThrows(PACDecodingException.class, () -> new KerberosApRequest(seq, null));
        assertTrue(ex.getMessage().contains("Invalid kerberos version"));
    }

    @ParameterizedTest
    @ValueSource(ints = { -1, 0, 13, 15, 99 })
    @DisplayName("seq ctor: invalid msgType values throw")
    void sequenceConstructor_invalidMsgType_throws(int badType) throws Exception {
        // Arrange: correct version, wrong msg type
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(true, 0, new ASN1Integer(Integer.parseInt(KerberosConstants.KERBEROS_VERSION))));
        v.add(new DERTaggedObject(true, 1, new ASN1Integer(badType)));
        v.add(new DERTaggedObject(true, 2, new DERBitString(new byte[] { 0x01 })));
        ASN1Sequence seq = new DERSequence(v);

        // Act + Assert
        PACDecodingException ex = assertThrows(PACDecodingException.class, () -> new KerberosApRequest(seq, null));
        assertTrue(ex.getMessage().contains("Invalid kerberos request"));
    }

    @Test
    @DisplayName("seq ctor: unknown field tag causes failure")
    void sequenceConstructor_unknownField_throws() {
        // Arrange: only an unexpected tag is present
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(true, 99, new ASN1Integer(1)));
        ASN1Sequence seq = new DERSequence(v);

        // Act + Assert
        PACDecodingException ex = assertThrows(PACDecodingException.class, () -> new KerberosApRequest(seq, null));
        assertTrue(ex.getMessage().contains("Invalid field in kerberos ticket"));
    }

    @Test
    @DisplayName("seq ctor: tag 3 with wrong tag class is rejected")
    void sequenceConstructor_ticketTag_wrongClass_throws() {
        // Arrange: minimal valid fields + tag 3 as CONTEXT-SPECIFIC instead of APPLICATION
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(true, 0, new ASN1Integer(Integer.parseInt(KerberosConstants.KERBEROS_VERSION))));
        v.add(new DERTaggedObject(true, 1, new ASN1Integer(Integer.parseInt(KerberosConstants.KERBEROS_AP_REQ))));
        v.add(new DERTaggedObject(true, 2, new DERBitString(new byte[] { 0x02 })));
        // Tag 3 should be passed as ASN1TaggedObject which will be checked for APPLICATION tag class
        // Create a context-specific tagged object (wrong tag class)
        v.add(new DERTaggedObject(true, 3, new DERTaggedObject(true, 0, new DERSequence(new ASN1EncodableVector()))));
        ASN1Sequence seq = new DERSequence(v);

        // Act + Assert
        // Note: The actual error will be from ASN1Util.as() trying to cast to ASN1TaggedObject
        assertThrows(PACDecodingException.class, () -> new KerberosApRequest(seq, null));
    }

    @Test
    @DisplayName("seq ctor: tag 3 APPLICATION triggers ticket parsing")
    void sequenceConstructor_ticketTag_application_triggersTicketParsing() throws Exception {
        // Arrange: minimal valid fields + APPLICATION tag 3
        ASN1EncodableVector v = new ASN1EncodableVector();
        byte ap = (byte) 0x12;
        v.add(new DERTaggedObject(true, 0, new ASN1Integer(Integer.parseInt(KerberosConstants.KERBEROS_VERSION))));
        v.add(new DERTaggedObject(true, 1, new ASN1Integer(Integer.parseInt(KerberosConstants.KERBEROS_AP_REQ))));
        v.add(new DERTaggedObject(true, 2, new DERBitString(new byte[] { ap })));

        // APPLICATION tag 3 with empty sequence - will fail during KerberosTicket parsing
        // but shows that APPLICATION tag is properly recognized
        DERSequence emptyBase = new DERSequence(new ASN1EncodableVector());
        DERTaggedObject appTag = new DERTaggedObject(false, BERTags.APPLICATION, 3, emptyBase);
        v.add(appTag);
        ASN1Sequence seq = new DERSequence(v);

        // Act + Assert
        // The KerberosTicket constructor will throw because the empty sequence is not a valid ticket
        assertThrows(PACDecodingException.class, () -> new KerberosApRequest(seq, new KerberosKey[0]));

        // Verify apOptions is set correctly in a minimal sequence without ticket
        KerberosApRequest req = new KerberosApRequest(buildMinimalApReqSeq(ap), null);
        assertEquals(ap, req.getApOptions());
        assertNull(req.getTicket());
    }

    @Test
    @DisplayName("seq ctor: IOException while encoding base ticket is wrapped")
    void sequenceConstructor_ticketBaseEncodingIOException_isWrapped() throws Exception {
        // Arrange minimal valid fields
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(true, 0, new ASN1Integer(Integer.parseInt(KerberosConstants.KERBEROS_VERSION))));
        v.add(new DERTaggedObject(true, 1, new ASN1Integer(Integer.parseInt(KerberosConstants.KERBEROS_AP_REQ))));
        v.add(new DERTaggedObject(true, 2, new DERBitString(new byte[] { 0x01 })));

        // Create a custom APPLICATION tagged object that throws IOException when encoding
        // We need to create a proper ASN1TaggedObject with APPLICATION tag class
        // Create a custom base object that throws IOException
        ASN1Encodable badBase = new ASN1Encodable() {
            @Override
            public ASN1Primitive toASN1Primitive() {
                // Return a primitive that will throw IOException when getEncoded is called
                return new DEROctetString(new byte[0]) {
                    @Override
                    public byte[] getEncoded() throws IOException {
                        throw new IOException("encode failure");
                    }
                };
            }
        };

        DERTaggedObject appTag = new DERTaggedObject(false, BERTags.APPLICATION, 3, badBase);
        v.add(appTag);
        ASN1Sequence seq = new BERSequence(v);

        // Act + Assert
        // When IOException occurs during encoding, it should be wrapped in a PACDecodingException
        assertThrows(PACDecodingException.class, () -> new KerberosApRequest(seq, null));
    }
}
