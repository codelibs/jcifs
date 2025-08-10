package jcifs.spnego;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class NegTokenInitTest {

    // Common OIDs used in tests
    private static final ASN1ObjectIdentifier OID_KRB = new ASN1ObjectIdentifier(SpnegoConstants.KERBEROS_MECHANISM);
    private static final ASN1ObjectIdentifier OID_KRB_LEGACY = new ASN1ObjectIdentifier(SpnegoConstants.LEGACY_KERBEROS_MECHANISM);
    private static final ASN1ObjectIdentifier OID_NTLM = new ASN1ObjectIdentifier(SpnegoConstants.NTLMSSP_MECHANISM);
    private static final String SPNEGO_OID_STR = SpnegoConstants.SPNEGO_MECHANISM;

    // Helper to build a SPNEGO NegTokenInit as per NegTokenInit#toByteArray but parameterized for tests
    private static byte[] buildInitToken(ASN1ObjectIdentifier[] mechs,
                                         Integer flags,
                                         byte[] mechToken,
                                         byte[] mic,
                                         boolean micInTag4,
                                         String spnegoOidOverride,
                                         Integer outerTagNoOverride,
                                         ASN1TaggedObject extraField) throws IOException {

        ASN1EncodableVector fields = new ASN1EncodableVector();
        if (mechs != null) {
            ASN1EncodableVector v = new ASN1EncodableVector();
            for (ASN1ObjectIdentifier m : mechs) {
                v.add(m);
            }
            fields.add(new DERTaggedObject(true, 0, new DERSequence(v)));
        }
        if (flags != null && flags != 0) {
            fields.add(new DERTaggedObject(true, 1, new DERBitString(flags)));
        }
        if (mechToken != null) {
            fields.add(new DERTaggedObject(true, 2, new DEROctetString(mechToken)));
        }
        if (mic != null) {
            int tag = micInTag4 ? 4 : 3;
            fields.add(new DERTaggedObject(true, tag, new DEROctetString(mic)));
        }
        if (extraField != null) {
            fields.add(extraField);
        }

        ASN1EncodableVector ev = new ASN1EncodableVector();
        String oid = (spnegoOidOverride != null) ? spnegoOidOverride : SPNEGO_OID_STR;
        ev.add(new ASN1ObjectIdentifier(oid));
        ev.add(new DERTaggedObject(true, 0, new DERSequence(fields)));

        int outerTagNo = (outerTagNoOverride != null) ? outerTagNoOverride : 0;

        ByteArrayOutputStream collector = new ByteArrayOutputStream();
        ASN1OutputStream der = ASN1OutputStream.create(collector, ASN1Encoding.DER);
        try {
            DERTaggedObject applicationWrapper = new DERTaggedObject(false, BERTags.APPLICATION, outerTagNo, new DERSequence(ev));
            der.writeObject(applicationWrapper);
        } finally {
            der.close();
        }
        return collector.toByteArray();
    }

    @Test
    @DisplayName("Round-trip: all fields set encodes and parses back correctly")
    void testRoundTripAllFields() throws Exception {
        ASN1ObjectIdentifier[] mechs = new ASN1ObjectIdentifier[] { OID_KRB, OID_NTLM };
        int flags = NegTokenInit.DELEGATION | NegTokenInit.MUTUAL_AUTHENTICATION | NegTokenInit.INTEGRITY;
        byte[] mechToken = new byte[] { 0x01, 0x02, 0x03 };
        byte[] mic = new byte[] { (byte) 0xFE, 0x55 };

        NegTokenInit init = new NegTokenInit(mechs, flags, mechToken, mic);
        byte[] bytes = init.toByteArray();

        NegTokenInit parsed = new NegTokenInit(bytes);

        assertArrayEquals(mechs, parsed.getMechanisms(), "Mechanism OIDs should round-trip");
        assertEquals(flags, parsed.getContextFlags(), "Flags should round-trip");
        assertArrayEquals(mechToken, parsed.getMechanismToken(), "Mechanism token should round-trip");
        assertArrayEquals(mic, parsed.getMechanismListMIC(), "MIC should round-trip");

        assertTrue(parsed.getContextFlag(NegTokenInit.DELEGATION));
        assertTrue(parsed.getContextFlag(NegTokenInit.MUTUAL_AUTHENTICATION));
        assertTrue(parsed.getContextFlag(NegTokenInit.INTEGRITY));
        assertFalse(parsed.getContextFlag(NegTokenInit.CONFIDENTIALITY));
    }

    @Test
    @DisplayName("Minimal token: no fields present")
    void testMinimalTokenRoundTrip() throws Exception {
        NegTokenInit init = new NegTokenInit(); // no fields
        byte[] bytes = init.toByteArray();

        NegTokenInit parsed = new NegTokenInit(bytes);
        assertNull(parsed.getMechanisms(), "Mechanisms should be null when absent");
        assertEquals(0, parsed.getContextFlags(), "Flags should be zero when absent");
        assertNull(parsed.getMechanismToken(), "Mechanism token should be null when absent");
        assertNull(parsed.getMechanismListMIC(), "MIC should be null when absent");
    }

    @Test
    @DisplayName("toString includes flags, mechanisms and MIC in hex")
    void testToStringIncludesFields() {
        ASN1ObjectIdentifier[] mechs = new ASN1ObjectIdentifier[] { OID_KRB_LEGACY };
        int flags = NegTokenInit.REPLAY_DETECTION | NegTokenInit.SEQUENCE_CHECKING;
        byte[] mic = new byte[] { 0x00, 0x0A, (byte) 0xFF };

        NegTokenInit init = new NegTokenInit(mechs, flags, null, mic);
        String s = init.toString();

        assertTrue(s.contains("flags=" + flags), "toString should include flags");
        assertTrue(s.contains(Arrays.toString(mechs)), "toString should include mechanisms");
        assertTrue(s.contains("000AFF"), "toString should include MIC hex");
    }

    @Test
    @DisplayName("Mechanism ordering is preserved after parse")
    void testMechanismOrderPreserved() throws Exception {
        ASN1ObjectIdentifier[] mechs = new ASN1ObjectIdentifier[] { OID_NTLM, OID_KRB, OID_KRB_LEGACY };
        NegTokenInit init = new NegTokenInit(mechs, 0, null, null);

        NegTokenInit parsed = new NegTokenInit(init.toByteArray());
        assertArrayEquals(mechs, parsed.getMechanisms(), "Mechanism order must be preserved");
    }

    @Test
    @DisplayName("setContextFlag toggles bits correctly")
    void testSetAndGetContextFlags() {
        NegTokenInit init = new NegTokenInit();
        assertEquals(0, init.getContextFlags());

        init.setContextFlag(NegTokenInit.CONFIDENTIALITY, true);
        assertTrue(init.getContextFlag(NegTokenInit.CONFIDENTIALITY));
        assertEquals(NegTokenInit.CONFIDENTIALITY, init.getContextFlags());

        init.setContextFlag(NegTokenInit.INTEGRITY, true);
        assertTrue(init.getContextFlag(NegTokenInit.INTEGRITY));
        assertEquals(NegTokenInit.CONFIDENTIALITY | NegTokenInit.INTEGRITY, init.getContextFlags());

        init.setContextFlag(NegTokenInit.CONFIDENTIALITY, false);
        assertFalse(init.getContextFlag(NegTokenInit.CONFIDENTIALITY));
        assertEquals(NegTokenInit.INTEGRITY, init.getContextFlags());
    }

    @Test
    @DisplayName("Parse rejects wrong SPNEGO OID")
    void testParseRejectsWrongOid() throws Exception {
        byte[] token = buildInitToken(
            new ASN1ObjectIdentifier[] { OID_KRB },
            0,
            null,
            null,
            false,
            "1.2.840.113554.1.2.2", // Kerberos OID instead of SPNEGO OID
            null,
            null
        );

        IOException ex = assertThrows(IOException.class, () -> new NegTokenInit(token));
        assertTrue(ex.getMessage().contains("OID"), "Error should mention OID");
    }

    @Test
    @DisplayName("Parse rejects wrong outer context tag number")
    void testParseRejectsWrongOuterTag() throws Exception {
        byte[] token = buildInitToken(
            new ASN1ObjectIdentifier[] { OID_KRB },
            0,
            null,
            null,
            false,
            null,
            1, // must be 0 per implementation
            null
        );

        IOException ex = assertThrows(IOException.class, () -> new NegTokenInit(token));
        assertTrue(ex.getMessage().contains("tag 1"), "Error should mention wrong tag number");
    }

    @Test
    @DisplayName("Parse rejects unknown nested token field")
    void testParseRejectsUnknownField() throws Exception {
        ASN1TaggedObject unknown = new DERTaggedObject(true, 7, new DEROctetString(new byte[] { 0x01 }));
        byte[] token = buildInitToken(
            new ASN1ObjectIdentifier[] { OID_KRB },
            0,
            null,
            null,
            false,
            null,
            null,
            unknown
        );

        IOException ex = assertThrows(IOException.class, () -> new NegTokenInit(token));
        assertTrue(ex.getMessage().contains("Malformed token field"), "Error should mention malformed field");
    }

    @Test
    @DisplayName("Parse handles MIC in tag [3] and [4] (compatibility)")
    void testParsesMicInTag4Compatibility() throws Exception {
        byte[] mic = new byte[] { 0x11, 0x22, 0x33 };

        // Tag [4]
        byte[] tokenTag4 = buildInitToken(
            new ASN1ObjectIdentifier[] { OID_KRB },
            null,
            null,
            mic,
            true,
            null,
            null,
            null
        );
        NegTokenInit p4 = new NegTokenInit(tokenTag4);
        assertArrayEquals(mic, p4.getMechanismListMIC(), "MIC should be parsed from tag [4]");

        // Tag [3]
        byte[] tokenTag3 = buildInitToken(
            new ASN1ObjectIdentifier[] { OID_KRB },
            null,
            null,
            mic,
            false,
            null,
            null,
            null
        );
        NegTokenInit p3 = new NegTokenInit(tokenTag3);
        assertArrayEquals(mic, p3.getMechanismListMIC(), "MIC should be parsed from tag [3]");
    }

    @Test
    @DisplayName("Tag [3] MIC with non-OctetString is ignored (no crash)")
    void testMicTag3NonOctetIgnored() throws Exception {
        // Manually craft a token where field [3] is not an OctetString (e.g., BitString)
        ASN1EncodableVector fields = new ASN1EncodableVector();
        // Add a dummy [3] BIT STRING which should be ignored by implementation
        fields.add(new DERTaggedObject(true, 3, new DERBitString(0xA5)));

        ASN1EncodableVector ev = new ASN1EncodableVector();
        ev.add(new ASN1ObjectIdentifier(SPNEGO_OID_STR));
        ev.add(new DERTaggedObject(true, 0, new DERSequence(fields)));

        ByteArrayOutputStream collector = new ByteArrayOutputStream();
        ASN1OutputStream der = ASN1OutputStream.create(collector, ASN1Encoding.DER);
        try {
            DERTaggedObject app = new DERTaggedObject(false, BERTags.APPLICATION, 0, new DERSequence(ev));
            der.writeObject(app);
        } finally {
            der.close();
        }
        byte[] token = collector.toByteArray();

        NegTokenInit parsed = new NegTokenInit(token);
        assertNull(parsed.getMechanismListMIC(), "Non-Octet MIC in tag [3] should be ignored");
    }

    @Test
    @DisplayName("Context flags encode as DER BIT STRING and parse back")
    void testContextFlagsRoundTripViaAsn1() throws Exception {
        int flags = NegTokenInit.ANONYMITY | NegTokenInit.CONFIDENTIALITY | NegTokenInit.SEQUENCE_CHECKING;
        byte[] token = buildInitToken(
            new ASN1ObjectIdentifier[] { OID_KRB },
            flags,
            null,
            null,
            false,
            null,
            null,
            null
        );
        NegTokenInit parsed = new NegTokenInit(token);
        assertEquals(flags, parsed.getContextFlags(), "Context flags should parse from DER BIT STRING");
    }

    @Test
    @DisplayName("Sanity: toByteArray produces APPLICATION class wrapper and valid structure")
    void testToByteArrayStructureSanity() throws Exception {
        NegTokenInit init = new NegTokenInit(
            new ASN1ObjectIdentifier[] { OID_KRB },
            NegTokenInit.INTEGRITY,
            new byte[] { 0x01 },
            new byte[] { 0x02 }
        );

        byte[] der = init.toByteArray();

        try (ASN1InputStream is = new ASN1InputStream(der)) {
            Object obj = is.readObject();
            assertTrue(obj instanceof ASN1TaggedObject, "Top-level should be tagged (APPLICATION)");
            ASN1TaggedObject top = (ASN1TaggedObject) obj;
            assertEquals(BERTags.APPLICATION, top.getTagClass(), "Top-level tag class should be APPLICATION");
            assertEquals(0, top.getTagNo(), "Top-level tag number should be 0");
            assertTrue(top.getBaseObject() instanceof ASN1Sequence, "Base object should be a sequence");
            ASN1Sequence seq = (ASN1Sequence) top.getBaseObject();
            assertEquals(2, seq.size(), "Sequence should contain OID and [0] NegTokenInit");
            assertTrue(seq.getObjectAt(0) instanceof ASN1ObjectIdentifier, "First element should be OID");
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) seq.getObjectAt(0);
            assertEquals(SPNEGO_OID_STR, oid.getId(), "OID should be SPNEGO");
        }
    }
}

