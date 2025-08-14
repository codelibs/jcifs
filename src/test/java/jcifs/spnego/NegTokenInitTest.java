package jcifs.spnego;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Stream;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("NegTokenInit SPNEGO Token Tests")
class NegTokenInitTest {

    // Common OIDs used in tests
    private static final ASN1ObjectIdentifier OID_KRB = new ASN1ObjectIdentifier(SpnegoConstants.KERBEROS_MECHANISM);
    private static final ASN1ObjectIdentifier OID_KRB_LEGACY = new ASN1ObjectIdentifier(SpnegoConstants.LEGACY_KERBEROS_MECHANISM);
    private static final ASN1ObjectIdentifier OID_NTLM = new ASN1ObjectIdentifier(SpnegoConstants.NTLMSSP_MECHANISM);
    private static final String SPNEGO_OID_STR = SpnegoConstants.SPNEGO_MECHANISM;

    // Helper to build a SPNEGO NegTokenInit as per NegTokenInit#toByteArray but parameterized for tests
    private static byte[] buildInitToken(ASN1ObjectIdentifier[] mechs, Integer flags, byte[] mechToken, byte[] mic, boolean micInTag4,
            String spnegoOidOverride, Integer outerTagNoOverride, ASN1TaggedObject extraField) throws IOException {

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
        byte[] token = buildInitToken(new ASN1ObjectIdentifier[] { OID_KRB }, 0, null, null, false, "1.2.840.113554.1.2.2", // Kerberos OID instead of SPNEGO OID
                null, null);

        IOException ex = assertThrows(IOException.class, () -> new NegTokenInit(token));
        assertTrue(ex.getMessage().contains("OID"), "Error should mention OID");
    }

    @Test
    @DisplayName("Parse accepts non-zero outer tag numbers (current implementation behavior)")
    void testParseAcceptsNonZeroOuterTag() throws Exception {
        // Note: The current implementation does not validate the outer APPLICATION tag number
        // This test documents the actual behavior - any tag number is accepted
        byte[] token =
                buildInitToken(new ASN1ObjectIdentifier[] { OID_KRB }, NegTokenInit.INTEGRITY, new byte[] { 0x42 }, null, false, null, 1, // Non-zero tag number is currently accepted
                        null);

        // The implementation accepts any tag number without validation
        assertDoesNotThrow(() -> {
            NegTokenInit parsed = new NegTokenInit(token);
            assertNotNull(parsed.getMechanisms(), "Should parse mechanisms");
            assertEquals(NegTokenInit.INTEGRITY, parsed.getContextFlags(), "Should parse flags");
            assertArrayEquals(new byte[] { 0x42 }, parsed.getMechanismToken(), "Should parse token");
        });
    }

    @Test
    @DisplayName("Parse rejects unknown nested token field")
    void testParseRejectsUnknownField() throws Exception {
        ASN1TaggedObject unknown = new DERTaggedObject(true, 7, new DEROctetString(new byte[] { 0x01 }));
        byte[] token = buildInitToken(new ASN1ObjectIdentifier[] { OID_KRB }, 0, null, null, false, null, null, unknown);

        IOException ex = assertThrows(IOException.class, () -> new NegTokenInit(token));
        assertTrue(ex.getMessage().contains("Malformed token field"), "Error should mention malformed field");
    }

    @Test
    @DisplayName("Parse handles MIC in tag [3] and [4] (compatibility)")
    void testParsesMicInTag4Compatibility() throws Exception {
        byte[] mic = new byte[] { 0x11, 0x22, 0x33 };

        // Tag [4]
        byte[] tokenTag4 = buildInitToken(new ASN1ObjectIdentifier[] { OID_KRB }, null, null, mic, true, null, null, null);
        NegTokenInit p4 = new NegTokenInit(tokenTag4);
        assertArrayEquals(mic, p4.getMechanismListMIC(), "MIC should be parsed from tag [4]");

        // Tag [3]
        byte[] tokenTag3 = buildInitToken(new ASN1ObjectIdentifier[] { OID_KRB }, null, null, mic, false, null, null, null);
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
        byte[] token = buildInitToken(new ASN1ObjectIdentifier[] { OID_KRB }, flags, null, null, false, null, null, null);
        NegTokenInit parsed = new NegTokenInit(token);
        assertEquals(flags, parsed.getContextFlags(), "Context flags should parse from DER BIT STRING");
    }

    @Test
    @DisplayName("Sanity: toByteArray produces APPLICATION class wrapper and valid structure")
    void testToByteArrayStructureSanity() throws Exception {
        NegTokenInit init =
                new NegTokenInit(new ASN1ObjectIdentifier[] { OID_KRB }, NegTokenInit.INTEGRITY, new byte[] { 0x01 }, new byte[] { 0x02 });

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

    @Nested
    @DisplayName("Context Flags Tests")
    class ContextFlagsTests {

        @ParameterizedTest
        @ValueSource(ints = { NegTokenInit.DELEGATION, NegTokenInit.MUTUAL_AUTHENTICATION, NegTokenInit.REPLAY_DETECTION,
                NegTokenInit.SEQUENCE_CHECKING, NegTokenInit.ANONYMITY, NegTokenInit.CONFIDENTIALITY, NegTokenInit.INTEGRITY })
        @DisplayName("Individual flag values are correctly set and retrieved")
        void testIndividualFlagValues(int flag) {
            NegTokenInit init = new NegTokenInit();

            // Initially false
            assertFalse(init.getContextFlag(flag));

            // Set to true
            init.setContextFlag(flag, true);
            assertTrue(init.getContextFlag(flag));
            assertEquals(flag, init.getContextFlags());

            // Set to false
            init.setContextFlag(flag, false);
            assertFalse(init.getContextFlag(flag));
            assertEquals(0, init.getContextFlags());
        }

        @Test
        @DisplayName("Multiple flags can be combined correctly")
        void testMultipleFlagsCombination() {
            NegTokenInit init = new NegTokenInit();

            // Set multiple flags
            init.setContextFlag(NegTokenInit.DELEGATION, true);
            init.setContextFlag(NegTokenInit.INTEGRITY, true);
            init.setContextFlag(NegTokenInit.CONFIDENTIALITY, true);

            int expected = NegTokenInit.DELEGATION | NegTokenInit.INTEGRITY | NegTokenInit.CONFIDENTIALITY;
            assertEquals(expected, init.getContextFlags());

            // Verify each flag individually
            assertTrue(init.getContextFlag(NegTokenInit.DELEGATION));
            assertTrue(init.getContextFlag(NegTokenInit.INTEGRITY));
            assertTrue(init.getContextFlag(NegTokenInit.CONFIDENTIALITY));
            assertFalse(init.getContextFlag(NegTokenInit.MUTUAL_AUTHENTICATION));
        }
    }

    @Nested
    @DisplayName("Edge Cases and Error Conditions")
    class EdgeCasesTests {

        @Test
        @DisplayName("Parse handles empty token gracefully")
        void testParseEmptyToken() {
            byte[] emptyToken = new byte[0];
            assertThrows(IOException.class, () -> new NegTokenInit(emptyToken));
        }

        @Test
        @DisplayName("Parse handles null mechanisms array")
        void testNullMechanisms() {
            NegTokenInit init = new NegTokenInit(null, 0, null, null);
            assertNull(init.getMechanisms());

            // Should not throw when converting to byte array
            assertDoesNotThrow(() -> init.toByteArray());
        }

        @Test
        @DisplayName("Large MIC values are handled correctly")
        void testLargeMicValue() throws Exception {
            byte[] largeMic = new byte[1024];
            Arrays.fill(largeMic, (byte) 0xAB);

            NegTokenInit init = new NegTokenInit(new ASN1ObjectIdentifier[] { OID_KRB }, 0, null, largeMic);

            byte[] encoded = init.toByteArray();
            NegTokenInit parsed = new NegTokenInit(encoded);

            assertArrayEquals(largeMic, parsed.getMechanismListMIC());
        }
    }

    @Nested
    @DisplayName("Parameterized Tests for Multiple Scenarios")
    class ParameterizedTests {

        @ParameterizedTest
        @MethodSource("provideMechanismCombinations")
        @DisplayName("Various mechanism combinations round-trip correctly")
        void testMechanismCombinations(ASN1ObjectIdentifier[] mechanisms) throws Exception {
            NegTokenInit init = new NegTokenInit(mechanisms, 0, null, null);
            byte[] encoded = init.toByteArray();
            NegTokenInit parsed = new NegTokenInit(encoded);

            if (mechanisms == null) {
                assertNull(parsed.getMechanisms());
            } else {
                assertArrayEquals(mechanisms, parsed.getMechanisms());
            }
        }

        static Stream<Arguments> provideMechanismCombinations() {
            return Stream.of(Arguments.of((Object) null), Arguments.of((Object) new ASN1ObjectIdentifier[] {}),
                    Arguments.of((Object) new ASN1ObjectIdentifier[] { OID_KRB }),
                    Arguments.of((Object) new ASN1ObjectIdentifier[] { OID_NTLM }),
                    Arguments.of((Object) new ASN1ObjectIdentifier[] { OID_KRB_LEGACY }),
                    Arguments.of((Object) new ASN1ObjectIdentifier[] { OID_KRB, OID_NTLM }),
                    Arguments.of((Object) new ASN1ObjectIdentifier[] { OID_KRB, OID_KRB_LEGACY, OID_NTLM }),
                    Arguments.of((Object) new ASN1ObjectIdentifier[] { OID_NTLM, OID_KRB, OID_KRB_LEGACY }));
        }

        @ParameterizedTest
        @MethodSource("provideFlagCombinations")
        @DisplayName("Various flag combinations encode and parse correctly")
        void testFlagCombinations(int flags) throws Exception {
            NegTokenInit init = new NegTokenInit(new ASN1ObjectIdentifier[] { OID_KRB }, flags, null, null);

            byte[] encoded = init.toByteArray();
            NegTokenInit parsed = new NegTokenInit(encoded);

            assertEquals(flags, parsed.getContextFlags());
        }

        static Stream<Arguments> provideFlagCombinations() {
            return Stream.of(Arguments.of(0), Arguments.of(NegTokenInit.DELEGATION), Arguments.of(NegTokenInit.MUTUAL_AUTHENTICATION),
                    Arguments.of(NegTokenInit.DELEGATION | NegTokenInit.MUTUAL_AUTHENTICATION),
                    Arguments.of(NegTokenInit.INTEGRITY | NegTokenInit.CONFIDENTIALITY), Arguments.of(0xFF) // All flags set
            );
        }
    }

    @Nested
    @DisplayName("Performance and Stability Tests")
    class PerformanceTests {

        @RepeatedTest(value = 10, name = "Repeated encoding/decoding stability test {currentRepetition}/{totalRepetitions}")
        @DisplayName("Encoding and decoding is stable across multiple iterations")
        void testEncodingDecodingStability() throws Exception {
            ASN1ObjectIdentifier[] mechs = new ASN1ObjectIdentifier[] { OID_KRB, OID_NTLM };
            int flags = NegTokenInit.DELEGATION | NegTokenInit.INTEGRITY;
            byte[] mechToken = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
            byte[] mic = new byte[] { (byte) 0xAA, (byte) 0xBB, (byte) 0xCC };

            NegTokenInit original = new NegTokenInit(mechs, flags, mechToken, mic);
            byte[] firstEncoding = original.toByteArray();

            // Multiple round-trips should produce identical results
            NegTokenInit parsed1 = new NegTokenInit(firstEncoding);
            byte[] secondEncoding = parsed1.toByteArray();

            NegTokenInit parsed2 = new NegTokenInit(secondEncoding);
            byte[] thirdEncoding = parsed2.toByteArray();

            assertArrayEquals(firstEncoding, secondEncoding, "First and second encoding should be identical");
            assertArrayEquals(secondEncoding, thirdEncoding, "Second and third encoding should be identical");

            // Verify content preservation
            assertArrayEquals(mechs, parsed2.getMechanisms());
            assertEquals(flags, parsed2.getContextFlags());
            assertArrayEquals(mechToken, parsed2.getMechanismToken());
            assertArrayEquals(mic, parsed2.getMechanismListMIC());
        }
    }
}
