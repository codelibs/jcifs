package org.codelibs.jcifs.smb.spnego;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link NegTokenTarg}. The class has no external
 * collaborators so tests are mostly focused on round‑trip
 * serialisation and invalid input handling.
 */
class NegTokenTargTest {

    @Test
    @DisplayName("happy path – full token round‑trip")
    void testRoundTripFull() throws IOException {
        // Arrange – create a fully populated token
        ASN1ObjectIdentifier mech = new ASN1ObjectIdentifier("1.2.840.113554.1.2.2");
        byte[] tokenArray = new byte[] { 1, 2, 3 };
        byte[] mic = new byte[] { 9, 9, 9 };
        NegTokenTarg original = new NegTokenTarg(NegTokenTarg.ACCEPT_COMPLETED, mech, tokenArray, mic);

        // Act – serialise and parse back
        byte[] bytes = original.toByteArray();
        NegTokenTarg roundTrip = new NegTokenTarg(bytes);

        // Assert – all getters match the original values
        assertEquals(NegTokenTarg.ACCEPT_COMPLETED, roundTrip.getResult(), "result should roundtrip");
        assertEquals(mech, roundTrip.getMechanism(), "mechanism should roundtrip");
        assertArrayEquals(tokenArray, roundTrip.getMechanismToken(), "mechanism token should roundtrip");
        assertArrayEquals(mic, roundTrip.getMechanismListMIC(), "mic should roundtrip");
    }

    @Test
    @DisplayName("default constructor – unspecified result")
    void testDefaultResult() {
        NegTokenTarg nt = new NegTokenTarg();
        assertEquals(NegTokenTarg.UNSPECIFIED_RESULT, nt.getResult(), "new object should have UNSPECIFIED_RESULT");
    }

    @Test
    @DisplayName("serialization omits tags when field is null")
    void testSerializationOmittingNullFields() throws IOException {
        NegTokenTarg token = new NegTokenTarg();
        token.setResult(NegTokenTarg.ACCEPT_INCOMPLETE);
        // mechanism, token and mic are left null

        byte[] bytes = token.toByteArray();
        NegTokenTarg parsed = new NegTokenTarg(bytes);

        assertEquals(NegTokenTarg.ACCEPT_INCOMPLETE, parsed.getResult(), "result should be present");
        assertNull(parsed.getMechanism(), "mechanism should be null when omitted");
        assertNull(parsed.getMechanismToken(), "mechanism token should be null when omitted");
        assertNull(parsed.getMechanismListMIC(), "MIC should be null when omitted");
    }

    @Test
    @DisplayName("parsing malformed token throws IOException")
    void testMalformedToken() {
        byte[] bad = new byte[] { 0x01, 0x02, 0x03 }; // not a valid ASN.1 tagged object
        assertThrows(IOException.class, () -> new NegTokenTarg(bad), "Malformed byte[] should cause IOException");
    }

    @Test
    @DisplayName("mechanism token empty array – preserved after round‑trip")
    void testEmptyMechanismToken() throws IOException {
        NegTokenTarg nt = new NegTokenTarg();
        nt.setResult(NegTokenTarg.REQUEST_MIC);
        nt.setMechanismToken(new byte[0]); // empty but non‑null
        nt.setMechanism(new ASN1ObjectIdentifier("2.16.840.1.101.3.6.1"));
        nt.setMechanismListMIC(null);
        byte[] bytes = nt.toByteArray();
        NegTokenTarg parsed = new NegTokenTarg(bytes);
        assertArrayEquals(new byte[0], parsed.getMechanismToken(), "empty token preserved");
    }
}
