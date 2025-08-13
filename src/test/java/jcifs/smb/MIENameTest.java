package jcifs.smb;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.provider.Arguments;

@ExtendWith(MockitoExtension.class)
class MIENameTest {

    // Helper to build a valid buffer according to the expected layout.
    private static byte[] buildBuffer(byte[] oidDer, byte[] nameBytes) {
        byte[] tokId = new byte[] { 0x04, 0x01 };
        int oidLen = oidDer.length;
        int nameLen = nameBytes.length;

        byte[] buf = new byte[2 + 2 + oidLen + 4 + nameLen];
        int i = 0;
        // TOK_ID
        buf[i++] = tokId[0];
        buf[i++] = tokId[1];
        // MECH_OID_LEN (2 bytes big-endian)
        buf[i++] = (byte) ((oidLen >>> 8) & 0xFF);
        buf[i++] = (byte) (oidLen & 0xFF);
        // MECH_OID
        System.arraycopy(oidDer, 0, buf, i, oidLen);
        i += oidLen;
        // NAME_LEN (4 bytes big-endian)
        buf[i++] = (byte) ((nameLen >>> 24) & 0xFF);
        buf[i++] = (byte) ((nameLen >>> 16) & 0xFF);
        buf[i++] = (byte) ((nameLen >>> 8) & 0xFF);
        buf[i++] = (byte) (nameLen & 0xFF);
        // NAME
        System.arraycopy(nameBytes, 0, buf, i, nameLen);
        return buf;
    }

    // Provide a common OID for tests (Kerberos V5 mechanism OID encoded in DER)
    private static ASN1ObjectIdentifier testOid() {
        return new ASN1ObjectIdentifier("1.2.840.113554.1.2.2");
    }

    private static byte[] oidDer() {
        // Full DER encoding of the OID
        try {
            return testOid().toASN1Primitive().getEncoded();
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Parses a valid buffer and exposes fields")
    void parseValidBuffer() {
        // Arrange
        String name = "user@EXAMPLE.COM";
        byte[] buf = buildBuffer(oidDer(), name.getBytes(StandardCharsets.US_ASCII));

        // Act
        MIEName parsed = new MIEName(buf);

        // Assert
        // equals should match case-insensitively for name and equal OID
        MIEName expected = new MIEName(testOid(), name);
        assertEquals(expected, parsed, "Parsed object should equal expected");
        assertEquals(name, parsed.toString(), "toString should return the name");
        assertEquals(testOid().hashCode(), parsed.hashCode(), "hashCode should derive from OID");
    }

    @Test
    @DisplayName("Parses empty name length (NAME_LEN=0) as empty string")
    void parseEmptyName() {
        // Arrange
        String name = "";
        byte[] buf = buildBuffer(oidDer(), name.getBytes(StandardCharsets.US_ASCII));

        // Act
        MIEName parsed = new MIEName(buf);

        // Assert
        assertEquals(name, parsed.toString());
    }

    static Stream<Arguments> invalidBuffers() {
        ASN1ObjectIdentifier oid = testOid();
        byte[] der;
        try {
            der = oid.toASN1Primitive().getEncoded();
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }
        byte[] nameBytes = "bob".getBytes(StandardCharsets.US_ASCII);

        return Stream.of(
            // Too short for TOK_ID + MECH_OID_LEN
            Arguments.of("too short header", new byte[] { 0x04, 0x01, 0x00 }, IllegalArgumentException.class),

            // Wrong TOK_ID
            Arguments.of("wrong TOK_ID", new byte[] { 0x00, 0x02, 0x00, 0x01 }, IllegalArgumentException.class),

            // OID length claims more than available
            Arguments.of("oid length exceeds buffer", new byte[] { 0x04, 0x01, 0x00, 0x10, 0x06 }, IllegalArgumentException.class),

            // Missing NAME_LEN (not enough bytes for 4-byte length)
            Arguments.of("missing NAME_LEN bytes", new byte[] { 0x04, 0x01, 0x00, (byte) der.length, der[0] }, IllegalArgumentException.class),

            // Name length larger than remaining bytes - use method reference
            Arguments.of("name length exceeds remaining", 
                (java.util.function.Supplier<byte[]>) () -> {
                    byte[] buf = buildBuffer(der, nameBytes);
                    // Corrupt NAME_LEN to be larger than actual by +5
                    int i = 2 + 2 + der.length; // index where NAME_LEN starts
                    int fakeLen = nameBytes.length + 5;
                    buf[i] = (byte) ((fakeLen >>> 24) & 0xFF);
                    buf[i + 1] = (byte) ((fakeLen >>> 16) & 0xFF);
                    buf[i + 2] = (byte) ((fakeLen >>> 8) & 0xFF);
                    buf[i + 3] = (byte) (fakeLen & 0xFF);
                    return buf;
                }, IllegalArgumentException.class),

            // Negative NAME_LEN (0xFFFFFFFF) causes StringIndexOutOfBoundsException
            Arguments.of("negative name length triggers SIOOBE", 
                (java.util.function.Supplier<byte[]>) () -> {
                    byte[] tok = new byte[] { 0x04, 0x01 };
                    byte[] buf = new byte[2 + 2 + der.length + 4];
                    int p = 0;
                    buf[p++] = tok[0];
                    buf[p++] = tok[1];
                    buf[p++] = 0x00;
                    buf[p++] = (byte) der.length;
                    System.arraycopy(der, 0, buf, p, der.length);
                    p += der.length;
                    // NAME_LEN = 0xFF FF FF FF
                    buf[p++] = (byte) 0xFF;
                    buf[p++] = (byte) 0xFF;
                    buf[p++] = (byte) 0xFF;
                    buf[p++] = (byte) 0xFF;
                    return buf;
                }, StringIndexOutOfBoundsException.class)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidBuffers")
    @DisplayName("Invalid buffers throw appropriate exceptions")
    void invalidInputsThrow(String name, Object bufferSupplierOrBytes, Class<? extends Throwable> expected) {
        // Arrange
        byte[] buf;
        if (bufferSupplierOrBytes instanceof byte[]) {
            buf = (byte[]) bufferSupplierOrBytes;
        } else {
            @SuppressWarnings("unchecked")
            java.util.function.Supplier<byte[]> sup = (java.util.function.Supplier<byte[]>) bufferSupplierOrBytes;
            buf = sup.get();
        }

        // Act + Assert
        Throwable t = assertThrows(expected, () -> new MIEName(buf));
        // MIEName throws IllegalArgumentException without messages, so we don't assert on message presence
        assertNotNull(t, "Exception should be thrown");
    }

    @Nested
    @DisplayName("equals, hashCode, toString")
    class EqualityContract {

        @Test
        void equalsIgnoresCaseForName() {
            ASN1ObjectIdentifier oid = testOid();
            MIEName a = new MIEName(oid, "Alice");
            MIEName b = new MIEName(oid, "alice");
            assertEquals(a, b);
            assertEquals(a.hashCode(), b.hashCode());
        }

        @Test
        void equalsHandlesNullNames() {
            ASN1ObjectIdentifier oid = testOid();
            MIEName a = new MIEName(oid, null);
            MIEName b = new MIEName(oid, null);
            assertEquals(a, b);
            assertNull(a.toString()); // toString returns field as-is
        }

        @Test
        void notEqualWhenOidDiffersOrNameNullityDiffers() {
            MIEName a = new MIEName(new ASN1ObjectIdentifier("1.2.3"), "X");
            MIEName b = new MIEName(new ASN1ObjectIdentifier("1.2.4"), "X");
            MIEName c = new MIEName(new ASN1ObjectIdentifier("1.2.3"), null);
            assertNotEquals(a, b);
            assertNotEquals(a, c);
            assertNotEquals(a, new Object());
        }
    }

    @Test
    @DisplayName("Mockito presence: no collaborator interactions to verify")
    void noDependenciesToMock() {
        // This class has no external collaborators; nothing to verify.
        // Keep Mockito import usage minimal to satisfy build-time linkage.
        Runnable r = mock(Runnable.class);
        r.run();
        verify(r, times(1)).run();
    }
}
