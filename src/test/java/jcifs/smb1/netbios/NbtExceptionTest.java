package jcifs.smb1.netbios;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@DisplayName("NbtException Tests")
class NbtExceptionTest {

    @Test
    @DisplayName("getErrorString success returns SUCCESS")
    void testSuccess() {
        assertEquals("SUCCESS", NbtException.getErrorString(NbtException.SUCCESS, 0));
    }

    @Test
    @DisplayName("getErrorString for name service error with known code")
    void testNameServiceKnown() {
        String expected = "ERR_NAM_SRVC/FMT_ERR: Format ErrorUnknown error code: 1";
        assertEquals(expected, NbtException.getErrorString(NbtException.ERR_NAM_SRVC, NbtException.FMT_ERR));
    }

    @Test
    @DisplayName("getErrorString for name service error with unknown code")
    void testNameServiceUnknown() {
        int unknown = 99;
        String expected = "ERR_NAM_SRVC/Unknown error code: 99";
        assertEquals(expected, NbtException.getErrorString(NbtException.ERR_NAM_SRVC, unknown));
    }

    @ParameterizedTest(name = "session error {1} -\\u003e {2}")
    @CsvSource({ "-1,Connection refused", "0x80,Not listening on called name", "0x81,Not listening for calling name",
            "0x82,Called name not present", "0x83,Called name present, but insufficient resources", "0x8F,Unspecified error",
            "999,Unknown error code: 999" })
    @DisplayName("getErrorString for SSN service errors")
    void testSessionServiceErrors(int errorCode, String description) {
        int errSsn = NbtException.ERR_SSN_SRVC;
        String message = NbtException.getErrorString(errSsn, errorCode);
        assertTrue(message.contains(description));
    }

    @Test
    @DisplayName("getErrorString for unknown error class")
    void testUnknownErrorClass() {
        int unknownClass = 1234;
        String expected = "unknown error class: 1234";
        assertEquals(expected, NbtException.getErrorString(unknownClass, 0));
    }

    @Test
    @DisplayName("Constructor sets fields and message correctly")
    void testConstructor() {
        NbtException e = new NbtException(NbtException.ERR_SSN_SRVC, NbtException.CONNECTION_REFUSED);
        assertEquals(NbtException.ERR_SSN_SRVC, e.errorClass);
        assertEquals(NbtException.CONNECTION_REFUSED, e.errorCode);
        assertEquals(e.getMessage(), NbtException.getErrorString(NbtException.ERR_SSN_SRVC, NbtException.CONNECTION_REFUSED));
    }

    @Test
    @DisplayName("toString includes class, code and error string")
    void testToString() {
        NbtException e = new NbtException(NbtException.ERR_SSN_SRVC, NbtException.NO_RESOURCES);
        String str = e.toString();
        assertTrue(str.contains("errorClass=2"));
        assertTrue(str.contains("errorCode=" + NbtException.NO_RESOURCES));
        assertTrue(str.contains("Called name present, but insufficient resources"));
    }
}
