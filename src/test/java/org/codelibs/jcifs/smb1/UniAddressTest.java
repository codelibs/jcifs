package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.stream.Stream;

import org.codelibs.jcifs.smb1.netbios.NbtAddress;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link UniAddress}.  The focus of these tests is on
 * the public API of {@code UniAddress} and its behaviour when provided
 * with different kinds of inputs.  Many static helpers in {@code
 * UniAddress} are network dependent and therefore not exercised here – they
 * would require complex stubbing of static methods.  Instead the tests
 * concentrate on the instance methods and simple static predicates
 * that are observable without network access.
 */
@ExtendWith(MockitoExtension.class)
class UniAddressTest {

    /* ---------------------------------------------------------------------
     * 0. Helper methods for parameterised tests
     * --------------------------------------------------------------------- */
    private static Stream<Arguments> hostnamesProvider() {
        return Stream.of(Arguments.of("localhost", "127.0.0.1", "LOCALHOST"), Arguments.of("mycomputer.local", "mycomputer", "MYCOMPUTER"),
                Arguments.of("mycomputer.example.com", "mycomputer", "MYCOMPUTER"));
    }

    /* ---------------------------------------------------------------------
     * 1. Basic constructor validation
     * --------------------------------------------------------------------- */
    @Test
    void constructorAcceptsNonNullObject() {
        // Arrange : create a dummy address
        InetAddress dummy = mock(InetAddress.class);
        // Act
        UniAddress ua = new UniAddress(dummy);
        // Assert
        assertSame(dummy, ua.getAddress(), "constructor should store the supplied address");
    }

    @Test
    void constructorRejectsNull() {
        // Expect constructor to throw IllegalArgumentException when passed null
        assertThrows(IllegalArgumentException.class, () -> new UniAddress(null));
    }

    /* ---------------------------------------------------------------------
     * 2. Value based tests for instance methods
     * --------------------------------------------------------------------- */
    @ParameterizedTest
    @MethodSource("hostnamesProvider")
    void firstCalledNameForInetAddressConformsToUpperCase(String hostname, String hostWithoutDot, String expectedPrefix) {
        // Arrange
        InetAddress addr = mock(InetAddress.class);
        when(addr.getHostName()).thenReturn(hostname);
        UniAddress ua = new UniAddress(addr);
        // Act
        String called = ua.firstCalledName();
        // Assert
        assertEquals(expectedPrefix, called, "firstCalledName should return uppercase prefix or SMBSERVER_NAME");
    }

    @Test
    void nextCalledNameWithNbtAddressReturnsDelegateValue() {
        // Arrange
        NbtAddress nbtMock = mock(NbtAddress.class);
        when(nbtMock.nextCalledName()).thenReturn("NEXT");
        UniAddress ua = new UniAddress(nbtMock);
        // Act
        String next = ua.nextCalledName();
        // Assert
        assertEquals("NEXT", next, "nextCalledName should delegate to NbtAddress when called");
    }

    @Test
    void nextCalledNameWithInetAddressReturnsSMBSERVERFirstIfNotDefault() {
        // Arrange
        InetAddress addr = mock(InetAddress.class);
        when(addr.getHostName()).thenReturn("mycomputer.foo.com");
        UniAddress ua = new UniAddress(addr);
        // Act: first call should set to SMBSERVER_NAME
        String initial = ua.firstCalledName();
        // verify that subsequent call gives SMBSERVER_NAME
        String next = ua.nextCalledName();
        // Assert
        assertEquals(NbtAddress.SMBSERVER_NAME, next, "nextCalledName should return SMBSERVER_NAME after first call");
    }

    @Test
    void getAddressReturnsOriginalObject() {
        InetAddress dummy = mock(InetAddress.class);
        UniAddress ua = new UniAddress(dummy);
        assertSame(dummy, ua.getAddress(), "getAddress should return the wrapped address");
    }

    @Test
    void getHostNameDelegatesToWrappedInetAddress() {
        InetAddress dummy = mock(InetAddress.class);
        when(dummy.getHostName()).thenReturn("host.example.com");
        UniAddress ua = new UniAddress(dummy);
        assertEquals("host.example.com", ua.getHostName(), "should forward hostName to underlying InetAddress");
    }

    @Test
    void getHostAddressDelegatesToWrappedInetAddress() {
        InetAddress dummy = mock(InetAddress.class);
        when(dummy.getHostAddress()).thenReturn("192.0.2.1");
        UniAddress ua = new UniAddress(dummy);
        assertEquals("192.0.2.1", ua.getHostAddress(), "should forward hostAddress to underlying InetAddress");
    }

    @Test
    void toStringDelegatesToUnderlyingAddress() {
        InetAddress dummy = mock(InetAddress.class);
        when(dummy.toString()).thenReturn("mockedInet");
        UniAddress ua = new UniAddress(dummy);
        assertEquals("mockedInet", ua.toString(), "toString() should delegate to wrapped address");
    }

    /* ---------------------------------------------------------------------
     * 3. Static predicate checks
     * --------------------------------------------------------------------- */
    @ParameterizedTest
    @ValueSource(strings = { "192.168.0.1", "123.45.67.89", "1.2.3.4" })
    void isDotQuadIPRecognizesDotQuadIP(String ip) {
        // Arrange & Act
        boolean result = UniAddress.isDotQuadIP(ip);
        // Assert
        assertTrue(result, "isDotQuadIP should return true for dot-quad IP");
    }

    @ParameterizedTest
    @ValueSource(strings = { "192.168.0", "abcd", "192.168" })
    void isDotQuadIPRejectsNonDotQuad(String value) {
        assertFalse(UniAddress.isDotQuadIP(value), "isDotQuadIP should return false for non IP-like values");
    }

    @Test
    void isDotQuadIPHandlesEmptyString() {
        // Empty string should return false, not throw exception
        assertFalse(UniAddress.isDotQuadIP(""), "isDotQuadIP should return false for empty string");
    }

    @ParameterizedTest
    @ValueSource(strings = { "123456", "007", "999" })
    void isAllDigitsTrueForPureNumeric(String numeric) {
        assertTrue(UniAddress.isAllDigits(numeric));
    }

    @ParameterizedTest
    @ValueSource(strings = { "12a", "abc", "123 " })
    void isAllDigitsFalseForNonNumeric(String nonNumeric) {
        assertFalse(UniAddress.isAllDigits(nonNumeric));
    }

    @Test
    void isAllDigitsHandlesEmptyString() {
        // Empty string technically has no non-digit characters, so it returns true
        assertTrue(UniAddress.isAllDigits(""), "isAllDigits should return true for empty string (no non-digits)");
    }

    /* ---------------------------------------------------------------------
     * 4. Exceptions from static methods that don't resolve without stubbing
     * --------------------------------------------------------------------- */
    @Test
    void getAllByNameRejectsNullOrEmptyHostname() {
        assertThrows(UnknownHostException.class, () -> UniAddress.getAllByName("", false),
                "getAllByName should throw UnknownHostException for empty string");
        assertThrows(UnknownHostException.class, () -> UniAddress.getAllByName(null, false),
                "getAllByName should throw UnknownHostException for null name");
    }
}
