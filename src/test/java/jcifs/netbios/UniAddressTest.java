package jcifs.netbios;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.Address;
import jcifs.CIFSContext;

class UniAddressTest {

    @Nested
    @DisplayName("isDotQuadIP method tests")
    class IsDotQuadIPTests {

        @ParameterizedTest(name = "should return true for valid IP address: {0}")
        @ValueSource(strings = { "192.168.1.1", "10.0.0.255", "0.0.0.0", "255.255.255.255" })
        void shouldReturnTrueForValidIpAddresses(String ip) {
            assertTrue(UniAddress.isDotQuadIP(ip));
        }

        @ParameterizedTest(name = "should return false for invalid IP address or hostname: {0}")
        @ValueSource(strings = { "192.168.1", "hostname", "1.2.3.4.5", "192.168.1.1a", "a.b.c.d" })
        void shouldReturnFalseForInvalidIpAddressesOrHostnames(String input) {
            assertFalse(UniAddress.isDotQuadIP(input));
        }

        @Test
        void shouldReturnTrueForInvalidOctetValues() {
            // isDotQuadIP does not validate octet values, only checks format
            assertTrue(UniAddress.isDotQuadIP("192.168.1.256"));
            assertTrue(UniAddress.isDotQuadIP("999.999.999.999"));
        }

        @Test
        void shouldThrowExceptionForNullInput() {
            assertThrows(NullPointerException.class, () -> UniAddress.isDotQuadIP(null));
        }

        @Test
        void shouldThrowExceptionForEmptyInput() {
            assertThrows(StringIndexOutOfBoundsException.class, () -> UniAddress.isDotQuadIP(""));
        }
    }

    @Nested
    @DisplayName("Constructor tests")
    class ConstructorTests {

        @Test
        void shouldConstructWithInetAddress() throws UnknownHostException {
            InetAddress inetAddress = InetAddress.getByName("127.0.0.1");
            UniAddress uniAddress = new UniAddress(inetAddress);
            assertNotNull(uniAddress);
            assertEquals(inetAddress, uniAddress.getAddress());
        }

        @Test
        void shouldConstructWithNbtAddress() {
            NbtAddress nbtAddress = mock(NbtAddress.class);
            UniAddress uniAddress = new UniAddress(nbtAddress);
            assertNotNull(uniAddress);
            assertEquals(nbtAddress, uniAddress.getAddress());
        }

        @Test
        void shouldThrowIllegalArgumentExceptionForNullAddress() {
            assertThrows(IllegalArgumentException.class, () -> new UniAddress(null));
        }
    }

    @Nested
    @DisplayName("hashCode and equals tests")
    class HashCodeAndEqualsTests {

        private InetAddress inetAddress1;
        private InetAddress inetAddress2;
        private NbtAddress nbtAddress1;
        private NbtAddress nbtAddress2;

        @BeforeEach
        void setup() throws UnknownHostException {
            inetAddress1 = InetAddress.getByName("192.168.1.1");
            inetAddress2 = InetAddress.getByName("192.168.1.2");
            nbtAddress1 = mock(NbtAddress.class);
            nbtAddress2 = mock(NbtAddress.class);
        }

        @Test
        void hashCodeShouldBeConsistentWithWrappedAddress() {
            UniAddress uniAddress1 = new UniAddress(inetAddress1);
            assertEquals(inetAddress1.hashCode(), uniAddress1.hashCode());

            UniAddress uniAddress2 = new UniAddress(nbtAddress1);
            assertEquals(nbtAddress1.hashCode(), uniAddress2.hashCode());
        }

        @Test
        void equalsShouldReturnTrueForSameWrappedAddress() {
            UniAddress uniAddress1 = new UniAddress(inetAddress1);
            UniAddress uniAddress2 = new UniAddress(inetAddress1);
            assertTrue(uniAddress1.equals(uniAddress2));
        }

        @Test
        void equalsShouldReturnFalseForDifferentWrappedAddress() {
            UniAddress uniAddress1 = new UniAddress(inetAddress1);
            UniAddress uniAddress2 = new UniAddress(inetAddress2);
            assertFalse(uniAddress1.equals(uniAddress2));
        }

        @Test
        void equalsShouldReturnFalseForDifferentWrappedAddressTypes() {
            UniAddress uniAddress1 = new UniAddress(inetAddress1);
            UniAddress uniAddress2 = new UniAddress(nbtAddress1);
            assertFalse(uniAddress1.equals(uniAddress2));
        }

        @Test
        void equalsShouldReturnFalseForNull() {
            UniAddress uniAddress = new UniAddress(inetAddress1);
            assertFalse(uniAddress.equals(null));
        }

        @Test
        void equalsShouldReturnFalseForDifferentClass() {
            UniAddress uniAddress = new UniAddress(inetAddress1);
            assertFalse(uniAddress.equals(new Object()));
        }
    }

    @Nested
    @DisplayName("firstCalledName method tests")
    class FirstCalledNameTests {

        private NbtAddress mockNbtAddress;
        private InetAddress mockInetAddress;

        @BeforeEach
        void setup() {
            mockNbtAddress = mock(NbtAddress.class);
            mockInetAddress = mock(InetAddress.class);
        }

        @Test
        void shouldReturnNbtAddressFirstCalledNameWhenWrappedIsNbtAddress() {
            UniAddress uniAddress = new UniAddress(mockNbtAddress);
            when(mockNbtAddress.firstCalledName()).thenReturn("NBT_NAME");
            assertEquals("NBT_NAME", uniAddress.firstCalledName());
            verify(mockNbtAddress, times(1)).firstCalledName();
        }

        @Test
        void shouldReturnSmbServerNameWhenInetAddressIsDotQuadIP() throws UnknownHostException {
            when(mockInetAddress.getHostName()).thenReturn("192.168.1.100");
            UniAddress uniAddress = new UniAddress(mockInetAddress);
            assertEquals(NbtAddress.SMBSERVER_NAME, uniAddress.firstCalledName());
        }

        @Test
        void shouldReturnUppercaseHostnameBeforeFirstDotWhenInetAddressHostnameHasDotAndLengthLessThan15() throws UnknownHostException {
            when(mockInetAddress.getHostName()).thenReturn("myhost.domain.com");
            UniAddress uniAddress = new UniAddress(mockInetAddress);
            assertEquals("MYHOST", uniAddress.firstCalledName());
        }

        @Test
        void shouldReturnSmbServerNameWhenInetAddressHostnameLengthGreaterThan15() throws UnknownHostException {
            when(mockInetAddress.getHostName()).thenReturn("thisisverylonghostname");
            UniAddress uniAddress = new UniAddress(mockInetAddress);
            assertEquals(NbtAddress.SMBSERVER_NAME, uniAddress.firstCalledName());
        }

        @Test
        void shouldReturnUppercaseHostnameWhenInetAddressHostnameHasNoDotAndLengthLessThan15() throws UnknownHostException {
            when(mockInetAddress.getHostName()).thenReturn("shortname");
            UniAddress uniAddress = new UniAddress(mockInetAddress);
            assertEquals("SHORTNAME", uniAddress.firstCalledName());
        }

        @Test
        void shouldReturnUppercaseWhenInetAddressHostnameHasDotAtStart() throws UnknownHostException {
            when(mockInetAddress.getHostName()).thenReturn(".hostname");
            UniAddress uniAddress = new UniAddress(mockInetAddress);
            // Dot at position 0, which is NOT > 1, so whole string is uppercased
            assertEquals(".HOSTNAME", uniAddress.firstCalledName());
        }

        @Test
        void shouldReturnFullUppercaseHostnameWhenInetAddressHostnameHasDotButNotInValidRange() throws UnknownHostException {
            when(mockInetAddress.getHostName()).thenReturn("h.ostname");
            UniAddress uniAddress = new UniAddress(mockInetAddress);
            // Dot at position 1, which is NOT > 1, so it doesn't substring, just uppercase
            assertEquals("H.OSTNAME", uniAddress.firstCalledName());
        }
    }

    @Nested
    @DisplayName("nextCalledName method tests")
    class NextCalledNameTests {

        private NbtAddress mockNbtAddress;
        private InetAddress mockInetAddress;
        private CIFSContext mockCIFSContext;

        @BeforeEach
        void setup() {
            mockNbtAddress = mock(NbtAddress.class);
            mockInetAddress = mock(InetAddress.class);
            mockCIFSContext = mock(CIFSContext.class);
        }

        @Test
        void shouldReturnNbtAddressNextCalledNameWhenWrappedIsNbtAddress() {
            UniAddress uniAddress = new UniAddress(mockNbtAddress);
            when(mockNbtAddress.nextCalledName(mockCIFSContext)).thenReturn("NEXT_NBT_NAME");
            assertEquals("NEXT_NBT_NAME", uniAddress.nextCalledName(mockCIFSContext));
            verify(mockNbtAddress, times(1)).nextCalledName(mockCIFSContext);
        }

        @Test
        void shouldReturnSmbServerNameWhenInetAddressAndCalledNameIsNotSmbServerName() throws UnknownHostException {
            when(mockInetAddress.getHostName()).thenReturn("somehost");
            UniAddress uniAddress = new UniAddress(mockInetAddress);
            uniAddress.firstCalledName(); // Initialize calledName
            assertEquals(NbtAddress.SMBSERVER_NAME, uniAddress.nextCalledName(mockCIFSContext));
        }

        @Test
        void shouldReturnNullWhenInetAddressAndCalledNameIsAlreadySmbServerName() throws UnknownHostException {
            when(mockInetAddress.getHostName()).thenReturn("192.168.1.1"); // This will set calledName to SMBSERVER_NAME
            UniAddress uniAddress = new UniAddress(mockInetAddress);
            uniAddress.firstCalledName(); // Initialize calledName to SMBSERVER_NAME
            assertNull(uniAddress.nextCalledName(mockCIFSContext));
        }
    }

    @Nested
    @DisplayName("getAddress method tests")
    class GetAddressTests {

        private InetAddress mockInetAddress;
        private NbtAddress mockNbtAddress;

        @BeforeEach
        void setup() {
            mockInetAddress = mock(InetAddress.class);
            mockNbtAddress = mock(NbtAddress.class);
        }

        @Test
        void shouldReturnWrappedInetAddress() {
            UniAddress uniAddress = new UniAddress(mockInetAddress);
            assertEquals(mockInetAddress, uniAddress.getAddress());
        }

        @Test
        void shouldReturnWrappedNbtAddress() {
            UniAddress uniAddress = new UniAddress(mockNbtAddress);
            assertEquals(mockNbtAddress, uniAddress.getAddress());
        }
    }

    @Nested
    @DisplayName("getHostName method tests")
    class GetHostNameTests {

        private InetAddress mockInetAddress;
        private NbtAddress mockNbtAddress;

        @BeforeEach
        void setup() {
            mockInetAddress = mock(InetAddress.class);
            mockNbtAddress = mock(NbtAddress.class);
        }

        @Test
        void shouldReturnInetAddressHostnameWhenWrappedIsInetAddress() {
            when(mockInetAddress.getHostName()).thenReturn("inet-host");
            UniAddress uniAddress = new UniAddress(mockInetAddress);
            assertEquals("inet-host", uniAddress.getHostName());
        }

        @Test
        void shouldReturnNbtAddressHostnameWhenWrappedIsNbtAddress() {
            when(mockNbtAddress.getHostName()).thenReturn("nbt-host");
            UniAddress uniAddress = new UniAddress(mockNbtAddress);
            assertEquals("nbt-host", uniAddress.getHostName());
        }
    }

    @Nested
    @DisplayName("getHostAddress method tests")
    class GetHostAddressTests {

        private InetAddress mockInetAddress;
        private NbtAddress mockNbtAddress;

        @BeforeEach
        void setup() {
            mockInetAddress = mock(InetAddress.class);
            mockNbtAddress = mock(NbtAddress.class);
        }

        @Test
        void shouldReturnInetAddressHostAddressWhenWrappedIsInetAddress() {
            when(mockInetAddress.getHostAddress()).thenReturn("1.2.3.4");
            UniAddress uniAddress = new UniAddress(mockInetAddress);
            assertEquals("1.2.3.4", uniAddress.getHostAddress());
        }

        @Test
        void shouldReturnNbtAddressHostAddressWhenWrappedIsNbtAddress() {
            when(mockNbtAddress.getHostAddress()).thenReturn("5.6.7.8");
            UniAddress uniAddress = new UniAddress(mockNbtAddress);
            assertEquals("5.6.7.8", uniAddress.getHostAddress());
        }
    }

    @Nested
    @DisplayName("toInetAddress method tests")
    class ToInetAddressTests {

        private InetAddress mockInetAddress;
        private Address mockAddress;

        @BeforeEach
        void setup() {
            mockInetAddress = mock(InetAddress.class);
            mockAddress = mock(Address.class);
        }

        @Test
        void shouldReturnWrappedInetAddressWhenWrappedIsInetAddress() throws UnknownHostException {
            UniAddress uniAddress = new UniAddress(mockInetAddress);
            assertEquals(mockInetAddress, uniAddress.toInetAddress());
        }

        @Test
        void shouldReturnInetAddressFromWrappedAddressWhenWrappedIsAddress() throws UnknownHostException {
            InetAddress expectedInetAddress = InetAddress.getByName("10.0.0.1");
            when(mockAddress.toInetAddress()).thenReturn(expectedInetAddress);
            UniAddress uniAddress = new UniAddress(mockAddress);
            assertEquals(expectedInetAddress, uniAddress.toInetAddress());
            verify(mockAddress, times(1)).toInetAddress();
        }

        @Test
        void shouldReturnNullWhenWrappedIsNeitherInetAddressNorAddress() throws Exception {
            // UniAddress only accepts InetAddress, NbtAddress (which implements Address), or Address
            // Testing with NbtAddress which doesn't return anything from toInetAddress
            NbtAddress nbtAddress = mock(NbtAddress.class);
            when(nbtAddress.toInetAddress()).thenReturn(null);
            UniAddress uniAddress = new UniAddress(nbtAddress);
            assertNull(uniAddress.toInetAddress());
        }
    }

    @Nested
    @DisplayName("unwrap method tests")
    class UnwrapTests {

        private Address mockAddress;

        @BeforeEach
        void setup() {
            mockAddress = mock(Address.class);
        }

        @Test
        void shouldReturnUnwrappedAddressWhenWrappedIsAddress() {
            when(mockAddress.unwrap(Address.class)).thenReturn(mockAddress);
            UniAddress uniAddress = new UniAddress(mockAddress);
            assertEquals(mockAddress, uniAddress.unwrap(Address.class));
            verify(mockAddress, times(1)).unwrap(Address.class);
        }

        @Test
        void shouldReturnThisWhenTypeIsUniAddress() throws UnknownHostException {
            InetAddress inetAddress = InetAddress.getByName("127.0.0.1");
            UniAddress uniAddress = new UniAddress(inetAddress);
            assertEquals(uniAddress, uniAddress.unwrap(UniAddress.class));
        }

        @Test
        void shouldReturnNullWhenTypeIsNotAssignable() throws UnknownHostException {
            InetAddress inetAddress = InetAddress.getByName("127.0.0.1");
            UniAddress uniAddress = new UniAddress(inetAddress);
            assertNull(uniAddress.unwrap(NbtAddress.class));
        }
    }

    @Nested
    @DisplayName("toString method tests")
    class ToStringTests {

        private InetAddress mockInetAddress;
        private NbtAddress mockNbtAddress;

        @BeforeEach
        void setup() {
            mockInetAddress = mock(InetAddress.class);
            mockNbtAddress = mock(NbtAddress.class);
        }

        @Test
        void shouldReturnWrappedAddressToStringWhenWrappedIsInetAddress() {
            when(mockInetAddress.toString()).thenReturn("/192.168.1.1");
            UniAddress uniAddress = new UniAddress(mockInetAddress);
            assertEquals("/192.168.1.1", uniAddress.toString());
        }

        @Test
        void shouldReturnWrappedAddressToStringWhenWrappedIsNbtAddress() {
            when(mockNbtAddress.toString()).thenReturn("NBT_HOST/192.168.1.2");
            UniAddress uniAddress = new UniAddress(mockNbtAddress);
            assertEquals("NBT_HOST/192.168.1.2", uniAddress.toString());
        }
    }
}