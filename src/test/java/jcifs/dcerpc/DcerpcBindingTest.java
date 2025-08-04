package jcifs.dcerpc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DcerpcBindingTest {

    private DcerpcBinding dcerpcBinding;
    private static final String PROTO = "ncacn_np";
    private static final String SERVER = "testServer";

    @BeforeEach
    void setUp() {
        dcerpcBinding = new DcerpcBinding(PROTO, SERVER);
        // Initialize static INTERFACES map for tests
        DcerpcBinding.addInterface("srvsvc", "4B324FC8-1670-01D3-1278-5A47BF6EE188:3.0");
        DcerpcBinding.addInterface("lsarpc", "12345778-1234-ABCD-EF00-0123456789AB:2.1");
        DcerpcBinding.addInterface("samr", "12345778-1234-ABCD-EF00-0123456789AC:1.0");
        DcerpcBinding.addInterface("netlogon", "12345678-1234-abcd-ef00-01234567cffb:1.0");
        DcerpcBinding.addInterface("wkssvc", "6BFFD098-A112-3610-9833-46C3F87E345A:1.0");
    }

    @Test
    void testConstructorAndGetters() {
        assertEquals(PROTO, dcerpcBinding.getProto(), "Protocol should match the constructor argument.");
        assertEquals(SERVER, dcerpcBinding.getServer(), "Server should match the constructor argument.");
        assertNull(dcerpcBinding.getOptions(), "Options should be null initially.");
        assertNull(dcerpcBinding.getEndpoint(), "Endpoint should be null initially.");
        assertNull(dcerpcBinding.getUuid(), "UUID should be null initially.");
        assertEquals(0, dcerpcBinding.getMajor(), "Major version should be 0 initially.");
        assertEquals(0, dcerpcBinding.getMinor(), "Minor version should be 0 initially.");
    }

    @Test
    void testSetOptionEndpointValidPipe() throws DcerpcException {
        String endpoint = "\\pipe\\srvsvc";
        dcerpcBinding.setOption("endpoint", endpoint);

        assertEquals(endpoint, dcerpcBinding.getEndpoint(), "Endpoint should be set correctly.");
        assertNotNull(dcerpcBinding.getUuid(), "UUID should be set for a valid pipe endpoint.");
        assertEquals("4B324FC8-1670-01D3-1278-5A47BF6EE188", dcerpcBinding.getUuid().toString(), "UUID should be parsed correctly.");
        assertEquals(3, dcerpcBinding.getMajor(), "Major version should be parsed correctly.");
        assertEquals(0, dcerpcBinding.getMinor(), "Minor version should be parsed correctly.");
    }

    @Test
    void testSetOptionEndpointInvalidPipe() {
        String endpoint = "\\pipe\\unknown";
        DcerpcException thrown = assertThrows(DcerpcException.class, () -> {
            dcerpcBinding.setOption("endpoint", endpoint);
        }, "Should throw DcerpcException for unknown pipe endpoint.");

        assertTrue(thrown.getMessage().contains("Bad endpoint"), "Exception message should indicate a bad endpoint.");
    }

    @Test
    void testSetOptionEndpointInvalidFormat() {
        String endpoint = "135"; // Example non-pipe endpoint that is not recognized
        DcerpcException thrown = assertThrows(DcerpcException.class, () -> {
            dcerpcBinding.setOption("endpoint", endpoint);
        }, "Should throw DcerpcException for invalid endpoint format.");

        assertTrue(thrown.getMessage().contains("Bad endpoint"), "Exception message should indicate a bad endpoint.");
    }

    @Test
    void testSetOptionOtherKey() throws DcerpcException {
        dcerpcBinding.setOption("connect", "80");
        assertNotNull(dcerpcBinding.getOptions(), "Options map should be initialized.");
        assertEquals("80", dcerpcBinding.getOptions().get("connect"), "Option value should be set correctly.");
    }

    @Test
    void testGetOptionEndpoint() throws DcerpcException {
        String endpoint = "\\pipe\\srvsvc";
        dcerpcBinding.setOption("endpoint", endpoint);
        assertEquals(endpoint, dcerpcBinding.getOption("endpoint"), "Should return the set endpoint.");
    }

    @Test
    void testGetOptionOtherKey() throws DcerpcException {
        dcerpcBinding.setOption("connect", "80");
        assertEquals("80", dcerpcBinding.getOption("connect"), "Should return the set option value.");
    }

    @Test
    void testGetOptionNonExistent() {
        assertNull(dcerpcBinding.getOption("nonExistent"), "Should return null for a non-existent option.");
    }

    @Test
    void testToStringWithoutOptionsAndEndpoint() {
        String expected = PROTO + ":" + SERVER + "[null]";
        assertEquals(expected, dcerpcBinding.toString(), "toString should correctly represent the binding without options or endpoint.");
    }

    @Test
    void testToStringWithEndpoint() throws DcerpcException {
        String endpoint = "\\pipe\\srvsvc";
        dcerpcBinding.setOption("endpoint", endpoint);
        String expected = PROTO + ":" + SERVER + "[" + endpoint + "]";
        assertEquals(expected, dcerpcBinding.toString(), "toString should correctly represent the binding with an endpoint.");
    }

    @Test
    void testToStringWithOptions() throws DcerpcException {
        dcerpcBinding.setOption("connect", "80");
        dcerpcBinding.setOption("bind", "123");
        // Order of options in toString might vary due to HashMap, so check for containment
        String result = dcerpcBinding.toString();
        assertTrue(result.startsWith(PROTO + ":" + SERVER + "[null,"), "toString should start correctly.");
        assertTrue(result.contains("connect=80"), "toString should contain connect option.");
        assertTrue(result.contains("bind=123"), "toString should contain bind option.");
    }

    @Test
    void testToStringWithEndpointAndOptions() throws DcerpcException {
        String endpoint = "\\pipe\\srvsvc";
        dcerpcBinding.setOption("endpoint", endpoint);
        dcerpcBinding.setOption("connect", "80");
        String result = dcerpcBinding.toString();
        assertTrue(result.startsWith(PROTO + ":" + SERVER + "[" + endpoint + ","), "toString should start correctly with endpoint.");
        assertTrue(result.contains("connect=80"), "toString should contain connect option.");
    }

    @Test
    void testSetOptionEndpointWithVariousValidPipes() throws DcerpcException {
        Object[][] testData = {
                {"\\pipe\\srvsvc", "srvsvc", "4B324FC8-1670-01D3-1278-5A47BF6EE188", 3, 0},
                {"\\pipe\\lsarpc", "lsarpc", "12345778-1234-ABCD-EF00-0123456789AB", 2, 1},
                {"\\pipe\\samr", "samr", "12345778-1234-ABCD-EF00-0123456789AC", 1, 0}
        };

        for (Object[] data : testData) {
            String endpoint = (String) data[0];
            String pipeName = (String) data[1];
            String expectedUuid = (String) data[2];
            int expectedMajor = (int) data[3];
            int expectedMinor = (int) data[4];

            // The interfaces are added in setUp()
            dcerpcBinding.setOption("endpoint", endpoint);

            assertEquals(endpoint, dcerpcBinding.getEndpoint(), "Endpoint should be set correctly for " + pipeName);
            assertNotNull(dcerpcBinding.getUuid(), "UUID should be set for " + pipeName);
            assertEquals(expectedUuid, dcerpcBinding.getUuid().toString(), "UUID should be parsed correctly for " + pipeName);
            assertEquals(expectedMajor, dcerpcBinding.getMajor(), "Major version should be parsed correctly for " + pipeName);
            assertEquals(expectedMinor, dcerpcBinding.getMinor(), "Minor version should be parsed correctly for " + pipeName);
        }
    }

    @Test
    void testAddInterfaceAndUseIt() throws DcerpcException {
        String newInterfaceName = "testinterface";
        String newInterfaceSyntax = "11111111-2222-3333-4444-555555555555:1.0";
        String newEndpoint = "\\pipe\\" + newInterfaceName;

        DcerpcBinding.addInterface(newInterfaceName, newInterfaceSyntax);

        dcerpcBinding.setOption("endpoint", newEndpoint);

        assertEquals(newEndpoint, dcerpcBinding.getEndpoint(), "Endpoint should be set correctly for newly added interface.");
        assertNotNull(dcerpcBinding.getUuid(), "UUID should be set for newly added interface.");
        assertEquals("11111111-2222-3333-4444-555555555555", dcerpcBinding.getUuid().toString(), "UUID should be parsed correctly for newly added interface.");
        assertEquals(1, dcerpcBinding.getMajor(), "Major version should be parsed correctly for newly added interface.");
        assertEquals(0, dcerpcBinding.getMinor(), "Minor version should be parsed correctly for newly added interface.");
    }
}