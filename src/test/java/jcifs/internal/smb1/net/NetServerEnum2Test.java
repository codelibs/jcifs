package jcifs.internal.smb1.net;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.config.BaseConfiguration;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for NetServerEnum2
 */
class NetServerEnum2Test {

    @Mock
    private Configuration mockConfig;

    private NetServerEnum2 netServerEnum2;
    private Configuration realConfig;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        // Use real configuration for most tests
        realConfig = new BaseConfiguration(false);
        // Mock configuration setup
        when(mockConfig.getTransactionBufferSize()).thenReturn(65535);
    }

    @Test
    @DisplayName("Test constructor with domain and server types")
    void testConstructor() {
        String domain = "WORKGROUP";
        int serverTypes = NetServerEnum2.SV_TYPE_ALL;

        netServerEnum2 = new NetServerEnum2(realConfig, domain, serverTypes);

        assertNotNull(netServerEnum2);
        assertEquals(domain, getFieldValue(netServerEnum2, "domain"));
        assertEquals(serverTypes, getFieldValue(netServerEnum2, "serverTypes"));
        assertEquals("\\PIPE\\LANMAN", getFieldValue(netServerEnum2, "name"));
        assertEquals(8, getFieldValue(netServerEnum2, "maxParameterCount"));
        assertEquals(16384, getFieldValue(netServerEnum2, "maxDataCount"));
        assertEquals((byte) 0x00, getFieldValue(netServerEnum2, "maxSetupCount"));
        assertEquals(0, getFieldValue(netServerEnum2, "setupCount"));
        assertEquals(5000, getFieldValue(netServerEnum2, "timeout"));
    }

    @Test
    @DisplayName("Test constructor with empty domain")
    void testConstructorEmptyDomain() {
        String domain = "";
        int serverTypes = NetServerEnum2.SV_TYPE_DOMAIN_ENUM;

        netServerEnum2 = new NetServerEnum2(realConfig, domain, serverTypes);

        assertNotNull(netServerEnum2);
        assertEquals(domain, getFieldValue(netServerEnum2, "domain"));
        assertEquals(serverTypes, getFieldValue(netServerEnum2, "serverTypes"));
    }

    @Test
    @DisplayName("Test constructor with mock configuration")
    void testConstructorWithMockConfig() {
        String domain = "TESTDOMAIN";
        int serverTypes = 0x00000801;

        netServerEnum2 = new NetServerEnum2(mockConfig, domain, serverTypes);

        assertNotNull(netServerEnum2);
        assertEquals(domain, getFieldValue(netServerEnum2, "domain"));
        assertEquals(serverTypes, getFieldValue(netServerEnum2, "serverTypes"));
        verify(mockConfig).getTransactionBufferSize();
    }

    @Test
    @DisplayName("Test reset method with lastName")
    void testReset() {
        String domain = "WORKGROUP";
        int serverTypes = NetServerEnum2.SV_TYPE_ALL;
        netServerEnum2 = new NetServerEnum2(realConfig, domain, serverTypes);

        String lastName = "LASTSERVER";
        netServerEnum2.reset(1, lastName);

        assertEquals(lastName, getFieldValue(netServerEnum2, "lastName"));
    }

    @Test
    @DisplayName("Test reset method with null lastName")
    void testResetWithNull() {
        String domain = "WORKGROUP";
        int serverTypes = NetServerEnum2.SV_TYPE_ALL;
        netServerEnum2 = new NetServerEnum2(realConfig, domain, serverTypes);

        netServerEnum2.reset(1, null);

        assertNull(getFieldValue(netServerEnum2, "lastName"));
    }

    @Test
    @DisplayName("Test writeSetupWireFormat returns 0")
    void testWriteSetupWireFormat() {
        netServerEnum2 = new NetServerEnum2(realConfig, "DOMAIN", NetServerEnum2.SV_TYPE_ALL);
        byte[] dst = new byte[100];

        int result = netServerEnum2.writeSetupWireFormat(dst, 0);
        assertEquals(0, result);

        // Test with different offset
        result = netServerEnum2.writeSetupWireFormat(dst, 50);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat for NET_SERVER_ENUM2")
    void testWriteParametersWireFormatNetServerEnum2() throws Exception {
        String domain = "TESTDOMAIN";
        int serverTypes = NetServerEnum2.SV_TYPE_ALL;
        netServerEnum2 = new NetServerEnum2(realConfig, domain, serverTypes);

        byte[] dst = new byte[1024];
        int dstIndex = 0;

        int bytesWritten = netServerEnum2.writeParametersWireFormat(dst, dstIndex);

        // Verify bytes written
        assertTrue(bytesWritten > 0);

        // Verify subcommand
        assertEquals(SmbComTransaction.NET_SERVER_ENUM2, dst[0]);
        assertEquals(0, dst[1]);

        // Verify descriptor (WrLehDO\0B16BBDz\0 in ASCII)
        String expectedDescr = "WrLehDO\u0000B16BBDz\u0000";
        byte[] expectedDescrBytes = expectedDescr.getBytes("ASCII");
        byte[] actualDescrBytes = new byte[expectedDescrBytes.length];
        System.arraycopy(dst, 2, actualDescrBytes, 0, expectedDescrBytes.length);
        assertArrayEquals(expectedDescrBytes, actualDescrBytes);

        // Verify level (0x0001)
        int descrEnd = 2 + expectedDescrBytes.length;
        assertEquals(0x01, dst[descrEnd]);
        assertEquals(0x00, dst[descrEnd + 1]);

        // Verify maxDataCount (16384)
        assertEquals(16384, SMBUtil.readInt2(dst, descrEnd + 2));

        // Verify serverTypes
        assertEquals(serverTypes, SMBUtil.readInt4(dst, descrEnd + 4));

        // Verify domain (should be uppercase)
        int domainStart = descrEnd + 8;
        String writtenDomain = readNullTerminatedString(dst, domainStart);
        assertEquals(domain.toUpperCase(), writtenDomain);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat for NET_SERVER_ENUM3")
    void testWriteParametersWireFormatNetServerEnum3() throws Exception {
        String domain = "WORKGROUP";
        String lastName = "SERVER99";
        int serverTypes = NetServerEnum2.SV_TYPE_DOMAIN_ENUM;

        netServerEnum2 = new NetServerEnum2(realConfig, domain, serverTypes);
        // Set subcommand to NET_SERVER_ENUM3
        setFieldValue(netServerEnum2, "subCommand", SmbComTransaction.NET_SERVER_ENUM3);
        netServerEnum2.reset(1, lastName);

        byte[] dst = new byte[1024];
        int dstIndex = 0;

        int bytesWritten = netServerEnum2.writeParametersWireFormat(dst, dstIndex);

        // Verify bytes written
        assertTrue(bytesWritten > 0);

        // Verify subcommand
        assertEquals(SmbComTransaction.NET_SERVER_ENUM3, dst[0]);

        // Verify descriptor for NET_SERVER_ENUM3 (WrLehDz\0B16BBDz\0 in ASCII)
        String expectedDescr = "WrLehDz\u0000B16BBDz\u0000";
        byte[] expectedDescrBytes = expectedDescr.getBytes("ASCII");
        byte[] actualDescrBytes = new byte[expectedDescrBytes.length];
        System.arraycopy(dst, 2, actualDescrBytes, 0, expectedDescrBytes.length);
        assertArrayEquals(expectedDescrBytes, actualDescrBytes);

        // Verify domain
        int domainStart = 2 + expectedDescrBytes.length + 8;
        String writtenDomain = readNullTerminatedString(dst, domainStart);
        assertEquals(domain.toUpperCase(), writtenDomain);

        // Verify lastName is written for NET_SERVER_ENUM3
        int lastNameStart = domainStart + domain.length() + 1;
        String writtenLastName = readNullTerminatedString(dst, lastNameStart);
        assertEquals(lastName.toUpperCase(), writtenLastName);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat with null lastName for NET_SERVER_ENUM3 throws NPE")
    void testWriteParametersWireFormatNetServerEnum3NullLastName() throws Exception {
        String domain = "WORKGROUP";
        int serverTypes = NetServerEnum2.SV_TYPE_ALL;

        netServerEnum2 = new NetServerEnum2(realConfig, domain, serverTypes);
        // Set subcommand to NET_SERVER_ENUM3 without setting lastName
        setFieldValue(netServerEnum2, "subCommand", SmbComTransaction.NET_SERVER_ENUM3);

        byte[] dst = new byte[1024];

        // Should throw NullPointerException when lastName is null for NET_SERVER_ENUM3
        assertThrows(NullPointerException.class, () -> {
            netServerEnum2.writeParametersWireFormat(dst, 0);
        });
    }

    @Test
    @DisplayName("Test writeParametersWireFormat with special characters in domain")
    void testWriteParametersWireFormatSpecialCharacters() {
        String domain = "Test-Domain_123";
        int serverTypes = 0x00000001;
        netServerEnum2 = new NetServerEnum2(realConfig, domain, serverTypes);

        byte[] dst = new byte[1024];
        int bytesWritten = netServerEnum2.writeParametersWireFormat(dst, 0);

        assertTrue(bytesWritten > 0);

        // Find and verify domain
        String expectedDescr = "WrLehDO\u0000B16BBDz\u0000";
        int domainStart = 2 + expectedDescr.getBytes().length + 8;
        String writtenDomain = readNullTerminatedString(dst, domainStart);
        assertEquals(domain.toUpperCase(), writtenDomain);
    }

    @ParameterizedTest
    @DisplayName("Test writeParametersWireFormat with various server types")
    @ValueSource(ints = { 0x00000000, 0x00000001, 0x00000801, 0x80000000, 0xFFFFFFFF })
    void testWriteParametersWireFormatVariousServerTypes(int serverType) {
        String domain = "DOMAIN";
        netServerEnum2 = new NetServerEnum2(realConfig, domain, serverType);

        byte[] dst = new byte[1024];
        int bytesWritten = netServerEnum2.writeParametersWireFormat(dst, 0);

        assertTrue(bytesWritten > 0);

        // Verify server type is written correctly
        String expectedDescr = "WrLehDO\u0000B16BBDz\u0000";
        int serverTypeOffset = 2 + expectedDescr.getBytes().length + 4;
        assertEquals(serverType, SMBUtil.readInt4(dst, serverTypeOffset));
    }

    @Test
    @DisplayName("Test writeParametersWireFormat with small buffer throws ArrayIndexOutOfBoundsException")
    void testWriteParametersWireFormatSmallBuffer() {
        String domain = "DOMAIN";
        netServerEnum2 = new NetServerEnum2(realConfig, domain, NetServerEnum2.SV_TYPE_ALL);

        // Test with very small buffer
        byte[] dst = new byte[10]; // Too small for the full parameters

        // Should throw ArrayIndexOutOfBoundsException
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            netServerEnum2.writeParametersWireFormat(dst, 0);
        });
    }

    @Test
    @DisplayName("Test writeParametersWireFormat with large buffer succeeds")
    void testWriteParametersWireFormatLargeBuffer() {
        String domain = "DOMAIN";
        netServerEnum2 = new NetServerEnum2(realConfig, domain, NetServerEnum2.SV_TYPE_ALL);

        // Test with adequately sized buffer
        byte[] dst = new byte[1024];

        assertDoesNotThrow(() -> {
            int result = netServerEnum2.writeParametersWireFormat(dst, 0);
            assertTrue(result > 0);
        });
    }

    @Test
    @DisplayName("Test writeDataWireFormat returns 0")
    void testWriteDataWireFormat() {
        netServerEnum2 = new NetServerEnum2(realConfig, "DOMAIN", NetServerEnum2.SV_TYPE_ALL);
        byte[] dst = new byte[100];

        int result = netServerEnum2.writeDataWireFormat(dst, 0);
        assertEquals(0, result);

        // Test with different offset
        result = netServerEnum2.writeDataWireFormat(dst, 25);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readSetupWireFormat returns 0")
    void testReadSetupWireFormat() {
        netServerEnum2 = new NetServerEnum2(realConfig, "DOMAIN", NetServerEnum2.SV_TYPE_ALL);
        byte[] buffer = new byte[100];

        int result = netServerEnum2.readSetupWireFormat(buffer, 0, 100);
        assertEquals(0, result);

        // Test with different parameters
        result = netServerEnum2.readSetupWireFormat(buffer, 10, 50);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readParametersWireFormat returns 0")
    void testReadParametersWireFormat() {
        netServerEnum2 = new NetServerEnum2(realConfig, "DOMAIN", NetServerEnum2.SV_TYPE_ALL);
        byte[] buffer = new byte[100];

        int result = netServerEnum2.readParametersWireFormat(buffer, 0, 100);
        assertEquals(0, result);

        // Test with different parameters
        result = netServerEnum2.readParametersWireFormat(buffer, 25, 75);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readDataWireFormat returns 0")
    void testReadDataWireFormat() {
        netServerEnum2 = new NetServerEnum2(realConfig, "DOMAIN", NetServerEnum2.SV_TYPE_ALL);
        byte[] buffer = new byte[100];

        int result = netServerEnum2.readDataWireFormat(buffer, 0, 100);
        assertEquals(0, result);

        // Test with different parameters
        result = netServerEnum2.readDataWireFormat(buffer, 50, 50);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test toString with SV_TYPE_ALL")
    void testToStringWithSvTypeAll() {
        String domain = "WORKGROUP";
        netServerEnum2 = new NetServerEnum2(realConfig, domain, NetServerEnum2.SV_TYPE_ALL);

        String result = netServerEnum2.toString();

        assertNotNull(result);
        assertTrue(result.contains("NetServerEnum2["));
        assertTrue(result.contains("name=\\PIPE\\LANMAN"));
        assertTrue(result.contains("serverTypes=SV_TYPE_ALL"));
        assertTrue(result.endsWith("]"));
    }

    @Test
    @DisplayName("Test toString with SV_TYPE_DOMAIN_ENUM")
    void testToStringWithSvTypeDomainEnum() {
        String domain = "DOMAIN";
        netServerEnum2 = new NetServerEnum2(realConfig, domain, NetServerEnum2.SV_TYPE_DOMAIN_ENUM);

        String result = netServerEnum2.toString();

        assertNotNull(result);
        assertTrue(result.contains("NetServerEnum2["));
        assertTrue(result.contains("name=\\PIPE\\LANMAN"));
        assertTrue(result.contains("serverTypes=SV_TYPE_DOMAIN_ENUM"));
        assertTrue(result.endsWith("]"));
    }

    @Test
    @DisplayName("Test toString with custom server type")
    void testToStringWithCustomServerType() {
        String domain = "CUSTOM";
        int customType = 0x00000801;
        netServerEnum2 = new NetServerEnum2(realConfig, domain, customType);

        String result = netServerEnum2.toString();

        assertNotNull(result);
        assertTrue(result.contains("NetServerEnum2["));
        assertTrue(result.contains("name=\\PIPE\\LANMAN"));
        // For custom types, it defaults to SV_TYPE_DOMAIN_ENUM in toString
        assertTrue(result.contains("serverTypes=SV_TYPE_DOMAIN_ENUM"));
        assertTrue(result.endsWith("]"));
    }

    @ParameterizedTest
    @DisplayName("Test constants values")
    @CsvSource({ "SV_TYPE_ALL, -1", "SV_TYPE_DOMAIN_ENUM, -2147483648" })
    void testConstants(String constantName, int expectedValue) {
        if ("SV_TYPE_ALL".equals(constantName)) {
            assertEquals(expectedValue, NetServerEnum2.SV_TYPE_ALL);
            assertEquals(0xFFFFFFFF, NetServerEnum2.SV_TYPE_ALL);
        } else if ("SV_TYPE_DOMAIN_ENUM".equals(constantName)) {
            assertEquals(expectedValue, NetServerEnum2.SV_TYPE_DOMAIN_ENUM);
            assertEquals(0x80000000, NetServerEnum2.SV_TYPE_DOMAIN_ENUM);
        }
    }

    @Test
    @DisplayName("Test DESCR array contents")
    void testDescrArray() throws Exception {
        Field descrField = NetServerEnum2.class.getDeclaredField("DESCR");
        descrField.setAccessible(true);
        String[] descr = (String[]) descrField.get(null);

        assertNotNull(descr);
        assertEquals(2, descr.length);
        assertEquals("WrLehDO\u0000B16BBDz\u0000", descr[0]);
        assertEquals("WrLehDz\u0000B16BBDz\u0000", descr[1]);
    }

    @Test
    @DisplayName("Test inheritance from SmbComTransaction")
    void testInheritance() {
        netServerEnum2 = new NetServerEnum2(realConfig, "DOMAIN", NetServerEnum2.SV_TYPE_ALL);

        assertTrue(netServerEnum2 instanceof SmbComTransaction);

        // Test inherited getSubCommand method
        byte subCommand = netServerEnum2.getSubCommand();
        assertEquals(SmbComTransaction.NET_SERVER_ENUM2, subCommand);
    }

    @Test
    @DisplayName("Test with very long domain name")
    void testVeryLongDomainName() {
        String longDomain = "A".repeat(256); // Very long domain name
        netServerEnum2 = new NetServerEnum2(realConfig, longDomain, NetServerEnum2.SV_TYPE_ALL);

        byte[] dst = new byte[2048];
        int bytesWritten = netServerEnum2.writeParametersWireFormat(dst, 0);

        assertTrue(bytesWritten > 0);

        // Verify domain is written (uppercase)
        String expectedDescr = "WrLehDO\u0000B16BBDz\u0000";
        int domainStart = 2 + expectedDescr.getBytes().length + 8;
        String writtenDomain = readNullTerminatedString(dst, domainStart);
        assertEquals(longDomain.toUpperCase(), writtenDomain);
    }

    @Test
    @DisplayName("Test with empty lastName for NET_SERVER_ENUM3")
    void testEmptyLastNameNetServerEnum3() throws Exception {
        String domain = "WORKGROUP";
        String lastName = "";
        int serverTypes = NetServerEnum2.SV_TYPE_ALL;

        netServerEnum2 = new NetServerEnum2(realConfig, domain, serverTypes);
        setFieldValue(netServerEnum2, "subCommand", SmbComTransaction.NET_SERVER_ENUM3);
        netServerEnum2.reset(1, lastName);

        byte[] dst = new byte[1024];
        int bytesWritten = netServerEnum2.writeParametersWireFormat(dst, 0);

        assertTrue(bytesWritten > 0);

        // Verify empty lastName is written
        String expectedDescr = "WrLehDz\u0000B16BBDz\u0000";
        int domainStart = 2 + expectedDescr.getBytes().length + 8;
        String writtenDomain = readNullTerminatedString(dst, domainStart);
        assertEquals(domain.toUpperCase(), writtenDomain);

        int lastNameStart = domainStart + domain.length() + 1;
        String writtenLastName = readNullTerminatedString(dst, lastNameStart);
        assertEquals("", writtenLastName);
    }

    // Helper methods

    private Object getFieldValue(Object obj, String fieldName) {
        try {
            Field field = getField(obj.getClass(), fieldName);
            field.setAccessible(true);
            return field.get(obj);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get field value: " + fieldName, e);
        }
    }

    private void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = getField(obj.getClass(), fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    private Field getField(Class<?> clazz, String fieldName) throws NoSuchFieldException {
        while (clazz != null) {
            try {
                return clazz.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException("Field " + fieldName + " not found");
    }

    private String readNullTerminatedString(byte[] buffer, int offset) {
        int end = offset;
        while (end < buffer.length && buffer[end] != 0) {
            end++;
        }
        return new String(buffer, offset, end - offset);
    }
}
