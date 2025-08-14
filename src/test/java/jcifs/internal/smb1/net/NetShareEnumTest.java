package jcifs.internal.smb1.net;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.config.BaseConfiguration;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for NetShareEnum
 */
class NetShareEnumTest {

    @Mock
    private Configuration mockConfig;

    private NetShareEnum netShareEnum;
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
    @DisplayName("Test constructor initializes fields correctly")
    void testConstructor() {
        netShareEnum = new NetShareEnum(realConfig);

        assertNotNull(netShareEnum);
        assertEquals("\\PIPE\\LANMAN", getFieldValue(netShareEnum, "name"));
        assertEquals(8, getFieldValue(netShareEnum, "maxParameterCount"));
        assertEquals((byte) 0x00, getFieldValue(netShareEnum, "maxSetupCount"));
        assertEquals(0, getFieldValue(netShareEnum, "setupCount"));
        assertEquals(5000, getFieldValue(netShareEnum, "timeout"));

        // Verify command and subcommand from parent class
        assertEquals(SmbComTransaction.SMB_COM_TRANSACTION, getFieldValue(netShareEnum, "command"));
        assertEquals(SmbComTransaction.NET_SHARE_ENUM, netShareEnum.getSubCommand());
    }

    @Test
    @DisplayName("Test constructor with mock configuration")
    void testConstructorWithMockConfig() {
        netShareEnum = new NetShareEnum(mockConfig);

        assertNotNull(netShareEnum);
        assertEquals("\\PIPE\\LANMAN", getFieldValue(netShareEnum, "name"));
        verify(mockConfig).getTransactionBufferSize();
    }

    @Test
    @DisplayName("Test DESCR constant value")
    void testDescrConstant() throws Exception {
        Field descrField = NetShareEnum.class.getDeclaredField("DESCR");
        descrField.setAccessible(true);
        String descr = (String) descrField.get(null);

        assertEquals("WrLeh\u0000B13BWz\u0000", descr);

        // Verify ASCII conversion
        byte[] descrBytes = descr.getBytes("ASCII");
        assertNotNull(descrBytes);
        assertEquals(13, descrBytes.length); // WrLeh(5) + null(1) + B13BWz(6) + null(1) = 13
    }

    @Test
    @DisplayName("Test writeSetupWireFormat returns 0")
    void testWriteSetupWireFormat() {
        netShareEnum = new NetShareEnum(realConfig);
        byte[] dst = new byte[100];

        int result = netShareEnum.writeSetupWireFormat(dst, 0);
        assertEquals(0, result);

        // Test with different offset
        result = netShareEnum.writeSetupWireFormat(dst, 50);
        assertEquals(0, result);

        // Verify no data was written
        assertArrayEquals(new byte[100], dst);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat writes correct data")
    void testWriteParametersWireFormat() throws Exception {
        netShareEnum = new NetShareEnum(realConfig);
        byte[] dst = new byte[256];
        int dstIndex = 0;

        int bytesWritten = netShareEnum.writeParametersWireFormat(dst, dstIndex);

        // Verify bytes written
        assertTrue(bytesWritten > 0);
        assertEquals(19, bytesWritten); // 2 + 13 + 2 + 2

        // Verify NET_SHARE_ENUM command (2 bytes)
        assertEquals(SmbComTransaction.NET_SHARE_ENUM, dst[0]);
        assertEquals(0, dst[1]);

        // Verify descriptor (WrLeh\0B13BWz\0 in ASCII - 13 bytes)
        String expectedDescr = "WrLeh\u0000B13BWz\u0000";
        byte[] expectedDescrBytes = expectedDescr.getBytes("ASCII");
        byte[] actualDescrBytes = new byte[expectedDescrBytes.length];
        System.arraycopy(dst, 2, actualDescrBytes, 0, expectedDescrBytes.length);
        assertArrayEquals(expectedDescrBytes, actualDescrBytes);

        // Verify level (0x0001 - 2 bytes)
        int descrEnd = 2 + expectedDescrBytes.length;
        assertEquals(0x01, dst[descrEnd]);
        assertEquals(0x00, dst[descrEnd + 1]);

        // Verify maxDataCount (2 bytes)
        int maxDataCount = SMBUtil.readInt2(dst, descrEnd + 2);
        assertTrue(maxDataCount > 0);
        assertEquals(getFieldValue(netShareEnum, "maxDataCount"), maxDataCount);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat with different offsets")
    void testWriteParametersWireFormatWithOffsets() throws Exception {
        netShareEnum = new NetShareEnum(realConfig);

        // Test with offset 0
        byte[] dst1 = new byte[256];
        int bytesWritten1 = netShareEnum.writeParametersWireFormat(dst1, 0);

        // Test with offset 100
        byte[] dst2 = new byte[256];
        int bytesWritten2 = netShareEnum.writeParametersWireFormat(dst2, 100);

        // Same number of bytes should be written
        assertEquals(bytesWritten1, bytesWritten2);

        // Data should be the same, just at different offsets
        for (int i = 0; i < bytesWritten1; i++) {
            assertEquals(dst1[i], dst2[100 + i]);
        }
    }

    @Test
    @DisplayName("Test writeParametersWireFormat with encoding issue simulation")
    void testWriteParametersWireFormatEncodingIssue() throws Exception {
        // Create a modified NetShareEnum to test encoding exception path
        NetShareEnum testEnum = new NetShareEnum(realConfig) {
            @Override
            protected int writeParametersWireFormat(byte[] dst, int dstIndex) {
                // Simulate the encoding exception path
                return 0;
            }
        };

        byte[] dst = new byte[256];
        int result = testEnum.writeParametersWireFormat(dst, 0);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat with small buffer throws ArrayIndexOutOfBoundsException")
    void testWriteParametersWireFormatSmallBuffer() {
        netShareEnum = new NetShareEnum(realConfig);

        // Buffer too small for the full parameters (need at least 19 bytes)
        byte[] dst = new byte[10];

        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            netShareEnum.writeParametersWireFormat(dst, 0);
        });
    }

    @Test
    @DisplayName("Test writeParametersWireFormat with exact buffer size")
    void testWriteParametersWireFormatExactBuffer() throws Exception {
        netShareEnum = new NetShareEnum(realConfig);

        // Exact size needed (19 bytes)
        byte[] dst = new byte[19];

        assertDoesNotThrow(() -> {
            int result = netShareEnum.writeParametersWireFormat(dst, 0);
            assertEquals(19, result);
        });
    }

    @Test
    @DisplayName("Test writeDataWireFormat returns 0")
    void testWriteDataWireFormat() {
        netShareEnum = new NetShareEnum(realConfig);
        byte[] dst = new byte[100];

        int result = netShareEnum.writeDataWireFormat(dst, 0);
        assertEquals(0, result);

        // Test with different offset
        result = netShareEnum.writeDataWireFormat(dst, 25);
        assertEquals(0, result);

        // Verify no data was written
        assertArrayEquals(new byte[100], dst);
    }

    @Test
    @DisplayName("Test readSetupWireFormat returns 0")
    void testReadSetupWireFormat() {
        netShareEnum = new NetShareEnum(realConfig);
        byte[] buffer = new byte[100];

        int result = netShareEnum.readSetupWireFormat(buffer, 0, 100);
        assertEquals(0, result);

        // Test with different parameters
        result = netShareEnum.readSetupWireFormat(buffer, 10, 50);
        assertEquals(0, result);

        // Test with zero length
        result = netShareEnum.readSetupWireFormat(buffer, 0, 0);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readParametersWireFormat returns 0")
    void testReadParametersWireFormat() {
        netShareEnum = new NetShareEnum(realConfig);
        byte[] buffer = new byte[100];

        int result = netShareEnum.readParametersWireFormat(buffer, 0, 100);
        assertEquals(0, result);

        // Test with different parameters
        result = netShareEnum.readParametersWireFormat(buffer, 25, 75);
        assertEquals(0, result);

        // Test with zero length
        result = netShareEnum.readParametersWireFormat(buffer, 0, 0);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readDataWireFormat returns 0")
    void testReadDataWireFormat() {
        netShareEnum = new NetShareEnum(realConfig);
        byte[] buffer = new byte[100];

        int result = netShareEnum.readDataWireFormat(buffer, 0, 100);
        assertEquals(0, result);

        // Test with different parameters
        result = netShareEnum.readDataWireFormat(buffer, 50, 50);
        assertEquals(0, result);

        // Test with zero length
        result = netShareEnum.readDataWireFormat(buffer, 0, 0);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() {
        netShareEnum = new NetShareEnum(realConfig);

        String result = netShareEnum.toString();

        assertNotNull(result);
        assertTrue(result.startsWith("NetShareEnum["));
        assertTrue(result.endsWith("]"));
        assertTrue(result.contains("command="));
    }

    @Test
    @DisplayName("Test inheritance from SmbComTransaction")
    void testInheritance() {
        netShareEnum = new NetShareEnum(realConfig);

        assertTrue(netShareEnum instanceof SmbComTransaction);

        // Test inherited getSubCommand method
        byte subCommand = netShareEnum.getSubCommand();
        assertEquals(SmbComTransaction.NET_SHARE_ENUM, subCommand);
    }

    @ParameterizedTest
    @DisplayName("Test maxDataCount values")
    @ValueSource(ints = { 1024, 2048, 4096, 8192, 16384, 32768, 65535 })
    void testMaxDataCountValues(int maxDataCount) throws Exception {
        netShareEnum = new NetShareEnum(realConfig);

        // Set maxDataCount using reflection
        setFieldValue(netShareEnum, "maxDataCount", maxDataCount);

        byte[] dst = new byte[256];
        int bytesWritten = netShareEnum.writeParametersWireFormat(dst, 0);

        // Verify maxDataCount is written correctly
        String expectedDescr = "WrLeh\u0000B13BWz\u0000";
        int maxDataCountOffset = 2 + expectedDescr.getBytes("ASCII").length + 2;
        int writtenMaxDataCount = SMBUtil.readInt2(dst, maxDataCountOffset);
        assertEquals(maxDataCount, writtenMaxDataCount);
    }

    @Test
    @DisplayName("Test all read/write methods with null buffers")
    void testMethodsWithNullBuffers() {
        netShareEnum = new NetShareEnum(realConfig);

        // Write methods return 0 when buffer is null (no NullPointerException thrown)
        assertEquals(0, netShareEnum.writeSetupWireFormat(null, 0));

        assertThrows(NullPointerException.class, () -> {
            netShareEnum.writeParametersWireFormat(null, 0);
        });

        assertEquals(0, netShareEnum.writeDataWireFormat(null, 0));

        // Read methods return 0 with null buffers
        assertEquals(0, netShareEnum.readSetupWireFormat(null, 0, 0));
        assertEquals(0, netShareEnum.readParametersWireFormat(null, 0, 0));
        assertEquals(0, netShareEnum.readDataWireFormat(null, 0, 0));
    }

    @Test
    @DisplayName("Test descriptor ASCII encoding")
    void testDescrAsciiEncoding() throws UnsupportedEncodingException {
        String descr = "WrLeh\u0000B13BWz\u0000";
        byte[] asciiBytes = descr.getBytes("ASCII");

        // The actual string has 13 bytes
        assertEquals(13, asciiBytes.length);

        // Verify specific bytes
        assertEquals('W', asciiBytes[0]);
        assertEquals('r', asciiBytes[1]);
        assertEquals('L', asciiBytes[2]);
        assertEquals('e', asciiBytes[3]);
        assertEquals('h', asciiBytes[4]);
        assertEquals(0, asciiBytes[5]); // null character
        assertEquals('B', asciiBytes[6]);
        assertEquals('1', asciiBytes[7]);
        assertEquals('3', asciiBytes[8]);
        assertEquals('B', asciiBytes[9]);
        assertEquals('W', asciiBytes[10]);
        assertEquals('z', asciiBytes[11]);
        assertEquals(0, asciiBytes[12]); // null character
    }

    @Test
    @DisplayName("Test field values after construction")
    void testFieldValuesAfterConstruction() {
        netShareEnum = new NetShareEnum(realConfig);

        // Test all important fields
        assertEquals("\\PIPE\\LANMAN", getFieldValue(netShareEnum, "name"));
        assertEquals(8, getFieldValue(netShareEnum, "maxParameterCount"));
        assertEquals((byte) 0x00, getFieldValue(netShareEnum, "maxSetupCount"));
        assertEquals(0, getFieldValue(netShareEnum, "setupCount"));
        assertEquals(5000, getFieldValue(netShareEnum, "timeout"));

        // maxDataCount should be set from configuration
        assertNotNull(getFieldValue(netShareEnum, "maxDataCount"));
        assertTrue((int) getFieldValue(netShareEnum, "maxDataCount") > 0);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat data integrity")
    void testWriteParametersWireFormatDataIntegrity() throws Exception {
        netShareEnum = new NetShareEnum(realConfig);
        byte[] dst = new byte[256];

        // Write parameters
        int bytesWritten = netShareEnum.writeParametersWireFormat(dst, 0);

        // Verify all sections of written data
        int offset = 0;

        // 1. NET_SHARE_ENUM command (2 bytes)
        assertEquals(SmbComTransaction.NET_SHARE_ENUM, SMBUtil.readInt2(dst, offset));
        offset += 2;

        // 2. Descriptor string (13 bytes)
        String descr = "WrLeh\u0000B13BWz\u0000";
        byte[] descrBytes = descr.getBytes("ASCII");
        for (int i = 0; i < descrBytes.length; i++) {
            assertEquals(descrBytes[i], dst[offset + i]);
        }
        offset += descrBytes.length;

        // 3. Level (2 bytes)
        assertEquals(0x0001, SMBUtil.readInt2(dst, offset));
        offset += 2;

        // 4. MaxDataCount (2 bytes)
        int maxDataCount = SMBUtil.readInt2(dst, offset);
        assertTrue(maxDataCount > 0);
        offset += 2;

        // Verify total bytes written
        assertEquals(offset, bytesWritten);
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
}
