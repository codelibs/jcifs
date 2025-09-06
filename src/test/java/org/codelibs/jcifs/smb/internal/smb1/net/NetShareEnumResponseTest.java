package org.codelibs.jcifs.smb.internal.smb1.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.FileEntry;
import org.codelibs.jcifs.smb.config.BaseConfiguration;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Test class for NetShareEnumResponse
 */
class NetShareEnumResponseTest {

    @Mock
    private Configuration mockConfig;

    private NetShareEnumResponse response;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        // Use real configuration for most tests
        mockConfig = new BaseConfiguration(false);
        response = new NetShareEnumResponse(mockConfig);
    }

    @Test
    @DisplayName("Test constructor with configuration")
    void testConstructor() {
        assertNotNull(response);
        // Response is successfully created with configuration
        assertTrue(response instanceof NetShareEnumResponse);
    }

    @Test
    @DisplayName("Test writeSetupWireFormat returns 0")
    void testWriteSetupWireFormat() {
        byte[] dst = new byte[100];
        int result = response.writeSetupWireFormat(dst, 0);
        assertEquals(0, result);

        // Test with different offset
        result = response.writeSetupWireFormat(dst, 50);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat returns 0")
    void testWriteParametersWireFormat() {
        byte[] dst = new byte[100];
        int result = response.writeParametersWireFormat(dst, 0);
        assertEquals(0, result);

        // Test with different offset
        result = response.writeParametersWireFormat(dst, 25);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeDataWireFormat returns 0")
    void testWriteDataWireFormat() {
        byte[] dst = new byte[100];
        int result = response.writeDataWireFormat(dst, 0);
        assertEquals(0, result);

        // Test with different offset
        result = response.writeDataWireFormat(dst, 75);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readSetupWireFormat returns 0")
    void testReadSetupWireFormat() {
        byte[] buffer = new byte[100];
        int result = response.readSetupWireFormat(buffer, 0, 100);
        assertEquals(0, result);

        // Test with different parameters
        result = response.readSetupWireFormat(buffer, 10, 50);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readParametersWireFormat with valid data")
    void testReadParametersWireFormat() throws Exception {
        byte[] buffer = new byte[8];
        int bufferIndex = 0;

        // status (2 bytes)
        SMBUtil.writeInt2(0, buffer, bufferIndex);
        bufferIndex += 2;
        // converter (2 bytes)
        SMBUtil.writeInt2(100, buffer, bufferIndex);
        bufferIndex += 2;
        // numEntries (2 bytes)
        SMBUtil.writeInt2(3, buffer, bufferIndex);
        bufferIndex += 2;
        // totalAvailableEntries (2 bytes)
        SMBUtil.writeInt2(5, buffer, bufferIndex);

        int bytesRead = response.readParametersWireFormat(buffer, 0, 8);

        assertEquals(8, bytesRead);
        assertEquals(0, getStatus(response));
        assertEquals(100, getConverter(response));
        assertEquals(3, getNumEntries(response));
        assertEquals(5, getTotalAvailableEntries(response));
    }

    @ParameterizedTest
    @DisplayName("Test readParametersWireFormat with various status values")
    @ValueSource(ints = { 0, 1, 100, 255, 32767, 65535 })
    void testReadParametersWireFormatWithVariousStatus(int status) throws Exception {
        byte[] buffer = new byte[8];
        int bufferIndex = 0;

        SMBUtil.writeInt2(status, buffer, bufferIndex);
        bufferIndex += 2;
        SMBUtil.writeInt2(0, buffer, bufferIndex);
        bufferIndex += 2;
        SMBUtil.writeInt2(0, buffer, bufferIndex);
        bufferIndex += 2;
        SMBUtil.writeInt2(0, buffer, bufferIndex);

        response.readParametersWireFormat(buffer, 0, 8);
        assertEquals(status, getStatus(response));
    }

    @Test
    @DisplayName("Test readDataWireFormat with single share")
    void testReadDataWireFormatSingleShare() throws Exception {
        // Prepare test data
        String shareName = "SHARE1";
        int shareType = 0x00000000; // Disk share
        String remark = "Test share";

        // Calculate buffer size
        int shareNameSize = 14; // 13 bytes + null terminator (fixed field)
        int typeSize = 2;
        int offsetSize = 4;
        int remarkSize = remark.length() + 1;
        int totalSize = shareNameSize + typeSize + offsetSize + remarkSize;

        byte[] buffer = new byte[totalSize + 100]; // Extra space for safety
        int bufferIndex = 0;
        int start = 0;

        // Set converter value first
        setConverter(response, 0);

        // Set number of entries
        setNumEntries(response, 1);

        // Write share name (13 bytes, null padded)
        byte[] nameBytes = shareName.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(nameBytes, 0, buffer, bufferIndex, Math.min(nameBytes.length, 13));
        bufferIndex += 14;

        // Write type (2 bytes)
        SMBUtil.writeInt2(shareType, buffer, bufferIndex);
        bufferIndex += 2;

        // Write remark offset (4 bytes)
        int remarkOffset = shareNameSize + typeSize + offsetSize;
        SMBUtil.writeInt4(remarkOffset, buffer, bufferIndex);
        bufferIndex += 4;

        // Write remark at the calculated offset
        byte[] remarkBytes = remark.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(remarkBytes, 0, buffer, remarkOffset, remarkBytes.length);
        buffer[remarkOffset + remarkBytes.length] = 0; // null terminator

        // Read the data
        int bytesRead = response.readDataWireFormat(buffer, start, buffer.length);

        // Verify results
        assertTrue(bytesRead > 0);
        FileEntry[] results = getResults(response);
        assertNotNull(results);
        assertEquals(1, results.length);

        SmbShareInfo share = (SmbShareInfo) results[0];
        assertEquals(shareName, share.netName);
        assertEquals(shareType, share.type);
        assertEquals(remark, share.remark);
    }

    @Test
    @DisplayName("Test readDataWireFormat with multiple shares")
    void testReadDataWireFormatMultipleShares() throws Exception {
        int numShares = 3;
        String[] shareNames = { "SHARE1", "ADMIN$", "IPC$" };
        int[] shareTypes = { 0, 0x8000, 3 }; // Disk, Hidden flag (stored in 2 bytes), IPC
        String[] remarks = { "First share", "Admin share", "IPC share" };

        // Set converter and number of entries
        setConverter(response, 0);
        setNumEntries(response, numShares);

        // Calculate total buffer size
        int entrySize = 20; // 14 + 2 + 4
        int totalEntrySize = entrySize * numShares;
        int totalRemarkSize = 0;
        for (String remark : remarks) {
            totalRemarkSize += remark.length() + 1;
        }

        byte[] buffer = new byte[totalEntrySize + totalRemarkSize + 100];
        int bufferIndex = 0;
        int remarkOffset = totalEntrySize;

        // Write all entries
        for (int i = 0; i < numShares; i++) {
            // Write share name (14 bytes)
            byte[] nameBytes = shareNames[i].getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(nameBytes, 0, buffer, bufferIndex, Math.min(nameBytes.length, 13));
            bufferIndex += 14;

            // Write type (2 bytes)
            SMBUtil.writeInt2(shareTypes[i], buffer, bufferIndex);
            bufferIndex += 2;

            // Write remark offset (4 bytes)
            SMBUtil.writeInt4(remarkOffset, buffer, bufferIndex);
            bufferIndex += 4;

            // Write remark at offset
            byte[] remarkBytes = remarks[i].getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(remarkBytes, 0, buffer, remarkOffset, remarkBytes.length);
            buffer[remarkOffset + remarkBytes.length] = 0;
            remarkOffset += remarkBytes.length + 1;
        }

        // Read the data
        int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);

        // Verify results
        assertTrue(bytesRead > 0);
        FileEntry[] results = getResults(response);
        assertNotNull(results);
        assertEquals(numShares, results.length);

        for (int i = 0; i < numShares; i++) {
            SmbShareInfo share = (SmbShareInfo) results[i];
            assertEquals(shareNames[i], share.netName);
            assertEquals(shareTypes[i], share.type);
            assertEquals(remarks[i], share.remark);
        }
    }

    @Test
    @DisplayName("Test readDataWireFormat with empty shares list")
    void testReadDataWireFormatEmptyShares() throws Exception {
        setNumEntries(response, 0);
        byte[] buffer = new byte[100];

        int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);

        assertEquals(0, bytesRead);
        FileEntry[] results = getResults(response);
        assertNotNull(results);
        assertEquals(0, results.length);
    }

    @Test
    @DisplayName("Test readDataWireFormat with converter offset")
    void testReadDataWireFormatWithConverter() throws Exception {
        // Set converter to test offset calculation
        int converterValue = 100;
        setConverter(response, converterValue);
        setNumEntries(response, 1);

        String shareName = "TEST";
        String remark = "Test remark";

        byte[] buffer = new byte[200];
        int bufferIndex = 0;

        // Write share name
        byte[] nameBytes = shareName.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(nameBytes, 0, buffer, bufferIndex, Math.min(nameBytes.length, 13));
        bufferIndex += 14;

        // Write type
        SMBUtil.writeInt2(0, buffer, bufferIndex);
        bufferIndex += 2;

        // Write remark offset (with converter applied)
        int actualRemarkOffset = 20;
        int wireRemarkOffset = actualRemarkOffset + converterValue;
        SMBUtil.writeInt4(wireRemarkOffset, buffer, bufferIndex);
        bufferIndex += 4;

        // Write remark at actual offset
        byte[] remarkBytes = remark.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(remarkBytes, 0, buffer, actualRemarkOffset, remarkBytes.length);
        buffer[actualRemarkOffset + remarkBytes.length] = 0;

        // Read the data
        response.readDataWireFormat(buffer, 0, buffer.length);

        FileEntry[] results = getResults(response);
        SmbShareInfo share = (SmbShareInfo) results[0];
        assertEquals(remark, share.remark);
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() throws Exception {
        // Set some test values
        setStatus(response, 0);
        setConverter(response, 100);
        setNumEntries(response, 2);
        setTotalAvailableEntries(response, 5);

        String result = response.toString();

        assertNotNull(result);
        assertTrue(result.startsWith("NetShareEnumResponse["));
        assertTrue(result.contains("status=0"));
        assertTrue(result.contains("converter=100"));
        assertTrue(result.contains("entriesReturned=2"));
        assertTrue(result.contains("totalAvailableEntries=5"));
        assertTrue(result.endsWith("]"));
    }

    @Test
    @DisplayName("Test readString with ASCII encoding")
    void testReadStringAscii() throws Exception {
        String testString = "TestString";
        byte[] buffer = new byte[128];
        byte[] stringBytes = testString.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(stringBytes, 0, buffer, 10, stringBytes.length);
        buffer[10 + stringBytes.length] = 0; // null terminator

        // Use reflection to call protected readString method
        Method readStringMethod = getReadStringMethod();
        String result = (String) readStringMethod.invoke(response, buffer, 10, 128, false);

        assertEquals(testString, result);
    }

    @Test
    @DisplayName("Test readString with null terminator in middle")
    void testReadStringWithNullTerminator() throws Exception {
        byte[] buffer = new byte[128];
        String testString = "Test";
        byte[] stringBytes = testString.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(stringBytes, 0, buffer, 0, stringBytes.length);
        buffer[stringBytes.length] = 0; // null terminator

        Method readStringMethod = getReadStringMethod();
        String result = (String) readStringMethod.invoke(response, buffer, 0, 128, false);

        assertEquals(testString, result);
    }

    @ParameterizedTest
    @DisplayName("Test readDataWireFormat with various share types")
    @CsvSource({ "0, SHARE, Normal share", "1, PRINTER, Printer share", "3, IPC$, IPC share", "32768, HIDDEN, Hidden share", // 0x8000 - hidden flag in lower 16 bits
            "32769, HIDDENP, Hidden printer" // 0x8001 - hidden flag + printer type
    })
    void testReadDataWireFormatWithVariousShareTypes(int type, String name, String remark) throws Exception {
        setConverter(response, 0);
        setNumEntries(response, 1);

        byte[] buffer = new byte[200];
        int bufferIndex = 0;

        // Write share name
        byte[] nameBytes = name.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(nameBytes, 0, buffer, bufferIndex, Math.min(nameBytes.length, 13));
        bufferIndex += 14;

        // Write type
        SMBUtil.writeInt2(type, buffer, bufferIndex);
        bufferIndex += 2;

        // Write remark offset
        int remarkOffset = 20;
        SMBUtil.writeInt4(remarkOffset, buffer, bufferIndex);
        bufferIndex += 4;

        // Write remark
        byte[] remarkBytes = remark.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(remarkBytes, 0, buffer, remarkOffset, remarkBytes.length);
        buffer[remarkOffset + remarkBytes.length] = 0;

        // Read and verify
        response.readDataWireFormat(buffer, 0, buffer.length);

        FileEntry[] results = getResults(response);
        SmbShareInfo share = (SmbShareInfo) results[0];
        assertEquals(name, share.netName);
        assertEquals(type, share.type);
        assertEquals(remark, share.remark);
    }

    @Test
    @DisplayName("Test setUseUnicode is called with false")
    void testSetUseUnicode() throws Exception {
        // Create a spy to verify method call
        NetShareEnumResponse spyResponse = spy(new NetShareEnumResponse(mockConfig));

        setNumEntries(spyResponse, 0);
        byte[] buffer = new byte[100];

        spyResponse.readDataWireFormat(buffer, 0, buffer.length);

        // Verify setUseUnicode was called with false
        verify(spyResponse).setUseUnicode(false);
    }

    @Test
    @DisplayName("Test readDataWireFormat with maximum length share name")
    void testReadDataWireFormatMaxLengthShareName() throws Exception {
        setConverter(response, 0);
        setNumEntries(response, 1);

        // Create a 13-character share name (maximum)
        String shareName = "SHARE12345678"; // 13 characters
        String remark = "Max length name";

        byte[] buffer = new byte[200];
        int bufferIndex = 0;

        // Write share name (exactly 13 bytes)
        byte[] nameBytes = shareName.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(nameBytes, 0, buffer, bufferIndex, 13);
        buffer[13] = 0; // null terminator at position 13
        bufferIndex += 14;

        // Write type
        SMBUtil.writeInt2(0, buffer, bufferIndex);
        bufferIndex += 2;

        // Write remark offset
        SMBUtil.writeInt4(20, buffer, bufferIndex);
        bufferIndex += 4;

        // Write remark
        byte[] remarkBytes = remark.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(remarkBytes, 0, buffer, 20, remarkBytes.length);
        buffer[20 + remarkBytes.length] = 0;

        response.readDataWireFormat(buffer, 0, buffer.length);

        FileEntry[] results = getResults(response);
        SmbShareInfo share = (SmbShareInfo) results[0];
        assertEquals(shareName, share.netName);
    }

    // Helper methods using reflection to access private fields

    private int getStatus(NetShareEnumResponse response) throws Exception {
        Field field = getSuperclassField(response.getClass(), "status");
        field.setAccessible(true);
        return field.getInt(response);
    }

    private void setStatus(NetShareEnumResponse response, int value) throws Exception {
        Method method = getSuperclassMethod(response.getClass(), "setStatus", int.class);
        method.setAccessible(true);
        method.invoke(response, value);
    }

    private int getConverter(NetShareEnumResponse response) throws Exception {
        Field field = response.getClass().getDeclaredField("converter");
        field.setAccessible(true);
        return field.getInt(response);
    }

    private void setConverter(NetShareEnumResponse response, int value) throws Exception {
        Field field = response.getClass().getDeclaredField("converter");
        field.setAccessible(true);
        field.setInt(response, value);
    }

    private int getNumEntries(NetShareEnumResponse response) throws Exception {
        Method method = getSuperclassMethod(response.getClass(), "getNumEntries");
        method.setAccessible(true);
        return (int) method.invoke(response);
    }

    private void setNumEntries(NetShareEnumResponse response, int value) throws Exception {
        Method method = getSuperclassMethod(response.getClass(), "setNumEntries", int.class);
        method.setAccessible(true);
        method.invoke(response, value);
    }

    private int getTotalAvailableEntries(NetShareEnumResponse response) throws Exception {
        Field field = response.getClass().getDeclaredField("totalAvailableEntries");
        field.setAccessible(true);
        return field.getInt(response);
    }

    private void setTotalAvailableEntries(NetShareEnumResponse response, int value) throws Exception {
        Field field = response.getClass().getDeclaredField("totalAvailableEntries");
        field.setAccessible(true);
        field.setInt(response, value);
    }

    private FileEntry[] getResults(NetShareEnumResponse response) throws Exception {
        Method method = getSuperclassMethod(response.getClass(), "getResults");
        method.setAccessible(true);
        return (FileEntry[]) method.invoke(response);
    }

    private Method getReadStringMethod() throws Exception {
        Class<?> clazz = response.getClass();
        while (clazz != null) {
            try {
                Method method = clazz.getDeclaredMethod("readString", byte[].class, int.class, int.class, boolean.class);
                method.setAccessible(true);
                return method;
            } catch (NoSuchMethodException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchMethodException("readString method not found");
    }

    private Field getSuperclassField(Class<?> clazz, String fieldName) throws NoSuchFieldException {
        while (clazz != null) {
            try {
                return clazz.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException("Field " + fieldName + " not found");
    }

    private Method getSuperclassMethod(Class<?> clazz, String methodName, Class<?>... paramTypes) throws NoSuchMethodException {
        while (clazz != null) {
            try {
                return clazz.getDeclaredMethod(methodName, paramTypes);
            } catch (NoSuchMethodException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchMethodException("Method " + methodName + " not found");
    }
}
