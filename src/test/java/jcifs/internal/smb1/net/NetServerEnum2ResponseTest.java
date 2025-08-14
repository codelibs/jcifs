package jcifs.internal.smb1.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.config.BaseConfiguration;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.FileEntry;

/**
 * Test class for NetServerEnum2Response
 */
class NetServerEnum2ResponseTest {

    @Mock
    private Configuration mockConfig;

    private NetServerEnum2Response response;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        // Use real configuration for most tests
        mockConfig = new BaseConfiguration(false);
        response = new NetServerEnum2Response(mockConfig);
    }

    @Test
    @DisplayName("Test constructor with configuration")
    void testConstructor() {
        assertNotNull(response);
        // Response is successfully created with configuration
        assertTrue(response instanceof NetServerEnum2Response);
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
    @DisplayName("Test readDataWireFormat with single server")
    void testReadDataWireFormatSingleServer() throws Exception {
        // Prepare test data
        String serverName = "SERVER01";
        int versionMajor = 5;
        int versionMinor = 2;
        int serverType = 0x00000801; // SV_TYPE_WORKSTATION | SV_TYPE_NT
        String comment = "Test server";

        // Set converter value first
        setConverter(response, 0);

        // Set number of entries
        setNumEntries(response, 1);

        // Calculate buffer size
        int serverNameSize = 16; // Fixed field size
        int versionSize = 2;
        int typeSize = 4;
        int offsetSize = 4;
        int commentSize = comment.length() + 1;
        int totalSize = serverNameSize + versionSize + typeSize + offsetSize + commentSize;

        byte[] buffer = new byte[totalSize + 100];
        int bufferIndex = 0;
        int start = 0;

        // Write server name (16 bytes, null padded)
        byte[] nameBytes = serverName.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(nameBytes, 0, buffer, bufferIndex, Math.min(nameBytes.length, 15));
        bufferIndex += 16;

        // Write version major (1 byte)
        buffer[bufferIndex++] = (byte) versionMajor;

        // Write version minor (1 byte)
        buffer[bufferIndex++] = (byte) versionMinor;

        // Write type (4 bytes)
        SMBUtil.writeInt4(serverType, buffer, bufferIndex);
        bufferIndex += 4;

        // Write comment offset (4 bytes)
        int commentOffset = serverNameSize + versionSize + typeSize + offsetSize;
        SMBUtil.writeInt4(commentOffset, buffer, bufferIndex);
        bufferIndex += 4;

        // Write comment at the calculated offset
        byte[] commentBytes = comment.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(commentBytes, 0, buffer, commentOffset, commentBytes.length);
        buffer[commentOffset + commentBytes.length] = 0; // null terminator

        // Read the data
        int bytesRead = response.readDataWireFormat(buffer, start, buffer.length);

        // Verify results
        assertTrue(bytesRead > 0);
        FileEntry[] results = getResults(response);
        assertNotNull(results);
        assertEquals(1, results.length);

        NetServerEnum2Response.ServerInfo1 server = (NetServerEnum2Response.ServerInfo1) results[0];
        assertEquals(serverName, server.name);
        assertEquals(versionMajor, server.versionMajor);
        assertEquals(versionMinor, server.versionMinor);
        assertEquals(serverType, server.type);
        assertEquals(comment, server.commentOrMasterBrowser);

        // Test getLastName
        assertEquals(serverName, response.getLastName());
    }

    @Test
    @DisplayName("Test readDataWireFormat with multiple servers")
    void testReadDataWireFormatMultipleServers() throws Exception {
        int numServers = 3;
        String[] serverNames = { "SERVER01", "SERVER02", "DC01" };
        int[] versionMajors = { 6, 10, 10 };
        int[] versionMinors = { 1, 0, 0 };
        int[] serverTypes = { 0x00000801, 0x00000809, 0x0000101B }; // Various server types
        String[] comments = { "Workstation", "File server", "Domain Controller" };

        // Set converter and number of entries
        setConverter(response, 0);
        setNumEntries(response, numServers);

        // Calculate total buffer size
        int entrySize = 26; // 16 + 2 + 4 + 4
        int totalEntrySize = entrySize * numServers;
        int totalCommentSize = 0;
        for (String comment : comments) {
            totalCommentSize += comment.length() + 1;
        }

        byte[] buffer = new byte[totalEntrySize + totalCommentSize + 100];
        int bufferIndex = 0;
        int commentOffset = totalEntrySize;

        // Write all entries
        for (int i = 0; i < numServers; i++) {
            // Write server name (16 bytes)
            byte[] nameBytes = serverNames[i].getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(nameBytes, 0, buffer, bufferIndex, Math.min(nameBytes.length, 15));
            bufferIndex += 16;

            // Write version major (1 byte)
            buffer[bufferIndex++] = (byte) versionMajors[i];

            // Write version minor (1 byte)
            buffer[bufferIndex++] = (byte) versionMinors[i];

            // Write type (4 bytes)
            SMBUtil.writeInt4(serverTypes[i], buffer, bufferIndex);
            bufferIndex += 4;

            // Write comment offset (4 bytes)
            SMBUtil.writeInt4(commentOffset, buffer, bufferIndex);
            bufferIndex += 4;

            // Write comment at offset
            byte[] commentBytes = comments[i].getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(commentBytes, 0, buffer, commentOffset, commentBytes.length);
            buffer[commentOffset + commentBytes.length] = 0;
            commentOffset += commentBytes.length + 1;
        }

        // Read the data
        int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);

        // Verify results
        assertTrue(bytesRead > 0);
        FileEntry[] results = getResults(response);
        assertNotNull(results);
        assertEquals(numServers, results.length);

        for (int i = 0; i < numServers; i++) {
            NetServerEnum2Response.ServerInfo1 server = (NetServerEnum2Response.ServerInfo1) results[i];
            assertEquals(serverNames[i], server.name);
            assertEquals(versionMajors[i], server.versionMajor);
            assertEquals(versionMinors[i], server.versionMinor);
            assertEquals(serverTypes[i], server.type);
            assertEquals(comments[i], server.commentOrMasterBrowser);
        }

        // Test getLastName returns last server name
        assertEquals(serverNames[numServers - 1], response.getLastName());
    }

    @Test
    @DisplayName("Test readDataWireFormat with empty servers list")
    void testReadDataWireFormatEmptyServers() throws Exception {
        setNumEntries(response, 0);
        byte[] buffer = new byte[100];

        int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);

        assertEquals(0, bytesRead);
        FileEntry[] results = getResults(response);
        assertNotNull(results);
        assertEquals(0, results.length);
        assertNull(response.getLastName());
    }

    @Test
    @DisplayName("Test readDataWireFormat with converter offset")
    void testReadDataWireFormatWithConverter() throws Exception {
        // Set converter to test offset calculation
        int converterValue = 100;
        setConverter(response, converterValue);
        setNumEntries(response, 1);

        String serverName = "TEST";
        String comment = "Test comment";

        byte[] buffer = new byte[200];
        int bufferIndex = 0;

        // Write server name
        byte[] nameBytes = serverName.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(nameBytes, 0, buffer, bufferIndex, Math.min(nameBytes.length, 15));
        bufferIndex += 16;

        // Write version
        buffer[bufferIndex++] = 6;
        buffer[bufferIndex++] = 1;

        // Write type
        SMBUtil.writeInt4(0x00000801, buffer, bufferIndex);
        bufferIndex += 4;

        // Write comment offset (with converter applied)
        int actualCommentOffset = 26;
        int wireCommentOffset = actualCommentOffset + converterValue;
        SMBUtil.writeInt4(wireCommentOffset, buffer, bufferIndex);
        bufferIndex += 4;

        // Write comment at actual offset
        byte[] commentBytes = comment.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(commentBytes, 0, buffer, actualCommentOffset, commentBytes.length);
        buffer[actualCommentOffset + commentBytes.length] = 0;

        // Read the data
        response.readDataWireFormat(buffer, 0, buffer.length);

        FileEntry[] results = getResults(response);
        NetServerEnum2Response.ServerInfo1 server = (NetServerEnum2Response.ServerInfo1) results[0];
        assertEquals(comment, server.commentOrMasterBrowser);
    }

    @Test
    @DisplayName("Test ServerInfo1 getType for workgroup")
    void testServerInfo1GetTypeWorkgroup() throws Exception {
        NetServerEnum2Response.ServerInfo1 server = response.new ServerInfo1();
        server.type = 0x80000000; // SV_TYPE_DOMAIN_ENUM flag
        assertEquals(SmbConstants.TYPE_WORKGROUP, server.getType());
    }

    @Test
    @DisplayName("Test ServerInfo1 getType for server")
    void testServerInfo1GetTypeServer() throws Exception {
        NetServerEnum2Response.ServerInfo1 server = response.new ServerInfo1();
        server.type = 0x00000801; // Regular server type
        assertEquals(SmbConstants.TYPE_SERVER, server.getType());
    }

    @ParameterizedTest
    @DisplayName("Test ServerInfo1 getType with various server types")
    @CsvSource({ "0x00000000, " + SmbConstants.TYPE_SERVER, "0x00000001, " + SmbConstants.TYPE_SERVER,
            "0x00000801, " + SmbConstants.TYPE_SERVER, "0x80000000, " + SmbConstants.TYPE_WORKGROUP,
            "0x80000001, " + SmbConstants.TYPE_WORKGROUP, "0xFFFFFFFF, " + SmbConstants.TYPE_WORKGROUP })
    void testServerInfo1GetTypeVariousTypes(String typeHex, int expectedType) throws Exception {
        NetServerEnum2Response.ServerInfo1 server = response.new ServerInfo1();
        server.type = (int) Long.parseLong(typeHex.substring(2), 16);
        assertEquals(expectedType, server.getType());
    }

    @Test
    @DisplayName("Test ServerInfo1 getName")
    void testServerInfo1GetName() throws Exception {
        NetServerEnum2Response.ServerInfo1 server = response.new ServerInfo1();
        String testName = "TESTSERVER";
        server.name = testName;
        assertEquals(testName, server.getName());
    }

    @Test
    @DisplayName("Test ServerInfo1 getAttributes")
    void testServerInfo1GetAttributes() throws Exception {
        NetServerEnum2Response.ServerInfo1 server = response.new ServerInfo1();
        int expectedAttributes = SmbConstants.ATTR_READONLY | SmbConstants.ATTR_DIRECTORY;
        assertEquals(expectedAttributes, server.getAttributes());
    }

    @Test
    @DisplayName("Test ServerInfo1 getFileIndex")
    void testServerInfo1GetFileIndex() throws Exception {
        NetServerEnum2Response.ServerInfo1 server = response.new ServerInfo1();
        assertEquals(0, server.getFileIndex());
    }

    @Test
    @DisplayName("Test ServerInfo1 time methods")
    void testServerInfo1TimeMethods() throws Exception {
        NetServerEnum2Response.ServerInfo1 server = response.new ServerInfo1();
        assertEquals(0L, server.createTime());
        assertEquals(0L, server.lastModified());
        assertEquals(0L, server.lastAccess());
        assertEquals(0L, server.length());
    }

    @Test
    @DisplayName("Test ServerInfo1 toString")
    void testServerInfo1ToString() throws Exception {
        NetServerEnum2Response.ServerInfo1 server = response.new ServerInfo1();
        server.name = "SERVER01";
        server.versionMajor = 6;
        server.versionMinor = 1;
        server.type = 0x00000801;
        server.commentOrMasterBrowser = "Test server";

        String result = server.toString();

        assertNotNull(result);
        assertTrue(result.startsWith("ServerInfo1["));
        assertTrue(result.contains("name=SERVER01"));
        assertTrue(result.contains("versionMajor=6"));
        assertTrue(result.contains("versionMinor=1"));
        assertTrue(result.contains("type=0x00000801"));
        assertTrue(result.contains("commentOrMasterBrowser=Test server"));
        assertTrue(result.endsWith("]"));
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() throws Exception {
        // Set some test values
        setStatus(response, 0);
        setConverter(response, 100);
        setNumEntries(response, 2);
        setTotalAvailableEntries(response, 5);

        // Set lastName through reflection
        Field lastNameField = response.getClass().getDeclaredField("lastName");
        lastNameField.setAccessible(true);
        lastNameField.set(response, "LASTSERVER");

        String result = response.toString();

        assertNotNull(result);
        assertTrue(result.startsWith("NetServerEnum2Response["));
        assertTrue(result.contains("status=0"));
        assertTrue(result.contains("converter=100"));
        assertTrue(result.contains("entriesReturned=2"));
        assertTrue(result.contains("totalAvailableEntries=5"));
        assertTrue(result.contains("lastName=LASTSERVER"));
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

    @Test
    @DisplayName("Test readDataWireFormat with maximum length server name")
    void testReadDataWireFormatMaxLengthServerName() throws Exception {
        setConverter(response, 0);
        setNumEntries(response, 1);

        // Create a 15-character server name (maximum for NetBIOS name)
        String serverName = "SERVERNAME12345"; // 15 characters
        String comment = "Max length name";

        byte[] buffer = new byte[200];
        int bufferIndex = 0;

        // Write server name (exactly 15 bytes)
        byte[] nameBytes = serverName.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(nameBytes, 0, buffer, bufferIndex, 15);
        buffer[15] = 0; // null terminator at position 15
        bufferIndex += 16;

        // Write version
        buffer[bufferIndex++] = 6;
        buffer[bufferIndex++] = 1;

        // Write type
        SMBUtil.writeInt4(0, buffer, bufferIndex);
        bufferIndex += 4;

        // Write comment offset
        SMBUtil.writeInt4(26, buffer, bufferIndex);
        bufferIndex += 4;

        // Write comment
        byte[] commentBytes = comment.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(commentBytes, 0, buffer, 26, commentBytes.length);
        buffer[26 + commentBytes.length] = 0;

        response.readDataWireFormat(buffer, 0, buffer.length);

        FileEntry[] results = getResults(response);
        NetServerEnum2Response.ServerInfo1 server = (NetServerEnum2Response.ServerInfo1) results[0];
        assertEquals(serverName, server.name);
    }

    @ParameterizedTest
    @DisplayName("Test readDataWireFormat with various server versions")
    @CsvSource({ "3, 51, Windows NT 3.51", "4, 0, Windows NT 4.0", "5, 0, Windows 2000", "5, 1, Windows XP", "5, 2, Windows Server 2003",
            "6, 0, Windows Vista", "6, 1, Windows 7", "6, 2, Windows 8", "6, 3, Windows 8.1", "10, 0, Windows 10" })
    void testReadDataWireFormatWithVariousVersions(int major, int minor, String description) throws Exception {
        setConverter(response, 0);
        setNumEntries(response, 1);

        String serverName = "TESTSERVER";

        byte[] buffer = new byte[200];
        int bufferIndex = 0;

        // Write server name
        byte[] nameBytes = serverName.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(nameBytes, 0, buffer, bufferIndex, Math.min(nameBytes.length, 15));
        bufferIndex += 16;

        // Write version
        buffer[bufferIndex++] = (byte) major;
        buffer[bufferIndex++] = (byte) minor;

        // Write type
        SMBUtil.writeInt4(0x00000801, buffer, bufferIndex);
        bufferIndex += 4;

        // Write comment offset
        int commentOffset = 26;
        SMBUtil.writeInt4(commentOffset, buffer, bufferIndex);
        bufferIndex += 4;

        // Write comment
        byte[] commentBytes = description.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(commentBytes, 0, buffer, commentOffset, commentBytes.length);
        buffer[commentOffset + commentBytes.length] = 0;

        // Read and verify
        response.readDataWireFormat(buffer, 0, buffer.length);

        FileEntry[] results = getResults(response);
        NetServerEnum2Response.ServerInfo1 server = (NetServerEnum2Response.ServerInfo1) results[0];
        assertEquals(major, server.versionMajor);
        assertEquals(minor, server.versionMinor);
        assertEquals(description, server.commentOrMasterBrowser);
    }

    // Helper methods using reflection to access private fields

    private int getStatus(NetServerEnum2Response response) throws Exception {
        Field field = getSuperclassField(response.getClass(), "status");
        field.setAccessible(true);
        return field.getInt(response);
    }

    private void setStatus(NetServerEnum2Response response, int value) throws Exception {
        Method method = getSuperclassMethod(response.getClass(), "setStatus", int.class);
        method.setAccessible(true);
        method.invoke(response, value);
    }

    private int getConverter(NetServerEnum2Response response) throws Exception {
        Field field = response.getClass().getDeclaredField("converter");
        field.setAccessible(true);
        return field.getInt(response);
    }

    private void setConverter(NetServerEnum2Response response, int value) throws Exception {
        Field field = response.getClass().getDeclaredField("converter");
        field.setAccessible(true);
        field.setInt(response, value);
    }

    private int getNumEntries(NetServerEnum2Response response) throws Exception {
        Method method = getSuperclassMethod(response.getClass(), "getNumEntries");
        method.setAccessible(true);
        return (int) method.invoke(response);
    }

    private void setNumEntries(NetServerEnum2Response response, int value) throws Exception {
        Method method = getSuperclassMethod(response.getClass(), "setNumEntries", int.class);
        method.setAccessible(true);
        method.invoke(response, value);
    }

    private int getTotalAvailableEntries(NetServerEnum2Response response) throws Exception {
        Field field = response.getClass().getDeclaredField("totalAvailableEntries");
        field.setAccessible(true);
        return field.getInt(response);
    }

    private void setTotalAvailableEntries(NetServerEnum2Response response, int value) throws Exception {
        Field field = response.getClass().getDeclaredField("totalAvailableEntries");
        field.setAccessible(true);
        field.setInt(response, value);
    }

    private FileEntry[] getResults(NetServerEnum2Response response) throws Exception {
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
