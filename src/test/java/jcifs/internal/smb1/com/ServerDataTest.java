package jcifs.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Field;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for ServerData class
 */
public class ServerDataTest {

    private ServerData serverData;

    @BeforeEach
    public void setUp() {
        serverData = new ServerData();
    }

    /**
     * Test default constructor initializes all fields with default values
     */
    @Test
    @DisplayName("Test default constructor initializes fields with default values")
    public void testDefaultConstructor() {
        // Then - verify all fields have default values
        assertEquals((byte) 0, serverData.sflags);
        assertEquals(0, serverData.sflags2);
        assertEquals(0, serverData.smaxMpxCount);
        assertEquals(0, serverData.maxBufferSize);
        assertEquals(0, serverData.sessKey);
        assertEquals(0, serverData.scapabilities);
        assertNull(serverData.oemDomainName);
        assertEquals(0, serverData.securityMode);
        assertEquals(0, serverData.security);
        assertFalse(serverData.encryptedPasswords);
        assertFalse(serverData.signaturesEnabled);
        assertFalse(serverData.signaturesRequired);
        assertEquals(0, serverData.maxNumberVcs);
        assertEquals(0, serverData.maxRawSize);
        assertEquals(0L, serverData.serverTime);
        assertEquals(0, serverData.serverTimeZone);
        assertEquals(0, serverData.encryptionKeyLength);
        assertNull(serverData.encryptionKey);
        assertNull(serverData.guid);
    }

    /**
     * Test setting and getting byte field (sflags)
     */
    @ParameterizedTest
    @ValueSource(bytes = {0x00, 0x01, 0x7F, (byte) 0x80, (byte) 0xFF})
    @DisplayName("Test sflags field with various byte values")
    public void testSflagsField(byte value) {
        // When
        serverData.sflags = value;

        // Then
        assertEquals(value, serverData.sflags);
    }

    /**
     * Test setting and getting int fields
     */
    @Test
    @DisplayName("Test int fields with various values")
    public void testIntFields() {
        // When
        serverData.sflags2 = 0x12345678;
        serverData.smaxMpxCount = 50;
        serverData.maxBufferSize = 65536;
        serverData.sessKey = 0xABCDEF01;
        serverData.scapabilities = 0x80000000;
        serverData.securityMode = 0x0F;
        serverData.security = 1;
        serverData.maxNumberVcs = 1;
        serverData.maxRawSize = 65536;
        serverData.serverTimeZone = -300;
        serverData.encryptionKeyLength = 8;

        // Then
        assertEquals(0x12345678, serverData.sflags2);
        assertEquals(50, serverData.smaxMpxCount);
        assertEquals(65536, serverData.maxBufferSize);
        assertEquals(0xABCDEF01, serverData.sessKey);
        assertEquals(0x80000000, serverData.scapabilities);
        assertEquals(0x0F, serverData.securityMode);
        assertEquals(1, serverData.security);
        assertEquals(1, serverData.maxNumberVcs);
        assertEquals(65536, serverData.maxRawSize);
        assertEquals(-300, serverData.serverTimeZone);
        assertEquals(8, serverData.encryptionKeyLength);
    }

    /**
     * Test setting and getting boolean fields
     */
    @Test
    @DisplayName("Test boolean fields")
    public void testBooleanFields() {
        // When - set all to true
        serverData.encryptedPasswords = true;
        serverData.signaturesEnabled = true;
        serverData.signaturesRequired = true;

        // Then
        assertTrue(serverData.encryptedPasswords);
        assertTrue(serverData.signaturesEnabled);
        assertTrue(serverData.signaturesRequired);

        // When - set all to false
        serverData.encryptedPasswords = false;
        serverData.signaturesEnabled = false;
        serverData.signaturesRequired = false;

        // Then
        assertFalse(serverData.encryptedPasswords);
        assertFalse(serverData.signaturesEnabled);
        assertFalse(serverData.signaturesRequired);
    }

    /**
     * Test setting and getting String field (oemDomainName)
     */
    @Test
    @DisplayName("Test oemDomainName field with various string values")
    public void testOemDomainNameField() {
        // Test with normal string
        serverData.oemDomainName = "WORKGROUP";
        assertEquals("WORKGROUP", serverData.oemDomainName);

        // Test with empty string
        serverData.oemDomainName = "";
        assertEquals("", serverData.oemDomainName);

        // Test with null
        serverData.oemDomainName = null;
        assertNull(serverData.oemDomainName);

        // Test with special characters
        serverData.oemDomainName = "DOMAIN-01.LOCAL";
        assertEquals("DOMAIN-01.LOCAL", serverData.oemDomainName);

        // Test with Unicode characters
        serverData.oemDomainName = "ドメイン";
        assertEquals("ドメイン", serverData.oemDomainName);
    }

    /**
     * Test setting and getting long field (serverTime)
     */
    @Test
    @DisplayName("Test serverTime field with various long values")
    public void testServerTimeField() {
        // Test with zero
        serverData.serverTime = 0L;
        assertEquals(0L, serverData.serverTime);

        // Test with positive value
        serverData.serverTime = 132514080000000000L; // Windows file time
        assertEquals(132514080000000000L, serverData.serverTime);

        // Test with negative value
        serverData.serverTime = -1L;
        assertEquals(-1L, serverData.serverTime);

        // Test with max value
        serverData.serverTime = Long.MAX_VALUE;
        assertEquals(Long.MAX_VALUE, serverData.serverTime);

        // Test with min value
        serverData.serverTime = Long.MIN_VALUE;
        assertEquals(Long.MIN_VALUE, serverData.serverTime);
    }

    /**
     * Test setting and getting byte array fields
     */
    @Test
    @DisplayName("Test byte array fields (encryptionKey and guid)")
    public void testByteArrayFields() {
        // Test encryptionKey
        byte[] key = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        serverData.encryptionKey = key;
        assertNotNull(serverData.encryptionKey);
        assertArrayEquals(key, serverData.encryptionKey);

        // Test with empty array
        serverData.encryptionKey = new byte[0];
        assertNotNull(serverData.encryptionKey);
        assertEquals(0, serverData.encryptionKey.length);

        // Test with null
        serverData.encryptionKey = null;
        assertNull(serverData.encryptionKey);

        // Test guid (typically 16 bytes)
        byte[] guid = new byte[16];
        Arrays.fill(guid, (byte) 0xAB);
        serverData.guid = guid;
        assertNotNull(serverData.guid);
        assertArrayEquals(guid, serverData.guid);
        assertEquals(16, serverData.guid.length);
    }

    /**
     * Test that modifying the original array affects the field (reference test)
     */
    @Test
    @DisplayName("Test byte array reference behavior")
    public void testByteArrayReference() {
        // Given
        byte[] originalKey = new byte[]{0x01, 0x02, 0x03, 0x04};
        serverData.encryptionKey = originalKey;

        // When - modify the original array
        originalKey[0] = (byte) 0xFF;

        // Then - the field should also be modified (same reference)
        assertEquals((byte) 0xFF, serverData.encryptionKey[0]);
        assertSame(originalKey, serverData.encryptionKey);
    }

    /**
     * Test multiple ServerData instances are independent
     */
    @Test
    @DisplayName("Test multiple instances are independent")
    public void testMultipleInstancesIndependence() {
        // Given
        ServerData serverData1 = new ServerData();
        ServerData serverData2 = new ServerData();

        // When
        serverData1.sflags = (byte) 0x11;
        serverData1.smaxMpxCount = 100;
        serverData1.oemDomainName = "DOMAIN1";
        serverData1.encryptedPasswords = true;

        serverData2.sflags = (byte) 0x22;
        serverData2.smaxMpxCount = 200;
        serverData2.oemDomainName = "DOMAIN2";
        serverData2.encryptedPasswords = false;

        // Then - instances should be independent
        assertEquals((byte) 0x11, serverData1.sflags);
        assertEquals((byte) 0x22, serverData2.sflags);
        assertEquals(100, serverData1.smaxMpxCount);
        assertEquals(200, serverData2.smaxMpxCount);
        assertEquals("DOMAIN1", serverData1.oemDomainName);
        assertEquals("DOMAIN2", serverData2.oemDomainName);
        assertTrue(serverData1.encryptedPasswords);
        assertFalse(serverData2.encryptedPasswords);
    }

    /**
     * Test all fields are public and accessible
     */
    @Test
    @DisplayName("Test all fields are public")
    public void testAllFieldsArePublic() {
        // Get all declared fields
        Field[] fields = ServerData.class.getDeclaredFields();

        // Verify we have the expected number of fields
        assertEquals(19, fields.length);

        // Verify all fields are public
        for (Field field : fields) {
            assertTrue(java.lang.reflect.Modifier.isPublic(field.getModifiers()),
                    "Field " + field.getName() + " should be public");
        }
    }

    /**
     * Test typical server configuration scenario
     */
    @Test
    @DisplayName("Test typical server configuration scenario")
    public void testTypicalServerConfiguration() {
        // Given - typical SMB server configuration
        serverData.sflags = (byte) 0x98;
        serverData.sflags2 = 0xC853; // Unicode, extended security, etc.
        serverData.smaxMpxCount = 50;
        serverData.maxBufferSize = 16644;
        serverData.sessKey = 0x12345678;
        serverData.scapabilities = 0x8000F3FD; // Various capabilities
        serverData.oemDomainName = "WORKGROUP";
        serverData.securityMode = 0x0F; // User + encrypt passwords + signatures
        serverData.security = 1; // User level
        serverData.encryptedPasswords = true;
        serverData.signaturesEnabled = true;
        serverData.signaturesRequired = false;
        serverData.maxNumberVcs = 1;
        serverData.maxRawSize = 65536;
        serverData.serverTime = System.currentTimeMillis();
        serverData.serverTimeZone = -480; // PST
        serverData.encryptionKeyLength = 8;
        serverData.encryptionKey = new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88};
        serverData.guid = new byte[16];

        // Then - verify all values are set correctly
        assertEquals((byte) 0x98, serverData.sflags);
        assertEquals(0xC853, serverData.sflags2);
        assertEquals(50, serverData.smaxMpxCount);
        assertEquals(16644, serverData.maxBufferSize);
        assertEquals(0x12345678, serverData.sessKey);
        assertEquals(0x8000F3FD, serverData.scapabilities);
        assertEquals("WORKGROUP", serverData.oemDomainName);
        assertEquals(0x0F, serverData.securityMode);
        assertEquals(1, serverData.security);
        assertTrue(serverData.encryptedPasswords);
        assertTrue(serverData.signaturesEnabled);
        assertFalse(serverData.signaturesRequired);
        assertEquals(1, serverData.maxNumberVcs);
        assertEquals(65536, serverData.maxRawSize);
        assertTrue(serverData.serverTime > 0);
        assertEquals(-480, serverData.serverTimeZone);
        assertEquals(8, serverData.encryptionKeyLength);
        assertEquals(8, serverData.encryptionKey.length);
        assertEquals(16, serverData.guid.length);
    }

    /**
     * Test edge cases for numeric fields
     */
    @Test
    @DisplayName("Test edge cases for numeric fields")
    public void testNumericFieldsEdgeCases() {
        // Test maximum values for int fields
        serverData.sflags2 = Integer.MAX_VALUE;
        serverData.smaxMpxCount = Integer.MAX_VALUE;
        serverData.maxBufferSize = Integer.MAX_VALUE;
        serverData.sessKey = Integer.MAX_VALUE;
        serverData.scapabilities = Integer.MAX_VALUE;

        assertEquals(Integer.MAX_VALUE, serverData.sflags2);
        assertEquals(Integer.MAX_VALUE, serverData.smaxMpxCount);
        assertEquals(Integer.MAX_VALUE, serverData.maxBufferSize);
        assertEquals(Integer.MAX_VALUE, serverData.sessKey);
        assertEquals(Integer.MAX_VALUE, serverData.scapabilities);

        // Test minimum values for int fields
        serverData.sflags2 = Integer.MIN_VALUE;
        serverData.smaxMpxCount = Integer.MIN_VALUE;
        serverData.maxBufferSize = Integer.MIN_VALUE;
        serverData.sessKey = Integer.MIN_VALUE;
        serverData.scapabilities = Integer.MIN_VALUE;

        assertEquals(Integer.MIN_VALUE, serverData.sflags2);
        assertEquals(Integer.MIN_VALUE, serverData.smaxMpxCount);
        assertEquals(Integer.MIN_VALUE, serverData.maxBufferSize);
        assertEquals(Integer.MIN_VALUE, serverData.sessKey);
        assertEquals(Integer.MIN_VALUE, serverData.scapabilities);
    }

    /**
     * Test large byte arrays
     */
    @Test
    @DisplayName("Test large byte arrays")
    public void testLargeByteArrays() {
        // Test with large encryption key
        byte[] largeKey = new byte[256];
        for (int i = 0; i < largeKey.length; i++) {
            largeKey[i] = (byte) (i % 256);
        }
        serverData.encryptionKey = largeKey;
        serverData.encryptionKeyLength = largeKey.length;

        assertEquals(256, serverData.encryptionKey.length);
        assertEquals(256, serverData.encryptionKeyLength);
        assertEquals((byte) 0, serverData.encryptionKey[0]);
        assertEquals((byte) 255, serverData.encryptionKey[255]);

        // Test with large GUID (though typically 16 bytes)
        byte[] largeGuid = new byte[1024];
        Arrays.fill(largeGuid, (byte) 0xCA);
        serverData.guid = largeGuid;

        assertEquals(1024, serverData.guid.length);
        assertEquals((byte) 0xCA, serverData.guid[0]);
        assertEquals((byte) 0xCA, serverData.guid[1023]);
    }

    /**
     * Test that ServerData can be used in collections
     */
    @Test
    @DisplayName("Test ServerData can be used in collections")
    public void testUseInCollections() {
        // Given
        java.util.List<ServerData> serverList = new java.util.ArrayList<>();
        
        // When
        ServerData server1 = new ServerData();
        server1.oemDomainName = "SERVER1";
        ServerData server2 = new ServerData();
        server2.oemDomainName = "SERVER2";
        
        serverList.add(server1);
        serverList.add(server2);
        
        // Then
        assertEquals(2, serverList.size());
        assertEquals("SERVER1", serverList.get(0).oemDomainName);
        assertEquals("SERVER2", serverList.get(1).oemDomainName);
    }

    /**
     * Test field types match expected types
     */
    @Test
    @DisplayName("Test field types are correct")
    public void testFieldTypes() throws NoSuchFieldException {
        // Verify field types
        assertEquals(byte.class, ServerData.class.getDeclaredField("sflags").getType());
        assertEquals(int.class, ServerData.class.getDeclaredField("sflags2").getType());
        assertEquals(int.class, ServerData.class.getDeclaredField("smaxMpxCount").getType());
        assertEquals(int.class, ServerData.class.getDeclaredField("maxBufferSize").getType());
        assertEquals(int.class, ServerData.class.getDeclaredField("sessKey").getType());
        assertEquals(int.class, ServerData.class.getDeclaredField("scapabilities").getType());
        assertEquals(String.class, ServerData.class.getDeclaredField("oemDomainName").getType());
        assertEquals(int.class, ServerData.class.getDeclaredField("securityMode").getType());
        assertEquals(int.class, ServerData.class.getDeclaredField("security").getType());
        assertEquals(boolean.class, ServerData.class.getDeclaredField("encryptedPasswords").getType());
        assertEquals(boolean.class, ServerData.class.getDeclaredField("signaturesEnabled").getType());
        assertEquals(boolean.class, ServerData.class.getDeclaredField("signaturesRequired").getType());
        assertEquals(int.class, ServerData.class.getDeclaredField("maxNumberVcs").getType());
        assertEquals(int.class, ServerData.class.getDeclaredField("maxRawSize").getType());
        assertEquals(long.class, ServerData.class.getDeclaredField("serverTime").getType());
        assertEquals(int.class, ServerData.class.getDeclaredField("serverTimeZone").getType());
        assertEquals(int.class, ServerData.class.getDeclaredField("encryptionKeyLength").getType());
        assertEquals(byte[].class, ServerData.class.getDeclaredField("encryptionKey").getType());
        assertEquals(byte[].class, ServerData.class.getDeclaredField("guid").getType());
    }
}
