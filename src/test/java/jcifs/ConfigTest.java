package jcifs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for Config utility functionality
 */
@DisplayName("Config Utility Tests")
class ConfigTest extends BaseTest {

    private Properties testProperties;

    @BeforeEach
    void setUp() {
        testProperties = new Properties();
        testProperties.setProperty("test.int", "123");
        testProperties.setProperty("test.long", "1234567890123");
        testProperties.setProperty("test.bool.true", "true");
        testProperties.setProperty("test.bool.false", "false");
        testProperties.setProperty("test.host", "localhost");
        testProperties.setProperty("test.invalid.int", "abc");
    }

    @Test
    @DisplayName("Should get integer property with default value")
    void testGetIntWithDefault() {
        assertEquals(123, Config.getInt(testProperties, "test.int", 0));
        assertEquals(456, Config.getInt(testProperties, "nonexistent.int", 456));
        assertEquals(789, Config.getInt(testProperties, "test.invalid.int", 789));
    }

    @Test
    @DisplayName("Should get integer property")
    void testGetInt() {
        assertEquals(123, Config.getInt(testProperties, "test.int"));
        assertEquals(-1, Config.getInt(testProperties, "nonexistent.int"));
        assertEquals(-1, Config.getInt(testProperties, "test.invalid.int"));
    }

    @Test
    @DisplayName("Should get long property with default value")
    void testGetLongWithDefault() {
        assertEquals(1234567890123L, Config.getLong(testProperties, "test.long", 0L));
        assertEquals(987654321L, Config.getLong(testProperties, "nonexistent.long", 987654321L));
    }

    @Test
    @DisplayName("Should get InetAddress property with default value")
    void testGetInetAddressWithDefault() throws UnknownHostException {
        InetAddress localhost = InetAddress.getByName("localhost");
        InetAddress defaultAddress = InetAddress.getByName("127.0.0.1");
        assertEquals(localhost, Config.getInetAddress(testProperties, "test.host", null));
        assertEquals(defaultAddress, Config.getInetAddress(testProperties, "nonexistent.host", defaultAddress));
    }

    @Test
    @DisplayName("Should get boolean property with default value")
    void testGetBooleanWithDefault() {
        assertTrue(Config.getBoolean(testProperties, "test.bool.true", false));
        assertFalse(Config.getBoolean(testProperties, "test.bool.false", true));
        assertTrue(Config.getBoolean(testProperties, "nonexistent.bool", true));
    }

    @Test
    @DisplayName("Should get InetAddress array property")
    void testGetInetAddressArray() throws UnknownHostException {
        testProperties.setProperty("test.hosts", "localhost,127.0.0.1");
        InetAddress[] defaultArray = { InetAddress.getByName("0.0.0.0") };

        InetAddress[] result = Config.getInetAddressArray(testProperties, "test.hosts", ",", defaultArray);
        assertEquals(2, result.length);
        assertEquals(InetAddress.getByName("localhost"), result[0]);
        assertEquals(InetAddress.getByName("127.0.0.1"), result[1]);

        result = Config.getInetAddressArray(testProperties, "nonexistent.hosts", ",", defaultArray);
        assertSame(defaultArray, result);
    }
}
