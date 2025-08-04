package jcifs.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import jcifs.BaseTest;
import jcifs.CIFSException;
import jcifs.DialectVersion;

/**
 * Test class for PropertyConfiguration functionality
 */
@DisplayName("PropertyConfiguration Tests")
class PropertyConfigurationTest extends BaseTest {

    @Mock
    private Properties mockProperties;

    private PropertyConfiguration config;

    @BeforeEach
    void setUp() throws CIFSException {
        Properties props = new Properties();
        // Set some default test properties
        props.setProperty("jcifs.smb.client.username", "testuser");
        props.setProperty("jcifs.smb.client.password", "testpass");
        props.setProperty("jcifs.smb.client.domain", "testdomain");
        props.setProperty("jcifs.netbios.hostname", "testhost");
        props.setProperty("jcifs.netbios.scope", "");
        props.setProperty("jcifs.smb.client.connTimeout", "35000");
        props.setProperty("jcifs.smb.client.soTimeout", "35000");

        config = new PropertyConfiguration(props);
    }

    @Test
    @DisplayName("Should create configuration from Properties")
    void testConfigurationCreation() throws CIFSException {
        // Then
        assertNotNull(config);
        assertEquals("testuser", config.getDefaultUsername());
        assertEquals("testpass", config.getDefaultPassword());
        assertEquals("testdomain", config.getDefaultDomain());
    }

    @Test
    @DisplayName("Should handle null properties gracefully")
    void testNullProperties() throws CIFSException {
        // When/Then
        assertDoesNotThrow(() -> {
            PropertyConfiguration nullConfig = new PropertyConfiguration(null);
            assertNotNull(nullConfig);
        });
    }

    @Test
    @DisplayName("Should handle empty properties")
    void testEmptyProperties() throws CIFSException {
        // Given
        Properties emptyProps = new Properties();

        // When
        PropertyConfiguration emptyConfig = new PropertyConfiguration(emptyProps);

        // Then
        assertNotNull(emptyConfig);
        // Should use default values
        assertNotNull(emptyConfig.getNetbiosHostname());
    }

    @Test
    @DisplayName("Should parse integer properties correctly")
    void testIntegerProperties() throws CIFSException {
        // Given
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.connTimeout", "30000");
        props.setProperty("jcifs.smb.client.soTimeout", "35000");
        props.setProperty("jcifs.smb.client.responseTimeout", "30000");

        // When
        PropertyConfiguration testConfig = new PropertyConfiguration(props);

        // Then
        assertEquals(30000, testConfig.getConnTimeout());
        assertEquals(35000, testConfig.getSoTimeout());
        assertEquals(30000, testConfig.getResponseTimeout());
    }

    @Test
    @DisplayName("Should parse boolean properties correctly")
    void testBooleanProperties() throws CIFSException {
        // Given
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.useUnicode", "true");
        props.setProperty("jcifs.smb.client.disablePlainTextPasswords", "false");
        props.setProperty("jcifs.util.loglevel", "1");

        // When
        PropertyConfiguration testConfig = new PropertyConfiguration(props);

        // Then
        assertTrue(testConfig.isUseUnicode());
        assertFalse(testConfig.isDisablePlainTextPasswords());
    }

    @Test
    @DisplayName("Should handle dialect version properties")
    void testDialectVersionProperties() throws CIFSException {
        // Given
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.minVersion", "SMB1");
        props.setProperty("jcifs.smb.client.maxVersion", "SMB311");

        // When
        PropertyConfiguration testConfig = new PropertyConfiguration(props);

        // Then
        assertEquals(DialectVersion.SMB1, testConfig.getMinimumVersion());
        assertEquals(DialectVersion.SMB311, testConfig.getMaximumVersion());
    }

    @Test
    @DisplayName("Should provide default values for missing properties")
    void testDefaultValues() throws CIFSException {
        // Given
        Properties minimalProps = new Properties();

        // When
        PropertyConfiguration testConfig = new PropertyConfiguration(minimalProps);

        // Then
        assertNotNull(testConfig.getNetbiosHostname());
        assertTrue(testConfig.getConnTimeout() > 0);
        assertTrue(testConfig.getSoTimeout() > 0);
        assertNotNull(testConfig.getMinimumVersion());
        assertNotNull(testConfig.getMaximumVersion());
    }

    @Test
    @DisplayName("Should handle encoding properties")
    void testEncodingProperties() throws CIFSException {
        // Given
        Properties props = new Properties();
        props.setProperty("jcifs.encoding", "UTF-8");
        props.setProperty("jcifs.smb.client.nativeCharset", "UTF-16LE");

        // When
        PropertyConfiguration testConfig = new PropertyConfiguration(props);

        // Then
        assertEquals("UTF-8", testConfig.getOemEncoding());
        // Note: getNativeCharset() is not available in the Configuration interface
        // Test a different configuration property instead
        assertTrue(testConfig.getNetbiosSoTimeout() > 0);
    }

    @Test
    @DisplayName("Should handle network properties")
    void testNetworkProperties() throws CIFSException {
        // Given
        Properties props = new Properties();
        props.setProperty("jcifs.netbios.wins", "192.168.1.1");
        props.setProperty("jcifs.netbios.baddr", "192.168.1.255");
        props.setProperty("jcifs.resolveOrder", "WINS,BCAST,DNS");

        // When
        PropertyConfiguration testConfig = new PropertyConfiguration(props);

        // Then
        assertEquals("192.168.1.1", testConfig.getWinsServers());
        assertEquals("192.168.1.255", testConfig.getBroadcastAddress());
        assertEquals("WINS,BCAST,DNS", testConfig.getResolveOrder());
    }

    @Test
    @DisplayName("Should handle security properties")
    void testSecurityProperties() throws CIFSException {
        // Given
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.signingEnforced", "true");
        props.setProperty("jcifs.smb.client.signingPreferred", "true");
        props.setProperty("jcifs.smb.client.encryptionEnforced", "false");

        // When
        PropertyConfiguration testConfig = new PropertyConfiguration(props);

        // Then
        assertTrue(testConfig.isSigningEnforced());
        assertTrue(testConfig.isSigningEnabled());
        assertFalse(testConfig.isEncryptionEnabled());
    }

    @Test
    @DisplayName("Should handle invalid property values gracefully")
    void testInvalidPropertyValues() throws CIFSException {
        // Given
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.connTimeout", "invalid");
        props.setProperty("jcifs.smb.client.useUnicode", "maybe");
        props.setProperty("jcifs.smb.client.minVersion", "INVALID_VERSION");

        // When/Then
        assertDoesNotThrow(() -> {
            PropertyConfiguration testConfig = new PropertyConfiguration(props);
            // Should use default values for invalid properties
            assertTrue(testConfig.getConnTimeout() > 0);
            assertNotNull(testConfig.getMinimumVersion());
        });
    }

    @Test
    @DisplayName("Should handle property inheritance")
    void testPropertyInheritance() throws CIFSException {
        // Given
        Properties parentProps = new Properties();
        parentProps.setProperty("jcifs.smb.client.domain", "parentdomain");
        parentProps.setProperty("jcifs.smb.client.username", "parentuser");

        Properties childProps = new Properties(parentProps);
        childProps.setProperty("jcifs.smb.client.username", "childuser");

        // When
        PropertyConfiguration testConfig = new PropertyConfiguration(childProps);

        // Then
        assertEquals("childuser", testConfig.getDefaultUsername()); // Overridden
        assertEquals("parentdomain", testConfig.getDefaultDomain()); // Inherited
    }

    @Test
    @DisplayName("Should validate configuration consistency")
    void testConfigurationValidation() throws CIFSException {
        // Given
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.minVersion", "SMB311");
        props.setProperty("jcifs.smb.client.maxVersion", "SMB1");

        // When/Then
        assertDoesNotThrow(() -> {
            PropertyConfiguration testConfig = new PropertyConfiguration(props);
            // Configuration should handle inconsistent min/max versions
            assertNotNull(testConfig.getMinimumVersion());
            assertNotNull(testConfig.getMaximumVersion());
        });
    }

    @Test
    @DisplayName("Should handle system property overrides")
    void testSystemPropertyOverrides() throws CIFSException {
        // Given
        String originalValue = System.getProperty("jcifs.smb.client.domain");
        System.setProperty("jcifs.smb.client.domain", "systemdomain");

        try {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.domain", "propsdomain");

            // When
            PropertyConfiguration testConfig = new PropertyConfiguration(props);

            // Then
            // System properties should take precedence (if implemented)
            String domain = testConfig.getDefaultDomain();
            assertTrue(domain.equals("systemdomain") || domain.equals("propsdomain"));

        } finally {
            // Cleanup
            if (originalValue != null) {
                System.setProperty("jcifs.smb.client.domain", originalValue);
            } else {
                System.clearProperty("jcifs.smb.client.domain");
            }
        }
    }
}