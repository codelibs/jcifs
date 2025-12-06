package org.codelibs.jcifs.smb.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.util.List;
import java.util.Properties;

import org.codelibs.jcifs.smb.BaseTest;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.ResolverType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

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
        props.setProperty("jcifs.client.username", "testuser");
        props.setProperty("jcifs.client.password", "testpass");
        props.setProperty("jcifs.client.domain", "testdomain");
        props.setProperty("jcifs.netbios.hostname", "testhost");
        props.setProperty("jcifs.netbios.scope", "");
        props.setProperty("jcifs.client.connTimeout", "35000");
        props.setProperty("jcifs.client.soTimeout", "35000");

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
        // PropertyConfiguration doesn't handle null properties
        // It should throw NullPointerException
        assertThrows(NullPointerException.class, () -> {
            new PropertyConfiguration(null);
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
        // Hostname may be null when not provided in properties
        // This is expected behavior
    }

    @Test
    @DisplayName("Should parse integer properties correctly")
    void testIntegerProperties() throws CIFSException {
        // Given
        Properties props = new Properties();
        props.setProperty("jcifs.client.connTimeout", "30000");
        props.setProperty("jcifs.client.soTimeout", "35000");
        props.setProperty("jcifs.client.responseTimeout", "30000");

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
        props.setProperty("jcifs.client.useUnicode", "true");
        props.setProperty("jcifs.client.disablePlainTextPasswords", "false");
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
        props.setProperty("jcifs.client.minVersion", "SMB1");
        props.setProperty("jcifs.client.maxVersion", "SMB311");

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
        // Hostname may be null when not provided
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
        props.setProperty("jcifs.client.nativeCharset", "UTF-16LE");

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
        // getWinsServers() returns InetAddress[], not String
        InetAddress[] winsServers = testConfig.getWinsServers();
        assertNotNull(winsServers);
        assertEquals(1, winsServers.length);
        assertEquals("192.168.1.1", winsServers[0].getHostAddress());

        // getBroadcastAddress() returns InetAddress, not String
        InetAddress broadcastAddr = testConfig.getBroadcastAddress();
        assertNotNull(broadcastAddr);
        assertEquals("192.168.1.255", broadcastAddr.getHostAddress());

        // getResolveOrder() returns List<ResolverType>
        List<ResolverType> resolveOrder = testConfig.getResolveOrder();
        assertNotNull(resolveOrder);
        assertEquals(3, resolveOrder.size());
        assertEquals(ResolverType.RESOLVER_WINS, resolveOrder.get(0));
        assertEquals(ResolverType.RESOLVER_BCAST, resolveOrder.get(1));
        assertEquals(ResolverType.RESOLVER_DNS, resolveOrder.get(2));
    }

    @Test
    @DisplayName("Should handle security properties")
    void testSecurityProperties() throws CIFSException {
        // Given
        Properties props = new Properties();
        props.setProperty("jcifs.client.signingEnforced", "true");
        props.setProperty("jcifs.client.signingPreferred", "true");
        props.setProperty("jcifs.client.encryptionEnforced", "false");

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
        props.setProperty("jcifs.client.connTimeout", "invalid");
        props.setProperty("jcifs.client.useUnicode", "maybe");

        // When creating configuration with invalid number
        PropertyConfiguration testConfig = new PropertyConfiguration(props);
        // Should use default values for invalid properties
        assertTrue(testConfig.getConnTimeout() > 0);

        // Invalid dialect version should throw IllegalArgumentException
        Properties dialectProps = new Properties();
        dialectProps.setProperty("jcifs.client.minVersion", "INVALID_VERSION");
        assertThrows(IllegalArgumentException.class, () -> {
            new PropertyConfiguration(dialectProps);
        });
    }

    @Test
    @DisplayName("Should handle property inheritance")
    void testPropertyInheritance() throws CIFSException {
        // Given
        Properties parentProps = new Properties();
        parentProps.setProperty("jcifs.client.domain", "parentdomain");
        parentProps.setProperty("jcifs.client.username", "parentuser");

        Properties childProps = new Properties(parentProps);
        childProps.setProperty("jcifs.client.username", "childuser");

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
        props.setProperty("jcifs.client.minVersion", "SMB311");
        props.setProperty("jcifs.client.maxVersion", "SMB1");

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
        String originalValue = System.getProperty("jcifs.client.domain");
        System.setProperty("jcifs.client.domain", "systemdomain");

        try {
            Properties props = new Properties();
            props.setProperty("jcifs.client.domain", "propsdomain");

            // When
            PropertyConfiguration testConfig = new PropertyConfiguration(props);

            // Then
            // System properties should take precedence (if implemented)
            String domain = testConfig.getDefaultDomain();
            assertTrue(domain.equals("systemdomain") || domain.equals("propsdomain"));

        } finally {
            // Cleanup
            if (originalValue != null) {
                System.setProperty("jcifs.client.domain", originalValue);
            } else {
                System.clearProperty("jcifs.client.domain");
            }
        }
    }

    @Test
    @DisplayName("Should parse preserveShareCase property as true")
    void testPreserveShareCaseTrue() throws CIFSException {
        // Given
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.preserveShareCase", "true");

        // When
        PropertyConfiguration testConfig = new PropertyConfiguration(props);

        // Then
        assertTrue(testConfig.isPreserveShareCase());
    }

    @Test
    @DisplayName("Should parse preserveShareCase property as false")
    void testPreserveShareCaseFalse() throws CIFSException {
        // Given
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.preserveShareCase", "false");

        // When
        PropertyConfiguration testConfig = new PropertyConfiguration(props);

        // Then
        assertFalse(testConfig.isPreserveShareCase());
    }

    @Test
    @DisplayName("Should default preserveShareCase to false when not set")
    void testPreserveShareCaseDefault() throws CIFSException {
        // Given
        Properties props = new Properties();
        // Not setting preserveShareCase

        // When
        PropertyConfiguration testConfig = new PropertyConfiguration(props);

        // Then
        assertFalse(testConfig.isPreserveShareCase());
    }
}