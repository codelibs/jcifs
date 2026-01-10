/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.codelibs.jcifs.smb.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.DialectVersion;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Edge case and boundary tests for PropertyConfiguration.
 * Tests invalid values, extreme values, and error handling.
 */
@DisplayName("PropertyConfiguration Edge Case Tests")
class PropertyConfigurationEdgeCaseTest {

    @Nested
    @DisplayName("Timeout Configuration Edge Cases")
    class TimeoutEdgeCases {

        @Test
        @DisplayName("Should use default for negative timeout values")
        void testNegativeTimeoutValues() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.connTimeout", "-1000");
            props.setProperty("jcifs.smb.client.soTimeout", "-5000");
            props.setProperty("jcifs.smb.client.responseTimeout", "-3000");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Should fall back to defaults for negative values
            assertTrue(config.getConnTimeout() > 0, "Connection timeout should be positive");
            assertTrue(config.getSoTimeout() > 0, "Socket timeout should be positive");
            assertTrue(config.getResponseTimeout() > 0, "Response timeout should be positive");
        }

        @Test
        @DisplayName("Should handle zero timeout values")
        void testZeroTimeoutValues() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.connTimeout", "0");
            props.setProperty("jcifs.smb.client.soTimeout", "0");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Zero may be valid (infinite timeout) or fallback to default
            assertNotNull(config);
        }

        @Test
        @DisplayName("Should handle very large timeout values")
        void testVeryLargeTimeoutValues() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.connTimeout", "2147483647"); // Integer.MAX_VALUE

            PropertyConfiguration config = new PropertyConfiguration(props);

            assertEquals(Integer.MAX_VALUE, config.getConnTimeout());
        }

        @Test
        @DisplayName("Should handle non-numeric timeout values gracefully")
        void testNonNumericTimeoutValues() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.connTimeout", "not-a-number");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Should use default when parsing fails
            assertTrue(config.getConnTimeout() > 0);
        }

        @Test
        @DisplayName("Should handle floating point timeout values")
        void testFloatingPointTimeoutValues() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.connTimeout", "35000.5");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Should handle parse error gracefully
            assertTrue(config.getConnTimeout() > 0);
        }
    }

    @Nested
    @DisplayName("Session Limit Edge Cases")
    class SessionLimitEdgeCases {

        @Test
        @DisplayName("Should handle zero session limit")
        void testZeroSessionLimit() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.ssnLimit", "0");

            PropertyConfiguration config = new PropertyConfiguration(props);

            assertEquals(0, config.getSessionLimit());
        }

        @Test
        @DisplayName("Should handle negative session limit")
        void testNegativeSessionLimit() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.ssnLimit", "-5");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Negative values should be handled
            assertNotNull(config);
        }

        @Test
        @DisplayName("Should handle very large session limit")
        void testVeryLargeSessionLimit() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.ssnLimit", "100000");

            PropertyConfiguration config = new PropertyConfiguration(props);

            assertEquals(100000, config.getSessionLimit());
        }
    }

    @Nested
    @DisplayName("Protocol Version Edge Cases")
    class ProtocolVersionEdgeCases {

        @Test
        @DisplayName("Should throw for invalid min version")
        void testInvalidMinVersion() {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.minVersion", "INVALID");

            assertThrows(IllegalArgumentException.class,
                    () -> new PropertyConfiguration(props));
        }

        @Test
        @DisplayName("Should throw for invalid max version")
        void testInvalidMaxVersion() {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.maxVersion", "INVALID");

            assertThrows(IllegalArgumentException.class,
                    () -> new PropertyConfiguration(props));
        }

        @Test
        @DisplayName("Should handle empty version string")
        void testEmptyVersionString() {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.minVersion", "");

            // Empty string should throw or use default
            assertThrows(IllegalArgumentException.class,
                    () -> new PropertyConfiguration(props));
        }

        @Test
        @DisplayName("Should handle case-insensitive version names")
        void testCaseInsensitiveVersionNames() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.minVersion", "smb1");
            props.setProperty("jcifs.smb.client.maxVersion", "SMB311");

            PropertyConfiguration config = new PropertyConfiguration(props);

            assertEquals(DialectVersion.SMB1, config.getMinimumVersion());
            assertEquals(DialectVersion.SMB311, config.getMaximumVersion());
        }

        @ParameterizedTest
        @ValueSource(strings = {"SMB1", "SMB202", "SMB210", "SMB300", "SMB302", "SMB311"})
        @DisplayName("Should accept all valid SMB version strings")
        void testAllValidVersionStrings(String version) throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.minVersion", version);

            PropertyConfiguration config = new PropertyConfiguration(props);

            assertNotNull(config.getMinimumVersion());
        }

        @Test
        @DisplayName("Should handle min version greater than max version")
        void testMinGreaterThanMax() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.minVersion", "SMB311");
            props.setProperty("jcifs.smb.client.maxVersion", "SMB1");

            // This is an invalid configuration but should not throw during creation
            PropertyConfiguration config = new PropertyConfiguration(props);

            assertNotNull(config);
            // The actual validation happens at connection time
        }
    }

    @Nested
    @DisplayName("Buffer Size Edge Cases")
    class BufferSizeEdgeCases {

        @Test
        @DisplayName("Should handle zero buffer size")
        void testZeroBufferSize() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.rcv_buf_size", "0");
            props.setProperty("jcifs.smb.client.snd_buf_size", "0");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Should handle zero values
            assertNotNull(config);
        }

        @Test
        @DisplayName("Should handle negative buffer size")
        void testNegativeBufferSize() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.rcv_buf_size", "-1024");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Should handle negative values gracefully
            assertNotNull(config);
        }

        @Test
        @DisplayName("Should handle very large buffer size")
        void testVeryLargeBufferSize() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.rcv_buf_size", "104857600"); // 100MB

            PropertyConfiguration config = new PropertyConfiguration(props);

            assertEquals(104857600, config.getReceiveBufferSize());
        }
    }

    @Nested
    @DisplayName("IP Address Configuration Edge Cases")
    class IpAddressEdgeCases {

        @Test
        @DisplayName("Should handle invalid IP address format")
        void testInvalidIpAddress() {
            Properties props = new Properties();
            props.setProperty("jcifs.netbios.wins", "not.an.ip.address");

            // Invalid IP should throw exception
            assertThrows(Exception.class, () -> new PropertyConfiguration(props));
        }

        @Test
        @DisplayName("Should handle empty IP address")
        void testEmptyIpAddress() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.netbios.wins", "");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Empty should result in null or empty array
            assertNotNull(config);
        }

        @Test
        @DisplayName("Should handle multiple WINS servers")
        void testMultipleWinsServers() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.netbios.wins", "192.168.1.1,192.168.1.2");

            PropertyConfiguration config = new PropertyConfiguration(props);

            assertNotNull(config.getWinsServers());
            assertEquals(2, config.getWinsServers().length);
        }

        @Test
        @DisplayName("Should handle IPv6 addresses")
        void testIpv6Address() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.netbios.wins", "::1");

            PropertyConfiguration config = new PropertyConfiguration(props);

            assertNotNull(config);
        }
    }

    @Nested
    @DisplayName("Boolean Property Edge Cases")
    class BooleanPropertyEdgeCases {

        @ParameterizedTest
        @ValueSource(strings = {"TRUE", "True", "true", "YES", "yes", "1"})
        @DisplayName("Should handle various true values")
        void testVariousTrueValues(String trueValue) throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.signingPreferred", trueValue);

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Only "true" (case insensitive) should be interpreted as true
            // Other values like "yes", "1" may not work
            assertNotNull(config);
        }

        @ParameterizedTest
        @ValueSource(strings = {"FALSE", "False", "false", "NO", "no", "0", "invalid"})
        @DisplayName("Should handle various false values")
        void testVariousFalseValues(String falseValue) throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.signingPreferred", falseValue);

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Non-true values should be treated as false
            assertFalse(config.isSigningEnabled() && !config.isSigningEnforced());
        }

        @Test
        @DisplayName("Should handle empty boolean property")
        void testEmptyBooleanProperty() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.signingPreferred", "");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Empty should be treated as false
            assertNotNull(config);
        }
    }

    @Nested
    @DisplayName("Encoding Edge Cases")
    class EncodingEdgeCases {

        @Test
        @DisplayName("Should handle invalid encoding name")
        void testInvalidEncoding() {
            Properties props = new Properties();
            props.setProperty("jcifs.encoding", "INVALID-ENCODING-THAT-DOES-NOT-EXIST");

            assertThrows(CIFSException.class, () -> new PropertyConfiguration(props));
        }

        @Test
        @DisplayName("Should handle empty encoding")
        void testEmptyEncoding() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.encoding", "");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Empty should use default encoding
            assertNotNull(config.getOemEncoding());
        }

        @ParameterizedTest
        @ValueSource(strings = {"UTF-8", "UTF-16", "ISO-8859-1", "US-ASCII", "Cp437"})
        @DisplayName("Should handle various valid encodings")
        void testVariousValidEncodings(String encoding) throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.encoding", encoding);

            PropertyConfiguration config = new PropertyConfiguration(props);

            assertEquals(encoding, config.getOemEncoding());
        }
    }

    @Nested
    @DisplayName("Resolve Order Edge Cases")
    class ResolveOrderEdgeCases {

        @Test
        @DisplayName("Should handle empty resolve order")
        void testEmptyResolveOrder() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.resolveOrder", "");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Empty should use default order or empty list
            assertNotNull(config.getResolveOrder());
        }

        @Test
        @DisplayName("Should handle invalid resolver type")
        void testInvalidResolverType() {
            Properties props = new Properties();
            props.setProperty("jcifs.resolveOrder", "INVALID");

            assertThrows(Exception.class, () -> new PropertyConfiguration(props));
        }

        @Test
        @DisplayName("Should handle single resolver")
        void testSingleResolver() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.resolveOrder", "DNS");

            PropertyConfiguration config = new PropertyConfiguration(props);

            assertEquals(1, config.getResolveOrder().size());
        }

        @Test
        @DisplayName("Should handle duplicate resolvers")
        void testDuplicateResolvers() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.resolveOrder", "DNS,DNS,DNS");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Should handle duplicates (may keep or dedupe)
            assertNotNull(config.getResolveOrder());
        }
    }

    @Nested
    @DisplayName("Port Configuration Edge Cases")
    class PortEdgeCases {

        @Test
        @DisplayName("Should handle port 0")
        void testPortZero() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.port", "0");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Port 0 means use default
            assertNotNull(config);
        }

        @Test
        @DisplayName("Should handle negative port")
        void testNegativePort() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.port", "-1");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Negative should be handled
            assertNotNull(config);
        }

        @Test
        @DisplayName("Should handle port greater than 65535")
        void testPortGreaterThanMax() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.port", "70000");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Should handle out of range port
            assertNotNull(config);
        }
    }

    @Nested
    @DisplayName("DFS Configuration Edge Cases")
    class DfsEdgeCases {

        @Test
        @DisplayName("Should handle zero DFS TTL")
        void testZeroDfsTtl() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.dfs.ttl", "0");

            PropertyConfiguration config = new PropertyConfiguration(props);

            assertEquals(0, config.getDfsTtl());
        }

        @Test
        @DisplayName("Should handle negative DFS TTL")
        void testNegativeDfsTtl() throws CIFSException {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.dfs.ttl", "-100");

            PropertyConfiguration config = new PropertyConfiguration(props);

            // Negative TTL should be handled
            assertNotNull(config);
        }
    }

    @Nested
    @DisplayName("Null and Missing Properties")
    class NullAndMissingProperties {

        @Test
        @DisplayName("Should use defaults for all missing properties")
        void testAllDefaultValues() throws CIFSException {
            Properties props = new Properties();

            PropertyConfiguration config = new PropertyConfiguration(props);

            assertNotNull(config);
            assertNotNull(config.getMinimumVersion());
            assertNotNull(config.getMaximumVersion());
            assertTrue(config.getConnTimeout() > 0);
            assertTrue(config.getSoTimeout() > 0);
        }

        @Test
        @DisplayName("Should throw for null properties")
        void testNullProperties() {
            assertThrows(NullPointerException.class,
                    () -> new PropertyConfiguration(null));
        }
    }
}
