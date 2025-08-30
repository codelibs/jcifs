package jcifs.config;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.CIFSException;
import jcifs.DialectVersion;
import jcifs.ResolverType;
import jcifs.SmbConstants;

/**
 * Test class for BaseConfiguration
 */
class BaseConfigurationTest {

    private BaseConfiguration config;

    @BeforeEach
    void setUp() throws CIFSException {
        config = new BaseConfiguration(false);
    }

    @Test
    @DisplayName("Test constructor with initDefaults true")
    void testConstructorWithInitDefaults() throws CIFSException {
        BaseConfiguration configWithDefaults = new BaseConfiguration(true);

        assertNotNull(configWithDefaults.getRandom());
        assertNotNull(configWithDefaults.getLocalTimezone());
        assertNotNull(configWithDefaults.getMachineId());
        assertEquals(32, configWithDefaults.getMachineId().length);
        assertNotNull(configWithDefaults.getNativeOs());
        assertTrue(configWithDefaults.getFlags2() != 0, "Flags2 should be non-zero");
        assertTrue(configWithDefaults.getCapabilities() != 0, "Capabilities should be non-zero");
        assertNotNull(configWithDefaults.getBroadcastAddress());
        assertNotNull(configWithDefaults.getResolveOrder());
        assertNotNull(configWithDefaults.getMinimumVersion());
        assertNotNull(configWithDefaults.getMaximumVersion());
    }

    @Test
    @DisplayName("Test default constructor")
    void testDefaultConstructor() throws CIFSException {
        BaseConfiguration defaultConfig = new TestableBaseConfiguration();

        assertNotNull(defaultConfig.getRandom(), "Random should not be null");
        assertNotNull(defaultConfig.getLocalTimezone(), "Local timezone should not be null");
        assertNotNull(defaultConfig.getMachineId(), "Machine ID should not be null");
    }

    @Test
    @DisplayName("Test network configuration getters")
    void testNetworkConfigurationGetters() {
        assertEquals(0, config.getLocalPort());
        assertEquals(SmbConstants.DEFAULT_CONN_TIMEOUT, config.getConnTimeout());
        assertEquals(SmbConstants.DEFAULT_RESPONSE_TIMEOUT, config.getResponseTimeout());
        assertEquals(SmbConstants.DEFAULT_SO_TIMEOUT, config.getSoTimeout());
        assertEquals(SmbConstants.DEFAULT_SO_TIMEOUT, config.getSessionTimeout());
        assertEquals(SmbConstants.DEFAULT_SND_BUF_SIZE, config.getSendBufferSize());
        assertEquals(SmbConstants.DEFAULT_RCV_BUF_SIZE, config.getReceiveBufferSize());
        assertEquals(SmbConstants.DEFAULT_RCV_BUF_SIZE, config.getRecieveBufferSize()); // Deprecated method
        assertEquals(SmbConstants.DEFAULT_NOTIFY_BUF_SIZE, config.getNotifyBufferSize());
        assertEquals(SmbConstants.DEFAULT_MAX_MPX_COUNT, config.getMaxMpxCount());
    }

    @Test
    @DisplayName("Test SMB configuration getters")
    void testSmbConfigurationGetters() {
        assertEquals("jCIFS", config.getNativeLanman());
        assertNull(config.getNativeOs());
        assertEquals(1, config.getVcNumber());
        assertEquals(0, config.getCapabilities());
        assertNull(config.getMinimumVersion());
        assertNull(config.getMaximumVersion());
        assertFalse(config.isUseSMB2OnlyNegotiation());
        assertTrue(config.isRequireSecureNegotiate());
        assertFalse(config.isPort139FailoverEnabled());
        assertFalse(config.isUseBatching());
        assertTrue(config.isUseUnicode());
        assertFalse(config.isForceUnicode());
    }

    @Test
    @DisplayName("Test DFS configuration getters")
    void testDfsConfigurationGetters() {
        assertFalse(config.isDfsDisabled());
        assertFalse(config.isDfsStrictView());
        assertEquals(300L, config.getDfsTtl());
        assertFalse(config.isDfsConvertToFQDN());
        assertNull(config.getLogonShare());
    }

    @Test
    @DisplayName("Test authentication configuration getters")
    void testAuthenticationConfigurationGetters() {
        assertNull(config.getDefaultDomain());
        assertNull(config.getDefaultUsername());
        assertNull(config.getDefaultPassword());
        assertTrue(config.isDisablePlainTextPasswords());
        assertEquals(3, config.getLanManCompatibility());
        assertTrue(config.isAllowNTLMFallback());
        assertFalse(config.isUseRawNTLM());
        assertFalse(config.isDisableSpnegoIntegrity());
        assertTrue(config.isEnforceSpnegoIntegrity());
        assertTrue(config.isSendNTLMTargetName());
        assertEquals("GUEST", config.getGuestUsername());
        assertEquals("", config.getGuestPassword());
        assertFalse(config.isAllowGuestFallback());
    }

    @Test
    @DisplayName("Test NetBIOS configuration getters")
    void testNetBiosConfigurationGetters() {
        assertNull(config.getNetbiosHostname());
        assertNull(config.getLocalAddr());
        assertNull(config.getBroadcastAddress());
        assertNull(config.getResolveOrder());
        assertNotNull(config.getWinsServers());
        assertEquals(0, config.getWinsServers().length);
        assertEquals(0, config.getNetbiosLocalPort());
        assertNull(config.getNetbiosLocalAddress());
        assertEquals(5000, config.getNetbiosSoTimeout());
        assertNull(config.getNetbiosScope());
        assertEquals(60 * 60 * 10, config.getNetbiosCachePolicy());
        assertEquals(576, config.getNetbiosRcvBufSize());
        assertEquals(2, config.getNetbiosRetryCount());
        assertEquals(3000, config.getNetbiosRetryTimeout());
        assertEquals(576, config.getNetbiosSndBufSize());
        assertNull(config.getLmHostsFileName());
    }

    @Test
    @DisplayName("Test security configuration getters")
    void testSecurityConfigurationGetters() {
        assertFalse(config.isSigningEnabled());
        assertFalse(config.isSigningEnforced());
        assertTrue(config.isIpcSigningEnforced());
        assertFalse(config.isEncryptionEnabled());
        assertFalse(config.isForceExtendedSecurity());
    }

    @Test
    @DisplayName("Test buffer configuration getters")
    void testBufferConfigurationGetters() {
        assertEquals(0xFFFF - 512, config.getTransactionBufferSize());
        assertEquals(0x10000, config.getMaximumBufferSize());
        assertEquals(16, config.getBufferCacheSize());
        assertEquals(200, config.getListCount());
        assertEquals(65435, config.getListSize());
        assertEquals(5000L, config.getAttributeCacheTimeout());
    }

    @Test
    @DisplayName("Test miscellaneous configuration getters")
    void testMiscellaneousConfigurationGetters() {
        assertEquals(0, config.getFlags2());
        assertEquals(SmbConstants.DEFAULT_SSN_LIMIT, config.getSessionLimit());
        assertEquals(SmbConstants.DEFAULT_OEM_ENCODING, config.getOemEncoding());
        assertNull(config.getLocalTimezone());
        assertEquals(-1, config.getPid());
        assertFalse(config.isIgnoreCopyToException());
        assertEquals(2, config.getMaxRequestRetries());
        assertFalse(config.isTraceResourceUsage());
        assertFalse(config.isStrictResourceLifecycle());
        assertNull(config.getMachineId());
    }

    @Test
    @DisplayName("Test getBatchLimit method")
    void testGetBatchLimit() {
        // Test default batch limit
        assertEquals(0, config.getBatchLimit("TreeConnectAndX.QueryInformation"));

        // Test unspecified batch limit
        assertEquals(1, config.getBatchLimit("UnknownCommand"));

        // Test caching behavior
        assertEquals(0, config.getBatchLimit("TreeConnectAndX.QueryInformation"));
    }

    @Test
    @DisplayName("Test getBatchLimit with custom implementation")
    void testGetBatchLimitWithCustomImplementation() throws CIFSException {
        BaseConfiguration customConfig = new BaseConfiguration(false) {
            @Override
            protected Integer doGetBatchLimit(String cmd) {
                if ("CustomCommand".equals(cmd)) {
                    return 5;
                }
                return null;
            }
        };

        assertEquals(5, customConfig.getBatchLimit("CustomCommand"));
        assertEquals(1, customConfig.getBatchLimit("UnknownCommand"));
    }

    @Test
    @DisplayName("Test isAllowCompound method")
    void testIsAllowCompound() {
        // Default behavior when disallowCompound is null
        assertTrue(config.isAllowCompound("AnyCommand"));

        // Set disallowCompound
        config.disallowCompound = new HashSet<>(Arrays.asList("Command1", "Command2"));

        assertFalse(config.isAllowCompound("Command1"));
        assertFalse(config.isAllowCompound("Command2"));
        assertTrue(config.isAllowCompound("Command3"));
    }

    @Test
    @DisplayName("Test initResolverOrder with null/empty input")
    void testInitResolverOrderWithNullInput() {
        config.winsServer = new InetAddress[0];
        config.initResolverOrder(null);

        List<ResolverType> order = config.getResolveOrder();
        assertEquals(3, order.size());
        assertEquals(ResolverType.RESOLVER_LMHOSTS, order.get(0));
        assertEquals(ResolverType.RESOLVER_DNS, order.get(1));
        assertEquals(ResolverType.RESOLVER_BCAST, order.get(2));
    }

    @Test
    @DisplayName("Test initResolverOrder with WINS server")
    void testInitResolverOrderWithWinsServer() throws UnknownHostException {
        config.winsServer = new InetAddress[] { InetAddress.getByName("192.168.1.1") };
        config.initResolverOrder(null);

        List<ResolverType> order = config.getResolveOrder();
        assertEquals(4, order.size());
        assertEquals(ResolverType.RESOLVER_LMHOSTS, order.get(0));
        assertEquals(ResolverType.RESOLVER_DNS, order.get(1));
        assertEquals(ResolverType.RESOLVER_WINS, order.get(2));
        assertEquals(ResolverType.RESOLVER_BCAST, order.get(3));
    }

    @Test
    @DisplayName("Test initResolverOrder with custom order")
    void testInitResolverOrderWithCustomOrder() throws UnknownHostException {
        config.winsServer = new InetAddress[] { InetAddress.getByName("192.168.1.1") };
        config.initResolverOrder("DNS,WINS,LMHOSTS,BCAST");

        List<ResolverType> order = config.getResolveOrder();
        assertEquals(4, order.size());
        assertEquals(ResolverType.RESOLVER_DNS, order.get(0));
        assertEquals(ResolverType.RESOLVER_WINS, order.get(1));
        assertEquals(ResolverType.RESOLVER_LMHOSTS, order.get(2));
        assertEquals(ResolverType.RESOLVER_BCAST, order.get(3));
    }

    @Test
    @DisplayName("Test initResolverOrder with invalid resolver and WINS without server")
    void testInitResolverOrderWithInvalidResolver() {
        config.winsServer = new InetAddress[0];
        config.initResolverOrder("DNS,INVALID,WINS,LMHOSTS");

        List<ResolverType> order = config.getResolveOrder();
        assertEquals(2, order.size());
        assertEquals(ResolverType.RESOLVER_DNS, order.get(0));
        assertEquals(ResolverType.RESOLVER_LMHOSTS, order.get(1));
    }

    @Test
    @DisplayName("Test initProtocolVersions with strings")
    void testInitProtocolVersionsWithStrings() {
        config.initProtocolVersions("SMB202", "SMB311");

        assertEquals(DialectVersion.SMB202, config.getMinimumVersion());
        assertEquals(DialectVersion.SMB311, config.getMaximumVersion());
    }

    @Test
    @DisplayName("Test initProtocolVersions with null/empty strings")
    void testInitProtocolVersionsWithNullStrings() {
        config.initProtocolVersions(null, "");

        assertEquals(DialectVersion.SMB202, config.getMinimumVersion());
        assertEquals(DialectVersion.SMB311, config.getMaximumVersion());
    }

    @Test
    @DisplayName("Test initProtocolVersions with min >= max")
    void testInitProtocolVersionsWithMinGreaterThanMax() {
        config.initProtocolVersions("SMB311", "SMB202");

        assertEquals(DialectVersion.SMB311, config.getMinimumVersion());
        assertEquals(DialectVersion.SMB311, config.getMaximumVersion());
    }

    @Test
    @DisplayName("Test initProtocolVersions with DialectVersion objects")
    void testInitProtocolVersionsWithDialectVersions() {
        config.initProtocolVersions(DialectVersion.SMB210, DialectVersion.SMB300);

        assertEquals(DialectVersion.SMB210, config.getMinimumVersion());
        assertEquals(DialectVersion.SMB300, config.getMaximumVersion());
    }

    @Test
    @DisplayName("Test initProtocolVersions with null DialectVersions")
    void testInitProtocolVersionsWithNullDialectVersions() {
        config.initProtocolVersions((DialectVersion) null, null);

        assertEquals(DialectVersion.SMB202, config.getMinimumVersion());
        assertEquals(DialectVersion.SMB311, config.getMaximumVersion());
    }

    @Test
    @DisplayName("Test initDisallowCompound with null")
    void testInitDisallowCompoundWithNull() {
        config.initDisallowCompound(null);

        assertNull(config.disallowCompound);
    }

    @Test
    @DisplayName("Test initDisallowCompound with command list")
    void testInitDisallowCompoundWithCommandList() {
        config.initDisallowCompound("Command1, Command2 , Command3");

        assertNotNull(config.disallowCompound);
        assertEquals(3, config.disallowCompound.size());
        assertTrue(config.disallowCompound.contains("Command1"));
        assertTrue(config.disallowCompound.contains("Command2"));
        assertTrue(config.disallowCompound.contains("Command3"));
    }

    @Test
    @DisplayName("Test initDefaults sets all required fields")
    void testInitDefaultsSetsAllFields() throws CIFSException {
        BaseConfiguration testConfig = new BaseConfiguration(false);
        testConfig.initDefaults();

        // Check random and time zone
        assertNotNull(testConfig.getRandom());
        assertNotNull(testConfig.getLocalTimezone());

        // Check PID is set
        assertTrue(testConfig.getPid() >= 0);
        assertTrue(testConfig.getPid() < 65536);

        // Check machine ID
        assertNotNull(testConfig.getMachineId());
        assertEquals(32, testConfig.getMachineId().length);

        // Check native OS
        assertNotNull(testConfig.getNativeOs());
        assertEquals(System.getProperty("os.name"), testConfig.getNativeOs());

        // Check flags2
        assertTrue(testConfig.getFlags2() > 0);
        assertTrue((testConfig.getFlags2() & SmbConstants.FLAGS2_LONG_FILENAMES) != 0);
        assertTrue((testConfig.getFlags2() & SmbConstants.FLAGS2_EXTENDED_ATTRIBUTES) != 0);

        // Check capabilities
        assertTrue(testConfig.getCapabilities() != 0, "Capabilities should be non-zero");

        // Check broadcast address
        assertNotNull(testConfig.getBroadcastAddress());
        assertEquals("255.255.255.255", testConfig.getBroadcastAddress().getHostAddress());

        // Check resolver order
        assertNotNull(testConfig.getResolveOrder());
        assertFalse(testConfig.getResolveOrder().isEmpty());

        // Check protocol versions
        assertNotNull(testConfig.getMinimumVersion());
        assertNotNull(testConfig.getMaximumVersion());

        // Check disallow compound
        assertNotNull(testConfig.disallowCompound);
        assertTrue(testConfig.disallowCompound.contains("Smb2SessionSetupRequest"));
        assertTrue(testConfig.disallowCompound.contains("Smb2TreeConnectRequest"));
    }

    @Test
    @DisplayName("Test initDefaults with pre-set machine ID")
    void testInitDefaultsWithPresetMachineId() throws Exception {
        BaseConfiguration testConfig = new BaseConfiguration(false);
        byte[] customMachineId = new byte[32];
        Arrays.fill(customMachineId, (byte) 0xFF);

        // Use reflection to set private field
        java.lang.reflect.Field machineIdField = BaseConfiguration.class.getDeclaredField("machineId");
        machineIdField.setAccessible(true);
        machineIdField.set(testConfig, customMachineId);

        testConfig.initDefaults();

        assertArrayEquals(customMachineId, testConfig.getMachineId());
    }

    @Test
    @DisplayName("Test initDefaults with pre-set native OS")
    void testInitDefaultsWithPresetNativeOs() throws CIFSException {
        BaseConfiguration testConfig = new BaseConfiguration(false);
        testConfig.nativeOs = "CustomOS";

        testConfig.initDefaults();

        assertEquals("CustomOS", testConfig.getNativeOs());
    }

    @Test
    @DisplayName("Test initDefaults with various flag combinations")
    void testInitDefaultsWithFlagCombinations() throws CIFSException {
        BaseConfiguration testConfig = new BaseConfiguration(false);
        testConfig.useExtendedSecurity = true;
        testConfig.signingPreferred = true;
        testConfig.useNtStatus = true;
        testConfig.useUnicode = true;
        testConfig.forceUnicode = true;

        testConfig.initDefaults();

        assertTrue((testConfig.getFlags2() & SmbConstants.FLAGS2_EXTENDED_SECURITY_NEGOTIATION) != 0);
        assertTrue((testConfig.getFlags2() & SmbConstants.FLAGS2_SECURITY_SIGNATURES) != 0);
        assertTrue((testConfig.getFlags2() & SmbConstants.FLAGS2_STATUS32) != 0);
        assertTrue((testConfig.getFlags2() & SmbConstants.FLAGS2_UNICODE) != 0);
    }

    @Test
    @DisplayName("Test initDefaults with various capability combinations")
    void testInitDefaultsWithCapabilityCombinations() throws CIFSException {
        BaseConfiguration testConfig = new BaseConfiguration(false);
        testConfig.useNTSmbs = true;
        testConfig.useNtStatus = true;
        testConfig.useExtendedSecurity = true;
        testConfig.useLargeReadWrite = true;
        testConfig.useUnicode = true;

        testConfig.initDefaults();

        assertTrue((testConfig.getCapabilities() & SmbConstants.CAP_NT_SMBS) != 0);
        assertTrue((testConfig.getCapabilities() & SmbConstants.CAP_STATUS32) != 0);
        assertTrue((testConfig.getCapabilities() & SmbConstants.CAP_EXTENDED_SECURITY) != 0);
        assertTrue((testConfig.getCapabilities() & SmbConstants.CAP_LARGE_READX) != 0);
        assertTrue((testConfig.getCapabilities() & SmbConstants.CAP_LARGE_WRITEX) != 0);
        assertTrue((testConfig.getCapabilities() & SmbConstants.CAP_UNICODE) != 0);
    }

    @Test
    @DisplayName("Test initDefaults with pre-set flags2 and capabilities")
    void testInitDefaultsWithPresetFlags() throws CIFSException {
        BaseConfiguration testConfig = new BaseConfiguration(false);
        testConfig.flags2 = 0x1234;
        testConfig.capabilities = 0x5678;

        testConfig.initDefaults();

        assertEquals(0x1234, testConfig.getFlags2());
        assertEquals(0x5678, testConfig.getCapabilities());
    }

    @Test
    @DisplayName("Test initDefaults with pre-set resolver order")
    void testInitDefaultsWithPresetResolverOrder() throws CIFSException {
        BaseConfiguration testConfig = new BaseConfiguration(false);
        testConfig.resolverOrder = Arrays.asList(ResolverType.RESOLVER_DNS);

        testConfig.initDefaults();

        assertEquals(1, testConfig.getResolveOrder().size());
        assertEquals(ResolverType.RESOLVER_DNS, testConfig.getResolveOrder().get(0));
    }

    @Test
    @DisplayName("Test initDefaults with pre-set protocol versions")
    void testInitDefaultsWithPresetProtocolVersions() throws CIFSException {
        BaseConfiguration testConfig = new BaseConfiguration(false);
        testConfig.minVersion = DialectVersion.SMB210;
        testConfig.maxVersion = DialectVersion.SMB300;

        testConfig.initDefaults();

        assertEquals(DialectVersion.SMB210, testConfig.getMinimumVersion());
        assertEquals(DialectVersion.SMB300, testConfig.getMaximumVersion());
    }

    @Test
    @DisplayName("Test initDefaults with pre-set disallow compound")
    void testInitDefaultsWithPresetDisallowCompound() throws CIFSException {
        BaseConfiguration testConfig = new BaseConfiguration(false);
        Set<String> customDisallow = new HashSet<>(Arrays.asList("CustomCommand"));
        testConfig.disallowCompound = customDisallow;

        testConfig.initDefaults();

        assertEquals(customDisallow, testConfig.disallowCompound);
    }

    /**
     * Testable subclass that exposes the default constructor
     */
    private static class TestableBaseConfiguration extends BaseConfiguration {
        TestableBaseConfiguration() throws CIFSException {
            super(true);
        }
    }
}
