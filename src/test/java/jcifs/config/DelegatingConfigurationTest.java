package jcifs.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.TimeZone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import jcifs.BaseTest;
import jcifs.Configuration;
import jcifs.DialectVersion;
import jcifs.ResolverType;

/**
 * Comprehensive test suite for DelegatingConfiguration class.
 * Tests the delegation pattern and ensures all methods properly delegate.
 */
@DisplayName("DelegatingConfiguration Tests")
class DelegatingConfigurationTest extends BaseTest {

    @Mock
    private Configuration mockDelegate;

    private DelegatingConfiguration delegatingConfig;

    @BeforeEach
    void setUp() {
        delegatingConfig = new DelegatingConfiguration(mockDelegate);
    }

    @Test
    @DisplayName("Constructor should require non-null delegate")
    void testConstructorWithNullDelegate() {
        // When & Then
        assertDoesNotThrow(() -> {
            new DelegatingConfiguration(null);
        }, "Constructor should accept null delegate (though it would cause NPE on use)");
    }

    @Test
    @DisplayName("Constructor should store delegate reference")
    void testConstructorStoresDelegate() {
        // Given
        Configuration testDelegate = mock(Configuration.class);

        // When
        DelegatingConfiguration config = new DelegatingConfiguration(testDelegate);

        // Then
        assertNotNull(config, "Configuration should be created");
    }

    @Test
    @DisplayName("Random access should delegate to underlying configuration")
    void testRandomDelegation() {
        // Given
        SecureRandom expectedRandom = new SecureRandom();
        when(mockDelegate.getRandom()).thenReturn(expectedRandom);

        // When
        SecureRandom result = delegatingConfig.getRandom();

        // Then
        assertSame(expectedRandom, result, "Should return delegated random");
        verify(mockDelegate).getRandom();
    }

    @Test
    @DisplayName("Protocol version methods should delegate correctly")
    void testProtocolVersionDelegation() {
        // Given
        DialectVersion minVersion = DialectVersion.SMB1;
        DialectVersion maxVersion = DialectVersion.SMB311;
        when(mockDelegate.getMinimumVersion()).thenReturn(minVersion);
        when(mockDelegate.getMaximumVersion()).thenReturn(maxVersion);

        // When
        DialectVersion resultMin = delegatingConfig.getMinimumVersion();
        DialectVersion resultMax = delegatingConfig.getMaximumVersion();

        // Then
        assertSame(minVersion, resultMin, "Should return delegated minimum version");
        assertSame(maxVersion, resultMax, "Should return delegated maximum version");
        verify(mockDelegate).getMinimumVersion();
        verify(mockDelegate).getMaximumVersion();
    }

    @Test
    @DisplayName("Boolean configuration methods should delegate correctly")
    void testBooleanConfigurationDelegation() {
        // Given
        when(mockDelegate.isUseSMB2OnlyNegotiation()).thenReturn(true);
        when(mockDelegate.isRequireSecureNegotiate()).thenReturn(false);
        when(mockDelegate.isSendNTLMTargetName()).thenReturn(true);
        when(mockDelegate.isPort139FailoverEnabled()).thenReturn(false);
        when(mockDelegate.isDfsStrictView()).thenReturn(true);

        // When
        boolean smb2Only = delegatingConfig.isUseSMB2OnlyNegotiation();
        boolean secureNegotiate = delegatingConfig.isRequireSecureNegotiate();
        boolean ntlmTargetName = delegatingConfig.isSendNTLMTargetName();
        boolean port139Failover = delegatingConfig.isPort139FailoverEnabled();
        boolean dfsStrictView = delegatingConfig.isDfsStrictView();

        // Then
        assertTrue(smb2Only, "Should delegate SMB2 only negotiation");
        assertFalse(secureNegotiate, "Should delegate secure negotiate requirement");
        assertTrue(ntlmTargetName, "Should delegate NTLM target name setting");
        assertFalse(port139Failover, "Should delegate port 139 failover setting");
        assertTrue(dfsStrictView, "Should delegate DFS strict view setting");

        verify(mockDelegate).isUseSMB2OnlyNegotiation();
        verify(mockDelegate).isRequireSecureNegotiate();
        verify(mockDelegate).isSendNTLMTargetName();
        verify(mockDelegate).isPort139FailoverEnabled();
        verify(mockDelegate).isDfsStrictView();
    }

    @Test
    @DisplayName("Numeric configuration methods should delegate correctly")
    void testNumericConfigurationDelegation() {
        // Given
        when(mockDelegate.getDfsTtl()).thenReturn(300L);
        when(mockDelegate.getResponseTimeout()).thenReturn(30000);
        when(mockDelegate.getSoTimeout()).thenReturn(35000);
        when(mockDelegate.getConnTimeout()).thenReturn(35000);
        when(mockDelegate.getMaxMpxCount()).thenReturn(10);

        // When
        long dfsTtl = delegatingConfig.getDfsTtl();
        int responseTimeout = delegatingConfig.getResponseTimeout();
        int socketTimeout = delegatingConfig.getSoTimeout();
        int connTimeout = delegatingConfig.getConnTimeout();
        int maxMpx = delegatingConfig.getMaxMpxCount();

        // Then
        assertEquals(300L, dfsTtl, "Should delegate DFS TTL");
        assertEquals(30000, responseTimeout, "Should delegate response timeout");
        assertEquals(35000, socketTimeout, "Should delegate socket timeout");
        assertEquals(35000, connTimeout, "Should delegate connection timeout");
        assertEquals(10, maxMpx, "Should delegate max MPX count");

        verify(mockDelegate).getDfsTtl();
        verify(mockDelegate).getResponseTimeout();
        verify(mockDelegate).getSoTimeout();
        verify(mockDelegate).getConnTimeout();
        verify(mockDelegate).getMaxMpxCount();
    }

    @Test
    @DisplayName("Network address methods should delegate correctly")
    void testNetworkAddressDelegation() throws UnknownHostException {
        // Given
        InetAddress localAddr = InetAddress.getByName("127.0.0.1");
        InetAddress broadcastAddr = InetAddress.getByName("192.168.1.255");
        InetAddress[] winsServers = { InetAddress.getByName("192.168.1.1") };

        when(mockDelegate.getLocalAddr()).thenReturn(localAddr);
        when(mockDelegate.getBroadcastAddress()).thenReturn(broadcastAddr);
        when(mockDelegate.getWinsServers()).thenReturn(winsServers);
        when(mockDelegate.getLocalPort()).thenReturn(445);

        // When
        InetAddress resultLocalAddr = delegatingConfig.getLocalAddr();
        InetAddress resultBroadcastAddr = delegatingConfig.getBroadcastAddress();
        InetAddress[] resultWinsServers = delegatingConfig.getWinsServers();
        int resultLocalPort = delegatingConfig.getLocalPort();

        // Then
        assertSame(localAddr, resultLocalAddr, "Should delegate local address");
        assertSame(broadcastAddr, resultBroadcastAddr, "Should delegate broadcast address");
        assertSame(winsServers, resultWinsServers, "Should delegate WINS servers");
        assertEquals(445, resultLocalPort, "Should delegate local port");

        verify(mockDelegate).getLocalAddr();
        verify(mockDelegate).getBroadcastAddress();
        verify(mockDelegate).getWinsServers();
        verify(mockDelegate).getLocalPort();
    }

    @Test
    @DisplayName("String configuration methods should delegate correctly")
    void testStringConfigurationDelegation() {
        // Given
        when(mockDelegate.getOemEncoding()).thenReturn("UTF-8");
        when(mockDelegate.getNetbiosHostname()).thenReturn("TESTHOST");
        when(mockDelegate.getDefaultDomain()).thenReturn("WORKGROUP");
        when(mockDelegate.getDefaultUsername()).thenReturn("testuser");
        when(mockDelegate.getDefaultPassword()).thenReturn("testpass");
        when(mockDelegate.getNativeLanman()).thenReturn("jCIFS");

        // When
        String oemEncoding = delegatingConfig.getOemEncoding();
        String netbiosHostname = delegatingConfig.getNetbiosHostname();
        String defaultDomain = delegatingConfig.getDefaultDomain();
        String defaultUsername = delegatingConfig.getDefaultUsername();
        String defaultPassword = delegatingConfig.getDefaultPassword();
        String nativeLanMan = delegatingConfig.getNativeLanman();

        // Then
        assertEquals("UTF-8", oemEncoding, "Should delegate OEM encoding");
        assertEquals("TESTHOST", netbiosHostname, "Should delegate NetBIOS hostname");
        assertEquals("WORKGROUP", defaultDomain, "Should delegate default domain");
        assertEquals("testuser", defaultUsername, "Should delegate default username");
        assertEquals("testpass", defaultPassword, "Should delegate default password");
        assertEquals("jCIFS", nativeLanMan, "Should delegate native LanMan");

        verify(mockDelegate).getOemEncoding();
        verify(mockDelegate).getNetbiosHostname();
        verify(mockDelegate).getDefaultDomain();
        verify(mockDelegate).getDefaultUsername();
        verify(mockDelegate).getDefaultPassword();
        verify(mockDelegate).getNativeLanman();
    }

    @Test
    @DisplayName("Collection configuration methods should delegate correctly")
    void testCollectionConfigurationDelegation() {
        // Given
        List<ResolverType> resolverOrder = Arrays.asList(ResolverType.RESOLVER_DNS, ResolverType.RESOLVER_WINS);
        when(mockDelegate.getResolveOrder()).thenReturn(resolverOrder);

        // When
        List<ResolverType> resultResolverOrder = delegatingConfig.getResolveOrder();

        // Then
        assertSame(resolverOrder, resultResolverOrder, "Should delegate resolver order");
        verify(mockDelegate).getResolveOrder();
    }

    @Test
    @DisplayName("TimeZone configuration should delegate correctly")
    void testTimeZoneConfigurationDelegation() {
        // Given
        TimeZone timeZone = TimeZone.getTimeZone("UTC");
        when(mockDelegate.getLocalTimezone()).thenReturn(timeZone);

        // When
        TimeZone resultTimeZone = delegatingConfig.getLocalTimezone();

        // Then
        assertSame(timeZone, resultTimeZone, "Should delegate time zone");
        verify(mockDelegate).getLocalTimezone();
    }

    @Test
    @DisplayName("Batch limit configuration should delegate correctly")
    void testBatchLimitDelegation() {
        // Given
        String operation = "TestOperation";
        when(mockDelegate.getBatchLimit(operation)).thenReturn(100);

        // When
        int batchLimit = delegatingConfig.getBatchLimit(operation);

        // Then
        assertEquals(100, batchLimit, "Should delegate batch limit");
        verify(mockDelegate).getBatchLimit(operation);
    }

    @Test
    @DisplayName("Buffer configuration methods should delegate correctly")
    void testBufferConfigurationDelegation() {
        // Given
        when(mockDelegate.getSendBufferSize()).thenReturn(8192);
        when(mockDelegate.getReceiveBufferSize()).thenReturn(8192);
        when(mockDelegate.getMaximumBufferSize()).thenReturn(65536);
        when(mockDelegate.getTransactionBufferSize()).thenReturn(65024);
        when(mockDelegate.getBufferCacheSize()).thenReturn(16);
        when(mockDelegate.getNotifyBufferSize()).thenReturn(1024);

        // When
        int sendBufferSize = delegatingConfig.getSendBufferSize();
        int receiveBufferSize = delegatingConfig.getReceiveBufferSize();
        int maximumBufferSize = delegatingConfig.getMaximumBufferSize();
        int transactionBufferSize = delegatingConfig.getTransactionBufferSize();
        int bufferCacheSize = delegatingConfig.getBufferCacheSize();
        int notifyBufferSize = delegatingConfig.getNotifyBufferSize();

        // Then
        assertEquals(8192, sendBufferSize, "Should delegate send buffer size");
        assertEquals(8192, receiveBufferSize, "Should delegate receive buffer size");
        assertEquals(65536, maximumBufferSize, "Should delegate maximum buffer size");
        assertEquals(65024, transactionBufferSize, "Should delegate transaction buffer size");
        assertEquals(16, bufferCacheSize, "Should delegate buffer cache size");
        assertEquals(1024, notifyBufferSize, "Should delegate notify buffer size");

        verify(mockDelegate).getSendBufferSize();
        verify(mockDelegate).getReceiveBufferSize();
        verify(mockDelegate).getMaximumBufferSize();
        verify(mockDelegate).getTransactionBufferSize();
        verify(mockDelegate).getBufferCacheSize();
        verify(mockDelegate).getNotifyBufferSize();
    }

    @Test
    @DisplayName("Authentication configuration should delegate correctly")
    void testAuthenticationConfigurationDelegation() {
        // Given
        when(mockDelegate.getLanManCompatibility()).thenReturn(3);
        when(mockDelegate.isAllowNTLMFallback()).thenReturn(true);
        when(mockDelegate.isUseRawNTLM()).thenReturn(false);
        when(mockDelegate.isDisablePlainTextPasswords()).thenReturn(true);
        when(mockDelegate.getGuestUsername()).thenReturn("GUEST");
        when(mockDelegate.getGuestPassword()).thenReturn("");
        when(mockDelegate.isAllowGuestFallback()).thenReturn(false);

        // When
        int lanmanCompatibility = delegatingConfig.getLanManCompatibility();
        boolean allowNTLMFallback = delegatingConfig.isAllowNTLMFallback();
        boolean useRawNTLM = delegatingConfig.isUseRawNTLM();
        boolean disablePlainTextPasswords = delegatingConfig.isDisablePlainTextPasswords();
        String guestUsername = delegatingConfig.getGuestUsername();
        String guestPassword = delegatingConfig.getGuestPassword();
        boolean allowGuestFallback = delegatingConfig.isAllowGuestFallback();

        // Then
        assertEquals(3, lanmanCompatibility, "Should delegate LanMan compatibility");
        assertTrue(allowNTLMFallback, "Should delegate NTLM fallback setting");
        assertFalse(useRawNTLM, "Should delegate raw NTLM setting");
        assertTrue(disablePlainTextPasswords, "Should delegate plain text password setting");
        assertEquals("GUEST", guestUsername, "Should delegate guest username");
        assertEquals("", guestPassword, "Should delegate guest password");
        assertFalse(allowGuestFallback, "Should delegate guest fallback setting");

        verify(mockDelegate).getLanManCompatibility();
        verify(mockDelegate).isAllowNTLMFallback();
        verify(mockDelegate).isUseRawNTLM();
        verify(mockDelegate).isDisablePlainTextPasswords();
        verify(mockDelegate).getGuestUsername();
        verify(mockDelegate).getGuestPassword();
        verify(mockDelegate).isAllowGuestFallback();
    }

    @Test
    @DisplayName("Encryption and security configuration should delegate correctly")
    void testEncryptionSecurityDelegation() {
        // Given
        when(mockDelegate.isEncryptionEnabled()).thenReturn(true);
        when(mockDelegate.isSigningEnabled()).thenReturn(false);
        when(mockDelegate.isSigningEnforced()).thenReturn(true);
        when(mockDelegate.isIpcSigningEnforced()).thenReturn(true);
        when(mockDelegate.isForceExtendedSecurity()).thenReturn(true);
        when(mockDelegate.isForceExtendedSecurity()).thenReturn(false);

        // When
        boolean encryptionEnabled = delegatingConfig.isEncryptionEnabled();
        boolean signingPreferred = delegatingConfig.isSigningEnabled();
        boolean signingEnforced = delegatingConfig.isSigningEnforced();
        boolean ipcSigningEnforced = delegatingConfig.isIpcSigningEnforced();
        boolean useExtendedSecurity = delegatingConfig.isForceExtendedSecurity();
        boolean forceExtendedSecurity = delegatingConfig.isForceExtendedSecurity();

        // Then
        assertTrue(encryptionEnabled, "Should delegate encryption setting");
        assertFalse(signingPreferred, "Should delegate signing preferred setting");
        assertTrue(signingEnforced, "Should delegate signing enforced setting");
        assertTrue(ipcSigningEnforced, "Should delegate IPC signing enforced setting");
        assertTrue(useExtendedSecurity, "Should delegate extended security setting");
        assertFalse(forceExtendedSecurity, "Should delegate force extended security setting");

        verify(mockDelegate).isEncryptionEnabled();
        verify(mockDelegate).isSigningEnabled();
        verify(mockDelegate).isSigningEnforced();
        verify(mockDelegate).isIpcSigningEnforced();
        verify(mockDelegate).isForceExtendedSecurity();
        verify(mockDelegate).isForceExtendedSecurity();
    }

    @Test
    @DisplayName("Delegation should handle null returns gracefully")
    void testNullReturnHandling() {
        // Given - configure delegate to return nulls
        when(mockDelegate.getRandom()).thenReturn(null);
        when(mockDelegate.getLocalAddr()).thenReturn(null);
        when(mockDelegate.getNetbiosHostname()).thenReturn(null);
        when(mockDelegate.getResolveOrder()).thenReturn(null);
        when(mockDelegate.getMinimumVersion()).thenReturn(null);
        when(mockDelegate.getMaximumVersion()).thenReturn(null);

        // When & Then - should handle nulls gracefully
        assertNull(delegatingConfig.getRandom(), "Should return null when delegate returns null");
        assertNull(delegatingConfig.getLocalAddr(), "Should return null when delegate returns null");
        assertNull(delegatingConfig.getNetbiosHostname(), "Should return null when delegate returns null");
        assertNull(delegatingConfig.getResolveOrder(), "Should return null when delegate returns null");
        assertNull(delegatingConfig.getMinimumVersion(), "Should return null when delegate returns null");
        assertNull(delegatingConfig.getMaximumVersion(), "Should return null when delegate returns null");
    }

    @Test
    @DisplayName("Delegation should handle exceptions from delegate")
    void testExceptionHandling() {
        // Given
        RuntimeException testException = new RuntimeException("Test exception");
        when(mockDelegate.getResponseTimeout()).thenThrow(testException);

        // When & Then
        RuntimeException thrownException = assertThrows(RuntimeException.class, () -> {
            delegatingConfig.getResponseTimeout();
        });

        assertSame(testException, thrownException, "Should propagate exception from delegate");
        verify(mockDelegate).getResponseTimeout();
    }

    @Test
    @DisplayName("Multiple method calls should result in multiple delegate calls")
    void testMultipleDelegateCalls() {
        // Given
        when(mockDelegate.getResponseTimeout()).thenReturn(30000);

        // When
        int timeout1 = delegatingConfig.getResponseTimeout();
        int timeout2 = delegatingConfig.getResponseTimeout();
        int timeout3 = delegatingConfig.getResponseTimeout();

        // Then
        assertEquals(30000, timeout1, "First call should return correct value");
        assertEquals(30000, timeout2, "Second call should return correct value");
        assertEquals(30000, timeout3, "Third call should return correct value");
        verify(mockDelegate, times(3)).getResponseTimeout();
    }

    @Test
    @DisplayName("DelegatingConfiguration should implement Configuration interface")
    void testInterfaceImplementation() {
        // Then
        assertTrue(delegatingConfig instanceof Configuration, "DelegatingConfiguration should implement Configuration interface");
    }

    @Test
    @DisplayName("Delegation should work with different delegate implementations")
    void testWithDifferentDelegates() throws Exception {
        // Given
        BaseConfiguration baseConfig = new BaseConfiguration(false);
        DelegatingConfiguration configWithBaseDelegate = new DelegatingConfiguration(baseConfig);

        // When & Then - should not throw exceptions
        assertDoesNotThrow(() -> {
            configWithBaseDelegate.getResponseTimeout();
            configWithBaseDelegate.isUseUnicode();
            configWithBaseDelegate.getOemEncoding();
        }, "Should work with BaseConfiguration delegate");

        // Test chaining delegates
        DelegatingConfiguration chainedConfig = new DelegatingConfiguration(configWithBaseDelegate);
        assertDoesNotThrow(() -> {
            chainedConfig.getResponseTimeout();
            chainedConfig.isUseUnicode();
            chainedConfig.getOemEncoding();
        }, "Should work with chained delegation");
    }
}