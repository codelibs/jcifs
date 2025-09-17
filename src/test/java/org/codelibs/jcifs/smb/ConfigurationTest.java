package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

/**
 * Test class for Configuration interface functionality
 */
@DisplayName("Configuration Interface Tests")
class ConfigurationTest extends BaseTest {

    @Mock
    private Configuration mockConfig;

    @Test
    @DisplayName("Should define all configuration methods")
    void testConfigurationInterface() {
        assertDoesNotThrow(() -> {
            mockConfig.getRandom();
            mockConfig.getDfsTtl();
            mockConfig.isDfsStrictView();
            mockConfig.isDfsDisabled();
            mockConfig.isDfsConvertToFQDN();
            mockConfig.getMinimumVersion();
            mockConfig.getMaximumVersion();
            mockConfig.isUseSMB2OnlyNegotiation();
            mockConfig.isRequireSecureNegotiate();
            mockConfig.isPort139FailoverEnabled();
            mockConfig.isUseUnicode();
            mockConfig.isForceUnicode();
            mockConfig.isUseBatching();
            mockConfig.getNativeOs();
            mockConfig.getNativeLanman();
            mockConfig.getReceiveBufferSize();
            mockConfig.getSendBufferSize();
            mockConfig.getSoTimeout();
            mockConfig.getConnTimeout();
            mockConfig.getSessionTimeout();
            mockConfig.getLocalPort();
            mockConfig.getLocalAddr();
            mockConfig.getNetbiosHostname();
            mockConfig.getLogonShare();
            mockConfig.getDefaultDomain();
            mockConfig.getDefaultUsername();
            mockConfig.getDefaultPassword();
            mockConfig.getLanManCompatibility();
            mockConfig.isAllowNTLMFallback();
            mockConfig.isUseRawNTLM();
            mockConfig.isDisablePlainTextPasswords();
            mockConfig.getResolveOrder();
            mockConfig.getBroadcastAddress();
            mockConfig.getWinsServers();
            mockConfig.getNetbiosLocalPort();
            mockConfig.getNetbiosLocalAddress();
            mockConfig.getNetbiosSoTimeout();
            mockConfig.getVcNumber();
            mockConfig.getCapabilities();
            mockConfig.getFlags2();
            mockConfig.getSessionLimit();
            mockConfig.getOemEncoding();
            mockConfig.getLocalTimezone();
            mockConfig.getPid();
            mockConfig.getMaxMpxCount();
            mockConfig.isSigningEnabled();
            mockConfig.isIpcSigningEnforced();
            mockConfig.isSigningEnforced();
            mockConfig.isEncryptionEnabled();
            mockConfig.isForceExtendedSecurity();
            mockConfig.getLmHostsFileName();
            mockConfig.getNetbiosScope();
            mockConfig.getNetbiosSndBufSize();
            mockConfig.getNetbiosRcvBufSize();
            mockConfig.getNetbiosRetryTimeout();
            mockConfig.getNetbiosRetryCount();
            mockConfig.getNetbiosCachePolicy();
            mockConfig.getMaximumBufferSize();
            mockConfig.getTransactionBufferSize();
            mockConfig.getBufferCacheSize();
            mockConfig.getListCount();
            mockConfig.getListSize();
            mockConfig.getAttributeCacheTimeout();
            mockConfig.isIgnoreCopyToException();
            mockConfig.getBatchLimit("cmd");
            mockConfig.getNotifyBufferSize();
            mockConfig.getMaxRequestRetries();
            mockConfig.isStrictResourceLifecycle();
            mockConfig.isTraceResourceUsage();
            mockConfig.isAllowCompound("cmd");
            mockConfig.getMachineId();
            mockConfig.isDisableSpnegoIntegrity();
            mockConfig.isEnforceSpnegoIntegrity();
            mockConfig.isSendNTLMTargetName();
            mockConfig.getGuestPassword();
            mockConfig.getGuestUsername();
            mockConfig.isAllowGuestFallback();
        });
    }
}
