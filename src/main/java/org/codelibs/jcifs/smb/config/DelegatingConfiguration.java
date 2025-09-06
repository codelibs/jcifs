/*
 * © 2016 AgNO3 Gmbh & Co. KG
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.codelibs.jcifs.smb.config;

import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.List;
import java.util.TimeZone;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.ResolverType;

/**
 * Configuration implementation that delegates to another configuration instance.
 * Provides a wrapper mechanism for configuration objects with delegation pattern.
 *
 * @author mbechler
 */
public class DelegatingConfiguration implements Configuration {

    private final Configuration delegate;

    /**
     * Creates a delegating configuration that forwards calls to another configuration
     * @param delegate
     *            delegate to pass all non-overridden method calls to
     *
     */
    public DelegatingConfiguration(final Configuration delegate) {
        this.delegate = delegate;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getRandom()
     */
    @Override
    public SecureRandom getRandom() {
        return this.delegate.getRandom();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getMinimumVersion()
     */
    @Override
    public DialectVersion getMinimumVersion() {
        return this.delegate.getMinimumVersion();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getMaximumVersion()
     */
    @Override
    public DialectVersion getMaximumVersion() {
        return this.delegate.getMaximumVersion();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isUseSMB2OnlyNegotiation()
     */
    @Override
    public boolean isUseSMB2OnlyNegotiation() {
        return this.delegate.isUseSMB2OnlyNegotiation();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isRequireSecureNegotiate()
     */
    @Override
    public boolean isRequireSecureNegotiate() {
        return this.delegate.isRequireSecureNegotiate();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isSendNTLMTargetName()
     */
    @Override
    public boolean isSendNTLMTargetName() {
        return this.delegate.isSendNTLMTargetName();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isPort139FailoverEnabled()
     */
    @Override
    public boolean isPort139FailoverEnabled() {
        return this.delegate.isPort139FailoverEnabled();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getDfsTtl()
     */
    @Override
    public long getDfsTtl() {
        return this.delegate.getDfsTtl();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isDfsStrictView()
     */
    @Override
    public boolean isDfsStrictView() {
        return this.delegate.isDfsStrictView();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isDfsDisabled()
     */
    @Override
    public boolean isDfsDisabled() {
        return this.delegate.isDfsDisabled();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isDfsConvertToFQDN()
     */
    @Override
    public boolean isDfsConvertToFQDN() {
        return this.delegate.isDfsConvertToFQDN();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isForceUnicode()
     */
    @Override
    public boolean isForceUnicode() {
        return this.delegate.isForceUnicode();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isUseUnicode()
     */
    @Override
    public boolean isUseUnicode() {
        return this.delegate.isUseUnicode();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isUseBatching()
     */
    @Override
    public boolean isUseBatching() {
        return this.delegate.isUseBatching();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getNativeOs()
     */
    @Override
    public String getNativeOs() {
        return this.delegate.getNativeOs();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getNativeLanman()
     */
    @Override
    public String getNativeLanman() {
        return this.delegate.getNativeLanman();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getMaximumBufferSize()
     */
    @Override
    public int getMaximumBufferSize() {
        return this.delegate.getMaximumBufferSize();
    }

    /**
     * {@inheritDoc}
     *
     * @deprecated use getReceiveBufferSize instead
     */
    @Deprecated
    @Override
    public int getRecieveBufferSize() {
        return this.delegate.getReceiveBufferSize();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getReceiveBufferSize()
     */
    @Override
    public int getReceiveBufferSize() {
        return this.delegate.getReceiveBufferSize();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getSendBufferSize()
     */
    @Override
    public int getSendBufferSize() {
        return this.delegate.getSendBufferSize();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getNotifyBufferSize()
     */
    @Override
    public int getNotifyBufferSize() {
        return this.delegate.getNotifyBufferSize();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getSoTimeout()
     */
    @Override
    public int getSoTimeout() {
        return this.delegate.getSoTimeout();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getResponseTimeout()
     */
    @Override
    public int getResponseTimeout() {
        return this.delegate.getResponseTimeout();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getConnTimeout()
     */
    @Override
    public int getConnTimeout() {
        return this.delegate.getConnTimeout();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getSessionTimeout()
     */
    @Override
    public int getSessionTimeout() {
        return this.delegate.getSessionTimeout();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getLocalPort()
     */
    @Override
    public int getLocalPort() {
        return this.delegate.getLocalPort();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getLocalAddr()
     */
    @Override
    public InetAddress getLocalAddr() {
        return this.delegate.getLocalAddr();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getNetbiosHostname()
     */
    @Override
    public String getNetbiosHostname() {
        return this.delegate.getNetbiosHostname();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getLogonShare()
     */
    @Override
    public String getLogonShare() {
        return this.delegate.getLogonShare();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getDefaultDomain()
     */
    @Override
    public String getDefaultDomain() {
        return this.delegate.getDefaultDomain();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getDefaultUsername()
     */
    @Override
    public String getDefaultUsername() {
        return this.delegate.getDefaultUsername();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getDefaultPassword()
     */
    @Override
    public String getDefaultPassword() {
        return this.delegate.getDefaultPassword();
    }

    /**
     *
     * @see org.codelibs.jcifs.smb.Configuration#isDisablePlainTextPasswords()
     */
    @Override
    public boolean isDisablePlainTextPasswords() {
        return this.delegate.isDisablePlainTextPasswords();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isForceExtendedSecurity()
     */
    @Override
    public boolean isForceExtendedSecurity() {
        return this.delegate.isForceExtendedSecurity();
    }

    @Override
    public boolean isUseLease() {
        return this.delegate.isUseLease();
    }

    @Override
    public int getLeaseTimeout() {
        return this.delegate.getLeaseTimeout();
    }

    @Override
    public int getMaxLeases() {
        return this.delegate.getMaxLeases();
    }

    @Override
    public int getLeaseVersion() {
        return this.delegate.getLeaseVersion();
    }

    @Override
    public int getLeaseBreakTimeout() {
        return this.delegate.getLeaseBreakTimeout();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getLanManCompatibility()
     */
    @Override
    public int getLanManCompatibility() {
        return this.delegate.getLanManCompatibility();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isAllowNTLMFallback()
     */
    @Override
    public boolean isAllowNTLMFallback() {
        return this.delegate.isAllowNTLMFallback();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isUseRawNTLM()
     */
    @Override
    public boolean isUseRawNTLM() {
        return this.delegate.isUseRawNTLM();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isDisableSpnegoIntegrity()
     */
    @Override
    public boolean isDisableSpnegoIntegrity() {
        return this.delegate.isDisableSpnegoIntegrity();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isEnforceSpnegoIntegrity()
     */
    @Override
    public boolean isEnforceSpnegoIntegrity() {
        return this.delegate.isEnforceSpnegoIntegrity();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getResolveOrder()
     */
    @Override
    public List<ResolverType> getResolveOrder() {
        return this.delegate.getResolveOrder();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getBroadcastAddress()
     */
    @Override
    public InetAddress getBroadcastAddress() {
        return this.delegate.getBroadcastAddress();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getWinsServers()
     */
    @Override
    public InetAddress[] getWinsServers() {
        return this.delegate.getWinsServers();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getNetbiosLocalPort()
     */
    @Override
    public int getNetbiosLocalPort() {
        return this.delegate.getNetbiosLocalPort();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getNetbiosLocalAddress()
     */
    @Override
    public InetAddress getNetbiosLocalAddress() {
        return this.delegate.getNetbiosLocalAddress();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getVcNumber()
     */
    @Override
    public int getVcNumber() {
        return this.delegate.getVcNumber();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getCapabilities()
     */
    @Override
    public int getCapabilities() {
        return this.delegate.getCapabilities();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getFlags2()
     */
    @Override
    public int getFlags2() {
        return this.delegate.getFlags2();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getSessionLimit()
     */
    @Override
    public int getSessionLimit() {
        return this.delegate.getSessionLimit();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getOemEncoding()
     */
    @Override
    public String getOemEncoding() {
        return this.delegate.getOemEncoding();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getLocalTimezone()
     */
    @Override
    public TimeZone getLocalTimezone() {
        return this.delegate.getLocalTimezone();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getPid()
     */
    @Override
    public int getPid() {
        return this.delegate.getPid();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getMaxMpxCount()
     */
    @Override
    public int getMaxMpxCount() {
        return this.delegate.getMaxMpxCount();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isSigningEnabled()
     */
    @Override
    public boolean isSigningEnabled() {
        return this.delegate.isSigningEnabled();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isSigningEnforced()
     */
    @Override
    public boolean isSigningEnforced() {
        return this.delegate.isSigningEnforced();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isIpcSigningEnforced()
     */
    @Override
    public boolean isIpcSigningEnforced() {
        return this.delegate.isIpcSigningEnforced();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isEncryptionEnabled()
     */
    @Override
    public boolean isEncryptionEnabled() {
        return this.delegate.isEncryptionEnabled();
    }

    @Override
    public boolean isCompressionEnabled() {
        return this.delegate.isCompressionEnabled();
    }

    @Override
    public String getPreferredCiphers() {
        return this.delegate.getPreferredCiphers();
    }

    @Override
    public boolean isAES256Enabled() {
        return this.delegate.isAES256Enabled();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getLmHostsFileName()
     */
    @Override
    public String getLmHostsFileName() {
        return this.delegate.getLmHostsFileName();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getNetbiosScope()
     */
    @Override
    public String getNetbiosScope() {
        return this.delegate.getNetbiosScope();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getNetbiosSoTimeout()
     */
    @Override
    public int getNetbiosSoTimeout() {
        return this.delegate.getNetbiosSoTimeout();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getNetbiosSndBufSize()
     */
    @Override
    public int getNetbiosSndBufSize() {
        return this.delegate.getNetbiosSndBufSize();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getNetbiosRetryTimeout()
     */
    @Override
    public int getNetbiosRetryTimeout() {
        return this.delegate.getNetbiosRetryTimeout();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getNetbiosRetryCount()
     */
    @Override
    public int getNetbiosRetryCount() {
        return this.delegate.getNetbiosRetryCount();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getNetbiosRcvBufSize()
     */
    @Override
    public int getNetbiosRcvBufSize() {
        return this.delegate.getNetbiosRcvBufSize();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getNetbiosCachePolicy()
     */
    @Override
    public int getNetbiosCachePolicy() {
        return this.delegate.getNetbiosCachePolicy();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getTransactionBufferSize()
     */
    @Override
    public int getTransactionBufferSize() {
        return this.delegate.getTransactionBufferSize();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getBufferCacheSize()
     */
    @Override
    public int getBufferCacheSize() {
        return this.delegate.getBufferCacheSize();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getListCount()
     */
    @Override
    public int getListCount() {
        return this.delegate.getListCount();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getListSize()
     */
    @Override
    public int getListSize() {
        return this.delegate.getListSize();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getAttributeCacheTimeout()
     */
    @Override
    public long getAttributeCacheTimeout() {
        return this.delegate.getAttributeCacheTimeout();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isIgnoreCopyToException()
     */
    @Override
    public boolean isIgnoreCopyToException() {
        return this.delegate.isIgnoreCopyToException();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getBatchLimit(java.lang.String)
     */
    @Override
    public int getBatchLimit(final String cmd) {
        return this.delegate.getBatchLimit(cmd);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isAllowCompound(java.lang.String)
     */
    @Override
    public boolean isAllowCompound(final String command) {
        return this.delegate.isAllowCompound(command);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isTraceResourceUsage()
     */
    @Override
    public boolean isTraceResourceUsage() {
        return this.delegate.isTraceResourceUsage();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isStrictResourceLifecycle()
     */
    @Override
    public boolean isStrictResourceLifecycle() {
        return this.delegate.isStrictResourceLifecycle();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getMaxRequestRetries()
     */
    @Override
    public int getMaxRequestRetries() {
        return this.delegate.getMaxRequestRetries();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getMachineId()
     */
    @Override
    public byte[] getMachineId() {
        return this.delegate.getMachineId();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getGuestUsername()
     */
    @Override
    public String getGuestUsername() {
        return this.delegate.getGuestUsername();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getGuestPassword()
     */
    @Override
    public String getGuestPassword() {
        return this.delegate.getGuestPassword();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isAllowGuestFallback()
     */
    @Override
    public boolean isAllowGuestFallback() {
        return this.delegate.isAllowGuestFallback();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isUseDurableHandles()
     */
    @Override
    public boolean isUseDurableHandles() {
        return this.delegate.isUseDurableHandles();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isUsePersistentHandles()
     */
    @Override
    public boolean isUsePersistentHandles() {
        return this.delegate.isUsePersistentHandles();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getDurableHandleTimeout()
     */
    @Override
    public long getDurableHandleTimeout() {
        return this.delegate.getDurableHandleTimeout();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getHandleReconnectRetries()
     */
    @Override
    public int getHandleReconnectRetries() {
        return this.delegate.getHandleReconnectRetries();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isUseMultiChannel()
     */
    @Override
    public boolean isUseMultiChannel() {
        return this.delegate.isUseMultiChannel();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getMaxChannels()
     */
    @Override
    public int getMaxChannels() {
        return this.delegate.getMaxChannels();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getChannelBindingPolicy()
     */
    @Override
    public int getChannelBindingPolicy() {
        return this.delegate.getChannelBindingPolicy();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getLoadBalancingStrategy()
     */
    @Override
    public String getLoadBalancingStrategy() {
        return this.delegate.getLoadBalancingStrategy();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getChannelHealthCheckInterval()
     */
    @Override
    public int getChannelHealthCheckInterval() {
        return this.delegate.getChannelHealthCheckInterval();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getHandleStateDirectory()
     */
    @Override
    public String getHandleStateDirectory() {
        return this.delegate.getHandleStateDirectory();
    }

    @Override
    public boolean isUseDirectoryLeasing() {
        return this.delegate.isUseDirectoryLeasing();
    }

    @Override
    public String getDirectoryCacheScope() {
        return this.delegate.getDirectoryCacheScope();
    }

    @Override
    public long getDirectoryCacheTimeout() {
        return this.delegate.getDirectoryCacheTimeout();
    }

    @Override
    public boolean isDirectoryNotificationsEnabled() {
        return this.delegate.isDirectoryNotificationsEnabled();
    }

    @Override
    public int getMaxDirectoryCacheEntries() {
        return this.delegate.getMaxDirectoryCacheEntries();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isUseRDMA()
     */
    @Override
    public boolean isUseRDMA() {
        return this.delegate.isUseRDMA();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getRdmaProvider()
     */
    @Override
    public String getRdmaProvider() {
        return this.delegate.getRdmaProvider();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getRdmaReadWriteThreshold()
     */
    @Override
    public int getRdmaReadWriteThreshold() {
        return this.delegate.getRdmaReadWriteThreshold();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getRdmaMaxSendSize()
     */
    @Override
    public int getRdmaMaxSendSize() {
        return this.delegate.getRdmaMaxSendSize();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getRdmaMaxReceiveSize()
     */
    @Override
    public int getRdmaMaxReceiveSize() {
        return this.delegate.getRdmaMaxReceiveSize();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getRdmaCredits()
     */
    @Override
    public int getRdmaCredits() {
        return this.delegate.getRdmaCredits();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isRdmaEnabled()
     */
    @Override
    public boolean isRdmaEnabled() {
        return this.delegate.isRdmaEnabled();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getRdmaPort()
     */
    @Override
    public int getRdmaPort() {
        return this.delegate.getRdmaPort();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isUseWitness()
     */
    @Override
    public boolean isUseWitness() {
        return this.delegate.isUseWitness();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getWitnessHeartbeatTimeout()
     */
    @Override
    public long getWitnessHeartbeatTimeout() {
        return this.delegate.getWitnessHeartbeatTimeout();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getWitnessRegistrationTimeout()
     */
    @Override
    public long getWitnessRegistrationTimeout() {
        return this.delegate.getWitnessRegistrationTimeout();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#getWitnessReconnectDelay()
     */
    @Override
    public long getWitnessReconnectDelay() {
        return this.delegate.getWitnessReconnectDelay();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Configuration#isWitnessServiceDiscovery()
     */
    @Override
    public boolean isWitnessServiceDiscovery() {
        return this.delegate.isWitnessServiceDiscovery();
    }

    @Override
    public boolean isUseLeases() {
        return this.delegate.isUseLeases();
    }

    @Override
    public long getPersistentHandleTimeout() {
        return this.delegate.getPersistentHandleTimeout();
    }
}
