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
import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Config;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.SmbConstants;

/**
 * Configuration implementation reading the classic org.codelibs.jcifs.smb settings from properties
 *
 * @author mbechler
 *
 */
public final class PropertyConfiguration extends BaseConfiguration implements Configuration {

    /**
     * Constructs a PropertyConfiguration from the provided properties.
     *
     * @param p
     *            read from properties
     * @throws CIFSException if configuration initialization fails
     *
     */
    public PropertyConfiguration(final Properties p) throws CIFSException {
        this.useBatching = Config.getBoolean(p, "jcifs.client.useBatching", false);
        this.useUnicode = Config.getBoolean(p, "jcifs.client.useUnicode", true);
        this.useLargeReadWrite = Config.getBoolean(p, "jcifs.client.useLargeReadWrite", true);
        this.forceUnicode = Config.getBoolean(p, "jcifs.client.forceUnicode", false);
        this.signingPreferred = Config.getBoolean(p, "jcifs.client.signingPreferred", false);
        this.signingEnforced = Config.getBoolean(p, "jcifs.client.signingEnforced", false);
        this.ipcSigningEnforced = Config.getBoolean(p, "jcifs.client.ipcSigningEnforced", true);
        this.encryptionEnabled = Config.getBoolean(p, "jcifs.client.encryptionEnabled", false);
        this.requireSecureNegotiate = Config.getBoolean(p, "jcifs.client.requireSecureNegotiate", true);
        this.sendNTLMTargetName = Config.getBoolean(p, "jcifs.client.SendNTLMTargetName", true);

        this.lanmanCompatibility = Config.getInt(p, "jcifs.lmCompatibility", 3);
        this.allowNTLMFallback = Config.getBoolean(p, "jcifs.allowNTLMFallback", true);
        this.useRawNTLM = Config.getBoolean(p, "jcifs.useRawNTLM", false);

        this.disableSpnegoIntegrity = Config.getBoolean(p, "jcifs.client.disableSpnegoIntegrity", false);
        this.enforceSpnegoIntegrity = Config.getBoolean(p, "jcifs.client.enforceSpnegoIntegrity", false);

        this.disablePlainTextPasswords = Config.getBoolean(p, "jcifs.client.disablePlainTextPasswords", true);

        this.oemEncoding = p.getProperty("jcifs.encoding", SmbConstants.DEFAULT_OEM_ENCODING);

        this.useNtStatus = Config.getBoolean(p, "jcifs.client.useNtStatus", true);
        this.useExtendedSecurity = Config.getBoolean(p, "jcifs.client.useExtendedSecurity", true);
        this.forceExtendedSecurity = Config.getBoolean(p, "jcifs.client.forceExtendedSecurity", false);

        this.smb2OnlyNegotiation = Config.getBoolean(p, "jcifs.client.useSMB2Negotiation", false);
        this.port139FailoverEnabled = Config.getBoolean(p, "jcifs.client.port139.enabled", false);

        this.useNTSmbs = Config.getBoolean(p, "jcifs.client.useNTSmbs", true);

        this.flags2 = Config.getInt(p, "jcifs.client.flags2", 0);

        this.capabilities = Config.getInt(p, "jcifs.client.capabilities", 0);

        this.sessionLimit = Config.getInt(p, "jcifs.client.ssnLimit", SmbConstants.DEFAULT_SSN_LIMIT);

        this.maxRequestRetries = Config.getInt(p, "jcifs.client.maxRequestRetries", 2);

        this.smbTcpNoDelay = Config.getBoolean(p, "jcifs.client.tcpNoDelay", false);
        this.smbResponseTimeout = Config.getInt(p, "jcifs.client.responseTimeout", SmbConstants.DEFAULT_RESPONSE_TIMEOUT);
        this.smbSocketTimeout = Config.getInt(p, "jcifs.client.soTimeout", SmbConstants.DEFAULT_SO_TIMEOUT);
        this.smbConnectionTimeout = Config.getInt(p, "jcifs.client.connTimeout", SmbConstants.DEFAULT_CONN_TIMEOUT);
        this.smbSessionTimeout = Config.getInt(p, "jcifs.client.sessionTimeout", SmbConstants.DEFAULT_CONN_TIMEOUT);
        this.idleTimeoutDisabled = Config.getBoolean(p, "jcifs.client.disableIdleTimeout", false);

        this.smbLocalAddress = Config.getLocalHost(p);
        this.smbLocalPort = Config.getInt(p, "jcifs.client.lport", 0);
        this.maxMpxCount = Config.getInt(p, "jcifs.client.maxMpxCount", SmbConstants.DEFAULT_MAX_MPX_COUNT);
        this.smbSendBufferSize = Config.getInt(p, "jcifs.client.snd_buf_size", SmbConstants.DEFAULT_SND_BUF_SIZE);
        this.smbRecvBufferSize = Config.getInt(p, "jcifs.client.rcv_buf_size", SmbConstants.DEFAULT_RCV_BUF_SIZE);
        this.smbNotifyBufferSize = Config.getInt(p, "jcifs.client.notify_buf_size", SmbConstants.DEFAULT_NOTIFY_BUF_SIZE);

        this.nativeOs = p.getProperty("jcifs.client.nativeOs", System.getProperty("os.name"));
        this.nativeLanMan = p.getProperty("jcifs.client.nativeLanMan", "jCIFS");
        this.vcNumber = 1;

        this.dfsDisabled = Config.getBoolean(p, "jcifs.client.dfs.disabled", false);
        this.dfsTTL = Config.getLong(p, "jcifs.client.dfs.ttl", 300);
        this.dfsStrictView = Config.getBoolean(p, "jcifs.client.dfs.strictView", false);
        this.dfsConvertToFqdn = Config.getBoolean(p, "jcifs.client.dfs.convertToFQDN", false);

        this.logonShare = p.getProperty("jcifs.client.logonShare", null);

        this.defaultDomain = p.getProperty("jcifs.client.domain", null);
        this.defaultUserName = p.getProperty("jcifs.client.username", null);
        this.defaultPassword = p.getProperty("jcifs.client.password", null);

        this.netbiosHostname = p.getProperty("jcifs.netbios.hostname", null);

        this.netbiosCachePolicy = Config.getInt(p, "jcifs.netbios.cachePolicy", 60 * 10) * 60; /* 10 hours */

        this.netbiosSocketTimeout = Config.getInt(p, "jcifs.netbios.soTimeout", 5000);
        this.netbiosSendBufferSize = Config.getInt(p, "jcifs.netbios.snd_buf_size", 576);
        this.netbiosRevcBufferSize = Config.getInt(p, "jcifs.netbios.rcv_buf_size", 576);
        this.netbiosRetryCount = Config.getInt(p, "jcifs.netbios.retryCount", 2);
        this.netbiosRetryTimeout = Config.getInt(p, "jcifs.netbios.retryTimeout", 3000);

        this.netbiosScope = p.getProperty("jcifs.netbios.scope");
        this.netbiosLocalPort = Config.getInt(p, "jcifs.netbios.lport", 0);
        this.netbiosLocalAddress = Config.getInetAddress(p, "jcifs.netbios.laddr", null);

        this.lmhostsFilename = p.getProperty("jcifs.netbios.lmhosts");
        this.winsServer = Config.getInetAddressArray(p, "jcifs.netbios.wins", ",", new InetAddress[0]);

        this.transactionBufferSize = Config.getInt(p, "jcifs.client.transaction_buf_size", 0xFFFF) - 512;
        this.bufferCacheSize = Config.getInt(p, "jcifs.maxBuffers", 16);

        this.smbListSize = Config.getInt(p, "jcifs.client.listSize", 65435);
        this.smbListCount = Config.getInt(p, "jcifs.client.listCount", 200);

        this.smbAttributeExpiration = Config.getLong(p, "jcifs.client.attrExpirationPeriod", 5000L);
        this.ignoreCopyToException = Config.getBoolean(p, "jcifs.client.ignoreCopyToException", false);
        this.broadcastAddress = Config.getInetAddress(p, "jcifs.netbios.baddr", null);

        this.traceResourceUsage = Config.getBoolean(p, "jcifs.traceResources", false);
        this.strictResourceLifecycle = Config.getBoolean(p, "jcifs.client.strictResourceLifecycle", false);

        this.allowGuestFallback = Config.getBoolean(p, "jcifs.client.allowGuestFallback", false);
        this.guestUsername = p.getProperty("jcifs.client.guestUsername", "JCIFSGUEST");
        this.guestPassword = p.getProperty("jcifs.client.guestPassword", "");

        final String minVer = p.getProperty("jcifs.client.minVersion");
        final String maxVer = p.getProperty("jcifs.client.maxVersion");

        if (minVer != null || maxVer != null) {
            initProtocolVersions(minVer, maxVer);
        } else {
            final boolean smb2 = Config.getBoolean(p, "jcifs.client.enableSMB2", true);
            final boolean nosmb1 = Config.getBoolean(p, "jcifs.client.disableSMB1", false);
            initProtocolVersions(nosmb1 ? DialectVersion.SMB202 : null, !smb2 ? DialectVersion.SMB1 : null);
        }

        initResolverOrder(p.getProperty("jcifs.resolveOrder"));
        initDisallowCompound(p.getProperty("jcifs.client.disallowCompound"));
        initDefaults();
    }

}
