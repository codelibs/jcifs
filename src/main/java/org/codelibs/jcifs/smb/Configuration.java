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
package org.codelibs.jcifs.smb;

import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.List;
import java.util.TimeZone;

/**
 *
 *
 * Implementors of this interface should extend {@link org.codelibs.jcifs.smb.config.BaseConfiguration} or
 * {@link org.codelibs.jcifs.smb.config.DelegatingConfiguration} to get forward compatibility.
 *
 * @author mbechler
 *
 */
public interface Configuration {

    /**
     * Gets the secure random number generator for cryptographic operations
     *
     * @return random source to use
     */
    SecureRandom getRandom();

    /**
     *
     *
     * Property {@code jcifs.client.dfs.ttl} (int, default 300)
     *
     * @return title to live, in seconds, for DFS cache entries
     */
    long getDfsTtl();

    /**
     *
     * Property {@code jcifs.client.dfs.strictView} (boolean, default false)
     *
     * @return whether a authentication failure during DFS resolving will throw an exception
     */
    boolean isDfsStrictView();

    /**
     *
     * Property {@code jcifs.client.dfs.disabled} (boolean, default false)
     *
     * @return whether DFS lookup is disabled
     */
    boolean isDfsDisabled();

    /**
     * Enable hack to make kerberos auth work with DFS sending short names
     *
     * This works by appending the domain name to the netbios short name and will fail horribly if this mapping is not
     * correct for your domain.
     *
     * Property {@code jcifs.client.dfs.convertToFQDN} (boolean, default false)
     *
     * @return whether to convert NetBIOS names returned by DFS to FQDNs
     */
    boolean isDfsConvertToFQDN();

    /**
     * Whether to preserve share name case
     *
     * When true, preserve the original case of share names instead of converting to uppercase.
     * This is required for DFS namespaces with case-sensitive link names.
     *
     * Property {@code jcifs.client.preserveShareCase} (boolean, default false)
     *
     * The 3.0.1 spelling {@code jcifs.smb.client.preserveShareCase} is still honoured
     * but deprecated.
     *
     * @return whether to preserve share name case
     */
    boolean isPreserveShareCase();

    /**
     * Minimum protocol version
     *
     * Property {@code jcifs.client.minVersion} (string, default SMB1)
     *
     * @see DialectVersion
     * @return minimum protocol version to use/allow
     * @since 2.1
     */
    DialectVersion getMinimumVersion();

    /**
     * Maximum protocol version
     *
     * Property {@code jcifs.client.maxVersion} (string, default SMB210)
     *
     * @see DialectVersion
     * @return maximum protocol version to use/allow
     * @since 2.1
     */
    DialectVersion getMaximumVersion();

    /**
     * Use SMB2 non-backward compatible negotiation style
     *
     * Property {@code jcifs.client.useSMB2Negotiation} (boolean, default false)
     *
     * @return whether to use non-backward compatible protocol negotiation
     */
    boolean isUseSMB2OnlyNegotiation();

    /**
     * Enforce secure negotiation
     *
     * Property {@code jcifs.client.requireSecureNegotiate} (boolean, default true)
     *
     * This does not provide any actual downgrade protection if SMB1 is allowed.
     *
     * It will also break connections with SMB2 servers that do not properly sign error responses.
     *
     * @return whether to enforce the use of secure negotiation.
     */
    boolean isRequireSecureNegotiate();

    /**
     * Enable port 139 failover
     *
     * Property {@code jcifs.client.port139.enabled} (boolean, default false)
     *
     * @return whether to failover to legacy transport on port 139
     */
    boolean isPort139FailoverEnabled();

    /**
     *
     * Property {@code jcifs.client.useUnicode} (boolean, default true)
     *
     * @return whether to announce support for unicode
     */
    boolean isUseUnicode();

    /**
     *
     * Property {@code jcifs.client.forceUnicode} (boolean, default false)
     *
     * @return whether to use unicode, even if the server does not announce it
     */
    boolean isForceUnicode();

    /**
     *
     * Property {@code jcifs.client.useBatching} (boolean, default false)
     *
     * @return whether to enable support for SMB1 AndX command batching
     */
    boolean isUseBatching();

    /**
     *
     * Property {@code jcifs.client.nativeOs} (string, default {@code os.name})
     *
     * @return OS string to report
     */
    String getNativeOs();

    /**
     *
     * Property {@code jcifs.client.nativeLanMan} (string, default {@code jCIFS})
     *
     * @return Lanman string to report
     */
    String getNativeLanman();

    /**
     *
     * Property {@code jcifs.client.rcv_buf_size} (int, default 65535)
     *
     * @return receive buffer size, in bytes
     * @deprecated use getReceiveBufferSize instead
     */
    @Deprecated
    int getRecieveBufferSize();

    /**
     *
     * Property {@code jcifs.client.rcv_buf_size} (int, default 65535)
     *
     * @return receive buffer size, in bytes
     */
    int getReceiveBufferSize();

    /**
     *
     * Property {@code jcifs.client.snd_buf_size} (int, default 65535)
     *
     * @return send buffer size, in bytes
     */
    int getSendBufferSize();

    /**
     *
     * Property {@code jcifs.client.soTimeout} (int, default 35000)
     *
     * @return socket timeout, in milliseconds
     */
    int getSoTimeout();

    /**
     *
     * Property {@code jcifs.client.connTimeout} (int, default 35000)
     *
     * @return timeout for establishing a socket connection, in milliseconds
     */
    int getConnTimeout();

    /**
     * Property {@code jcifs.client.sessionTimeout} (int, default 35000)
     *
     *
     * @return timeout for SMB sessions, in milliseconds
     */
    int getSessionTimeout();

    /**
     *
     * Property {@code jcifs.client.responseTimeout} (int, default 30000)
     *
     * @return timeout for SMB responses, in milliseconds
     */
    int getResponseTimeout();

    /**
     *
     * Property {@code jcifs.client.lport} (int)
     *
     * @return local port to use for outgoing connections
     */
    int getLocalPort();

    /**
     *
     * Property {@code jcifs.client.laddr} (string)
     *
     * @return local address to use for outgoing connections
     */
    InetAddress getLocalAddr();

    /**
     *
     * Property {@code org.codelibs.jcifs.smb.netbios.hostname} (string)
     *
     * @return local NETBIOS/short name to announce
     */
    String getNetbiosHostname();

    /**
     *
     * Property {@code jcifs.client.logonShare}
     *
     * @return share to connect to during authentication, if unset connect to IPC$
     */
    String getLogonShare();

    /**
     *
     *
     * Property {@code jcifs.client.domain}
     *
     * @return default credentials, domain name
     */
    String getDefaultDomain();

    /**
     *
     * Property {@code jcifs.client.username}
     *
     * @return default credentials, user name
     */
    String getDefaultUsername();

    /**
     *
     * Property {@code jcifs.client.password}
     *
     * @return default credentials, password
     */
    String getDefaultPassword();

    /**
     * Lanman compatibility level
     *
     * <a href="https://technet.microsoft.com/en-us/library/cc960646.aspx">Microsoft TechNet Documentation</a>
     *
     *
     * <table>
     * <caption>LM Compatibility Levels</caption>
     * <tr>
     * <td>0 or 1</td>
     * <td>LM and NTLM</td>
     * </tr>
     * <tr>
     * <td>2</td>
     * <td>NTLM only</td>
     * </tr>
     * <tr>
     * <td>3-5</td>
     * <td>NTLMv2 only</td>
     * </tr>
     * </table>
     *
     *
     * Property {@code jcifs.lmCompatibility} (int, default 3)
     *
     * @return lanman compatibility level, defaults to 3 i.e. NTLMv2 only
     */
    int getLanManCompatibility();

    /**
     *
     * Property {@code jcifs.allowNTLMFallback} (boolean, default true)
     *
     * @return whether to allow fallback from kerberos to NTLM
     */
    boolean isAllowNTLMFallback();

    /**
     * Property {@code jcifs.useRawNTLM} (boolean, default false)
     *
     * @return whether to use raw NTLMSSP tokens instead of SPNEGO wrapped ones
     * @since 2.1
     */
    boolean isUseRawNTLM();

    /**
     *
     * Property {@code jcifs.client.disablePlainTextPasswords} (boolean, default true)
     *
     * @return whether the usage of plaintext passwords is prohibited, defaults to false
     */
    boolean isDisablePlainTextPasswords();

    /**
     *
     *
     * Property {@code org.codelibs.jcifs.smb.resolveOrder} (string, default {@code LMHOSTS,DNS,WINS,BCAST})
     *
     * @return order and selection of resolver modules, see {@link ResolverType}
     */
    List<ResolverType> getResolveOrder();

    /**
     *
     * Property {@code org.codelibs.jcifs.smb.netbios.baddr} (string, default {@code 255.255.255.255})
     *
     * @return broadcast address to use
     */
    InetAddress getBroadcastAddress();

    /**
     *
     *
     * Property {@code org.codelibs.jcifs.smb.netbios.wins} (string, comma separated)
     *
     * @return WINS server to use
     */
    InetAddress[] getWinsServers();

    /**
     *
     * Property {@code org.codelibs.jcifs.smb.netbios.lport} (int)
     *
     * @return local bind port for nebios connections
     */
    int getNetbiosLocalPort();

    /**
     *
     * Property {@code org.codelibs.jcifs.smb.netbios.laddr} (string)
     *
     * @return local bind address for netbios connections
     */
    InetAddress getNetbiosLocalAddress();

    /**
     *
     *
     * Property {@code org.codelibs.jcifs.smb.netbios.soTimeout} (int, default 5000)
     *
     * @return socket timeout for netbios connections, in milliseconds
     */
    int getNetbiosSoTimeout();

    /**
     * Gets the virtual circuit number for SMB connections
     *
     * @return virtual circuit number to use
     */
    int getVcNumber();

    /**
     *
     * Property {@code jcifs.client.capabilities} (int)
     *
     * @return custom capabilities
     */
    int getCapabilities();

    /**
     *
     *
     * Property {@code jcifs.client.flags2} (int)
     *
     * @return custom flags2
     */
    int getFlags2();

    /**
     *
     * Property {@code jcifs.client.ssnLimit} (int, 250)
     *
     * @return maximum number of sessions on a single connection
     */
    int getSessionLimit();

    /**
     *
     * Property {@code org.codelibs.jcifs.smb.encoding} (string, default {@code Cp850})
     *
     * @return OEM encoding to use
     */
    String getOemEncoding();

    /**
     * Gets the local timezone for time-related operations
     *
     * @return local timezone
     */
    TimeZone getLocalTimezone();

    /**
     * Gets the process ID to use in SMB messages
     *
     * @return Process id to send, randomized if unset
     */
    int getPid();

    /**
     *
     * Property {@code jcifs.client.maxMpxCount} (int, default 10)
     *
     * @return maximum count of concurrent commands to announce
     */
    int getMaxMpxCount();

    /**
     *
     * Property {@code jcifs.client.signingPreferred} (boolean, default false)
     *
     * @return whether to enable SMB signing (for everything), if available
     */
    boolean isSigningEnabled();

    /**
     *
     * Property {@code jcifs.client.ipcSigningEnforced} (boolean, default true)
     *
     * @return whether to enforce SMB signing for IPC connections
     */
    boolean isIpcSigningEnforced();

    /**
     *
     * Property {@code jcifs.client.signingEnforced} (boolean, default false)
     *
     * @return whether to enforce SMB signing (for everything)
     */
    boolean isSigningEnforced();

    /**
     * Property {@code jcifs.client.encryptionEnabled} (boolean, default false)
     *
     * Enables SMB3 encryption. When enabled the client advertises the ciphers given by
     * {@link #getEncryptionCiphers()} during protocol negotiation and encrypts traffic on any session or share for
     * which the server requires it.
     *
     * @return whether SMB encryption is enabled
     * @since 2.1
     */
    boolean isEncryptionEnabled();

    /**
     * Property {@code jcifs.client.encryptionCiphers} (comma-separated, default
     * {@code AES-128-GCM, AES-128-CCM, AES-256-GCM, AES-256-CCM})
     *
     * The SMB 3.1.1 encryption ciphers to offer, in order of preference. Recognised names are
     * {@code AES-128-CCM}, {@code AES-128-GCM}, {@code AES-256-CCM} and {@code AES-256-GCM}; an unrecognised name
     * is an error rather than being ignored. Only consulted when {@link #isEncryptionEnabled()} is set, and only
     * on SMB 3.1.1, which is the only dialect that negotiates a cipher in a negotiate context - SMB 3.0 and 3.0.2
     * always use AES-128-CCM.
     *
     * <p>
     * Note that this states a preference rather than a requirement. The server picks one cipher from the offered
     * list and is free to apply its own order of preference when doing so, so listing AES-256 first does not
     * guarantee AES-256 is what gets negotiated. Offering only the AES-256 ciphers does require them, at the cost
     * of failing against a server that does not implement them.
     * </p>
     *
     * @return the encryption cipher identifiers to offer, in preference order
     */
    int[] getEncryptionCiphers();

    /**
     * Property {@code jcifs.client.signingAlgorithms} (comma-separated, default
     * {@code AES-CMAC, AES-GMAC, HMAC-SHA256})
     *
     * The SMB 3.1.1 signing algorithms to offer, in order of preference. Recognised names are
     * {@code HMAC-SHA256}, {@code AES-CMAC} and {@code AES-GMAC}; an unrecognised name is an error rather than
     * being ignored. Only consulted on SMB 3.1.1, which is the only dialect that negotiates a signing algorithm
     * in a negotiate context - SMB 3.0 and 3.0.2 always sign with AES-128-CMAC and SMB 2.x with HMAC-SHA256.
     *
     * <p>
     * As with the encryption ciphers, this states a preference rather than a requirement: the server picks one
     * algorithm from the offered list and may apply its own order when doing so. The default leads with AES-CMAC,
     * which is what the client has always used, so the algorithm negotiated against a given server does not
     * change unless this property does.
     * </p>
     *
     * @return the signing algorithm identifiers to offer, in preference order
     */
    int[] getSigningAlgorithms();

    /**
     *
     * Property {@code jcifs.client.forceExtendedSecurity} (boolean, default false)
     *
     * @return whether to force extended security usage
     */
    boolean isForceExtendedSecurity();

    /**
     *
     *
     * Property {@code org.codelibs.jcifs.smb.netbios.lmhosts} (string)
     *
     * @return lmhosts file to use
     */
    String getLmHostsFileName();

    /**
     *
     * Property {@code org.codelibs.jcifs.smb.netbios.scope} (string)
     *
     * @return default netbios scope to set in requests
     */
    String getNetbiosScope();

    /**
     *
     * Property {@code org.codelibs.jcifs.smb.netbios.snd_buf_size} (int, default 576)
     *
     * @return netbios send buffer size
     */
    int getNetbiosSndBufSize();

    /**
     *
     * Property {@code org.codelibs.jcifs.smb.netbios.rcv_buf_size} (int, default 576)
     *
     * @return netbios recieve buffer size
     */
    int getNetbiosRcvBufSize();

    /**
     *
     * Property {@code org.codelibs.jcifs.smb.netbios.retryTimeout} (int, default 3000)
     *
     * @return timeout of retry requests, in milliseconds
     */
    int getNetbiosRetryTimeout();

    /**
     *
     * Property {@code org.codelibs.jcifs.smb.netbios.retryCount} (int, default 2)
     *
     * @return maximum number of retries for netbios requests
     */
    int getNetbiosRetryCount();

    /**
     *
     *
     * Property {@code org.codelibs.jcifs.smb.netbios.cachePolicy} in minutes (int, default 600)
     *
     * @return netbios cache timeout, in seconds, 0 - disable caching, -1 - cache forever
     */
    int getNetbiosCachePolicy();

    /**
     * Gets the maximum buffer size for IO operations
     *
     * @return the maximum size of IO buffers, limits the maximum message size
     */
    int getMaximumBufferSize();

    /**
     * The largest payload a single SMB2 read or write may carry.
     *
     * <p>
     * Property {@code jcifs.client.maxTransferSize} (int, default 1048576). The negotiated size is the smaller of
     * this and what the server offers. Anything above 64 KiB needs multi-credit, which the client only gets on
     * SMB 2.1 and later; below that the server's own offer keeps the transfer at 64 KiB regardless of this value.
     * This governs SMB2 only - {@code jcifs.client.rcv_buf_size} and {@code jcifs.client.snd_buf_size} still govern
     * SMB1, whose receive path cannot carry more than 64 KiB.
     * </p>
     *
     * @return maximum size of a single SMB2 read or write, in bytes
     */
    int getMaximumTransferSize();

    /**
     *
     * Property {@code jcifs.client.transaction_buf_size} (int, default 65535)
     *
     * @return maximum data size for SMB transactions
     */
    int getTransactionBufferSize();

    /**
     *
     * Property {@code jcifs.maxBuffers} (int, default 16)
     *
     * @return number of buffers to keep in cache
     */
    int getBufferCacheSize();

    /**
     *
     * Property {@code jcifs.client.listCount} (int, default 200)
     *
     * @return maxmimum number of elements to request in a list request
     */
    int getListCount();

    /**
     *
     * Property {@code jcifs.client.listSize} (int, default 65435)
     *
     * @return maximum data size for list/info requests (known overhead is subtracted)
     */
    int getListSize();

    /**
     *
     *
     * Property {@code jcifs.client.attrExpirationPeriod} (int, 5000)
     *
     * @return timeout of file attribute cache
     */
    long getAttributeCacheTimeout();

    /**
     *
     *
     * Property {@code jcifs.client.ignoreCopyToException} (boolean, false)
     *
     * @return whether to ignore exceptions that occur during file copy
     */
    boolean isIgnoreCopyToException();

    /**
     * Gets the batch limit for a specific SMB command
     *
     * @param cmd the SMB command name
     * @return the batch limit for the given command
     */
    int getBatchLimit(String cmd);

    /**
     *
     * Property {@code jcifs.client.notify_buf_size} (int, default 1024)
     *
     * @return the size of the requested server notify buffer
     */
    int getNotifyBufferSize();

    /**
     *
     *
     * Property {@code jcifs.client.maxRequestRetries} (int, default 2)
     *
     * @return retry SMB requests on failure up to n times
     */
    int getMaxRequestRetries();

    /**
     * Property {@code jcifs.client.strictResourceLifecycle} (bool, default false)
     *
     * If enabled, SmbFile instances starting with their first use will hold a reference to their tree.
     * This means that trees/sessions/connections won't be idle-disconnected even if there are no other active
     * references (currently executing code, file descriptors).
     *
     * Depending on the usage scenario, this may have some benefit as there won't be any delays for restablishing these
     * resources, however comes at the cost of having to properly release all SmbFile instances you no longer need.
     *
     * @return whether to use strict resource lifecycle
     */
    boolean isStrictResourceLifecycle();

    /**
     * This is solely intended for debugging
     *
     * @return whether to track the locations from which resources were created
     */
    boolean isTraceResourceUsage();

    /**
     * Checks if compound requests are allowed for the specified command
     *
     * @param command the SMB command to check
     * @return whether to allow creating compound requests with that command
     */
    boolean isAllowCompound(String command);

    /**
     * Machine identifier
     *
     * ClientGuid, ... are derived from this value.
     *
     * Normally this should be randomly assigned for each client instance/configuration.
     *
     * @return machine identifier (32 byte)
     */
    byte[] getMachineId();

    /**
     *
     *
     * Property {@code jcifs.client.disableSpnegoIntegrity} (boolean, false)
     *
     * @return whether to disable sending/verifying SPNEGO mechanismListMIC
     */
    boolean isDisableSpnegoIntegrity();

    /**
     *
     * Property {@code jcifs.client.enforceSpnegoIntegrity} (boolean, false)
     *
     * @return whether to enforce verifying SPNEGO mechanismListMIC
     */
    boolean isEnforceSpnegoIntegrity();

    /**
     * Property {@code jcifs.client.SendNTLMTargetName} (boolean, true)
     *
     * @return whether to send an AvTargetName with the NTLM exchange
     */
    boolean isSendNTLMTargetName();

    /**
     * Property {@code jcifs.client.guestPassword}, defaults to empty string
     *
     * @return password used when guest authentication is requested
     */
    String getGuestPassword();

    /**
     * Property {@code jcifs.client.guestUsername}, defaults to GUEST
     *
     * @return username used when guest authentication is requested
     */
    String getGuestUsername();

    /**
     * Property {@code jcifs.client.allowGuestFallback}, defaults to false
     *
     * @return whether to permit guest logins when user authentication is requested
     */
    boolean isAllowGuestFallback();
}
