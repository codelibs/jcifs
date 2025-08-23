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
package jcifs;

import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.List;
import java.util.TimeZone;

/**
 *
 *
 * Implementors of this interface should extend {@link jcifs.config.BaseConfiguration} or
 * {@link jcifs.config.DelegatingConfiguration} to get forward compatibility.
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
     * Property {@code jcifs.smb.client.dfs.ttl} (int, default 300)
     *
     * @return title to live, in seconds, for DFS cache entries
     */
    long getDfsTtl();

    /**
     *
     * Property {@code jcifs.smb.client.dfs.strictView} (boolean, default false)
     *
     * @return whether a authentication failure during DFS resolving will throw an exception
     */
    boolean isDfsStrictView();

    /**
     *
     * Property {@code jcifs.smb.client.dfs.disabled} (boolean, default false)
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
     * Property {@code jcifs.smb.client.dfs.convertToFQDN} (boolean, default false)
     *
     * @return whether to convert NetBIOS names returned by DFS to FQDNs
     */
    boolean isDfsConvertToFQDN();

    /**
     * Minimum protocol version
     *
     * Property {@code jcifs.smb.client.minVersion} (string, default SMB1)
     *
     * @see DialectVersion
     * @return minimum protocol version to use/allow
     * @since 2.1
     */
    DialectVersion getMinimumVersion();

    /**
     * Maximum protocol version
     *
     * Property {@code jcifs.smb.client.maxVersion} (string, default SMB210)
     *
     * @see DialectVersion
     * @return maximum protocol version to use/allow
     * @since 2.1
     */
    DialectVersion getMaximumVersion();

    /**
     * Use SMB2 non-backward compatible negotiation style
     *
     * Property {@code jcifs.smb.client.useSMB2Negotiation} (boolean, default false)
     *
     * @return whether to use non-backward compatible protocol negotiation
     */
    boolean isUseSMB2OnlyNegotiation();

    /**
     * Enforce secure negotiation
     *
     * Property {@code jcifs.smb.client.requireSecureNegotiate} (boolean, default true)
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
     * Property {@code jcifs.smb.client.port139.enabled} (boolean, default false)
     *
     * @return whether to failover to legacy transport on port 139
     */
    boolean isPort139FailoverEnabled();

    /**
     *
     * Property {@code jcifs.smb.client.useUnicode} (boolean, default true)
     *
     * @return whether to announce support for unicode
     */
    boolean isUseUnicode();

    /**
     *
     * Property {@code jcifs.smb.client.forceUnicode} (boolean, default false)
     *
     * @return whether to use unicode, even if the server does not announce it
     */
    boolean isForceUnicode();

    /**
     *
     * Property {@code jcifs.smb.client.useBatching} (boolean, default false)
     *
     * @return whether to enable support for SMB1 AndX command batching
     */
    boolean isUseBatching();

    /**
     *
     * Property {@code jcifs.smb.client.nativeOs} (string, default {@code os.name})
     *
     * @return OS string to report
     */
    String getNativeOs();

    /**
     *
     * Property {@code jcifs.smb.client.nativeLanMan} (string, default {@code jCIFS})
     *
     * @return Lanman string to report
     */
    String getNativeLanman();

    /**
     *
     * Property {@code jcifs.smb.client.rcv_buf_size} (int, default 65535)
     *
     * @return receive buffer size, in bytes
     * @deprecated use getReceiveBufferSize instead
     */
    @Deprecated
    int getRecieveBufferSize();

    /**
     *
     * Property {@code jcifs.smb.client.rcv_buf_size} (int, default 65535)
     *
     * @return receive buffer size, in bytes
     */
    int getReceiveBufferSize();

    /**
     *
     * Property {@code jcifs.smb.client.snd_buf_size} (int, default 65535)
     *
     * @return send buffer size, in bytes
     */
    int getSendBufferSize();

    /**
     *
     * Property {@code jcifs.smb.client.soTimeout} (int, default 35000)
     *
     * @return socket timeout, in milliseconds
     */
    int getSoTimeout();

    /**
     *
     * Property {@code jcifs.smb.client.connTimeout} (int, default 35000)
     *
     * @return timeout for establishing a socket connection, in milliseconds
     */
    int getConnTimeout();

    /**
     * Property {@code jcifs.smb.client.sessionTimeout} (int, default 35000)
     *
     *
     * @return timeout for SMB sessions, in milliseconds
     */
    int getSessionTimeout();

    /**
     *
     * Property {@code jcifs.smb.client.responseTimeout} (int, default 30000)
     *
     * @return timeout for SMB responses, in milliseconds
     */
    int getResponseTimeout();

    /**
     *
     * Property {@code jcifs.smb.client.lport} (int)
     *
     * @return local port to use for outgoing connections
     */
    int getLocalPort();

    /**
     *
     * Property {@code jcifs.smb.client.laddr} (string)
     *
     * @return local address to use for outgoing connections
     */
    InetAddress getLocalAddr();

    /**
     *
     * Property {@code jcifs.netbios.hostname} (string)
     *
     * @return local NETBIOS/short name to announce
     */
    String getNetbiosHostname();

    /**
     *
     * Property {@code jcifs.smb.client.logonShare}
     *
     * @return share to connect to during authentication, if unset connect to IPC$
     */
    String getLogonShare();

    /**
     *
     *
     * Property {@code jcifs.smb.client.domain}
     *
     * @return default credentials, domain name
     */
    String getDefaultDomain();

    /**
     *
     * Property {@code jcifs.smb.client.username}
     *
     * @return default credentials, user name
     */
    String getDefaultUsername();

    /**
     *
     * Property {@code jcifs.smb.client.password}
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
     * Property {@code jcifs.smb.lmCompatibility} (int, default 3)
     *
     * @return lanman compatibility level, defaults to 3 i.e. NTLMv2 only
     */
    int getLanManCompatibility();

    /**
     *
     * Property {@code jcifs.smb.allowNTLMFallback} (boolean, default true)
     *
     * @return whether to allow fallback from kerberos to NTLM
     */
    boolean isAllowNTLMFallback();

    /**
     * Property {@code jcifs.smb.useRawNTLM} (boolean, default false)
     *
     * @return whether to use raw NTLMSSP tokens instead of SPNEGO wrapped ones
     * @since 2.1
     */
    boolean isUseRawNTLM();

    /**
     *
     * Property {@code jcifs.smb.client.disablePlainTextPasswords} (boolean, default true)
     *
     * @return whether the usage of plaintext passwords is prohibited, defaults to false
     */
    boolean isDisablePlainTextPasswords();

    /**
     *
     *
     * Property {@code jcifs.resolveOrder} (string, default {@code LMHOSTS,DNS,WINS,BCAST})
     *
     * @return order and selection of resolver modules, see {@link ResolverType}
     */
    List<ResolverType> getResolveOrder();

    /**
     *
     * Property {@code jcifs.netbios.baddr} (string, default {@code 255.255.255.255})
     *
     * @return broadcast address to use
     */
    InetAddress getBroadcastAddress();

    /**
     *
     *
     * Property {@code jcifs.netbios.wins} (string, comma separated)
     *
     * @return WINS server to use
     */
    InetAddress[] getWinsServers();

    /**
     *
     * Property {@code jcifs.netbios.lport} (int)
     *
     * @return local bind port for nebios connections
     */
    int getNetbiosLocalPort();

    /**
     *
     * Property {@code jcifs.netbios.laddr} (string)
     *
     * @return local bind address for netbios connections
     */
    InetAddress getNetbiosLocalAddress();

    /**
     *
     *
     * Property {@code jcifs.netbios.soTimeout} (int, default 5000)
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
     * Property {@code jcifs.smb.client.capabilities} (int)
     *
     * @return custom capabilities
     */
    int getCapabilities();

    /**
     *
     *
     * Property {@code jcifs.smb.client.flags2} (int)
     *
     * @return custom flags2
     */
    int getFlags2();

    /**
     *
     * Property {@code jcifs.smb.client.ssnLimit} (int, 250)
     *
     * @return maximum number of sessions on a single connection
     */
    int getSessionLimit();

    /**
     *
     * Property {@code jcifs.encoding} (string, default {@code Cp850})
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
     * Property {@code jcifs.smb.client.maxMpxCount} (int, default 10)
     *
     * @return maximum count of concurrent commands to announce
     */
    int getMaxMpxCount();

    /**
     *
     * Property {@code jcifs.smb.client.signingPreferred} (boolean, default false)
     *
     * @return whether to enable SMB signing (for everything), if available
     */
    boolean isSigningEnabled();

    /**
     *
     * Property {@code jcifs.smb.client.ipcSigningEnforced} (boolean, default true)
     *
     * @return whether to enforce SMB signing for IPC connections
     */
    boolean isIpcSigningEnforced();

    /**
     *
     * Property {@code jcifs.smb.client.signingEnforced} (boolean, default false)
     *
     * @return whether to enforce SMB signing (for everything)
     */
    boolean isSigningEnforced();

    /**
     * Property {@code jcifs.smb.client.encryptionEnabled} (boolean, default false)
     *
     * This is an experimental option allowing to indicate support during protocol
     * negotiation, SMB encryption is not implemented yet.
     *
     * @return whether SMB encryption is enabled
     * @since 2.1
     */
    boolean isEncryptionEnabled();

    /**
     *
     * Property {@code jcifs.smb.client.forceExtendedSecurity} (boolean, default false)
     *
     * @return whether to force extended security usage
     */
    boolean isForceExtendedSecurity();

    /**
     * Property {@code jcifs.smb.client.useLease} (boolean, default true)
     *
     * @return whether to use SMB2/SMB3 leases for caching
     * @since 2.2
     */
    boolean isUseLease();

    /**
     * Property {@code jcifs.smb.client.leaseTimeout} (int, default 30000)
     *
     * @return lease timeout in milliseconds
     * @since 2.2
     */
    int getLeaseTimeout();

    /**
     * Property {@code jcifs.smb.client.maxLeases} (int, default 1000)
     *
     * @return maximum number of concurrent leases
     * @since 2.2
     */
    int getMaxLeases();

    /**
     * Property {@code jcifs.smb.client.leaseVersion} (int, default 2)
     *
     * @return preferred lease version (1 or 2)
     * @since 2.2
     */
    int getLeaseVersion();

    /**
     * Property {@code jcifs.smb.client.leaseBreakTimeout} (int, default 60)
     *
     * @return lease break timeout in seconds (per MS-SMB2 spec)
     * @since 2.2
     */
    int getLeaseBreakTimeout();

    /**
     *
     *
     * Property {@code jcifs.netbios.lmhosts} (string)
     *
     * @return lmhosts file to use
     */
    String getLmHostsFileName();

    /**
     *
     * Property {@code jcifs.netbios.scope} (string)
     *
     * @return default netbios scope to set in requests
     */
    String getNetbiosScope();

    /**
     *
     * Property {@code jcifs.netbios.snd_buf_size} (int, default 576)
     *
     * @return netbios send buffer size
     */
    int getNetbiosSndBufSize();

    /**
     *
     * Property {@code jcifs.netbios.rcv_buf_size} (int, default 576)
     *
     * @return netbios recieve buffer size
     */
    int getNetbiosRcvBufSize();

    /**
     *
     * Property {@code jcifs.netbios.retryTimeout} (int, default 3000)
     *
     * @return timeout of retry requests, in milliseconds
     */
    int getNetbiosRetryTimeout();

    /**
     *
     * Property {@code jcifs.netbios.retryCount} (int, default 2)
     *
     * @return maximum number of retries for netbios requests
     */
    int getNetbiosRetryCount();

    /**
     *
     *
     * Property {@code jcifs.netbios.cachePolicy} in minutes (int, default 600)
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
     *
     * Property {@code jcifs.smb.client.transaction_buf_size} (int, default 65535)
     *
     * @return maximum data size for SMB transactions
     */
    int getTransactionBufferSize();

    /**
     *
     * Property {@code jcifs.smb.maxBuffers} (int, default 16)
     *
     * @return number of buffers to keep in cache
     */
    int getBufferCacheSize();

    /**
     *
     * Property {@code jcifs.smb.client.listCount} (int, default 200)
     *
     * @return maxmimum number of elements to request in a list request
     */
    int getListCount();

    /**
     *
     * Property {@code jcifs.smb.client.listSize} (int, default 65435)
     *
     * @return maximum data size for list/info requests (known overhead is subtracted)
     */
    int getListSize();

    /**
     *
     *
     * Property {@code jcifs.smb.client.attrExpirationPeriod} (int, 5000)
     *
     * @return timeout of file attribute cache
     */
    long getAttributeCacheTimeout();

    /**
     *
     *
     * Property {@code jcifs.smb.client.ignoreCopyToException} (boolean, false)
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
     * Property {@code jcifs.smb.client.notify_buf_size} (int, default 1024)
     *
     * @return the size of the requested server notify buffer
     */
    int getNotifyBufferSize();

    /**
     *
     *
     * Property {@code jcifs.smb.client.maxRequestRetries} (int, default 2)
     *
     * @return retry SMB requests on failure up to n times
     */
    int getMaxRequestRetries();

    /**
     * Property {@code jcifs.smb.client.strictResourceLifecycle} (bool, default false)
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
     * Property {@code jcifs.smb.client.disableSpnegoIntegrity} (boolean, false)
     *
     * @return whether to disable sending/verifying SPNEGO mechanismListMIC
     */
    boolean isDisableSpnegoIntegrity();

    /**
     *
     * Property {@code jcifs.smb.client.enforceSpnegoIntegrity} (boolean, false)
     *
     * @return whether to enforce verifying SPNEGO mechanismListMIC
     */
    boolean isEnforceSpnegoIntegrity();

    /**
     * Property {@code jcifs.smb.client.SendNTLMTargetName} (boolean, true)
     *
     * @return whether to send an AvTargetName with the NTLM exchange
     */
    boolean isSendNTLMTargetName();

    /**
     * Property {@code jcifs.smb.client.guestPassword}, defaults to empty string
     *
     * @return password used when guest authentication is requested
     */
    String getGuestPassword();

    /**
     * Property {@code jcifs.smb.client.guestUsername}, defaults to GUEST
     *
     * @return username used when guest authentication is requested
     */
    String getGuestUsername();

    /**
     * Property {@code jcifs.smb.client.allowGuestFallback}, defaults to false
     *
     * @return whether to permit guest logins when user authentication is requested
     */
    boolean isAllowGuestFallback();

    /**
     * Property {@code jcifs.smb.client.useDurableHandles}, defaults to true
     *
     * @return whether to use durable handles for improved reliability
     */
    boolean isUseDurableHandles();

    /**
     * Property {@code jcifs.smb.client.usePersistentHandles}, defaults to false
     *
     * @return whether to use persistent handles for maximum reliability
     */
    boolean isUsePersistentHandles();

    /**
     * Property {@code jcifs.smb.client.durableHandleTimeout}, defaults to 120000
     *
     * @return timeout for durable handles in milliseconds
     */
    long getDurableHandleTimeout();

    /**
     * Property {@code jcifs.smb.client.handleReconnectRetries}, defaults to 3
     *
     * @return maximum number of retry attempts for handle reconnection
     */
    int getHandleReconnectRetries();

    /**
     * Enable SMB3 Multi-Channel support
     *
     * Property {@code jcifs.smb.client.useMultiChannel} (boolean, default true)
     *
     * @return whether multi-channel is enabled
     */
    boolean isUseMultiChannel();

    /**
     * Maximum number of channels per session
     *
     * Property {@code jcifs.smb.client.maxChannels} (int, default 4)
     *
     * @return maximum channels per session
     */
    int getMaxChannels();

    /**
     * Channel binding policy
     *
     * Property {@code jcifs.smb.client.channelBindingPolicy} (String, default "preferred")
     * Values: "disabled", "preferred", "required"
     *
     * @return channel binding policy
     */
    int getChannelBindingPolicy();

    /**
     * Load balancing strategy for multi-channel
     *
     * Property {@code jcifs.smb.client.loadBalancingStrategy} (String, default "adaptive")
     * Values: "round_robin", "least_loaded", "weighted_random", "affinity_based", "adaptive"
     *
     * @return load balancing strategy
     */
    String getLoadBalancingStrategy();

    /**
     * Channel health check interval in seconds
     *
     * Property {@code jcifs.smb.client.channelHealthCheckInterval} (int, default 10)
     *
     * @return health check interval in seconds
     */
    int getChannelHealthCheckInterval();

    /**
     * Property {@code jcifs.smb.client.handleStateDirectory}
     *
     * @return directory to store persistent handle state
     */
    String getHandleStateDirectory();

    /**
     * Property {@code jcifs.smb.client.useDirectoryLeasing} (boolean, default true)
     *
     * @return whether to use directory leasing for caching
     */
    boolean isUseDirectoryLeasing();

    /**
     * Property {@code jcifs.smb.client.directoryCacheScope} (String, default "IMMEDIATE_CHILDREN")
     *
     * @return directory cache scope (IMMEDIATE_CHILDREN, RECURSIVE_TREE, METADATA_ONLY, FULL_ENUMERATION)
     */
    String getDirectoryCacheScope();

    /**
     * Property {@code jcifs.smb.client.directoryCacheTimeout} (long, default 30000)
     *
     * @return directory cache timeout in milliseconds
     */
    long getDirectoryCacheTimeout();

    /**
     * Property {@code jcifs.smb.client.directoryNotificationsEnabled} (boolean, default true)
     *
     * @return whether directory change notifications are enabled
     */
    boolean isDirectoryNotificationsEnabled();

    /**
     * Property {@code jcifs.smb.client.maxDirectoryCacheEntries} (int, default 1000)
     *
     * @return maximum number of directory cache entries
     */
    int getMaxDirectoryCacheEntries();

    /**
     * Get whether RDMA (SMB Direct) should be used
     *
     * @return true if RDMA should be used, false otherwise
     */
    boolean isUseRDMA();

    /**
     * Get RDMA provider preference
     *
     * @return RDMA provider name ("auto", "disni", "tcp", etc.)
     */
    String getRdmaProvider();

    /**
     * Get RDMA read/write threshold
     *
     * Operations larger than this size will use RDMA read/write
     * instead of send/receive.
     *
     * @return threshold in bytes
     */
    int getRdmaReadWriteThreshold();

    /**
     * Get maximum RDMA send size
     *
     * @return max send size in bytes
     */
    int getRdmaMaxSendSize();

    /**
     * Get maximum RDMA receive size
     *
     * @return max receive size in bytes
     */
    int getRdmaMaxReceiveSize();

    /**
     * Get RDMA credits
     *
     * Number of receive credits to advertise to the server.
     *
     * @return number of credits
     */
    int getRdmaCredits();

    /**
     * Get whether RDMA is enabled
     *
     * @return true if RDMA is enabled, false otherwise
     */
    boolean isRdmaEnabled();

    /**
     * Get RDMA port number
     *
     * @return RDMA port number (default 5445)
     */
    int getRdmaPort();
}
