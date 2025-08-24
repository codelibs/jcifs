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
package jcifs.config;

import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TimeZone;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.DialectVersion;
import jcifs.ResolverType;
import jcifs.SmbConstants;

/**
 * Base implementation of CIFS configuration providing default settings and behavior.
 * Serves as the foundation for configuration implementations in the jCIFS library.
 *
 * @author mbechler
 */
public class BaseConfiguration implements Configuration {

    private static final Logger log = LoggerFactory.getLogger(BaseConfiguration.class);
    private static final Map<String, Integer> DEFAULT_BATCH_LIMITS = new HashMap<>();

    static {
        DEFAULT_BATCH_LIMITS.put("TreeConnectAndX.QueryInformation", 0);
    }

    private final Map<String, Integer> batchLimits = new HashMap<>();

    /** Local process ID for SMB messages */
    protected int localPid = -1;
    /** Local timezone for time calculations */
    protected TimeZone localTimeZone;
    /** Secure random generator for cryptographic operations */
    protected SecureRandom random;
    /** Whether to use command batching for improved performance */
    protected boolean useBatching = false;
    /** Whether to use Unicode encoding for strings */
    protected boolean useUnicode = true;
    /** Force use of Unicode encoding regardless of negotiation */
    protected boolean forceUnicode = false;
    /** Whether SMB signing is preferred but not required */
    protected boolean signingPreferred = false;
    /** Whether SMB signing is enforced (required) */
    protected boolean signingEnforced = false;
    /** Whether to enforce signing for IPC connections */
    protected boolean ipcSigningEnforced = true;
    /** Whether SMB3 encryption is enabled */
    protected boolean encryptionEnabled = false;
    /** Whether to use SMB2/SMB3 leases for caching */
    protected boolean useLease = true;
    /** Lease timeout in milliseconds */
    protected int leaseTimeout = 30000;
    /** Maximum number of concurrent leases */
    protected int maxLeases = 1000;
    /** Preferred lease version (1 or 2) */
    protected int leaseVersion = 2;
    /** Lease break timeout in seconds (per MS-SMB2 spec) */
    protected int leaseBreakTimeout = 60;
    /** Whether to use NT status codes instead of DOS error codes */
    protected boolean useNtStatus = true;
    /** Whether to use extended security negotiation */
    protected boolean useExtendedSecurity = true;
    /** Force use of extended security negotiation */
    protected boolean forceExtendedSecurity = false;
    /** Whether to negotiate only SMB2 or higher protocols */
    protected boolean smb2OnlyNegotiation = false;
    /** Whether to failover to port 139 if port 445 fails */
    protected boolean port139FailoverEnabled = false;
    /** Whether to use NT SMB operations */
    protected boolean useNTSmbs = true;
    /** Whether to use large read/write operations for better performance */
    protected boolean useLargeReadWrite = true;
    /** LAN Manager compatibility level for authentication */
    protected int lanmanCompatibility = 3;
    /** Whether to allow fallback to NTLM authentication */
    protected boolean allowNTLMFallback = true;
    /** Whether to use raw NTLM authentication without SPNEGO */
    protected boolean useRawNTLM = false;
    /** Whether to disable SPNEGO integrity checking */
    protected boolean disableSpnegoIntegrity = false;
    /** Whether to enforce SPNEGO integrity checking */
    protected boolean enforceSpnegoIntegrity = true;
    /** Whether plain text passwords are disabled */
    protected boolean disablePlainTextPasswords = true;
    /** OEM encoding for non-Unicode operations */
    protected String oemEncoding = SmbConstants.DEFAULT_OEM_ENCODING;
    /** SMB flags2 field value */
    protected int flags2 = 0;
    /** SMB client capabilities */
    protected int capabilities = 0;
    /** Maximum number of concurrent SMB sessions */
    protected int sessionLimit = SmbConstants.DEFAULT_SSN_LIMIT;
    /** Whether to disable Nagle's algorithm for TCP connections */
    protected boolean smbTcpNoDelay = false;
    /** Response timeout in milliseconds for SMB operations */
    protected int smbResponseTimeout = SmbConstants.DEFAULT_RESPONSE_TIMEOUT;
    /** Socket timeout in milliseconds for SMB connections */
    protected int smbSocketTimeout = SmbConstants.DEFAULT_SO_TIMEOUT;
    /** Connection timeout in milliseconds for establishing SMB connections */
    protected int smbConnectionTimeout = SmbConstants.DEFAULT_CONN_TIMEOUT;
    /** Session timeout in milliseconds for SMB sessions */
    protected int smbSessionTimeout = SmbConstants.DEFAULT_SO_TIMEOUT;
    /** Whether idle timeout is disabled for connections */
    protected boolean idleTimeoutDisabled = false;
    /** Local address to bind for SMB connections */
    protected InetAddress smbLocalAddress;
    /** Local port to bind for SMB connections */
    protected int smbLocalPort = 0;
    /** Maximum multiplex count for concurrent requests */
    protected int maxMpxCount = SmbConstants.DEFAULT_MAX_MPX_COUNT;
    /** Send buffer size for SMB socket operations */
    protected int smbSendBufferSize = SmbConstants.DEFAULT_SND_BUF_SIZE;
    /** Receive buffer size for SMB socket operations */
    protected int smbRecvBufferSize = SmbConstants.DEFAULT_RCV_BUF_SIZE;
    /** Buffer size for SMB notification operations */
    protected int smbNotifyBufferSize = SmbConstants.DEFAULT_NOTIFY_BUF_SIZE;
    /** Native operating system name to report */
    protected String nativeOs;
    /** Native LAN Manager string to report */
    protected String nativeLanMan = "jCIFS";
    /** Virtual circuit number for SMB sessions */
    protected int vcNumber = 1;
    /** Whether DFS support is disabled */
    protected boolean dfsDisabled = false;
    /** DFS cache time-to-live in seconds */
    protected long dfsTTL = 300;
    /** Whether to use strict DFS path resolution */
    protected boolean dfsStrictView = false;
    /** Whether to convert DFS paths to FQDN */
    protected boolean dfsConvertToFqdn;
    /** Default logon share */
    protected String logonShare;
    /** Default domain for authentication */
    protected String defaultDomain;
    /** Default username for authentication */
    protected String defaultUserName;
    /** Default password for authentication */
    protected String defaultPassword;
    /** NetBIOS hostname */
    protected String netbiosHostname;
    /** NetBIOS name cache policy in seconds */
    protected int netbiosCachePolicy = 60 * 60 * 10;
    /** NetBIOS socket timeout in milliseconds */
    protected int netbiosSocketTimeout = 5000;
    /** NetBIOS send buffer size */
    protected int netbiosSendBufferSize = 576;
    /** NetBIOS receive buffer size */
    protected int netbiosRevcBufferSize = 576;
    /** NetBIOS retry count */
    protected int netbiosRetryCount = 2;
    /** NetBIOS retry timeout in milliseconds */
    protected int netbiosRetryTimeout = 3000;
    /** NetBIOS scope identifier */
    protected String netbiosScope;
    /** Local port for NetBIOS communications */
    protected int netbiosLocalPort = 0;
    /** Local address for NetBIOS communications */
    protected InetAddress netbiosLocalAddress;
    /** Path to lmhosts file for NetBIOS name resolution */
    protected String lmhostsFilename;
    /** Array of WINS server addresses for NetBIOS name resolution */
    protected InetAddress[] winsServer = {};
    /** Broadcast address for NetBIOS name resolution */
    protected InetAddress broadcastAddress;
    /** Order of name resolution methods to use */
    protected List<ResolverType> resolverOrder;
    /** Maximum buffer size for IO operations */
    protected int maximumBufferSize = 0x10000;
    /** Maximum buffer size for SMB transaction operations */
    protected int transactionBufferSize = 0xFFFF - 512;
    /** Number of buffers to keep in cache */
    protected int bufferCacheSize = 16;
    /** Maximum size for list operations */
    protected int smbListSize = 65435;
    /** Maximum number of entries to return in list operations */
    protected int smbListCount = 200;
    /** Time in milliseconds before cached file attributes expire */
    protected long smbAttributeExpiration = 5000L;
    /** Whether to ignore exceptions during file copy operations */
    protected boolean ignoreCopyToException = false;
    /** Maximum number of request retries on failure */
    protected int maxRequestRetries = 2;
    /** Whether to trace resource usage for debugging */
    protected boolean traceResourceUsage;
    /** Whether to enforce strict resource lifecycle management */
    protected boolean strictResourceLifecycle;
    /** Set of commands that should not be used in compound requests */
    protected Set<String> disallowCompound;
    /** Minimum SMB dialect version to negotiate */
    protected DialectVersion minVersion;
    /** Maximum SMB dialect version to negotiate */
    protected DialectVersion maxVersion;
    /** Whether to require secure negotiate validation */
    protected boolean requireSecureNegotiate = true;
    /** Whether to send NTLM target name during authentication */
    protected boolean sendNTLMTargetName = true;
    private byte[] machineId;
    /** Username for guest authentication */
    protected String guestUsername = "GUEST";
    /** Password for guest authentication */
    protected String guestPassword = "";
    /** Whether to allow fallback to guest authentication */
    protected boolean allowGuestFallback = false;
    /** Whether to use durable handles for improved reliability */
    protected boolean useDurableHandles = true;
    /** Whether to use persistent handles for maximum reliability */
    protected boolean usePersistentHandles = false;
    /** Timeout for durable handles in milliseconds */
    protected long durableHandleTimeout = 120000; // 2 minutes
    /** Maximum number of retry attempts for handle reconnection */
    protected int handleReconnectRetries = 3;
    /** Directory to store persistent handle state */
    protected String handleStateDirectory;

    // Directory leasing configuration fields
    /**
     * Whether to use directory leasing for cached directory listings
     */
    protected boolean useDirectoryLeasing = true;
    /**
     * The scope of directory caching: ALL (entire subtree) or IMMEDIATE_CHILDREN (direct children only)
     */
    protected String directoryCacheScope = "IMMEDIATE_CHILDREN";
    /**
     * Directory cache timeout in milliseconds
     */
    protected long directoryCacheTimeout = 30000L;
    /**
     * Whether directory change notifications are enabled for cache invalidation
     */
    protected boolean directoryNotificationsEnabled = true;
    /**
     * Maximum number of cached directory entries
     */
    protected int maxDirectoryCacheEntries = 1000;

    // Multi-channel configuration fields
    /**
     * Whether to use SMB3 multi-channel support for improved performance and redundancy
     */
    protected boolean useMultiChannel;
    /**
     * Maximum number of SMB3 channels to establish per session
     */
    protected int maxChannels;
    /**
     * Channel binding policy: -1=not set, 0=disabled, 1=preferred, 2=required
     */
    protected int channelBindingPolicy = -1; // -1=not set, 0=disabled, 1=preferred, 2=required
    /**
     * Load balancing strategy for distributing operations across channels
     */
    protected String loadBalancingStrategy;
    /**
     * Interval in milliseconds for checking channel health
     */
    protected int channelHealthCheckInterval;

    // RDMA configuration
    /**
     * Flag indicating whether RDMA transport should be used when available
     */
    protected boolean useRDMA;
    /**
     * RDMA provider implementation to use (e.g. "disni" or "tcp")
     */
    protected String rdmaProvider;
    /**
     * Minimum size in bytes for using RDMA read/write operations
     */
    protected int rdmaReadWriteThreshold;
    /**
     * Maximum size in bytes for RDMA send operations
     */
    protected int rdmaMaxSendSize;
    /**
     * Maximum size in bytes for RDMA receive operations
     */
    protected int rdmaMaxReceiveSize;
    /**
     * Number of RDMA credits to request during negotiation
     */
    protected int rdmaCredits;
    /**
     * Flag indicating whether RDMA is currently enabled and available
     */
    protected boolean rdmaEnabled = false;
    /**
     * Port number for RDMA connections (default: 5445)
     */
    protected int rdmaPort = 5445;
    // Witness protocol configuration fields
    /**
     * Flag indicating whether SMB Witness protocol should be used for failover
     */
    protected boolean useWitness = false; // Disabled by default
    /**
     * Timeout in milliseconds for witness heartbeat messages
     */
    protected long witnessHeartbeatTimeout = 120000; // 2 minutes
    /**
     * Timeout in milliseconds for witness registration
     */
    protected long witnessRegistrationTimeout = 300000; // 5 minutes
    /**
     * Delay in milliseconds before attempting witness reconnection
     */
    protected long witnessReconnectDelay = 1000; // 1 second
    /**
     * Flag indicating whether automatic witness service discovery is enabled
     */
    protected boolean witnessServiceDiscovery = true;

    // SMB3 Lease support
    protected boolean useLeases = true;

    // SMB3 Persistent handle support
    protected long persistentHandleTimeout = 120000; // 2 minutes default

    /**
     * Constructs a BaseConfiguration with default settings
     *
     * @throws CIFSException if configuration initialization fails
     */
    protected BaseConfiguration() throws CIFSException {
        this(false);
    }

    /**
     * Constructs a BaseConfiguration with optional default initialization
     *
     * @param initDefaults
     *            whether to initialize defaults based on other settings
     * @throws CIFSException if configuration initialization fails
     */
    public BaseConfiguration(final boolean initDefaults) throws CIFSException {
        if (initDefaults) {
            this.initDefaults();
        }
    }

    @Override
    public SecureRandom getRandom() {
        return this.random;
    }

    @Override
    public String getNetbiosHostname() {
        return this.netbiosHostname;
    }

    @Override
    public InetAddress getLocalAddr() {
        return this.smbLocalAddress;
    }

    @Override
    public int getLocalPort() {
        return this.smbLocalPort;
    }

    @Override
    public int getConnTimeout() {
        return this.smbConnectionTimeout;
    }

    @Override
    public int getResponseTimeout() {
        return this.smbResponseTimeout;
    }

    @Override
    public int getSoTimeout() {
        return this.smbSocketTimeout;
    }

    @Override
    public int getSessionTimeout() {
        return this.smbSessionTimeout;
    }

    @Override
    public int getSendBufferSize() {
        return this.smbSendBufferSize;
    }

    @Deprecated
    @Override
    public int getRecieveBufferSize() {
        return this.smbRecvBufferSize;
    }

    @Override
    public int getReceiveBufferSize() {
        return this.smbRecvBufferSize;
    }

    @Override
    public int getNotifyBufferSize() {
        return this.smbNotifyBufferSize;
    }

    @Override
    public int getMaxMpxCount() {
        return this.maxMpxCount;
    }

    @Override
    public String getNativeLanman() {
        return this.nativeLanMan;
    }

    @Override
    public String getNativeOs() {
        return this.nativeOs;
    }

    @Override
    public int getVcNumber() {
        return this.vcNumber;
    }

    @Override
    public int getCapabilities() {
        return this.capabilities;
    }

    @Override
    public DialectVersion getMinimumVersion() {
        return this.minVersion;
    }

    @Override
    public DialectVersion getMaximumVersion() {
        return this.maxVersion;
    }

    @Override
    public boolean isUseSMB2OnlyNegotiation() {
        return this.smb2OnlyNegotiation;
    }

    @Override
    public boolean isRequireSecureNegotiate() {
        return this.requireSecureNegotiate;
    }

    @Override
    public boolean isPort139FailoverEnabled() {
        return this.port139FailoverEnabled;
    }

    @Override
    public boolean isUseBatching() {
        return this.useBatching;
    }

    @Override
    public boolean isUseUnicode() {
        return this.useUnicode;
    }

    @Override
    public boolean isForceUnicode() {
        return this.forceUnicode;
    }

    @Override
    public boolean isDfsDisabled() {
        return this.dfsDisabled;
    }

    @Override
    public boolean isDfsStrictView() {
        return this.dfsStrictView;
    }

    @Override
    public long getDfsTtl() {
        return this.dfsTTL;
    }

    @Override
    public boolean isDfsConvertToFQDN() {
        return this.dfsConvertToFqdn;
    }

    @Override
    public String getLogonShare() {
        return this.logonShare;
    }

    @Override
    public String getDefaultDomain() {
        return this.defaultDomain;
    }

    @Override
    public String getDefaultUsername() {
        return this.defaultUserName;
    }

    @Override
    public String getDefaultPassword() {
        return this.defaultPassword;
    }

    @Override
    public boolean isDisablePlainTextPasswords() {
        return this.disablePlainTextPasswords;
    }

    @Override
    public int getLanManCompatibility() {
        return this.lanmanCompatibility;
    }

    @Override
    public boolean isAllowNTLMFallback() {
        return this.allowNTLMFallback;
    }

    @Override
    public boolean isUseRawNTLM() {
        return this.useRawNTLM;
    }

    @Override
    public boolean isDisableSpnegoIntegrity() {
        return this.disableSpnegoIntegrity;
    }

    @Override
    public boolean isEnforceSpnegoIntegrity() {
        return this.enforceSpnegoIntegrity;
    }

    @Override
    public InetAddress getBroadcastAddress() {
        return this.broadcastAddress;
    }

    @Override
    public List<ResolverType> getResolveOrder() {
        return this.resolverOrder;
    }

    @Override
    public InetAddress[] getWinsServers() {
        return this.winsServer;
    }

    @Override
    public int getNetbiosLocalPort() {
        return this.netbiosLocalPort;
    }

    @Override
    public InetAddress getNetbiosLocalAddress() {
        return this.netbiosLocalAddress;
    }

    @Override
    public int getNetbiosSoTimeout() {
        return this.netbiosSocketTimeout;
    }

    @Override
    public String getNetbiosScope() {
        return this.netbiosScope;
    }

    @Override
    public int getNetbiosCachePolicy() {
        return this.netbiosCachePolicy;
    }

    @Override
    public int getNetbiosRcvBufSize() {
        return this.netbiosRevcBufferSize;
    }

    @Override
    public int getNetbiosRetryCount() {
        return this.netbiosRetryCount;
    }

    @Override
    public int getNetbiosRetryTimeout() {
        return this.netbiosRetryTimeout;
    }

    @Override
    public int getNetbiosSndBufSize() {
        return this.netbiosSendBufferSize;
    }

    @Override
    public String getLmHostsFileName() {
        return this.lmhostsFilename;
    }

    @Override
    public int getFlags2() {
        return this.flags2;
    }

    @Override
    public int getSessionLimit() {
        return this.sessionLimit;
    }

    @Override
    public String getOemEncoding() {
        return this.oemEncoding;
    }

    @Override
    public TimeZone getLocalTimezone() {
        return this.localTimeZone;
    }

    @Override
    public int getPid() {
        return this.localPid;
    }

    @Override
    public boolean isSigningEnabled() {
        return this.signingPreferred;
    }

    @Override
    public boolean isSigningEnforced() {
        return this.signingEnforced;
    }

    @Override
    public boolean isIpcSigningEnforced() {
        return this.ipcSigningEnforced;
    }

    @Override
    public boolean isEncryptionEnabled() {
        return this.encryptionEnabled;
    }

    @Override
    public boolean isUseLease() {
        return this.useLease;
    }

    @Override
    public int getLeaseTimeout() {
        return this.leaseTimeout;
    }

    @Override
    public int getMaxLeases() {
        return this.maxLeases;
    }

    @Override
    public int getLeaseVersion() {
        return this.leaseVersion;
    }

    @Override
    public int getLeaseBreakTimeout() {
        return this.leaseBreakTimeout;
    }

    @Override
    public boolean isForceExtendedSecurity() {
        return this.forceExtendedSecurity;
    }

    @Override
    public int getTransactionBufferSize() {
        return this.transactionBufferSize;
    }

    @Override
    public int getMaximumBufferSize() {
        return this.maximumBufferSize;
    }

    @Override
    public int getBufferCacheSize() {
        return this.bufferCacheSize;
    }

    @Override
    public int getListCount() {
        return this.smbListCount;
    }

    @Override
    public int getListSize() {
        return this.smbListSize;
    }

    @Override
    public long getAttributeCacheTimeout() {
        return this.smbAttributeExpiration;
    }

    @Override
    public boolean isIgnoreCopyToException() {
        return this.ignoreCopyToException;
    }

    @Override
    public int getMaxRequestRetries() {
        return this.maxRequestRetries;
    }

    @Override
    public boolean isTraceResourceUsage() {
        return this.traceResourceUsage;
    }

    @Override
    public boolean isStrictResourceLifecycle() {
        return this.strictResourceLifecycle;
    }

    @Override
    public boolean isSendNTLMTargetName() {
        return this.sendNTLMTargetName;
    }

    @Override
    public String getGuestUsername() {
        return this.guestUsername;
    }

    @Override
    public String getGuestPassword() {
        return this.guestPassword;
    }

    @Override
    public boolean isAllowGuestFallback() {
        return this.allowGuestFallback;
    }

    @Override
    public byte[] getMachineId() {
        return this.machineId;
    }

    @Override
    public boolean isUseDurableHandles() {
        return this.useDurableHandles;
    }

    @Override
    public boolean isUsePersistentHandles() {
        return this.usePersistentHandles;
    }

    @Override
    public long getDurableHandleTimeout() {
        return this.durableHandleTimeout;
    }

    @Override
    public int getHandleReconnectRetries() {
        return this.handleReconnectRetries;
    }

    @Override
    public String getHandleStateDirectory() {
        return this.handleStateDirectory;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isUseMultiChannel()
     */
    @Override
    public boolean isUseMultiChannel() {
        return this.useMultiChannel;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#getMaxChannels()
     */
    @Override
    public int getMaxChannels() {
        return this.maxChannels;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#getChannelBindingPolicy()
     */
    @Override
    public int getChannelBindingPolicy() {
        return this.channelBindingPolicy;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#getLoadBalancingStrategy()
     */
    @Override
    public String getLoadBalancingStrategy() {
        return this.loadBalancingStrategy;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#getChannelHealthCheckInterval()
     */
    @Override
    public int getChannelHealthCheckInterval() {
        return this.channelHealthCheckInterval;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#getBatchLimit(java.lang.String)
     */
    @Override
    public int getBatchLimit(final String cmd) {
        Integer set = this.batchLimits.get(cmd);
        if (set != null) {
            return set;
        }

        set = doGetBatchLimit(cmd);
        if (set != null) {
            this.batchLimits.put(cmd, set);
            return set;
        }

        set = DEFAULT_BATCH_LIMITS.get(cmd);
        if (set != null) {
            return set;
        }
        return 1;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Configuration#isAllowCompound(java.lang.String)
     */
    @Override
    public boolean isAllowCompound(final String command) {
        if (this.disallowCompound == null) {
            return true;
        }
        return !this.disallowCompound.contains(command);
    }

    /**
     * Gets the batch limit for a specific command
     *
     * @param cmd the command to get the batch limit for
     * @return the batch limit for the command, or null if not set
     */
    protected Integer doGetBatchLimit(final String cmd) {
        return null;
    }

    /**
     * Initializes the resolver order for name resolution.
     *
     * @param ro comma-separated list of resolver types (LMHOSTS, WINS, BCAST, DNS)
     */
    protected void initResolverOrder(final String ro) {
        this.resolverOrder = new ArrayList<>();
        if (ro == null || ro.length() == 0) {
            /*
             * No resolveOrder has been specified, use the
             * default which is LMHOSTS,DNS,WINS,BCAST or just
             * LMHOSTS,DNS,BCAST if jcifs.netbios.wins has not
             * been specified.
             */
            if (this.winsServer.length == 0) {
                this.resolverOrder.add(ResolverType.RESOLVER_LMHOSTS);
                this.resolverOrder.add(ResolverType.RESOLVER_DNS);
            } else {
                this.resolverOrder.add(ResolverType.RESOLVER_LMHOSTS);
                this.resolverOrder.add(ResolverType.RESOLVER_DNS);
                this.resolverOrder.add(ResolverType.RESOLVER_WINS);
            }
            this.resolverOrder.add(ResolverType.RESOLVER_BCAST);
        } else {
            final StringTokenizer st = new StringTokenizer(ro, ",");
            while (st.hasMoreTokens()) {
                final String s = st.nextToken().trim();
                if (s.equalsIgnoreCase("LMHOSTS")) {
                    this.resolverOrder.add(ResolverType.RESOLVER_LMHOSTS);
                } else if (s.equalsIgnoreCase("WINS")) {
                    if (this.winsServer.length == 0) {
                        log.error("UniAddress resolveOrder specifies WINS however " + " WINS server has not been configured");
                        continue;
                    }
                    this.resolverOrder.add(ResolverType.RESOLVER_WINS);
                } else if (s.equalsIgnoreCase("BCAST")) {
                    this.resolverOrder.add(ResolverType.RESOLVER_BCAST);
                } else if (s.equalsIgnoreCase("DNS")) {
                    this.resolverOrder.add(ResolverType.RESOLVER_DNS);
                } else {
                    log.error("unknown resolver method: " + s);
                }
            }
        }
    }

    /**
     * Initializes the minimum and maximum protocol versions from string values.
     *
     * @param minStr string representation of minimum protocol version
     * @param maxStr string representation of maximum protocol version
     */
    protected void initProtocolVersions(final String minStr, final String maxStr) {
        final DialectVersion min = minStr != null && !minStr.isEmpty() ? DialectVersion.valueOf(minStr) : null;
        final DialectVersion max = maxStr != null && !maxStr.isEmpty() ? DialectVersion.valueOf(maxStr) : null;
        initProtocolVersions(min, max);
    }

    /**
     * Initializes the minimum and maximum protocol versions.
     *
     * @param min minimum protocol version
     * @param max maximum protocol version
     */
    protected void initProtocolVersions(final DialectVersion min, final DialectVersion max) {
        this.minVersion = min != null ? min : DialectVersion.SMB1;
        this.maxVersion = max != null ? max : DialectVersion.SMB311;

        if (this.minVersion.atLeast(this.maxVersion)) {
            this.maxVersion = this.minVersion;
        }
    }

    /**
     * Initializes the disallowed compound operations based on the provided property string.
     *
     * @param prop comma-separated list of operations to disallow in compound requests
     */
    protected void initDisallowCompound(final String prop) {
        if (prop == null) {
            return;
        }
        final Set<String> disallow = new HashSet<>();
        final StringTokenizer st = new StringTokenizer(prop, ",");
        while (st.hasMoreTokens()) {
            disallow.add(st.nextToken().trim());
        }
        this.disallowCompound = disallow;
    }

    /**
     * Initializes default configuration values.
     * Sets up default values for various configuration parameters if not already specified.
     *
     * @throws CIFSException if there is an error during initialization
     */
    protected void initDefaults() throws CIFSException {

        try {
            "".getBytes(SmbConstants.DEFAULT_OEM_ENCODING);
        } catch (final UnsupportedEncodingException uee) {
            throw new CIFSException(
                    "The default OEM encoding " + SmbConstants.DEFAULT_OEM_ENCODING + " does not appear to be supported by this JRE.");
        }

        this.localPid = (int) (Math.random() * 65536d);
        this.localTimeZone = TimeZone.getDefault();
        this.random = new SecureRandom();

        if (this.machineId == null) {
            final byte[] mid = new byte[32];
            this.random.nextBytes(mid);
            this.machineId = mid;
        }

        if (this.nativeOs == null) {
            this.nativeOs = System.getProperty("os.name");
        }

        if (this.flags2 == 0) {
            this.flags2 = SmbConstants.FLAGS2_LONG_FILENAMES | SmbConstants.FLAGS2_EXTENDED_ATTRIBUTES
                    | (this.useExtendedSecurity ? SmbConstants.FLAGS2_EXTENDED_SECURITY_NEGOTIATION : 0)
                    | (this.signingPreferred ? SmbConstants.FLAGS2_SECURITY_SIGNATURES : 0)
                    | (this.useNtStatus ? SmbConstants.FLAGS2_STATUS32 : 0)
                    | (this.useUnicode || this.forceUnicode ? SmbConstants.FLAGS2_UNICODE : 0);
        }

        if (this.capabilities == 0) {
            this.capabilities = (this.useNTSmbs ? SmbConstants.CAP_NT_SMBS : 0) | (this.useNtStatus ? SmbConstants.CAP_STATUS32 : 0)
                    | (this.useExtendedSecurity ? SmbConstants.CAP_EXTENDED_SECURITY : 0)
                    | (this.useLargeReadWrite ? SmbConstants.CAP_LARGE_READX : 0)
                    | (this.useLargeReadWrite ? SmbConstants.CAP_LARGE_WRITEX : 0) | (this.useUnicode ? SmbConstants.CAP_UNICODE : 0);
        }

        if (this.broadcastAddress == null) {
            try {
                this.broadcastAddress = InetAddress.getByName("255.255.255.255");
            } catch (final UnknownHostException uhe) {
                log.debug("Failed to get broadcast address", uhe);
            }
        }

        if (this.resolverOrder == null) {
            initResolverOrder(null);
        }

        if (this.minVersion == null || this.maxVersion == null) {
            initProtocolVersions((DialectVersion) null, null);
        }

        if (this.disallowCompound == null) {
            // Samba woes on these
            // Smb2SessionSetupRequest + X -> INTERNAL_ERROR
            // Smb2TreeConnectRequest + IoCtl -> NETWORK_NAME_DELETED
            this.disallowCompound = new HashSet<>(Arrays.asList("Smb2SessionSetupRequest", "Smb2TreeConnectRequest"));
        }

        // Initialize multi-channel defaults if not set
        // Note: useMultiChannel defaults are handled by PropertyConfiguration
        // Base configuration leaves it as false by default
        if (this.maxChannels == 0) {
            this.maxChannels = 4;
        }
        // channelBindingPolicy: 0=disabled, 1=preferred, 2=required, -1=not set
        if (this.channelBindingPolicy == -1) {
            this.channelBindingPolicy = 1; // Default to preferred
        }
        if (this.channelHealthCheckInterval == 0) {
            this.channelHealthCheckInterval = 10;
        }
        if (this.loadBalancingStrategy == null) {
            this.loadBalancingStrategy = "adaptive";
        }

        // Initialize RDMA defaults
        if (this.rdmaProvider == null) {
            this.rdmaProvider = "auto";
        }
        if (this.rdmaReadWriteThreshold == 0) {
            this.rdmaReadWriteThreshold = 8192; // 8KB
        }
        if (this.rdmaMaxSendSize == 0) {
            this.rdmaMaxSendSize = 65536; // 64KB
        }
        if (this.rdmaMaxReceiveSize == 0) {
            this.rdmaMaxReceiveSize = 65536; // 64KB
        }
        if (this.rdmaCredits == 0) {
            this.rdmaCredits = 255;
        }
    }

    /**
     * Parse channel binding policy from string
     *
     * @param policy policy string
     * @return policy constant
     */
    protected final int initChannelBindingPolicy(String policy) {
        if (policy == null)
            return 1; // preferred
        switch (policy.toLowerCase()) {
        case "disabled":
            return 0;
        case "required":
            return 2;
        default:
            return 1; // preferred
        }
    }

    @Override
    public boolean isUseDirectoryLeasing() {
        return this.useDirectoryLeasing;
    }

    @Override
    public String getDirectoryCacheScope() {
        return this.directoryCacheScope;
    }

    @Override
    public long getDirectoryCacheTimeout() {
        return this.directoryCacheTimeout;
    }

    @Override
    public boolean isDirectoryNotificationsEnabled() {
        return this.directoryNotificationsEnabled;
    }

    @Override
    public int getMaxDirectoryCacheEntries() {
        return this.maxDirectoryCacheEntries;
    }

    @Override
    public boolean isUseRDMA() {
        return this.useRDMA;
    }

    @Override
    public String getRdmaProvider() {
        return this.rdmaProvider;
    }

    @Override
    public int getRdmaReadWriteThreshold() {
        return this.rdmaReadWriteThreshold;
    }

    @Override
    public int getRdmaMaxSendSize() {
        return this.rdmaMaxSendSize;
    }

    @Override
    public int getRdmaMaxReceiveSize() {
        return this.rdmaMaxReceiveSize;
    }

    @Override
    public int getRdmaCredits() {
        return this.rdmaCredits;
    }

    @Override
    public boolean isRdmaEnabled() {
        return this.rdmaEnabled;
    }

    @Override
    public int getRdmaPort() {
        return this.rdmaPort;
    }

    @Override
    public boolean isUseWitness() {
        return this.useWitness;
    }

    @Override
    public long getWitnessHeartbeatTimeout() {
        return this.witnessHeartbeatTimeout;
    }

    @Override
    public long getWitnessRegistrationTimeout() {
        return this.witnessRegistrationTimeout;
    }

    @Override
    public long getWitnessReconnectDelay() {
        return this.witnessReconnectDelay;
    }

    @Override
    public boolean isWitnessServiceDiscovery() {
        return this.witnessServiceDiscovery;
    }

    @Override
    public boolean isUseLeases() {
        return this.useLeases;
    }

    @Override
    public long getPersistentHandleTimeout() {
        return this.persistentHandleTimeout;
    }

}
