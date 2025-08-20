/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package jcifs.internal.smb2.create;

import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.RequestWithPath;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.smb2.lease.Smb2LeaseKey;
import jcifs.internal.smb2.lease.Smb2LeaseState;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;

/**
 * SMB2 Create request message. This command is used to create or open a file or directory
 * on the server with specified access rights and sharing options.
 *
 * @author mbechler
 *
 */
public class Smb2CreateRequest extends ServerMessageBlock2Request<Smb2CreateResponse> implements RequestWithPath {

    private static final Logger log = LoggerFactory.getLogger(Smb2CreateRequest.class);

    /**
     * No oplock
     */
    public static final byte SMB2_OPLOCK_LEVEL_NONE = 0x0;
    /**
     * Level II oplock
     */
    public static final byte SMB2_OPLOCK_LEVEL_II = 0x1;
    /**
     * Exclusive oplock
     */
    public static final byte SMB2_OPLOCK_LEVEL_EXCLUSIVE = 0x8;
    /**
     * Batch oplock
     */
    public static final byte SMB2_OPLOCK_LEVEL_BATCH = 0x9;
    /**
     * Lease-based oplock
     */
    public static final byte SMB2_OPLOCK_LEVEL_LEASE = (byte) 0xFF;

    /**
     * Anonymous impersonation level - client cannot obtain identification information about itself
     */
    public static final int SMB2_IMPERSONATION_LEVEL_ANONYMOUS = 0x0;

    /**
     * Identification impersonation level - server can obtain the client's identity but cannot impersonate
     */
    public static final int SMB2_IMPERSONATION_LEVEL_IDENTIFICATION = 0x1;

    /**
     * Impersonation level - server can impersonate the client's security context on the local system
     */
    public static final int SMB2_IMPERSONATION_LEVEL_IMPERSONATION = 0x2;

    /**
     * Delegate impersonation level - server can impersonate the client's security context on remote systems
     */
    public static final int SMB2_IMPERSONATION_LEVEL_DELEGATE = 0x3;

    /**
     * Enable other opens for read access
     */
    public static final int FILE_SHARE_READ = 0x1;

    /**
     * Enable other opens for write access
     */
    public static final int FILE_SHARE_WRITE = 0x2;

    /**
     * Enable other opens for delete access
     */
    public static final int FILE_SHARE_DELETE = 0x4;

    /**
     * If file exists, supersede it. Otherwise create the file
     */
    public static final int FILE_SUPERSEDE = 0x0;
    /**
     * If file exists, open it. Otherwise fail
     */
    public static final int FILE_OPEN = 0x1;
    /**
     * If file exists, fail. Otherwise create the file
     */
    public static final int FILE_CREATE = 0x2;
    /**
     * If file exists, open it. Otherwise create the file
     */
    public static final int FILE_OPEN_IF = 0x3;
    /**
     * If file exists, overwrite it. Otherwise fail
     */
    public static final int FILE_OVERWRITE = 0x4;
    /**
     * If file exists, overwrite it. Otherwise create the file
     */
    public static final int FILE_OVERWRITE_IF = 0x5;

    /**
     * File being created or opened must be a directory
     */
    public static final int FILE_DIRECTORY_FILE = 0x1;
    /**
     * Write operations go directly to persistent storage
     */
    public static final int FILE_WRITE_THROUGH = 0x2;
    /**
     * Access to the file is sequential only
     */
    public static final int FILE_SEQUENTIAL_ONLY = 0x4;
    /**
     * File cannot be cached or buffered at intermediate levels
     */
    public static final int FILE_NO_IMTERMEDIATE_BUFFERING = 0x8;
    /**
     * All operations on the file are performed synchronously with alerts
     */
    public static final int FILE_SYNCHRONOUS_IO_ALERT = 0x10;
    /**
     * All operations on the file are performed synchronously without alerts
     */
    public static final int FILE_SYNCHRONOUS_IO_NONALERT = 0x20;
    /**
     * File being created or opened must not be a directory
     */
    public static final int FILE_NON_DIRECTORY_FILE = 0x40;
    /**
     * Complete this operation immediately with an oplock break if it would break an oplock
     */
    public static final int FILE_COMPLETE_IF_OPLOCKED = 0x100;
    /**
     * The client does not understand extended attributes
     */
    public static final int FILE_NO_EA_KNOWLEDGE = 0x200;
    /**
     * Open a remote instance of the file
     */
    public static final int FILE_OPEN_REMOTE_INSTANCE = 0x400;
    /**
     * Access to the file is random
     */
    public static final int FILE_RANDOM_ACCESS = 0x800;
    /**
     * Delete the file when the last handle to it is closed
     */
    public static final int FILE_DELETE_ON_CLOSE = 0x1000;
    /**
     * Open file by its file ID
     */
    public static final int FILE_OPEN_BY_FILE_ID = 0x2000;
    /**
     * The file is being opened for backup intent
     */
    public static final int FILE_OPEN_FOR_BACKUP_INTENT = 0x4000;
    /**
     * Disable compression on the file
     */
    public static final int FILE_NO_COMPRESSION = 0x8000;
    /**
     * The file is being opened and an oplock is being requested as an atomic operation
     */
    public static final int FILE_OPEN_REQUIRING_OPLOCK = 0x10000;
    /**
     * Any open of this file cannot be exclusive
     */
    public static final int FILE_DISALLOW_EXCLUSIVE = 0x20000;
    /**
     * Reserve an opportunistic lock filter on the open
     */
    public static final int FILE_RESERVE_OPFILTER = 0x100000;
    /**
     * Open a reparse point and bypass normal reparse point processing
     */
    public static final int FILE_OPEN_REPARSE_POINT = 0x200000;
    /**
     * Open does not cause an opportunistic lock break for the file
     */
    public static final int FILE_NOP_RECALL = 0x400000;
    /**
     * The file is being opened solely to query its free space
     */
    public static final int FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x800000;

    private byte securityFlags;
    private byte requestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
    private int impersonationLevel = SMB2_IMPERSONATION_LEVEL_IMPERSONATION;
    private long smbCreateFlags;
    private int desiredAccess = 0x00120089; // 0x80000000 | 0x1;
    private int fileAttributes;
    private int shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
    private int createDisposition = FILE_OPEN;
    private int createOptions = 0;

    private String name;
    private CreateContextRequest[] createContexts;
    private String fullName;

    private String domain;

    private String server;

    private boolean resolveDfs;

    /**
     * Constructs an SMB2 create request
     * @param config the client configuration
     * @param name uncPath to open, strips a leading \
     */
    public Smb2CreateRequest(final Configuration config, final String name) {
        super(config, SMB2_CREATE);
        setPath(name);
    }

    @Override
    protected Smb2CreateResponse createResponse(final CIFSContext tc, final ServerMessageBlock2Request<Smb2CreateResponse> req) {
        return new Smb2CreateResponse(tc.getConfig(), this.name);
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#getPath()
     */
    @Override
    public String getPath() {
        return '\\' + this.name;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#getFullUNCPath()
     */
    @Override
    public String getFullUNCPath() {
        return this.fullName;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#getServer()
     */
    @Override
    public String getServer() {
        return this.server;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#getDomain()
     */
    @Override
    public String getDomain() {
        return this.domain;
    }

    /**
     * @param fullName
     *            the fullName to set
     */
    @Override
    public void setFullUNCPath(final String domain, final String server, final String fullName) {
        this.domain = domain;
        this.server = server;
        this.fullName = fullName;
    }

    /**
     * {@inheritDoc}
     *
     * Strips a leading \
     *
     * @see jcifs.internal.RequestWithPath#setPath(java.lang.String)
     */
    @Override
    public void setPath(String path) {
        if (path.length() > 0 && path.charAt(0) == '\\') {
            path = path.substring(1);
        }
        // win8.1 returns ACCESS_DENIED if the trailing backslash is included
        if (path.length() > 1 && path.charAt(path.length() - 1) == '\\') {
            path = path.substring(0, path.length() - 1);
        }
        this.name = path;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#setResolveInDfs(boolean)
     */
    @Override
    public void setResolveInDfs(final boolean resolve) {
        addFlags(SMB2_FLAGS_DFS_OPERATIONS);
        this.resolveDfs = resolve;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#isResolveInDfs()
     */
    @Override
    public boolean isResolveInDfs() {
        return this.resolveDfs;
    }

    /**
     * Set the security flags for the create request
     * @param securityFlags the securityFlags to set
     */
    public void setSecurityFlags(final byte securityFlags) {
        this.securityFlags = securityFlags;
    }

    /**
     * Set the requested oplock level for the file
     * @param requestedOplockLevel the requestedOplockLevel to set
     */
    public void setRequestedOplockLevel(final byte requestedOplockLevel) {
        this.requestedOplockLevel = requestedOplockLevel;
    }

    /**
     * Set the impersonation level for the create request
     * @param impersonationLevel the impersonationLevel to set
     */
    public void setImpersonationLevel(final int impersonationLevel) {
        this.impersonationLevel = impersonationLevel;
    }

    /**
     * Set the SMB create flags
     * @param smbCreateFlags the smbCreateFlags to set
     */
    public void setSmbCreateFlags(final long smbCreateFlags) {
        this.smbCreateFlags = smbCreateFlags;
    }

    /**
     * Set the desired access mask for the file
     * @param desiredAccess the desiredAccess to set
     */
    public void setDesiredAccess(final int desiredAccess) {
        this.desiredAccess = desiredAccess;
    }

    /**
     * Set the file attributes for the created file
     * @param fileAttributes the fileAttributes to set
     */
    public void setFileAttributes(final int fileAttributes) {
        this.fileAttributes = fileAttributes;
    }

    /**
     * Set the share access mode for the file
     * @param shareAccess the shareAccess to set
     */
    public void setShareAccess(final int shareAccess) {
        this.shareAccess = shareAccess;
    }

    /**
     * Set the create disposition specifying what action to take if file exists or doesn't exist
     * @param createDisposition the createDisposition to set
     */
    public void setCreateDisposition(final int createDisposition) {
        this.createDisposition = createDisposition;
    }

    /**
     * Set the create options that control file creation behavior
     * @param createOptions the createOptions to set
     */
    public void setCreateOptions(final int createOptions) {
        this.createOptions = createOptions;
    }

    /**
     * Set the create contexts for this request
     * @param contexts the create contexts to set
     */
    public void setCreateContexts(CreateContextRequest[] contexts) {
        this.createContexts = contexts;
    }

    /**
     * Add a create context to this request
     * @param context the create context to add
     */
    public void addCreateContext(CreateContextRequest context) {
        if (context == null) {
            return;
        }
        if (this.createContexts == null) {
            this.createContexts = new CreateContextRequest[] { context };
        } else {
            CreateContextRequest[] newContexts = new CreateContextRequest[this.createContexts.length + 1];
            System.arraycopy(this.createContexts, 0, newContexts, 0, this.createContexts.length);
            newContexts[this.createContexts.length] = context;
            this.createContexts = newContexts;
        }
    }

    /**
     * Add a lease V1 context to this request
     * @param leaseKey the lease key
     * @param requestedState the requested lease state
     */
    public void addLeaseV1Context(Smb2LeaseKey leaseKey, int requestedState) {
        LeaseV1CreateContextRequest leaseContext = new LeaseV1CreateContextRequest(leaseKey, requestedState);
        addCreateContext(leaseContext);
        setRequestedOplockLevel(SMB2_OPLOCK_LEVEL_LEASE);
    }

    /**
     * Add a lease V2 context to this request
     * @param leaseKey the lease key
     * @param requestedState the requested lease state
     * @param parentLeaseKey the parent lease key (can be null)
     * @param epoch the lease epoch
     */
    public void addLeaseV2Context(Smb2LeaseKey leaseKey, int requestedState, Smb2LeaseKey parentLeaseKey, int epoch) {
        LeaseV2CreateContextRequest leaseContext = new LeaseV2CreateContextRequest(leaseKey, requestedState, parentLeaseKey, epoch);
        addCreateContext(leaseContext);
        setRequestedOplockLevel(SMB2_OPLOCK_LEVEL_LEASE);
    }

    /**
     * Remove lease contexts and fall back to oplock
     * @param oplockLevel the oplock level to fall back to
     */
    public void fallbackToOplock(byte oplockLevel) {
        // Remove any lease contexts
        if (this.createContexts != null) {
            CreateContextRequest[] filteredContexts = null;
            int count = 0;

            for (CreateContextRequest ctx : this.createContexts) {
                // Filter out lease contexts
                if (!(ctx instanceof LeaseV1CreateContextRequest) && !(ctx instanceof LeaseV2CreateContextRequest)) {
                    if (filteredContexts == null) {
                        filteredContexts = new CreateContextRequest[this.createContexts.length];
                    }
                    filteredContexts[count++] = ctx;
                }
            }

            if (count > 0) {
                CreateContextRequest[] newContexts = new CreateContextRequest[count];
                System.arraycopy(filteredContexts, 0, newContexts, 0, count);
                this.createContexts = newContexts;
            } else {
                this.createContexts = null;
            }
        }

        // Set oplock level
        setRequestedOplockLevel(oplockLevel);
    }

    /**
     * Check if this request has lease contexts
     * @return true if lease contexts are present
     */
    public boolean hasLeaseContext() {
        if (this.createContexts != null) {
            for (CreateContextRequest ctx : this.createContexts) {
                if (ctx instanceof LeaseV1CreateContextRequest || ctx instanceof LeaseV2CreateContextRequest) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size() {
        int size = Smb2Constants.SMB2_HEADER_LENGTH + 56;
        int nameLen = 2 * this.name.length();
        if (nameLen == 0) {
            nameLen++;
        }

        size += size8(nameLen);
        if (this.createContexts != null) {
            for (final CreateContextRequest ccr : this.createContexts) {
                size += size8(ccr.size());
            }
        }
        return size8(size);
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        if (log.isDebugEnabled()) {
            log.debug("Opening " + this.name);
            log.debug("Flags are " + Hexdump.toHexString(getFlags(), 4));
        }

        SMBUtil.writeInt2(57, dst, dstIndex);
        dst[dstIndex + 2] = this.securityFlags;
        dst[dstIndex + 3] = this.requestedOplockLevel;
        dstIndex += 4;

        SMBUtil.writeInt4(this.impersonationLevel, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt8(this.smbCreateFlags, dst, dstIndex);
        dstIndex += 8;
        dstIndex += 8; // Reserved

        SMBUtil.writeInt4(this.desiredAccess, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.fileAttributes, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.shareAccess, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.createDisposition, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.createOptions, dst, dstIndex);
        dstIndex += 4;

        final int nameOffsetOffset = dstIndex;
        final byte[] nameBytes = this.name.getBytes(StandardCharsets.UTF_16LE);
        SMBUtil.writeInt2(nameBytes.length, dst, dstIndex + 2);
        dstIndex += 4;

        final int createContextOffsetOffset = dstIndex;
        dstIndex += 4; // createContextOffset
        final int createContextLengthOffset = dstIndex;
        dstIndex += 4; // createContextLength

        SMBUtil.writeInt2(dstIndex - getHeaderStart(), dst, nameOffsetOffset);

        System.arraycopy(nameBytes, 0, dst, dstIndex, nameBytes.length);
        if (nameBytes.length == 0) {
            // buffer must contain at least one byte
            dstIndex++;
        } else {
            dstIndex += nameBytes.length;
        }

        dstIndex += pad8(dstIndex);

        if (this.createContexts == null || this.createContexts.length == 0) {
            SMBUtil.writeInt4(0, dst, createContextOffsetOffset);
        } else {
            SMBUtil.writeInt4(dstIndex - getHeaderStart(), dst, createContextOffsetOffset);
        }
        int totalCreateContextLength = 0;
        if (this.createContexts != null) {
            int lastStart = -1;
            for (final CreateContextRequest createContext : this.createContexts) {
                final int structStart = dstIndex;

                SMBUtil.writeInt4(0, dst, structStart); // Next
                if (lastStart > 0) {
                    // set next pointer of previous CREATE_CONTEXT
                    SMBUtil.writeInt4(structStart - dstIndex, dst, lastStart);
                }

                dstIndex += 4;
                final byte[] cnBytes = createContext.getName();
                final int cnOffsetOffset = dstIndex;
                SMBUtil.writeInt2(cnBytes.length, dst, dstIndex + 2);
                dstIndex += 4;

                final int dataOffsetOffset = dstIndex + 2;
                dstIndex += 4;
                final int dataLengthOffset = dstIndex;
                dstIndex += 4;

                SMBUtil.writeInt2(dstIndex - structStart, dst, cnOffsetOffset);
                System.arraycopy(cnBytes, 0, dst, dstIndex, cnBytes.length);
                dstIndex += cnBytes.length;
                dstIndex += pad8(dstIndex);

                SMBUtil.writeInt2(dstIndex - structStart, dst, dataOffsetOffset);
                final int len = createContext.encode(dst, dstIndex);
                SMBUtil.writeInt4(len, dst, dataLengthOffset);
                dstIndex += len;

                final int pad = pad8(dstIndex);
                totalCreateContextLength += len + pad;
                dstIndex += pad;
                lastStart = structStart;
            }
        }
        SMBUtil.writeInt4(totalCreateContextLength, dst, createContextLengthOffset);
        return dstIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

    @Override
    public String toString() {
        return "[" + super.toString() + ",name=" + this.name + ",resolveDfs=" + this.resolveDfs + "]";
    }
}
