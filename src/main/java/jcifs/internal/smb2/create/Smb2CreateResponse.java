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
import java.util.LinkedList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.SmbBasicFileInfo;
import jcifs.internal.smb2.RequestWithFileId;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;

/**
 * SMB2 Create response message. This response contains the file ID and attributes
 * of the created or opened file or directory.
 *
 * @author mbechler
 *
 */
public class Smb2CreateResponse extends ServerMessageBlock2Response implements SmbBasicFileInfo {

    private static final Logger log = LoggerFactory.getLogger(Smb2CreateResponse.class);

    private byte oplockLevel;
    private byte openFlags;
    private int createAction;
    private long creationTime;
    private long lastAccessTime;
    private long lastWriteTime;
    private long changeTime;
    private long allocationSize;
    private long endOfFile;
    private int fileAttributes;
    private final byte[] fileId = new byte[16];
    private CreateContextResponse[] createContexts;
    private final String fileName;

    /**
     * Constructs an SMB2 create response
     * @param config the client configuration
     * @param name the file name
     */
    public Smb2CreateResponse(final Configuration config, final String name) {
        super(config);
        this.fileName = name;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2Response#prepare(jcifs.internal.CommonServerMessageBlockRequest)
     */
    @Override
    public void prepare(final CommonServerMessageBlockRequest next) {
        if (isReceived() && next instanceof RequestWithFileId) {
            ((RequestWithFileId) next).setFileId(this.fileId);
        }
        super.prepare(next);
    }

    /**
     * Get the oplock level granted by the server
     * @return the oplockLevel
     */
    public final byte getOplockLevel() {
        return this.oplockLevel;
    }

    /**
     * Get the open flags returned by the server
     * @return the flags
     */
    public final byte getOpenFlags() {
        return this.openFlags;
    }

    /**
     * Get the create action taken by the server
     * @return the createAction
     */
    public final int getCreateAction() {
        return this.createAction;
    }

    /**
     * Get the file creation time
     * @return the creationTime
     */
    public final long getCreationTime() {
        return this.creationTime;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbBasicFileInfo#getCreateTime()
     */
    @Override
    public final long getCreateTime() {
        return getCreationTime();
    }

    /**
     * @return the lastAccessTime
     */
    @Override
    public final long getLastAccessTime() {
        return this.lastAccessTime;
    }

    /**
     * @return the lastWriteTime
     */
    @Override
    public final long getLastWriteTime() {
        return this.lastWriteTime;
    }

    /**
     * Get the file change time
     * @return the changeTime
     */
    public final long getChangeTime() {
        return this.changeTime;
    }

    /**
     * Get the allocation size of the file
     * @return the allocationSize
     */
    public final long getAllocationSize() {
        return this.allocationSize;
    }

    /**
     * Get the end of file position
     * @return the endOfFile
     */
    public final long getEndOfFile() {
        return this.endOfFile;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbBasicFileInfo#getSize()
     */
    @Override
    public final long getSize() {
        return getEndOfFile();
    }

    /**
     * Get the file attributes
     * @return the fileAttributes
     */
    public final int getFileAttributes() {
        return this.fileAttributes;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbBasicFileInfo#getAttributes()
     */
    @Override
    public final int getAttributes() {
        return getFileAttributes();
    }

    /**
     * Get the unique file identifier
     * @return the fileId
     */
    public final byte[] getFileId() {
        return this.fileId;
    }

    /**
     * Get the file name
     * @return the fileName
     */
    public final String getFileName() {
        return this.fileName;
    }

    /**
     * Get the create context responses
     * @return the createContexts
     */
    public CreateContextResponse[] getCreateContexts() {
        return this.createContexts;
    }

    /**
     * Get the lease V1 context response if present
     * @return the lease V1 context or null if not present
     */
    public LeaseV1CreateContextResponse getLeaseV1Context() {
        if (this.createContexts != null) {
            for (CreateContextResponse ctx : this.createContexts) {
                if (ctx instanceof LeaseV1CreateContextResponse) {
                    return (LeaseV1CreateContextResponse) ctx;
                }
            }
        }
        return null;
    }

    /**
     * Get the lease V2 context response if present
     * @return the lease V2 context or null if not present
     */
    public LeaseV2CreateContextResponse getLeaseV2Context() {
        if (this.createContexts != null) {
            for (CreateContextResponse ctx : this.createContexts) {
                if (ctx instanceof LeaseV2CreateContextResponse) {
                    return (LeaseV2CreateContextResponse) ctx;
                }
            }
        }
        return null;
    }

    /**
     * Get the durable handle response if present
     * @return the durable handle response or null if not present
     */
    public jcifs.internal.smb2.persistent.DurableHandleResponse getDurableHandleResponse() {
        if (this.createContexts != null) {
            for (CreateContextResponse ctx : this.createContexts) {
                if (ctx instanceof jcifs.internal.smb2.persistent.DurableHandleResponse) {
                    return (jcifs.internal.smb2.persistent.DurableHandleResponse) ctx;
                }
            }
        }
        return null;
    }

    /**
     * Get the durable handle V2 response if present
     * @return the durable handle V2 response or null if not present
     */
    public jcifs.internal.smb2.persistent.DurableHandleV2Response getDurableHandleV2Response() {
        if (this.createContexts != null) {
            for (CreateContextResponse ctx : this.createContexts) {
                if (ctx instanceof jcifs.internal.smb2.persistent.DurableHandleV2Response) {
                    return (jcifs.internal.smb2.persistent.DurableHandleV2Response) ctx;
                }
            }
        }
        return null;
    }

    /**
     * Get the durable handle reconnect response if present
     * @return the durable handle reconnect response or null if not present
     */
    public jcifs.internal.smb2.persistent.DurableHandleReconnectResponse getDurableHandleReconnectResponse() {
        if (this.createContexts != null) {
            for (CreateContextResponse ctx : this.createContexts) {
                if (ctx instanceof jcifs.internal.smb2.persistent.DurableHandleReconnectResponse) {
                    return (jcifs.internal.smb2.persistent.DurableHandleReconnectResponse) ctx;
                }
            }
        }
        return null;
    }

    /**
     * Check if the response contains any durable handle context
     * @return true if durable handle context is present
     */
    public boolean hasDurableHandleResponse() {
        return getDurableHandleResponse() != null || getDurableHandleV2Response() != null || getDurableHandleReconnectResponse() != null;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    /**
     * {@inheritDoc}
     *
     * @throws SMBProtocolDecodingException if there is an error decoding the response
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat(final byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        final int structureSize = SMBUtil.readInt2(buffer, bufferIndex);

        if (structureSize != 89) {
            throw new SMBProtocolDecodingException("Structure size is not 89");
        }

        this.oplockLevel = buffer[bufferIndex + 2];
        this.openFlags = buffer[bufferIndex + 3];
        bufferIndex += 4;

        this.createAction = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        this.creationTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.lastAccessTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.lastWriteTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.changeTime = SMBUtil.readTime(buffer, bufferIndex);
        bufferIndex += 8;

        this.allocationSize = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        this.endOfFile = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;

        this.fileAttributes = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        bufferIndex += 4; // Reserved2

        System.arraycopy(buffer, bufferIndex, this.fileId, 0, 16);
        bufferIndex += 16;

        final int createContextOffset = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        final int createContextLength = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        if (createContextOffset > 0 && createContextLength > 0) {
            final List<CreateContextResponse> contexts = new LinkedList<>();
            int createContextStart = getHeaderStart() + createContextOffset;
            int next = 0;
            do {
                int cci = createContextStart;
                next = SMBUtil.readInt4(buffer, cci);
                cci += 4;

                final int nameOffset = SMBUtil.readInt2(buffer, cci);
                final int nameLength = SMBUtil.readInt2(buffer, cci + 2);
                cci += 4;

                final int dataOffset = SMBUtil.readInt2(buffer, cci + 2);
                cci += 4;
                final int dataLength = SMBUtil.readInt4(buffer, cci);
                cci += 4;

                final byte[] nameBytes = new byte[nameLength];
                System.arraycopy(buffer, createContextStart + nameOffset, nameBytes, 0, nameBytes.length);
                cci = Math.max(cci, createContextStart + nameOffset + nameLength);

                final CreateContextResponse cc = createContext(nameBytes);
                if (cc != null) {
                    cc.decode(buffer, createContextStart + dataOffset, dataLength);
                    contexts.add(cc);
                }

                cci = Math.max(cci, createContextStart + dataOffset + dataLength);

                if (next > 0) {
                    createContextStart += next;
                }
                bufferIndex = Math.max(bufferIndex, cci);
            } while (next > 0);
            this.createContexts = contexts.toArray(new CreateContextResponse[0]);
        }

        if (log.isDebugEnabled()) {
            log.debug("Opened " + this.fileName + ": " + Hexdump.toHexString(this.fileId));
        }

        return bufferIndex - start;
    }

    /**
     * Factory method to create appropriate context response based on context name
     * @param nameBytes context name bytes
     * @return appropriate CreateContextResponse implementation or null if unknown
     */
    private static CreateContextResponse createContext(final byte[] nameBytes) {
        if (nameBytes == null || nameBytes.length != 4) {
            return null;
        }

        String contextName = new String(nameBytes, StandardCharsets.US_ASCII);

        switch (contextName) {
        case LeaseV1CreateContextRequest.CONTEXT_NAME: // "RqLs"
            return new LeaseV1CreateContextResponse();
        case LeaseV2CreateContextRequest.CONTEXT_NAME: // "RqL2"
            return new LeaseV2CreateContextResponse();
        default:
            // Unknown context type - log and return null
            if (log.isDebugEnabled()) {
                log.debug("Unknown create context: " + contextName);
            }
            return null;
        }
    }

}
