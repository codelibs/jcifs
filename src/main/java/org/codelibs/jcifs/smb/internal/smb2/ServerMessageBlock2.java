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
package org.codelibs.jcifs.smb.internal.smb2;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlock;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockResponse;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.SMBSigningDigest;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Hexdump;

/**
 * Base class for SMB2/SMB3 protocol messages.
 *
 * This abstract class provides common functionality for all SMB2/SMB3
 * message types including encoding, decoding, and message handling.
 *
 * @author mbechler
 */
public abstract class ServerMessageBlock2 implements CommonServerMessageBlock {

    /*
     * These are all the smbs supported by this library. This includes requests
     * and well as their responses for each type however the actual implementations
     * of the readXxxWireFormat and writeXxxWireFormat methods may not be in
     * place. For example at the time of this writing the readXxxWireFormat
     * for requests and the writeXxxWireFormat for responses are not implemented
     * and simply return 0. These would need to be completed for a server
     * implementation.
     */

    /** SMB2 negotiate protocol command */
    protected static final short SMB2_NEGOTIATE = 0x00;
    /** SMB2 session setup command */
    protected static final short SMB2_SESSION_SETUP = 0x01;
    /** SMB2 logoff command */
    protected static final short SMB2_LOGOFF = 0x02;
    /** SMB2 tree connect command */
    protected static final short SMB2_TREE_CONNECT = 0x0003;
    /** SMB2 tree disconnect command */
    protected static final short SMB2_TREE_DISCONNECT = 0x0004;
    /** SMB2 create/open file command */
    protected static final short SMB2_CREATE = 0x0005;
    /** SMB2 close file command */
    protected static final short SMB2_CLOSE = 0x0006;
    /** SMB2 flush file command */
    protected static final short SMB2_FLUSH = 0x0007;
    /** SMB2 read file command */
    protected static final short SMB2_READ = 0x0008;
    /** SMB2 write file command */
    protected static final short SMB2_WRITE = 0x0009;
    /** SMB2 lock file command */
    protected static final short SMB2_LOCK = 0x000A;
    /** SMB2 IO control command */
    protected static final short SMB2_IOCTL = 0x000B;
    /** SMB2 cancel command */
    protected static final short SMB2_CANCEL = 0x000C;
    /** SMB2 echo/keepalive command */
    protected static final short SMB2_ECHO = 0x000D;
    /** SMB2 query directory command */
    protected static final short SMB2_QUERY_DIRECTORY = 0x000E;
    /** SMB2 change notify command */
    protected static final short SMB2_CHANGE_NOTIFY = 0x000F;
    /** SMB2 query info command */
    protected static final short SMB2_QUERY_INFO = 0x0010;
    /** SMB2 set info command */
    protected static final short SMB2_SET_INFO = 0x0011;
    /** SMB2 opportunistic lock break notification */
    protected static final short SMB2_OPLOCK_BREAK = 0x0012;

    /**
     * Flag indicating the message is a response from server to client.
     */
    public static final int SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001;
    /**
     * Flag indicating this is an asynchronous command.
     */
    public static final int SMB2_FLAGS_ASYNC_COMMAND = 0x00000002;
    /**
     * Flag indicating this operation is related to the previous operation in a compound request.
     */
    public static final int SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004;
    /**
     * Flag indicating the message is signed.
     */
    public static final int SMB2_FLAGS_SIGNED = 0x00000008;
    /**
     * Mask for message priority bits.
     */
    public static final int SMB2_FLAGS_PRIORITY_MASK = 0x00000070;
    /**
     * Flag indicating the operation is a DFS operation.
     */
    public static final int SMB2_FLAGS_DFS_OPERATIONS = 0x10000000;
    /**
     * Flag indicating this is a replay operation.
     */
    public static final int SMB2_FLAGS_REPLAY_OPERATION = 0x20000000;

    private int command;
    private int flags;
    private int length, headerStart, wordCount, byteCount;

    private final byte[] signature = new byte[16];
    private Smb2SigningDigest digest = null;

    private final Configuration config;

    private int creditCharge;
    private int status;
    private int credit;
    private int nextCommand;
    private int readSize;
    private boolean async;
    private int treeId;
    private long mid, asyncId, sessionId;
    private byte errorContextCount;
    private byte[] errorData;

    private boolean retainPayload;
    private byte[] rawPayload;

    private ServerMessageBlock2 next;

    /**
     * Constructor for SMB2 message block with configuration.
     *
     * @param config the configuration object
     */
    protected ServerMessageBlock2(final Configuration config) {
        this.config = config;
    }

    /**
     * Constructor for SMB2 message block with configuration and command.
     *
     * @param config the configuration object
     * @param command the SMB2 command code
     */
    protected ServerMessageBlock2(final Configuration config, final int command) {
        this.config = config;
        this.command = command;
    }

    /**
     * Gets the configuration object for this message.
     *
     * @return the configuration object
     */
    protected Configuration getConfig() {
        return this.config;
    }

    @Override
    public void reset() {
        this.flags = 0;
        this.digest = null;
        this.sessionId = 0;
        this.treeId = 0;
    }

    /**
     * @return the command
     */
    @Override
    public final int getCommand() {
        return this.command;
    }

    /**
     * Gets the offset to the next compound command in the message chain.
     *
     * @return offset to next compound command
     */
    public final int getNextCommandOffset() {
        return this.nextCommand;
    }

    /**
     * Sets the read size for this message.
     *
     * @param readSize
     *            the readSize to set
     */
    public void setReadSize(final int readSize) {
        this.readSize = readSize;
    }

    /**
     * Checks whether this message is an asynchronous message.
     *
     * @return the async
     */
    public boolean isAsync() {
        return this.async;
    }

    /**
     * @param command
     *            the command to set
     */
    @Override
    public final void setCommand(final int command) {
        this.command = command;
    }

    /**
     * Gets the tree identifier for this message.
     *
     * @return the treeId
     */
    public final int getTreeId() {
        return this.treeId;
    }

    /**
     * Sets the tree identifier for this message.
     *
     * @param treeId
     *            the treeId to set
     */
    public final void setTreeId(final int treeId) {
        this.treeId = treeId;
        if (this.next != null) {
            this.next.setTreeId(treeId);
        }
    }

    /**
     * Gets the asynchronous identifier for this message.
     *
     * @return the asyncId
     */
    public final long getAsyncId() {
        return this.asyncId;
    }

    /**
     * Sets the asynchronous identifier for this message.
     *
     * @param asyncId
     *            the asyncId to set
     */
    public final void setAsyncId(final long asyncId) {
        this.asyncId = asyncId;
    }

    /**
     * Gets the credit count for this message.
     *
     * @return the credit
     */
    public final int getCredit() {
        return this.credit;
    }

    /**
     * Sets the credit count for this message.
     *
     * @param credit
     *            the credit to set
     */
    public final void setCredit(final int credit) {
        this.credit = credit;
    }

    /**
     * Gets the credit charge for this message.
     *
     * @return the creditCharge
     */
    public final int getCreditCharge() {
        return this.creditCharge;
    }

    @Override
    public void retainPayload() {
        this.retainPayload = true;
    }

    @Override
    public boolean isRetainPayload() {
        return this.retainPayload;
    }

    @Override
    public byte[] getRawPayload() {
        return this.rawPayload;
    }

    @Override
    public void setRawPayload(final byte[] rawPayload) {
        this.rawPayload = rawPayload;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlock#getDigest()
     */
    @Override
    public Smb2SigningDigest getDigest() {
        return this.digest;
    }

    /**
     *
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlock#setDigest(org.codelibs.jcifs.smb.internal.SMBSigningDigest)
     */
    @Override
    public void setDigest(final SMBSigningDigest digest) {
        this.digest = (Smb2SigningDigest) digest;
        if (this.next != null) {
            this.next.setDigest(digest);
        }
    }

    /**
     * Gets the status code for this message.
     *
     * @return the status
     */
    public final int getStatus() {
        return this.status;
    }

    /**
     * Gets the session identifier for this message.
     *
     * @return the sessionId
     */
    public long getSessionId() {
        return this.sessionId;
    }

    /**
     * @param sessionId
     *            the sessionId to set
     */
    @Override
    public final void setSessionId(final long sessionId) {
        this.sessionId = sessionId;
        if (this.next != null) {
            this.next.setSessionId(sessionId);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlock#setExtendedSecurity(boolean)
     */
    @Override
    public void setExtendedSecurity(final boolean extendedSecurity) {
        // ignore
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlock#setUid(int)
     */
    @Override
    public void setUid(final int uid) {
        // ignore
    }

    /**
     * Gets the flags for this message.
     *
     * @return the flags
     */
    public final int getFlags() {
        return this.flags;
    }

    /**
     * Adds the specified flags to this message.
     *
     * @param flag the flags to add
     */
    public final void addFlags(final int flag) {
        this.flags |= flag;
    }

    /**
     * Clears the specified flags from this message.
     *
     * @param flag the flags to clear
     */
    public final void clearFlags(final int flag) {
        this.flags &= ~flag;
    }

    /**
     * @return the mid
     */
    @Override
    public final long getMid() {
        return this.mid;
    }

    /**
     * @param mid
     *            the mid to set
     */
    @Override
    public final void setMid(final long mid) {
        this.mid = mid;
    }

    /**
     * Chains another message to this message for compound operations.
     *
     * @param n the message to chain
     * @return whether chaining was successful
     */
    public boolean chain(final ServerMessageBlock2 n) {
        if (this.next != null) {
            return this.next.chain(n);
        }

        n.addFlags(SMB2_FLAGS_RELATED_OPERATIONS);
        this.next = n;
        return true;
    }

    /**
     * Gets the next message in the compound chain.
     *
     * @return the next message or null if this is the last message
     */
    protected ServerMessageBlock2 getNext() {
        return this.next;
    }

    /**
     * Sets the next message in the compound chain.
     *
     * @param n the next message
     */
    protected void setNext(final ServerMessageBlock2 n) {
        this.next = n;
    }

    /**
     * @return the response
     */
    @Override
    public ServerMessageBlock2Response getResponse() {
        return null;
    }

    /**
     *
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlock#setResponse(org.codelibs.jcifs.smb.internal.CommonServerMessageBlockResponse)
     */
    @Override
    public void setResponse(final CommonServerMessageBlockResponse msg) {

    }

    /**
     * Gets the error data associated with this message.
     *
     * @return the errorData
     */
    public final byte[] getErrorData() {
        return this.errorData;
    }

    /**
     * Gets the error context count for this message.
     *
     * @return the errorContextCount
     */
    public final byte getErrorContextCount() {
        return this.errorContextCount;
    }

    /**
     * Gets the header start position for this message.
     *
     * @return the headerStart
     */
    public final int getHeaderStart() {
        return this.headerStart;
    }

    /**
     * Gets the total length of this message.
     *
     * @return the length
     */
    public final int getLength() {
        return this.length;
    }

    @Override
    public int encode(final byte[] dst, int dstIndex) {
        final int start = this.headerStart = dstIndex;
        dstIndex += writeHeaderWireFormat(dst, dstIndex);

        this.byteCount = writeBytesWireFormat(dst, dstIndex);
        dstIndex += this.byteCount;
        dstIndex += pad8(dstIndex);

        this.length = dstIndex - start;

        int len = this.length;

        if (this.next != null) {
            final int nextStart = dstIndex;
            dstIndex += this.next.encode(dst, dstIndex);
            final int off = nextStart - start;
            SMBUtil.writeInt4(off, dst, start + 20);
            len += dstIndex - nextStart;
        }

        if (this.digest != null) {
            this.digest.sign(dst, this.headerStart, this.length, this, getResponse());
        }

        if (isRetainPayload()) {
            this.rawPayload = new byte[len];
            System.arraycopy(dst, start, this.rawPayload, 0, len);
        }

        return len;
    }

    /**
     * Rounds up the size to 8-byte alignment.
     *
     * @param size the size to align
     * @return the aligned size
     */
    protected static final int size8(final int size) {
        return size8(size, 0);
    }

    /**
     * Rounds up the size to the specified alignment.
     *
     * @param size the size to align
     * @param align the alignment boundary
     * @return the aligned size
     */
    protected static final int size8(final int size, final int align) {

        int rem = size % 8 - align;
        if (rem == 0) {
            return size;
        }
        if (rem < 0) {
            rem = 8 + rem;
        }
        return size + 8 - rem;
    }

    /**
     * Calculates padding needed to align to 8-byte boundary from header start.
     *
     * @param dstIndex the current destination index
     * @return number of padding bytes needed
     */
    protected final int pad8(final int dstIndex) {
        final int fromHdr = dstIndex - this.headerStart;
        final int rem = fromHdr % 8;
        if (rem == 0) {
            return 0;
        }
        return 8 - rem;
    }

    @Override
    public int decode(final byte[] buffer, final int bufferIndex) throws SMBProtocolDecodingException {
        return decode(buffer, bufferIndex, false);
    }

    /**
     * Decodes the SMB2 message from the buffer.
     *
     * @param buffer the buffer containing the message
     * @param bufferIndex the starting position in the buffer
     * @param compound whether this is part of a compound chain
     * @return decoded length
     * @throws SMBProtocolDecodingException if decoding fails
     */
    public int decode(final byte[] buffer, int bufferIndex, final boolean compound) throws SMBProtocolDecodingException {
        final int start = this.headerStart = bufferIndex;
        bufferIndex += readHeaderWireFormat(buffer, bufferIndex);
        if (isErrorResponseStatus()) {
            bufferIndex += readErrorResponse(buffer, bufferIndex);
        } else {
            bufferIndex += readBytesWireFormat(buffer, bufferIndex);
        }

        this.length = bufferIndex - start;
        int len = this.length;

        if (this.nextCommand != 0) {
            // padding becomes part of signature if this is _PART_ of a compound chain
            len += pad8(bufferIndex);
        } else if (compound && this.nextCommand == 0 && this.readSize > 0) {
            // TODO: only apply this for actual compound chains, or is this correct for single responses, too?
            // 3.2.5.1.9 Handling Compounded Responses
            // The final response in the compounded response chain will have NextCommand equal to 0,
            // and it MUST be processed as an individual message of a size equal to the number of bytes
            // remaining in this receive.
            final int rem = this.readSize - this.length;
            len += rem;
        }

        haveResponse(buffer, start, len);

        if ((this.nextCommand != 0 && this.next != null) && (this.nextCommand % 8 != 0)) {
            throw new SMBProtocolDecodingException("Chained command is not aligned");
        }
        return len;
    }

    /**
     * Checks if this message has an error status.
     *
     * @return true if the message has an error status
     */
    protected boolean isErrorResponseStatus() {
        return getStatus() != 0;
    }

    /**
     * Called when a response has been received and decoded.
     *
     * @param buffer the buffer containing the response
     * @param start the starting position in the buffer
     * @param len the length of the response
     * @throws SMBProtocolDecodingException if processing fails
     */
    protected void haveResponse(final byte[] buffer, final int start, final int len) throws SMBProtocolDecodingException {
    }

    /**
     * Read error response from buffer
     *
     * @param buffer the buffer to read from
     * @param bufferIndex the starting index in the buffer
     * @return the number of bytes read
     * @throws SMBProtocolDecodingException if decoding fails
     */
    protected int readErrorResponse(final byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        final int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if (structureSize != 9) {
            throw new SMBProtocolDecodingException("Error structureSize should be 9");
        }
        this.errorContextCount = buffer[bufferIndex + 2];
        bufferIndex += 4;

        final int bc = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        if (bc > 0) {
            this.errorData = new byte[bc];
            System.arraycopy(buffer, bufferIndex, this.errorData, 0, bc);
            bufferIndex += bc;
        }
        return bufferIndex - start;
    }

    /**
     * Writes the SMB2 header to the wire format.
     *
     * @param dst the destination buffer
     * @param dstIndex the starting position in the buffer
     * @return number of bytes written
     */
    protected int writeHeaderWireFormat(final byte[] dst, final int dstIndex) {
        System.arraycopy(SMBUtil.SMB2_HEADER, 0, dst, dstIndex, SMBUtil.SMB2_HEADER.length);

        SMBUtil.writeInt2(this.creditCharge, dst, dstIndex + 6);
        SMBUtil.writeInt2(this.command, dst, dstIndex + 12);
        SMBUtil.writeInt2(this.credit, dst, dstIndex + 14);
        SMBUtil.writeInt4(this.flags, dst, dstIndex + 16);
        SMBUtil.writeInt4(this.nextCommand, dst, dstIndex + 20);
        SMBUtil.writeInt8(this.mid, dst, dstIndex + 24);

        if (this.async) {
            SMBUtil.writeInt8(this.asyncId, dst, dstIndex + 32);
        } else {
            // 4 reserved
            SMBUtil.writeInt4(this.treeId, dst, dstIndex + 36);
        }
        SMBUtil.writeInt8(this.sessionId, dst, dstIndex + 40);

        return Smb2Constants.SMB2_HEADER_LENGTH;
    }

    /**
     * Reads the SMB2 header from the wire format.
     *
     * @param buffer the buffer to read from
     * @param bufferIndex the starting position in the buffer
     * @return number of bytes read
     */
    protected int readHeaderWireFormat(final byte[] buffer, int bufferIndex) {
        // these are common between SYNC/ASYNC
        SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        SMBUtil.readInt2(buffer, bufferIndex);
        this.creditCharge = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;
        this.status = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.command = SMBUtil.readInt2(buffer, bufferIndex);
        this.credit = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;

        this.flags = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.nextCommand = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.mid = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;

        if ((this.flags & SMB2_FLAGS_ASYNC_COMMAND) == SMB2_FLAGS_ASYNC_COMMAND) {
            // async
            this.async = true;
            this.asyncId = SMBUtil.readInt8(buffer, bufferIndex);
            bufferIndex += 8;
        } else {
            // sync
            this.async = false;
            bufferIndex += 4; // reserved
            this.treeId = SMBUtil.readInt4(buffer, bufferIndex);
            bufferIndex += 4;
        }
        this.sessionId = SMBUtil.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        System.arraycopy(buffer, bufferIndex, this.signature, 0, 16);
        bufferIndex += 16;

        return Smb2Constants.SMB2_HEADER_LENGTH;
    }

    boolean isResponse() {
        return (this.flags & SMB2_FLAGS_SERVER_TO_REDIR) == SMB2_FLAGS_SERVER_TO_REDIR;
    }

    /**
     * Writes the message body to the wire format.
     *
     * @param dst the destination buffer
     * @param dstIndex the starting position in the buffer
     * @return number of bytes written
     */
    protected abstract int writeBytesWireFormat(byte[] dst, int dstIndex);

    /**
     * Reads the message body from the wire format.
     *
     * @param buffer the buffer to read from
     * @param bufferIndex the starting position in the buffer
     * @return number of bytes read
     * @throws SMBProtocolDecodingException if decoding fails
     */
    protected abstract int readBytesWireFormat(byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException;

    @Override
    public int hashCode() {
        return (int) this.mid;
    }

    @Override
    public boolean equals(final Object obj) {
        return obj instanceof ServerMessageBlock2 && ((ServerMessageBlock2) obj).mid == this.mid;
    }

    @Override
    public String toString() {
        String c = switch (this.command) {
        case SMB2_NEGOTIATE -> "SMB2_NEGOTIATE";
        case SMB2_SESSION_SETUP -> "SMB2_SESSION_SETUP";
        case SMB2_LOGOFF -> "SMB2_LOGOFF";
        case SMB2_TREE_CONNECT -> "SMB2_TREE_CONNECT";
        case SMB2_TREE_DISCONNECT -> "SMB2_TREE_DISCONNECT";
        case SMB2_CREATE -> "SMB2_CREATE";
        case SMB2_CLOSE -> "SMB2_CLOSE";
        case SMB2_FLUSH -> "SMB2_FLUSH";
        case SMB2_READ -> "SMB2_READ";
        case SMB2_WRITE -> "SMB2_WRITE";
        case SMB2_LOCK -> "SMB2_LOCK";
        case SMB2_IOCTL -> "SMB2_IOCTL";
        case SMB2_CANCEL -> "SMB2_CANCEL";
        case SMB2_ECHO -> "SMB2_ECHO";
        case SMB2_QUERY_DIRECTORY -> "SMB2_QUERY_DIRECTORY";
        case SMB2_CHANGE_NOTIFY -> "SMB2_CHANGE_NOTIFY";
        case SMB2_QUERY_INFO -> "SMB2_QUERY_INFO";
        case SMB2_SET_INFO -> "SMB2_SET_INFO";
        case SMB2_OPLOCK_BREAK -> "SMB2_OPLOCK_BREAK";
        default -> "UNKNOWN";
        };
        final String str = this.status == 0 ? "0" : SmbException.getMessageByCode(this.status);
        return ("command=" + c + ",status=" + str + ",flags=0x" + Hexdump.toHexString(this.flags, 4) + ",mid=" + this.mid + ",wordCount="
                + this.wordCount + ",byteCount=" + this.byteCount);
    }

}
