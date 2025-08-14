/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.internal.smb1;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Configuration;
import jcifs.RuntimeCIFSException;
import jcifs.SmbConstants;
import jcifs.internal.CommonServerMessageBlock;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.CommonServerMessageBlockResponse;
import jcifs.internal.RequestWithPath;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.SMBSigningDigest;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.SmbException;
import jcifs.util.Hexdump;
import jcifs.util.Strings;

/**
 * Base class for all SMB1/CIFS protocol message blocks.
 * This abstract class provides the fundamental structure and common functionality for SMB1 request
 * and response messages, including header fields, message encoding/decoding, and wire format handling.
 */
public abstract class ServerMessageBlock implements CommonServerMessageBlockRequest, CommonServerMessageBlockResponse, RequestWithPath {

    private static final Logger log = LoggerFactory.getLogger(ServerMessageBlock.class);

    /*
     * These are all the smbs supported by this library. This includes requests
     * and well as their responses for each type however the actuall implementations
     * of the readXxxWireFormat and writeXxxWireFormat methods may not be in
     * place. For example at the time of this writing the readXxxWireFormat
     * for requests and the writeXxxWireFormat for responses are not implemented
     * and simply return 0. These would need to be completed for a server
     * implementation.
     */

    /**
     * SMB command to create a directory.
     */
    public static final byte SMB_COM_CREATE_DIRECTORY = (byte) 0x00;

    /**
     * SMB command to delete a directory.
     */
    public static final byte SMB_COM_DELETE_DIRECTORY = (byte) 0x01;

    /**
     * SMB command to close a file handle.
     */
    public static final byte SMB_COM_CLOSE = (byte) 0x04;

    /**
     * SMB command to delete a file.
     */
    public static final byte SMB_COM_DELETE = (byte) 0x06;

    /**
     * SMB command to rename a file.
     */
    public static final byte SMB_COM_RENAME = (byte) 0x07;

    /**
     * SMB command to query file information.
     */
    public static final byte SMB_COM_QUERY_INFORMATION = (byte) 0x08;

    /**
     * SMB command to set file information.
     */
    public static final byte SMB_COM_SET_INFORMATION = (byte) 0x09;

    /**
     * SMB command to write data to a file.
     */
    public static final byte SMB_COM_WRITE = (byte) 0x0B;

    /**
     * SMB command to check if a directory exists.
     */
    public static final byte SMB_COM_CHECK_DIRECTORY = (byte) 0x10;

    /**
     * SMB command to seek within a file.
     */
    public static final byte SMB_COM_SEEK = (byte) 0x12;

    /**
     * SMB command for file locking operations.
     */
    public static final byte SMB_COM_LOCKING_ANDX = (byte) 0x24;

    /**
     * SMB command for transaction operations.
     */
    public static final byte SMB_COM_TRANSACTION = (byte) 0x25;

    /**
     * SMB command for secondary transaction operations.
     */
    public static final byte SMB_COM_TRANSACTION_SECONDARY = (byte) 0x26;

    /**
     * SMB command to move a file.
     */
    public static final byte SMB_COM_MOVE = (byte) 0x2A;

    /**
     * SMB command for echo/ping operations.
     */
    public static final byte SMB_COM_ECHO = (byte) 0x2B;

    /**
     * SMB command to open a file with extended attributes.
     */
    public static final byte SMB_COM_OPEN_ANDX = (byte) 0x2D;

    /**
     * SMB command to read from a file with extended attributes.
     */
    public static final byte SMB_COM_READ_ANDX = (byte) 0x2E;

    /**
     * SMB command to write to a file with extended attributes.
     */
    public static final byte SMB_COM_WRITE_ANDX = (byte) 0x2F;

    /**
     * SMB command for extended transaction operations.
     */
    public static final byte SMB_COM_TRANSACTION2 = (byte) 0x32;

    /**
     * SMB command to close a find operation.
     */
    public static final byte SMB_COM_FIND_CLOSE2 = (byte) 0x34;

    /**
     * SMB command to disconnect from a tree share.
     */
    public static final byte SMB_COM_TREE_DISCONNECT = (byte) 0x71;

    /**
     * SMB command to negotiate protocol dialect.
     */
    public static final byte SMB_COM_NEGOTIATE = (byte) 0x72;

    /**
     * SMB command to setup a session with extended attributes.
     */
    public static final byte SMB_COM_SESSION_SETUP_ANDX = (byte) 0x73;

    /**
     * SMB command to logoff from a session with extended attributes.
     */
    public static final byte SMB_COM_LOGOFF_ANDX = (byte) 0x74;

    /**
     * SMB command to connect to a tree share with extended attributes.
     */
    public static final byte SMB_COM_TREE_CONNECT_ANDX = (byte) 0x75;

    /**
     * SMB command for NT transaction operations.
     */
    public static final byte SMB_COM_NT_TRANSACT = (byte) 0xA0;

    /**
     * SMB command to cancel an NT operation.
     */
    public static final byte SMB_COM_NT_CANCEL = (byte) 0xA4;

    /**
     * SMB command for secondary NT transaction operations.
     */
    public static final byte SMB_COM_NT_TRANSACT_SECONDARY = (byte) 0xA1;

    /**
     * SMB command to create or open a file with NT extended attributes.
     */
    public static final byte SMB_COM_NT_CREATE_ANDX = (byte) 0xA2;

    /*
     * Some fields specify the offset from the beginning of the header. This
     * field should be used for calculating that. This would likely be zero
     * but an implemantation that encorporates the transport header(for
     * efficiency) might use a different initial bufferIndex. For example,
     * to eliminate copying data when writing NbtSession data one might
     * manage that 4 byte header specifically and therefore the initial
     * bufferIndex, and thus headerStart, would be 4).(NOTE: If one where
     * looking for a way to improve perfomance this is precisly what you
     * would want to do as the jcifs.netbios.SocketXxxputStream classes
     * arraycopy all data read or written into a new buffer shifted over 4!)
     */

    private byte command, flags;
    protected int headerStart, length, batchLevel, errorCode, flags2, pid, uid, mid, wordCount, byteCount;
    protected int tid = 0xFFFF;
    private boolean useUnicode, forceUnicode, extendedSecurity;
    private volatile boolean received;
    private int signSeq;
    private boolean verifyFailed;
    protected String path;
    protected SMB1SigningDigest digest = null;
    private ServerMessageBlock response;

    private final Configuration config;

    private Long expiration;

    private Exception exception;

    private boolean isError;

    private byte[] rawPayload;

    private boolean retainPayload;

    private String fullPath;
    private String server;
    private String domain;

    private Integer overrideTimeout;

    protected ServerMessageBlock(final Configuration config) {
        this(config, (byte) 0);
    }

    protected ServerMessageBlock(final Configuration config, final byte command) {
        this(config, command, null);
    }

    protected ServerMessageBlock(final Configuration config, final byte command, final String path) {
        this.config = config;
        this.command = command;
        this.path = path;
        this.flags = (byte) (SmbConstants.FLAGS_PATH_NAMES_CASELESS | SmbConstants.FLAGS_PATH_NAMES_CANONICALIZED);
        this.pid = config.getPid();
        this.batchLevel = 0;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size() {
        return 0;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockResponse#isAsync()
     */
    @Override
    public boolean isAsync() {
        return false;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#isResponseAsync()
     */
    @Override
    public boolean isResponseAsync() {
        return false;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#getOverrideTimeout()
     */
    @Override
    public final Integer getOverrideTimeout() {
        return this.overrideTimeout;
    }

    /**
     * Sets the timeout override for this message block
     * @param overrideTimeout
     *            the overrideTimeout to set
     */
    public final void setOverrideTimeout(final Integer overrideTimeout) {
        this.overrideTimeout = overrideTimeout;
    }

    /**
     *
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#getNext()
     */
    @Override
    public ServerMessageBlock getNext() {
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#allowChain(jcifs.internal.CommonServerMessageBlockRequest)
     */
    @Override
    public boolean allowChain(final CommonServerMessageBlockRequest next) {
        return false;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#split()
     */
    @Override
    public CommonServerMessageBlockRequest split() {
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockRequest#createCancel()
     */
    @Override
    public CommonServerMessageBlockRequest createCancel() {
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockResponse#getNextResponse()
     */
    @Override
    public CommonServerMessageBlockResponse getNextResponse() {
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.CommonServerMessageBlockResponse#prepare(jcifs.internal.CommonServerMessageBlockRequest)
     */
    @Override
    public void prepare(final CommonServerMessageBlockRequest next) {

    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Request#getCreditCost()
     */
    @Override
    public int getCreditCost() {
        return 1;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#getGrantedCredits()
     */
    @Override
    public int getGrantedCredits() {
        return 1;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Request#setRequestCredits(int)
     */
    @Override
    public void setRequestCredits(final int credits) {

    }

    /**
     * @return the command
     */
    @Override
    public final int getCommand() {
        return this.command;
    }

    /**
     * @param command
     *            the command to set
     */
    @Override
    public final void setCommand(final int command) {
        this.command = (byte) command;
    }

    /**
     * Gets the byte count of this message block
     * @return the byteCount
     */
    public final int getByteCount() {
        return this.byteCount;
    }

    /**
     * Gets the total length of this message block
     * @return the length
     */
    public final int getLength() {
        return this.length;
    }

    /**
     * Checks if Unicode encoding is forced for this message
     * @return the forceUnicode
     */
    public boolean isForceUnicode() {
        return this.forceUnicode;
    }

    /**
     * Gets the SMB message flags
     * @return the flags
     */
    public final byte getFlags() {
        return this.flags;
    }

    /**
     * Sets the SMB message flags
     * @param flags
     *            the flags to set
     */
    public final void setFlags(final byte flags) {
        this.flags = flags;
    }

    /**
     * Gets the SMB message flags2 field
     * @return the flags2
     */
    public final int getFlags2() {
        return this.flags2;
    }

    /**
     * Sets the SMB message flags2 field
     * @param fl
     *            the flags2 to set
     */
    public final void setFlags2(final int fl) {
        this.flags2 = fl;
    }

    /**
     * Adds flags to the flags2 field using bitwise OR
     * @param fl flags to add
     */
    public final void addFlags2(final int fl) {
        this.flags2 |= fl;
    }

    /**
     * Removes flags from the flags2 field using bitwise AND NOT
     * @param fl flags to remove
     */
    public final void remFlags2(final int fl) {
        this.flags2 &= ~fl;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#setResolveInDfs(boolean)
     */
    @Override
    public void setResolveInDfs(final boolean resolve) {
        if (resolve) {
            addFlags2(SmbConstants.FLAGS2_RESOLVE_PATHS_IN_DFS);
        } else {
            remFlags2(SmbConstants.FLAGS2_RESOLVE_PATHS_IN_DFS);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#isResolveInDfs()
     */
    @Override
    public boolean isResolveInDfs() {
        return (getFlags() & SmbConstants.FLAGS2_RESOLVE_PATHS_IN_DFS) == SmbConstants.FLAGS2_RESOLVE_PATHS_IN_DFS;
    }

    /**
     * @return the errorCode
     */
    @Override
    public final int getErrorCode() {
        return this.errorCode;
    }

    /**
     * Sets the error code for this message block
     * @param errorCode
     *            the errorCode to set
     */
    public final void setErrorCode(final int errorCode) {
        this.errorCode = errorCode;
    }

    /**
     * @return the path
     */
    @Override
    public final String getPath() {
        return this.path;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#getFullUNCPath()
     */
    @Override
    public String getFullUNCPath() {
        return this.fullPath;
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
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#getServer()
     */
    @Override
    public String getServer() {
        return this.server;
    }

    /**
     *
     * {@inheritDoc}
     *
     * @see jcifs.internal.RequestWithPath#setFullUNCPath(java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public void setFullUNCPath(final String domain, final String server, final String fullPath) {
        this.domain = domain;
        this.server = server;
        this.fullPath = fullPath;
    }

    /**
     * @param path
     *            the path to set
     */
    @Override
    public final void setPath(final String path) {
        this.path = path;
    }

    /**
     * @return the digest
     */
    @Override
    public final SMB1SigningDigest getDigest() {
        return this.digest;
    }

    /**
     * @param digest
     *            the digest to set
     */
    @Override
    public final void setDigest(final SMBSigningDigest digest) {
        this.digest = (SMB1SigningDigest) digest;
    }

    /**
     * Checks if extended security is enabled for this message
     * @return the extendedSecurity
     */
    public boolean isExtendedSecurity() {
        return this.extendedSecurity;
    }

    @Override
    public final void setSessionId(final long sessionId) {
        // ignore
    }

    /**
     * @param extendedSecurity
     *            the extendedSecurity to set
     */
    @Override
    public void setExtendedSecurity(final boolean extendedSecurity) {
        this.extendedSecurity = extendedSecurity;
    }

    /**
     * Checks if Unicode encoding is enabled for this message
     * @return the useUnicode
     */
    public final boolean isUseUnicode() {
        return this.useUnicode;
    }

    /**
     * Sets whether to use Unicode encoding for this message
     * @param useUnicode
     *            the useUnicode to set
     */
    public final void setUseUnicode(final boolean useUnicode) {
        this.useUnicode = useUnicode;
    }

    /**
     * @return the received
     */
    @Override
    public final boolean isReceived() {
        return this.received;
    }

    @Override
    public final void clearReceived() {
        this.received = false;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#received()
     */
    @Override
    public void received() {
        this.received = true;
        synchronized (this) {
            notifyAll();
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#exception(java.lang.Exception)
     */
    @Override
    public void exception(final Exception e) {
        this.exception = e;
        synchronized (this) {
            notifyAll();
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#error()
     */
    @Override
    public void error() {
        this.isError = true;
        synchronized (this) {
            notifyAll();
        }
    }

    /**
     * @return the response
     */
    @Override
    public ServerMessageBlock getResponse() {
        return this.response;
    }

    /**
     * Returns a message block that ignores disconnection
     * @return null
     */
    public CommonServerMessageBlock ignoreDisconnect() {
        return this;
    }

    /**
     * @param response
     *            the response to set
     */
    @Override
    public final void setResponse(final CommonServerMessageBlockResponse response) {
        if (!(response instanceof ServerMessageBlock)) {
            throw new IllegalArgumentException();
        }
        this.response = (ServerMessageBlock) response;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Request#isCancel()
     */
    @Override
    public boolean isCancel() {
        return false;
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
        this.mid = (int) mid;
    }

    /**
     * Gets the tree connection identifier
     * @return the tid
     */
    public final int getTid() {
        return this.tid;
    }

    /**
     * @param tid
     *            the tid to set
     */
    @Override
    public final void setTid(final int tid) {
        this.tid = tid;
    }

    /**
     * Gets the process identifier
     * @return the pid
     */
    public final int getPid() {
        return this.pid;
    }

    /**
     * Sets the process identifier
     * @param pid
     *            the pid to set
     */
    public final void setPid(final int pid) {
        this.pid = pid;
    }

    /**
     * Gets the user identifier
     * @return the uid
     */
    public final int getUid() {
        return this.uid;
    }

    /**
     * @param uid
     *            the uid to set
     */
    @Override
    public final void setUid(final int uid) {
        this.uid = uid;
    }

    /**
     * Gets the signature sequence number
     * @return the signSeq
     */
    public int getSignSeq() {
        return this.signSeq;
    }

    /**
     * Sets the signature sequence number
     * @param signSeq
     *            the signSeq to set
     */
    public final void setSignSeq(final int signSeq) {
        this.signSeq = signSeq;
    }

    /**
     * @return the verifyFailed
     */
    @Override
    public boolean isVerifyFailed() {
        return this.verifyFailed;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#getException()
     */
    @Override
    public Exception getException() {
        return this.exception;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#isError()
     */
    @Override
    public boolean isError() {
        return this.isError;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#getRawPayload()
     */
    @Override
    public byte[] getRawPayload() {
        return this.rawPayload;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#setRawPayload(byte[])
     */
    @Override
    public void setRawPayload(final byte[] rawPayload) {
        this.rawPayload = rawPayload;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#isRetainPayload()
     */
    @Override
    public boolean isRetainPayload() {
        return this.retainPayload;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#retainPayload()
     */
    @Override
    public void retainPayload() {
        this.retainPayload = true;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#getExpiration()
     */
    @Override
    public Long getExpiration() {
        return this.expiration;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#setExpiration(java.lang.Long)
     */
    @Override
    public void setExpiration(final Long exp) {
        this.expiration = exp;
    }

    /**
     * Gets the configuration object for this message block
     * @return the config
     */
    protected final Configuration getConfig() {
        return this.config;
    }

    /**
     *
     */
    @Override
    public void reset() {
        this.flags = (byte) (SmbConstants.FLAGS_PATH_NAMES_CASELESS | SmbConstants.FLAGS_PATH_NAMES_CANONICALIZED);
        this.flags2 = 0;
        this.errorCode = 0;
        this.received = false;
        this.digest = null;
        this.uid = 0;
        this.tid = 0xFFFF;
    }

    /**
     *
     * {@inheritDoc}
     *
     * @see jcifs.util.transport.Response#verifySignature(byte[], int, int)
     */
    @Override
    public boolean verifySignature(final byte[] buffer, final int i, final int size) {
        /*
         * Verification fails (w/ W2K3 server at least) if status is not 0. This
         * suggests MS doesn't compute the signature (correctly) for error responses
         * (perhaps for DOS reasons).
         */
        /*
         * Looks like the failure case also is just reflecting back the signature we sent
         */

        /**
         * Maybe this is related:
         *
         * If signing is not active, the SecuritySignature field of the SMB Header for all messages sent, except
         * the SMB_COM_SESSION_SETUP_ANDX Response (section 2.2.4.53.2), MUST be set to
         * 0x0000000000000000. For the SMB_COM_SESSION_SETUP_ANDX Response, the SecuritySignature
         * field of the SMB Header SHOULD<226> be set to the SecuritySignature received in the
         * SMB_COM_SESSION_SETUP_ANDX Request (section 2.2.4.53.1).
         */
        if (this.digest != null && getErrorCode() == 0) {
            final boolean verify = this.digest.verify(buffer, i, size, 0, this);
            this.verifyFailed = verify;
            return !verify;
        }
        return true;
    }

    protected int writeString(final String str, final byte[] dst, final int dstIndex) {
        return writeString(str, dst, dstIndex, this.useUnicode);
    }

    protected int writeString(final String str, final byte[] dst, int dstIndex, final boolean unicode) {
        final int start = dstIndex;
        if (unicode) {
            // Unicode requires word alignment
            if ((dstIndex - this.headerStart) % 2 != 0) {
                dst[dstIndex++] = (byte) '\0';
            }
            System.arraycopy(Strings.getUNIBytes(str), 0, dst, dstIndex, str.length() * 2);
            dstIndex += str.length() * 2;
            dst[dstIndex] = (byte) '\0';
            dstIndex++;
            dst[dstIndex++] = (byte) '\0';
        } else {
            final byte[] b = Strings.getOEMBytes(str, this.getConfig());
            System.arraycopy(b, 0, dst, dstIndex, b.length);
            dstIndex += b.length;
            dst[dstIndex] = (byte) '\0';
            dstIndex++;
        }
        return dstIndex - start;
    }

    /**
     * Reads a null-terminated string from the buffer
     * @param src source buffer
     * @param srcIndex starting index in the buffer
     * @return read string
     */
    public String readString(final byte[] src, final int srcIndex) {
        return readString(src, srcIndex, 255, this.useUnicode);
    }

    /**
     * Reads a null-terminated string from the buffer with specified encoding
     * @param src source buffer
     * @param srcIndex starting index in the buffer
     * @param maxLen maximum length to read
     * @param unicode whether to use Unicode encoding
     * @return read string
     */
    public String readString(final byte[] src, int srcIndex, final int maxLen, final boolean unicode) {
        if (unicode) {
            // Unicode requires word alignment
            if ((srcIndex - this.headerStart) % 2 != 0) {
                srcIndex++;
            }
            return Strings.fromUNIBytes(src, srcIndex, Strings.findUNITermination(src, srcIndex, maxLen));
        }

        return Strings.fromOEMBytes(src, srcIndex, Strings.findTermination(src, srcIndex, maxLen), getConfig());
    }

    /**
     * Reads a null-terminated string from the buffer with bounds checking
     * @param src source buffer
     * @param srcIndex starting index in the buffer
     * @param srcEnd ending index boundary
     * @param maxLen maximum length to read
     * @param unicode whether to use Unicode encoding
     * @return read string
     */
    public String readString(final byte[] src, int srcIndex, final int srcEnd, final int maxLen, final boolean unicode) {
        if (unicode) {
            // Unicode requires word alignment
            if ((srcIndex - this.headerStart) % 2 != 0) {
                srcIndex++;
            }
            return Strings.fromUNIBytes(src, srcIndex, Strings.findUNITermination(src, srcIndex, maxLen));
        }

        return Strings.fromOEMBytes(src, srcIndex, Strings.findTermination(src, srcIndex, maxLen), getConfig());
    }

    /**
     * Calculates the wire format length of a string
     * @param str string to measure
     * @param offset current buffer offset for alignment calculation
     * @return string length
     */
    public int stringWireLength(final String str, final int offset) {
        int len = str.length() + 1;
        if (this.useUnicode) {
            len = str.length() * 2 + 2;
            len = offset % 2 != 0 ? len + 1 : len;
        }
        return len;
    }

    protected int readStringLength(final byte[] src, final int srcIndex, final int max) {
        int len = 0;
        while (src[srcIndex + len] != (byte) 0x00) {
            if (len++ > max) {
                throw new RuntimeCIFSException("zero termination not found: " + this);
            }
        }
        return len;
    }

    @Override
    public int encode(final byte[] dst, int dstIndex) {
        final int start = this.headerStart = dstIndex;

        dstIndex += writeHeaderWireFormat(dst, dstIndex);
        this.wordCount = writeParameterWordsWireFormat(dst, dstIndex + 1);
        dst[dstIndex] = (byte) (this.wordCount / 2 & 0xFF);
        dstIndex++;
        dstIndex += this.wordCount;
        this.wordCount /= 2;
        this.byteCount = writeBytesWireFormat(dst, dstIndex + 2);
        dst[dstIndex++] = (byte) (this.byteCount & 0xFF);
        dst[dstIndex++] = (byte) (this.byteCount >> 8 & 0xFF);
        dstIndex += this.byteCount;

        this.length = dstIndex - start;

        if (this.digest != null) {
            this.digest.sign(dst, this.headerStart, this.length, this, this.response);
        }

        return this.length;
    }

    @Override
    public int decode(final byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
        final int start = this.headerStart = bufferIndex;

        bufferIndex += readHeaderWireFormat(buffer, bufferIndex);

        this.wordCount = buffer[bufferIndex];
        bufferIndex++;
        if (this.wordCount != 0) {
            int n = readParameterWordsWireFormat(buffer, bufferIndex);
            if ((n != this.wordCount * 2) && log.isTraceEnabled()) {
                log.trace("wordCount * 2=" + this.wordCount * 2 + " but readParameterWordsWireFormat returned " + n);
            }
            bufferIndex += this.wordCount * 2;
        }

        this.byteCount = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        if (this.byteCount != 0) {
            int n = readBytesWireFormat(buffer, bufferIndex);
            if ((n != this.byteCount) && log.isTraceEnabled()) {
                log.trace("byteCount=" + this.byteCount + " but readBytesWireFormat returned " + n);
            }
            // Don't think we can rely on n being correct here. Must use byteCount.
            // Last paragraph of section 3.13.3 eludes to this.

            bufferIndex += this.byteCount;
        }

        final int len = bufferIndex - start;
        this.length = len;

        if (isRetainPayload()) {
            final byte[] payload = new byte[len];
            System.arraycopy(buffer, 4, payload, 0, len);
            setRawPayload(payload);
        }

        if (!verifySignature(buffer, 4, len)) {
            throw new SMBProtocolDecodingException("Signature verification failed for " + this.getClass().getName());
        }

        return len;
    }

    protected int writeHeaderWireFormat(final byte[] dst, int dstIndex) {
        System.arraycopy(SMBUtil.SMB_HEADER, 0, dst, dstIndex, SMBUtil.SMB_HEADER.length);
        dst[dstIndex + SmbConstants.CMD_OFFSET] = this.command;
        dst[dstIndex + SmbConstants.FLAGS_OFFSET] = this.flags;
        SMBUtil.writeInt2(this.flags2, dst, dstIndex + SmbConstants.FLAGS_OFFSET + 1);
        dstIndex += SmbConstants.TID_OFFSET;
        SMBUtil.writeInt2(this.tid, dst, dstIndex);
        SMBUtil.writeInt2(this.pid, dst, dstIndex + 2);
        SMBUtil.writeInt2(this.uid, dst, dstIndex + 4);
        SMBUtil.writeInt2(this.mid, dst, dstIndex + 6);
        return SmbConstants.SMB1_HEADER_LENGTH;
    }

    protected int readHeaderWireFormat(final byte[] buffer, final int bufferIndex) {
        this.command = buffer[bufferIndex + SmbConstants.CMD_OFFSET];
        this.errorCode = SMBUtil.readInt4(buffer, bufferIndex + SmbConstants.ERROR_CODE_OFFSET);
        this.flags = buffer[bufferIndex + SmbConstants.FLAGS_OFFSET];
        this.flags2 = SMBUtil.readInt2(buffer, bufferIndex + SmbConstants.FLAGS_OFFSET + 1);
        this.tid = SMBUtil.readInt2(buffer, bufferIndex + SmbConstants.TID_OFFSET);
        this.pid = SMBUtil.readInt2(buffer, bufferIndex + SmbConstants.TID_OFFSET + 2);
        this.uid = SMBUtil.readInt2(buffer, bufferIndex + SmbConstants.TID_OFFSET + 4);
        this.mid = SMBUtil.readInt2(buffer, bufferIndex + SmbConstants.TID_OFFSET + 6);
        return SmbConstants.SMB1_HEADER_LENGTH;
    }

    protected boolean isResponse() {
        return (this.flags & SmbConstants.FLAGS_RESPONSE) == SmbConstants.FLAGS_RESPONSE;
    }

    /*
     * For this packet deconstruction technique to work for
     * other networking protocols the InputStream may need
     * to be passed to the readXxxWireFormat methods. This is
     * actually purer. However, in the case of smb we know the
     * wordCount and byteCount. And since every subclass of
     * ServerMessageBlock would have to perform the same read
     * operation on the input stream, we might as will pull that
     * common functionality into the superclass and read wordCount
     * and byteCount worth of data.
     *
     * We will still use the readXxxWireFormat return values to
     * indicate how many bytes(note: readParameterWordsWireFormat
     * returns bytes read and not the number of words(but the
     * wordCount member DOES store the number of words)) we
     * actually read. Incedentally this is important to the
     * AndXServerMessageBlock class that needs to potentially
     * read in another smb's parameter words and bytes based on
     * information in it's andxCommand, andxOffset, ...etc.
     */

    protected abstract int writeParameterWordsWireFormat(byte[] dst, int dstIndex);

    protected abstract int writeBytesWireFormat(byte[] dst, int dstIndex);

    protected abstract int readParameterWordsWireFormat(byte[] buffer, int bufferIndex);

    protected abstract int readBytesWireFormat(byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException;

    @Override
    public int hashCode() {
        return this.mid;
    }

    @Override
    public boolean equals(final Object obj) {
        return obj instanceof ServerMessageBlock && ((ServerMessageBlock) obj).mid == this.mid;
    }

    @Override
    public String toString() {
        String c = switch (this.command) {
        case SMB_COM_NEGOTIATE -> "SMB_COM_NEGOTIATE";
        case SMB_COM_SESSION_SETUP_ANDX -> "SMB_COM_SESSION_SETUP_ANDX";
        case SMB_COM_TREE_CONNECT_ANDX -> "SMB_COM_TREE_CONNECT_ANDX";
        case SMB_COM_QUERY_INFORMATION -> "SMB_COM_QUERY_INFORMATION";
        case SMB_COM_CHECK_DIRECTORY -> "SMB_COM_CHECK_DIRECTORY";
        case SMB_COM_TRANSACTION -> "SMB_COM_TRANSACTION";
        case SMB_COM_TRANSACTION2 -> "SMB_COM_TRANSACTION2";
        case SMB_COM_TRANSACTION_SECONDARY -> "SMB_COM_TRANSACTION_SECONDARY";
        case SMB_COM_FIND_CLOSE2 -> "SMB_COM_FIND_CLOSE2";
        case SMB_COM_TREE_DISCONNECT -> "SMB_COM_TREE_DISCONNECT";
        case SMB_COM_LOGOFF_ANDX -> "SMB_COM_LOGOFF_ANDX";
        case SMB_COM_ECHO -> "SMB_COM_ECHO";
        case SMB_COM_MOVE -> "SMB_COM_MOVE";
        case SMB_COM_RENAME -> "SMB_COM_RENAME";
        case SMB_COM_DELETE -> "SMB_COM_DELETE";
        case SMB_COM_DELETE_DIRECTORY -> "SMB_COM_DELETE_DIRECTORY";
        case SMB_COM_NT_CREATE_ANDX -> "SMB_COM_NT_CREATE_ANDX";
        case SMB_COM_OPEN_ANDX -> "SMB_COM_OPEN_ANDX";
        case SMB_COM_READ_ANDX -> "SMB_COM_READ_ANDX";
        case SMB_COM_CLOSE -> "SMB_COM_CLOSE";
        case SMB_COM_WRITE_ANDX -> "SMB_COM_WRITE_ANDX";
        case SMB_COM_CREATE_DIRECTORY -> "SMB_COM_CREATE_DIRECTORY";
        case SMB_COM_NT_TRANSACT -> "SMB_COM_NT_TRANSACT";
        case SMB_COM_NT_TRANSACT_SECONDARY -> "SMB_COM_NT_TRANSACT_SECONDARY";
        case SMB_COM_LOCKING_ANDX -> "SMB_COM_LOCKING_ANDX";
        default -> "UNKNOWN";
        };
        final String str = this.errorCode == 0 ? "0" : SmbException.getMessageByCode(this.errorCode);
        return ("command=" + c + ",received=" + this.received + ",errorCode=" + str + ",flags=0x"
                + Hexdump.toHexString(this.flags & 0xFF, 4) + ",flags2=0x" + Hexdump.toHexString(this.flags2, 4) + ",signSeq="
                + this.signSeq + ",tid=" + this.tid + ",pid=" + this.pid + ",uid=" + this.uid + ",mid=" + this.mid + ",wordCount="
                + this.wordCount + ",byteCount=" + this.byteCount);
    }

}
