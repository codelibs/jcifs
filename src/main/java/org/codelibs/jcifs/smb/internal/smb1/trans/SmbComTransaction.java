/*
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

package org.codelibs.jcifs.smb.internal.smb1.trans;

import java.util.Enumeration;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Hexdump;

/**
 * Base class for SMB1 transaction request messages.
 * This abstract class provides the foundation for all SMB1 transaction commands, handling
 * parameter and data buffer encoding, multi-part transactions, and setup word management.
 */
public abstract class SmbComTransaction extends ServerMessageBlock implements Enumeration<SmbComTransaction> {

    // relative to headerStart
    private static final int PRIMARY_SETUP_OFFSET = 61;
    private static final int SECONDARY_PARAMETER_OFFSET = 51;

    static final int DISCONNECT_TID = 0x01;
    static final int ONE_WAY_TRANSACTION = 0x02;

    static final int PADDING_SIZE = 4;

    private final int tflags = 0x00;
    private int pad1 = 0;
    private int pad2 = 0;
    private boolean hasMore = true;
    private boolean isPrimary = true;
    private int bufParameterOffset;
    private int bufDataOffset;

    static final int TRANSACTION_BUF_SIZE = 0xFFFF;

    /**
     * SMB TRANS2 subcommand for finding first matching files
     */
    public static final byte TRANS2_FIND_FIRST2 = (byte) 0x01;
    /**
     * SMB TRANS2 subcommand for finding next matching files
     */
    public static final byte TRANS2_FIND_NEXT2 = (byte) 0x02;
    /**
     * SMB TRANS2 subcommand for querying file system information
     */
    public static final byte TRANS2_QUERY_FS_INFORMATION = (byte) 0x03;
    /**
     * SMB TRANS2 subcommand for querying path information
     */
    public static final byte TRANS2_QUERY_PATH_INFORMATION = (byte) 0x05;
    /**
     * SMB TRANS2 subcommand for getting DFS referrals
     */
    public static final byte TRANS2_GET_DFS_REFERRAL = (byte) 0x10;
    /**
     * SMB TRANS2 subcommand for querying file information
     */
    public static final byte TRANS2_QUERY_FILE_INFORMATION = (byte) 0x07;
    /**
     * SMB TRANS2 subcommand for setting file information
     */
    public static final byte TRANS2_SET_FILE_INFORMATION = (byte) 0x08;

    /**
     * Network share enumeration subcommand
     */
    public static final byte NET_SHARE_ENUM = (byte) 0x00;
    /**
     * Network server enumeration subcommand version 2
     */
    public static final byte NET_SERVER_ENUM2 = (byte) 0x68;
    /**
     * Network server enumeration subcommand version 3
     */
    public static final byte NET_SERVER_ENUM3 = (byte) 0xD7;

    /**
     * Transaction subcommand for peeking data from a named pipe
     */
    public static final byte TRANS_PEEK_NAMED_PIPE = (byte) 0x23;
    /**
     * Transaction subcommand for waiting on a named pipe
     */
    public static final byte TRANS_WAIT_NAMED_PIPE = (byte) 0x53;
    /**
     * Transaction subcommand for calling a named pipe
     */
    public static final byte TRANS_CALL_NAMED_PIPE = (byte) 0x54;
    /**
     * Transaction subcommand for transacting with a named pipe
     */
    public static final byte TRANS_TRANSACT_NAMED_PIPE = (byte) 0x26;

    /** Offset to the setup words in the primary request */
    protected int primarySetupOffset;
    /** Offset to the parameters in secondary requests */
    protected int secondaryParameterOffset;
    /** Number of parameter bytes being sent in this request */
    protected int parameterCount;
    /** Offset from the start of the SMB header to the parameter bytes */
    protected int parameterOffset;
    /** Displacement of these parameter bytes from the start of the total parameter block */
    protected int parameterDisplacement;
    /** Number of data bytes being sent in this request */
    protected int dataCount;
    /** Offset from the start of the SMB header to the data bytes */
    protected int dataOffset;
    /** Displacement of these data bytes from the start of the total data block */
    protected int dataDisplacement;

    /** Total number of parameter bytes to be sent */
    protected int totalParameterCount;
    /** Total number of data bytes to be sent */
    protected int totalDataCount;
    /** Maximum number of parameter bytes the server should return */
    protected int maxParameterCount;
    /** Maximum number of data bytes the server should return */
    protected int maxDataCount;
    /** Maximum number of setup words the server should return */
    protected byte maxSetupCount;
    /** Timeout in milliseconds to wait for the transaction to complete */
    protected int timeout = 0;
    /** Number of setup words in this request */
    protected int setupCount = 1;
    private byte subCommand;
    /** The transaction name for named pipe transactions */
    protected String name = "";
    /** Maximum buffer size set in SmbTransport.sendTransaction() before nextElement called */
    protected int maxBufferSize; // set in SmbTransport.sendTransaction() before nextElement called

    private byte[] txn_buf;

    /**
     * Constructs a transaction request.
     *
     * @param config the configuration to use
     * @param command the SMB command code
     * @param subCommand the transaction subcommand code
     */
    protected SmbComTransaction(final Configuration config, final byte command, final byte subCommand) {
        super(config, command);
        this.subCommand = subCommand;
        this.maxDataCount = config.getTransactionBufferSize() - 512;
        this.maxParameterCount = 1024;
        this.primarySetupOffset = PRIMARY_SETUP_OFFSET;
        this.secondaryParameterOffset = SECONDARY_PARAMETER_OFFSET;
    }

    /**
     * Sets the maximum buffer size for this transaction
     * @param maxBufferSize
     *            the maxBufferSize to set
     */
    public final void setMaxBufferSize(final int maxBufferSize) {
        this.maxBufferSize = maxBufferSize;
    }

    /**
     * Sets the maximum data count for this transaction
     * @param maxDataCount
     *            the maxDataCount to set
     */
    public final void setMaxDataCount(final int maxDataCount) {
        this.maxDataCount = maxDataCount;
    }

    /**
     * Sets the transaction buffer
     * @param buffer
     *            the transaction buffer to use
     */
    public void setBuffer(final byte[] buffer) {
        this.txn_buf = buffer;
    }

    /**
     * Releases and returns the transaction buffer
     * @return the txn_buf
     */
    public byte[] releaseBuffer() {
        final byte[] buf = this.txn_buf;
        this.txn_buf = null;
        return buf;
    }

    /**
     * Gets the transaction subcommand
     * @return the subCommand
     */
    public final byte getSubCommand() {
        return this.subCommand;
    }

    /**
     * Sets the transaction subcommand
     * @param subCommand
     *            the subCommand to set
     */
    public final void setSubCommand(final byte subCommand) {
        this.subCommand = subCommand;
    }

    @Override
    public void reset() {
        super.reset();
        this.isPrimary = this.hasMore = true;
    }

    /**
     * Resets the transaction state with key and last name
     * @param key
     *            the key to use for reset
     * @param lastName
     *            the last name for the transaction
     */
    protected void reset(final int key, final String lastName) {
        reset();
    }

    @Override
    public boolean hasMoreElements() {
        return this.hasMore;
    }

    @Override
    public SmbComTransaction nextElement() {
        if (this.isPrimary) {
            this.isPrimary = false;

            // primarySetupOffset
            // SMB_COM_TRANSACTION: 61 = 32 SMB header + 1 (word count) + 28 (fixed words)
            // SMB_COM_NT_TRANSACTION: 69 = 32 SMB header + 1 (word count) + 38 (fixed words)
            this.parameterOffset = this.primarySetupOffset;

            // 2* setupCount
            this.parameterOffset += this.setupCount * 2;
            this.parameterOffset += 2; // ByteCount

            if (this.getCommand() == SMB_COM_TRANSACTION && !isResponse()) {
                this.parameterOffset += stringWireLength(this.name, this.parameterOffset);
            }

            this.pad1 = pad(this.parameterOffset);
            this.parameterOffset += this.pad1;

            this.totalParameterCount = writeParametersWireFormat(this.txn_buf, this.bufParameterOffset);
            this.bufDataOffset = this.totalParameterCount; // data comes right after data

            int available = this.maxBufferSize - this.parameterOffset;
            this.parameterCount = Math.min(this.totalParameterCount, available);
            available -= this.parameterCount;

            this.dataOffset = this.parameterOffset + this.parameterCount;
            this.pad2 = this.pad(this.dataOffset);
            this.dataOffset += this.pad2;

            this.totalDataCount = writeDataWireFormat(this.txn_buf, this.bufDataOffset);

            this.dataCount = Math.min(this.totalDataCount, available);
        } else {
            if (this.getCommand() != SMB_COM_NT_TRANSACT) {
                this.setCommand(SMB_COM_TRANSACTION_SECONDARY);
            } else {
                this.setCommand(SMB_COM_NT_TRANSACT_SECONDARY);
            }
            // totalParameterCount and totalDataCount are set ok from primary

            this.parameterOffset = SECONDARY_PARAMETER_OFFSET;
            if (this.totalParameterCount - this.parameterDisplacement > 0) {
                this.pad1 = this.pad(this.parameterOffset);
                this.parameterOffset += this.pad1;
            }

            // caclulate parameterDisplacement before calculating new parameterCount
            this.parameterDisplacement += this.parameterCount;

            int available = this.maxBufferSize - this.parameterOffset - this.pad1;
            this.parameterCount = Math.min(this.totalParameterCount - this.parameterDisplacement, available);
            available -= this.parameterCount;

            this.dataOffset = this.parameterOffset + this.parameterCount;
            this.pad2 = this.pad(this.dataOffset);
            this.dataOffset += this.pad2;

            this.dataDisplacement += this.dataCount;

            available -= this.pad2;
            this.dataCount = Math.min(this.totalDataCount - this.dataDisplacement, available);
        }
        if (this.parameterDisplacement + this.parameterCount >= this.totalParameterCount
                && this.dataDisplacement + this.dataCount >= this.totalDataCount) {
            this.hasMore = false;
        }
        return this;
    }

    /**
     * Calculates padding needed for the given offset
     * @param offset
     *            the current offset
     * @return padding size in bytes
     */
    protected int pad(final int offset) {
        final int p = offset % getPadding();
        if (p == 0) {
            return 0;
        }
        return getPadding() - p;
    }

    /**
     * Gets the padding size for alignment
     * @return padding size
     */
    public int getPadding() {
        return PADDING_SIZE;
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        SMBUtil.writeInt2(this.totalParameterCount, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.totalDataCount, dst, dstIndex);
        dstIndex += 2;
        if (this.getCommand() != SMB_COM_TRANSACTION_SECONDARY) {
            SMBUtil.writeInt2(this.maxParameterCount, dst, dstIndex);
            dstIndex += 2;
            SMBUtil.writeInt2(this.maxDataCount, dst, dstIndex);
            dstIndex += 2;
            dst[dstIndex] = this.maxSetupCount;
            dstIndex++;
            dst[dstIndex++] = (byte) 0x00; // Reserved1
            SMBUtil.writeInt2(this.tflags, dst, dstIndex);
            dstIndex += 2;
            SMBUtil.writeInt4(this.timeout, dst, dstIndex);
            dstIndex += 4;
            dst[dstIndex++] = (byte) 0x00; // Reserved2
            dst[dstIndex++] = (byte) 0x00;
        }
        SMBUtil.writeInt2(this.parameterCount, dst, dstIndex);
        dstIndex += 2;
        // writeInt2(( parameterCount == 0 ? 0 : parameterOffset ), dst, dstIndex );
        SMBUtil.writeInt2(this.parameterOffset, dst, dstIndex);
        dstIndex += 2;
        if (this.getCommand() == SMB_COM_TRANSACTION_SECONDARY) {
            SMBUtil.writeInt2(this.parameterDisplacement, dst, dstIndex);
            dstIndex += 2;
        }
        SMBUtil.writeInt2(this.dataCount, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.dataCount == 0 ? 0 : this.dataOffset, dst, dstIndex);
        dstIndex += 2;
        if (this.getCommand() == SMB_COM_TRANSACTION_SECONDARY) {
            SMBUtil.writeInt2(this.dataDisplacement, dst, dstIndex);
            dstIndex += 2;
        } else {
            dst[dstIndex] = (byte) this.setupCount;
            dstIndex++;
            dst[dstIndex++] = (byte) 0x00; // Reserved3
            dstIndex += writeSetupWireFormat(dst, dstIndex);
        }

        return dstIndex - start;
    }

    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        if (this.getCommand() == SMB_COM_TRANSACTION && !isResponse()) {
            dstIndex += writeString(this.name, dst, dstIndex);
        }

        int end = dstIndex + this.pad1;

        if (this.parameterCount > 0) {
            System.arraycopy(this.txn_buf, this.bufParameterOffset, dst, this.headerStart + this.parameterOffset, this.parameterCount);
            end = Math.max(end, this.headerStart + this.parameterOffset + this.parameterCount + this.pad2);
        }

        if (this.dataCount > 0) {
            System.arraycopy(this.txn_buf, this.bufDataOffset, dst, this.headerStart + this.dataOffset, this.dataCount);
            this.bufDataOffset += this.dataCount;
            end = Math.max(end, this.headerStart + this.dataOffset + this.dataCount);
        }

        return end - start;
    }

    @Override
    protected int readParameterWordsWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

    @Override
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

    /**
     * Writes setup data in wire format
     * @param dst destination buffer
     * @param dstIndex starting index in destination buffer
     * @return number of bytes written
     */
    protected abstract int writeSetupWireFormat(byte[] dst, int dstIndex);

    /**
     * Writes parameters in wire format
     * @param dst destination buffer
     * @param dstIndex starting index in destination buffer
     * @return number of bytes written
     */
    protected abstract int writeParametersWireFormat(byte[] dst, int dstIndex);

    /**
     * Writes data in wire format
     * @param dst destination buffer
     * @param dstIndex starting index in destination buffer
     * @return number of bytes written
     */
    protected abstract int writeDataWireFormat(byte[] dst, int dstIndex);

    /**
     * Reads setup data from wire format
     * @param buffer source buffer
     * @param bufferIndex starting index in source buffer
     * @param len length of data to read
     * @return number of bytes read
     */
    protected abstract int readSetupWireFormat(byte[] buffer, int bufferIndex, int len);

    /**
     * Reads parameters from wire format
     * @param buffer source buffer
     * @param bufferIndex starting index in source buffer
     * @param len length of data to read
     * @return number of bytes read
     */
    protected abstract int readParametersWireFormat(byte[] buffer, int bufferIndex, int len);

    /**
     * Reads data from wire format
     * @param buffer source buffer
     * @param bufferIndex starting index in source buffer
     * @param len length of data to read
     * @return number of bytes read
     */
    protected abstract int readDataWireFormat(byte[] buffer, int bufferIndex, int len);

    @Override
    public String toString() {
        return (super.toString() + ",totalParameterCount=" + this.totalParameterCount + ",totalDataCount=" + this.totalDataCount
                + ",maxParameterCount=" + this.maxParameterCount + ",maxDataCount=" + this.maxDataCount + ",maxSetupCount="
                + (int) this.maxSetupCount + ",flags=0x" + Hexdump.toHexString(this.tflags, 2) + ",timeout=" + this.timeout
                + ",parameterCount=" + this.parameterCount + ",parameterOffset=" + this.parameterOffset + ",parameterDisplacement="
                + this.parameterDisplacement + ",dataCount=" + this.dataCount + ",dataOffset=" + this.dataOffset + ",dataDisplacement="
                + this.dataDisplacement + ",setupCount=" + this.setupCount + ",pad=" + this.pad1 + ",pad1=" + this.pad2);
    }

}
