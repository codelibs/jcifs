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

package jcifs.internal.smb1.trans;

import java.util.Enumeration;

import jcifs.Configuration;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;

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
     *
     */
    public static final byte TRANS2_FIND_FIRST2 = (byte) 0x01;
    /**
     *
     */
    public static final byte TRANS2_FIND_NEXT2 = (byte) 0x02;
    /**
     *
     */
    public static final byte TRANS2_QUERY_FS_INFORMATION = (byte) 0x03;
    /**
     *
     */
    public static final byte TRANS2_QUERY_PATH_INFORMATION = (byte) 0x05;
    /**
     *
     */
    public static final byte TRANS2_GET_DFS_REFERRAL = (byte) 0x10;
    /**
     *
     */
    public static final byte TRANS2_QUERY_FILE_INFORMATION = (byte) 0x07;
    /**
     *
     */
    public static final byte TRANS2_SET_FILE_INFORMATION = (byte) 0x08;

    /**
     *
     */
    public static final byte NET_SHARE_ENUM = (byte) 0x00;
    /**
     *
     */
    public static final byte NET_SERVER_ENUM2 = (byte) 0x68;
    /**
     *
     */
    public static final byte NET_SERVER_ENUM3 = (byte) 0xD7;

    /**
     *
     */
    public static final byte TRANS_PEEK_NAMED_PIPE = (byte) 0x23;
    /**
     *
     */
    public static final byte TRANS_WAIT_NAMED_PIPE = (byte) 0x53;
    /**
     *
     */
    public static final byte TRANS_CALL_NAMED_PIPE = (byte) 0x54;
    /**
     *
     */
    public static final byte TRANS_TRANSACT_NAMED_PIPE = (byte) 0x26;

    protected int primarySetupOffset;
    protected int secondaryParameterOffset;
    protected int parameterCount;
    protected int parameterOffset;
    protected int parameterDisplacement;
    protected int dataCount;
    protected int dataOffset;
    protected int dataDisplacement;

    protected int totalParameterCount;
    protected int totalDataCount;
    protected int maxParameterCount;
    protected int maxDataCount;
    protected byte maxSetupCount;
    protected int timeout = 0;
    protected int setupCount = 1;
    private byte subCommand;
    protected String name = "";
    protected int maxBufferSize; // set in SmbTransport.sendTransaction() before nextElement called

    private byte[] txn_buf;

    protected SmbComTransaction(final Configuration config, final byte command, final byte subCommand) {
        super(config, command);
        this.subCommand = subCommand;
        this.maxDataCount = config.getTransactionBufferSize() - 512;
        this.maxParameterCount = 1024;
        this.primarySetupOffset = PRIMARY_SETUP_OFFSET;
        this.secondaryParameterOffset = SECONDARY_PARAMETER_OFFSET;
    }

    /**
     * @param maxBufferSize
     *            the maxBufferSize to set
     */
    public final void setMaxBufferSize(final int maxBufferSize) {
        this.maxBufferSize = maxBufferSize;
    }

    /**
     * @param maxDataCount
     *            the maxDataCount to set
     */
    public final void setMaxDataCount(final int maxDataCount) {
        this.maxDataCount = maxDataCount;
    }

    /**
     * @param buffer
     */
    public void setBuffer(final byte[] buffer) {
        this.txn_buf = buffer;
    }

    /**
     * @return the txn_buf
     */
    public byte[] releaseBuffer() {
        final byte[] buf = this.txn_buf;
        this.txn_buf = null;
        return buf;
    }

    /**
     * @return the subCommand
     */
    public final byte getSubCommand() {
        return this.subCommand;
    }

    /**
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
     * @return
     */
    protected int pad(final int offset) {
        final int p = offset % getPadding();
        if (p == 0) {
            return 0;
        }
        return getPadding() - p;
    }

    /**
     *
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

    protected abstract int writeSetupWireFormat(byte[] dst, int dstIndex);

    protected abstract int writeParametersWireFormat(byte[] dst, int dstIndex);

    protected abstract int writeDataWireFormat(byte[] dst, int dstIndex);

    protected abstract int readSetupWireFormat(byte[] buffer, int bufferIndex, int len);

    protected abstract int readParametersWireFormat(byte[] buffer, int bufferIndex, int len);

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
