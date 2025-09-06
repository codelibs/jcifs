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
import org.codelibs.jcifs.smb.FileEntry;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * Base class for SMB1 transaction response messages.
 * This abstract class handles the common functionality for all SMB1 transaction responses,
 * including parameter and data buffer management, multi-part responses, and enumeration support.
 */
public abstract class SmbComTransactionResponse extends ServerMessageBlock implements Enumeration<SmbComTransactionResponse> {

    // relative to headerStart
    static final int SETUP_OFFSET = 61;

    static final int DISCONNECT_TID = 0x01;
    static final int ONE_WAY_TRANSACTION = 0x02;

    private int pad;
    private int pad1;
    private boolean parametersDone, dataDone;

    /** Total number of parameter bytes the server is returning */
    protected int totalParameterCount;
    /** Total number of data bytes the server is returning */
    protected int totalDataCount;
    /** Number of parameter bytes in this response */
    protected int parameterCount;
    /** Offset from the start of the SMB header to the parameter bytes */
    protected int parameterOffset;
    /** Displacement of these parameter bytes from the start of the total parameter block */
    protected int parameterDisplacement;
    /** Offset from the start of the SMB header to the data bytes */
    protected int dataOffset;
    /** Displacement of these data bytes from the start of the total data block */
    protected int dataDisplacement;
    /** Number of setup words in this response */
    protected int setupCount;
    /** Start position of parameter data in the buffer */
    protected int bufParameterStart;
    /** Start position of data bytes in the buffer */
    protected int bufDataStart;

    int dataCount;
    byte subCommand;
    volatile boolean hasMore = true;
    volatile boolean isPrimary = true;
    byte[] txn_buf;

    /* for doNetEnum and doFindFirstNext */
    private int status;
    private int numEntries;
    private FileEntry[] results;

    /**
     * Constructs a transaction response.
     *
     * @param config the configuration to use
     */
    protected SmbComTransactionResponse(final Configuration config) {
        super(config);
    }

    /**
     * Constructs a transaction response with specified command.
     *
     * @param config the configuration to use
     * @param command the SMB command code
     * @param subcommand the transaction subcommand code
     */
    protected SmbComTransactionResponse(final Configuration config, final byte command, final byte subcommand) {
        super(config, command);
        this.subCommand = subcommand;
    }

    /**
     * Gets the data count for this transaction response
     * @return the dataCount
     */
    protected final int getDataCount() {
        return this.dataCount;
    }

    /**
     * Sets the data count for this transaction response
     * @param dataCount
     *            the dataCount to set
     */
    public final void setDataCount(final int dataCount) {
        this.dataCount = dataCount;
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

    /**
     * Gets the response status code
     * @return the status
     */
    public final int getStatus() {
        return this.status;
    }

    /**
     * Sets the response status code
     * @param status
     *            the status to set
     */
    protected final void setStatus(final int status) {
        this.status = status;
    }

    /**
     * Gets the number of entries in the response
     * @return the numEntries
     */
    public final int getNumEntries() {
        return this.numEntries;
    }

    /**
     * Sets the number of entries in the response
     * @param numEntries
     *            the numEntries to set
     */
    protected final void setNumEntries(final int numEntries) {
        this.numEntries = numEntries;
    }

    /**
     * Gets the file entry results from the response
     * @return the results
     */
    public final FileEntry[] getResults() {
        return this.results;
    }

    /**
     * Sets the file entry results for the response
     * @param results
     *            the results to set
     */
    protected final void setResults(final FileEntry[] results) {
        this.results = results;
    }

    @Override
    public void reset() {
        super.reset();
        this.bufDataStart = 0;
        this.isPrimary = this.hasMore = true;
        this.parametersDone = this.dataDone = false;
    }

    @Override
    public boolean hasMoreElements() {
        return this.errorCode == 0 && this.hasMore;
    }

    @Override
    public SmbComTransactionResponse nextElement() {
        if (this.isPrimary) {
            this.isPrimary = false;
        }
        return this;
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock#decode(byte[], int)
     */
    @Override
    public int decode(final byte[] buffer, final int bufferIndex) throws SMBProtocolDecodingException {
        final int len = super.decode(buffer, bufferIndex);
        if (this.byteCount == 0) {
            // otherwise hasMore may not be correctly set
            readBytesWireFormat(buffer, len + bufferIndex);
        }
        nextElement();
        return len;
    }

    @Override
    protected int readParameterWordsWireFormat(final byte[] buffer, int bufferIndex) {
        final int start = bufferIndex;

        this.totalParameterCount = SMBUtil.readInt2(buffer, bufferIndex);
        if (this.bufDataStart == 0) {
            this.bufDataStart = this.totalParameterCount;
        }
        bufferIndex += 2;
        this.totalDataCount = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 4; // Reserved
        this.parameterCount = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.parameterOffset = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.parameterDisplacement = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.dataCount = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.dataOffset = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.dataDisplacement = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.setupCount = buffer[bufferIndex] & 0xFF;
        bufferIndex += 2;

        return bufferIndex - start;
    }

    @Override
    protected int readBytesWireFormat(final byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
        this.pad = this.pad1 = 0;
        if (this.parameterCount > 0) {
            bufferIndex += this.pad = this.parameterOffset - (bufferIndex - this.headerStart);
            System.arraycopy(buffer, bufferIndex, this.txn_buf, this.bufParameterStart + this.parameterDisplacement, this.parameterCount);
            bufferIndex += this.parameterCount;
        }
        if (this.dataCount > 0) {
            bufferIndex += this.pad1 = this.dataOffset - (bufferIndex - this.headerStart);
            System.arraycopy(buffer, bufferIndex, this.txn_buf, this.bufDataStart + this.dataDisplacement, this.dataCount);
            bufferIndex += this.dataCount;
        }

        /*
         * Check to see if the entire transaction has been
         * read. If so call the read methods.
         */

        if (!this.parametersDone && this.parameterDisplacement + this.parameterCount == this.totalParameterCount) {
            this.parametersDone = true;
        }

        if (!this.dataDone && this.dataDisplacement + this.dataCount == this.totalDataCount) {
            this.dataDone = true;
        }

        if (this.parametersDone && this.dataDone) {
            readParametersWireFormat(this.txn_buf, this.bufParameterStart, this.totalParameterCount);
            readDataWireFormat(this.txn_buf, this.bufDataStart, this.totalDataCount);
            this.hasMore = false;
        }

        return this.pad + this.parameterCount + this.pad1 + this.dataCount;
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
     * @throws SMBProtocolDecodingException if decoding fails
     */
    protected abstract int readParametersWireFormat(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException;

    /**
     * Reads data from wire format
     * @param buffer source buffer
     * @param bufferIndex starting index in source buffer
     * @param len length of data to read
     * @return number of bytes read
     * @throws SMBProtocolDecodingException if decoding fails
     */
    protected abstract int readDataWireFormat(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException;

    @Override
    public String toString() {
        return (super.toString() + ",totalParameterCount=" + this.totalParameterCount + ",totalDataCount=" + this.totalDataCount
                + ",parameterCount=" + this.parameterCount + ",parameterOffset=" + this.parameterOffset + ",parameterDisplacement="
                + this.parameterDisplacement + ",dataCount=" + this.dataCount + ",dataOffset=" + this.dataOffset + ",dataDisplacement="
                + this.dataDisplacement + ",setupCount=" + this.setupCount + ",pad=" + this.pad + ",pad1=" + this.pad1);
    }
}
