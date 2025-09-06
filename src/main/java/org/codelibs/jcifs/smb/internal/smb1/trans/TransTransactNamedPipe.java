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

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SMB1 transaction subcommand for transacting with a named pipe.
 *
 * This class implements the TRANS_TRANSACT_NAMED_PIPE transaction which
 * combines writing data to a pipe and reading the response in a single operation.
 * This is more efficient than separate write and read operations.
 */
public class TransTransactNamedPipe extends SmbComTransaction {

    private static final Logger log = LoggerFactory.getLogger(TransTransactNamedPipe.class);

    private final byte[] pipeData;
    private final int pipeFid, pipeDataOff, pipeDataLen;

    /**
     * Constructs a transaction request for a named pipe operation.
     *
     * @param config the configuration to use
     * @param fid the file ID of the named pipe
     * @param data the data buffer to send
     * @param off the offset in the data buffer
     * @param len the length of data to send
     */
    public TransTransactNamedPipe(final Configuration config, final int fid, final byte[] data, final int off, final int len) {
        super(config, SMB_COM_TRANSACTION, TRANS_TRANSACT_NAMED_PIPE);
        this.pipeFid = fid;
        this.pipeData = data;
        this.pipeDataOff = off;
        this.pipeDataLen = len;
        this.maxParameterCount = 0;
        this.maxDataCount = 0xFFFF;
        this.maxSetupCount = (byte) 0x00;
        this.setupCount = 2;
        this.name = "\\PIPE\\";
    }

    @Override
    protected int writeSetupWireFormat(final byte[] dst, int dstIndex) {
        dst[dstIndex] = this.getSubCommand();
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00;
        SMBUtil.writeInt2(this.pipeFid, dst, dstIndex);
        dstIndex += 2;
        return 4;
    }

    @Override
    protected int readSetupWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    protected int writeParametersWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int writeDataWireFormat(final byte[] dst, final int dstIndex) {
        if (dst.length - dstIndex < this.pipeDataLen) {
            log.debug("TransTransactNamedPipe data too long for buffer");
            return 0;
        }
        System.arraycopy(this.pipeData, this.pipeDataOff, dst, dstIndex, this.pipeDataLen);
        return this.pipeDataLen;
    }

    @Override
    protected int readParametersWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    protected int readDataWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    public String toString() {
        return ("TransTransactNamedPipe[" + super.toString() + ",pipeFid=" + this.pipeFid + "]");
    }
}
