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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Configuration;

/**
 *
 */
public class TransCallNamedPipe extends SmbComTransaction {

    private static final Logger log = LoggerFactory.getLogger(TransCallNamedPipe.class);

    private final byte[] pipeData;
    private final int pipeDataOff, pipeDataLen;

    /**
     *
     * @param config
     * @param pipeName
     * @param data
     * @param off
     * @param len
     */
    public TransCallNamedPipe(final Configuration config, final String pipeName, final byte[] data, final int off, final int len) {
        super(config, SMB_COM_TRANSACTION, TRANS_CALL_NAMED_PIPE);
        this.name = pipeName;
        this.pipeData = data;
        this.pipeDataOff = off;
        this.pipeDataLen = len;
        this.timeout = 0xFFFFFFFF;
        this.maxParameterCount = 0;
        this.maxDataCount = 0xFFFF;
        this.maxSetupCount = (byte) 0x00;
        this.setupCount = 2;
    }

    @Override
    protected int writeSetupWireFormat(final byte[] dst, int dstIndex) {
        dst[dstIndex] = this.getSubCommand();
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00;
        // this says "Transaction priority" in netmon
        dst[dstIndex++] = (byte) 0x00; // no FID
        dst[dstIndex++] = (byte) 0x00;
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
            log.debug("TransCallNamedPipe data too long for buffer");
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
        return ("TransCallNamedPipe[" + super.toString() + ",pipeName=" + this.name + "]");
    }
}
