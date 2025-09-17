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
package org.codelibs.jcifs.smb.internal.smb1.com;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.smb1.AndXServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB1 COM_LOCKING_ANDX command implementation.
 *
 * This command locks or unlocks byte ranges within a file. It can also
 * be used to break oplocks and change oplock levels.
 *
 * @author mbechler
 */
public class SmbComLockingAndX extends AndXServerMessageBlock {

    private int fid;
    private byte typeOfLock;
    private byte newOpLockLevel;
    private long timeout;
    private LockingAndXRange[] locks;
    private LockingAndXRange[] unlocks;
    private boolean largeFile;

    /**
     * Creates a new SMB1 locking request for file byte-range locking operations.
     *
     * @param config the CIFS configuration
     */
    public SmbComLockingAndX(final Configuration config) {
        super(config);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock#writeParameterWordsWireFormat(byte[], int)
     */
    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        SMBUtil.writeInt2(this.fid, dst, dstIndex);
        dstIndex += 2;

        dst[dstIndex] = this.typeOfLock;
        dst[dstIndex + 1] = this.newOpLockLevel;
        dstIndex += 2;

        SMBUtil.writeInt4(this.timeout, dst, dstIndex);
        dstIndex += 4;

        SMBUtil.writeInt2(this.unlocks != null ? this.unlocks.length : 0, dst, dstIndex);
        dstIndex += 2;

        SMBUtil.writeInt2(this.locks != null ? this.locks.length : 0, dst, dstIndex);
        dstIndex += 2;
        return start - dstIndex;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock#readParameterWordsWireFormat(byte[], int)
     */
    @Override
    protected int readParameterWordsWireFormat(final byte[] buffer, int bufferIndex) {
        final int start = bufferIndex;

        this.fid = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        this.typeOfLock = buffer[bufferIndex];

        if ((this.typeOfLock & 0x10) == 0x10) {
            this.largeFile = true;
        }

        this.newOpLockLevel = buffer[bufferIndex + 1];
        bufferIndex += 2;

        this.timeout = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        final int nunlocks = SMBUtil.readInt2(buffer, bufferIndex);
        this.unlocks = new LockingAndXRange[nunlocks];
        bufferIndex += 2;

        final int nlocks = SMBUtil.readInt2(buffer, bufferIndex);
        this.locks = new LockingAndXRange[nlocks];
        bufferIndex += 2;
        return start - bufferIndex;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        if (this.unlocks != null) {
            for (final LockingAndXRange lockingAndXRange : this.unlocks) {
                dstIndex += lockingAndXRange.encode(dst, dstIndex);
            }
        }
        if (this.locks != null) {
            for (final LockingAndXRange lockingAndXRange : this.locks) {
                dstIndex += lockingAndXRange.encode(dst, dstIndex);
            }
        }
        return start - dstIndex;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat(final byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        for (int i = 0; i < this.unlocks.length; i++) {
            this.unlocks[i] = createLockRange();
            bufferIndex += this.unlocks[i].decode(buffer, bufferIndex, buffer.length);
        }

        for (int i = 0; i < this.locks.length; i++) {
            this.locks[i] = createLockRange();
            bufferIndex += this.locks[i].decode(buffer, bufferIndex, buffer.length);
        }

        return start - bufferIndex;
    }

    /**
     * @return
     */
    private LockingAndXRange createLockRange() {
        return new LockingAndXRange(this.largeFile);
    }

    @Override
    public String toString() {
        return ("SmbComLockingAndX[" + super.toString() + ",fid=" + this.fid + ",typeOfLock=" + this.typeOfLock + ",newOplockLevel="
                + this.newOpLockLevel + "]");
    }

}
