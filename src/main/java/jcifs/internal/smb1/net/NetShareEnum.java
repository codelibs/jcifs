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

package jcifs.internal.smb1.net;

import java.io.UnsupportedEncodingException;

import jcifs.Configuration;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.util.SMBUtil;

/**
 *
 *
 */
public class NetShareEnum extends SmbComTransaction {

    private static final String DESCR = "WrLeh\u0000B13BWz\u0000";

    /**
     *
     * @param config
     */
    public NetShareEnum(final Configuration config) {
        super(config, SMB_COM_TRANSACTION, NET_SHARE_ENUM);
        this.name = "\\PIPE\\LANMAN";
        this.maxParameterCount = 8;

        // maxDataCount = 4096; why was this set?
        this.maxSetupCount = (byte) 0x00;
        this.setupCount = 0;
        this.timeout = 5000;
    }

    @Override
    protected int writeSetupWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int writeParametersWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        byte[] descr;

        try {
            descr = DESCR.getBytes("ASCII");
        } catch (final UnsupportedEncodingException uee) {
            return 0;
        }

        SMBUtil.writeInt2(NET_SHARE_ENUM, dst, dstIndex);
        dstIndex += 2;
        System.arraycopy(descr, 0, dst, dstIndex, descr.length);
        dstIndex += descr.length;
        SMBUtil.writeInt2(0x0001, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.maxDataCount, dst, dstIndex);
        dstIndex += 2;

        return dstIndex - start;
    }

    @Override
    protected int writeDataWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int readSetupWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
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
        return ("NetShareEnum[" + super.toString() + "]");
    }
}
