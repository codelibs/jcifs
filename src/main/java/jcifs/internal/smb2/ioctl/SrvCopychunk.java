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
package jcifs.internal.smb2.ioctl;

import jcifs.Encodable;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 SRV_COPYCHUNK data structure. This structure represents a single chunk specification
 * for server-side copy operations.
 *
 * @author mbechler
 *
 */
public class SrvCopychunk implements Encodable {

    private final long sourceOffset;
    private final long targetOffset;
    private final int length;

    /**
     * @param soff
     * @param toff
     * @param len
     */
    public SrvCopychunk(final long soff, final long toff, final int len) {
        this.sourceOffset = soff;
        this.targetOffset = toff;
        this.length = len;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#encode(byte[], int)
     */
    @Override
    public int encode(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt8(this.sourceOffset, dst, dstIndex);
        dstIndex += 8;
        SMBUtil.writeInt8(this.targetOffset, dst, dstIndex);
        dstIndex += 8;
        SMBUtil.writeInt4(this.length, dst, dstIndex);
        dstIndex += 4;
        dstIndex += 4; // reserved
        return dstIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#size()
     */
    @Override
    public int size() {
        return 24;
    }

}
