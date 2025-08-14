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
package jcifs.internal.dfs;

import java.nio.charset.StandardCharsets;

import jcifs.Encodable;
import jcifs.internal.util.SMBUtil;

/**
 * DFS (Distributed File System) referral request buffer encoder.
 * Creates encoded request buffers for DFS referral requests, specifying the maximum
 * referral level and target path for which DFS resolution is requested.
 *
 * @author mbechler
 */
public class DfsReferralRequestBuffer implements Encodable {

    private final int maxReferralLevel;
    private final String path;

    /**
     * Constructs a DFS referral request buffer
     *
     * @param filename the DFS path to request referral for
     * @param maxReferralLevel the maximum referral level to request
     */
    public DfsReferralRequestBuffer(final String filename, final int maxReferralLevel) {
        this.path = filename;
        this.maxReferralLevel = maxReferralLevel;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#size()
     */
    @Override
    public int size() {
        return 4 + 2 * this.path.length();
    }

    @Override
    public int encode(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt2(this.maxReferralLevel, dst, dstIndex);
        dstIndex += 2;
        final byte[] pathBytes = this.path.getBytes(StandardCharsets.UTF_16LE);
        System.arraycopy(pathBytes, 0, dst, dstIndex, pathBytes.length);
        dstIndex += pathBytes.length;
        SMBUtil.writeInt2(0, dst, dstIndex);
        dstIndex += 2; // null terminator
        return dstIndex - start;
    }
}
