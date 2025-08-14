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
package jcifs.util;

import jcifs.Encodable;

/**
 * Interface for objects that can be encoded to byte arrays.
 * Provides standardized method for converting objects to their binary representation.
 *
 * @author mbechler
 */
public class ByteEncodable implements Encodable {

    private final byte[] bytes;
    private final int off;
    private final int len;

    /**
     * @param b
     * @param off
     * @param len
     */
    public ByteEncodable(final byte[] b, final int off, final int len) {
        this.bytes = b;
        this.off = off;
        this.len = len;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#size()
     */
    @Override
    public int size() {
        return this.len;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#encode(byte[], int)
     */
    @Override
    public int encode(final byte[] dst, final int dstIndex) {
        System.arraycopy(this.bytes, this.off, dst, dstIndex, this.len);
        return this.len;
    }

}
