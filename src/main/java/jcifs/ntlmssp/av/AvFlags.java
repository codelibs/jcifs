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
package jcifs.ntlmssp.av;

import jcifs.internal.util.SMBUtil;

/**
 * NTLMSSP AV (Attribute-Value) pair representing flags information.
 * Contains flag values used in NTLM authentication attribute-value pairs.
 *
 * @author mbechler
 */
public class AvFlags extends AvPair {

    /**
     * Constructs an AV flags pair from raw bytes
     * @param raw the raw flag bytes
     */
    public AvFlags(final byte[] raw) {
        super(AvPair.MsvAvFlags, raw);
    }

    /**
     * Constructs an AV flags pair from integer flags
     * @param flags the flag values as integer
     */
    public AvFlags(final int flags) {
        this(encode(flags));
    }

    /**
     * Gets the flags as an integer value
     * @return flags
     */
    public int getFlags() {
        return SMBUtil.readInt4(this.getRaw(), 0);
    }

    private static byte[] encode(final int flags) {
        final byte[] raw = new byte[4];
        SMBUtil.writeInt4(flags, raw, 0);
        return raw;
    }

}
