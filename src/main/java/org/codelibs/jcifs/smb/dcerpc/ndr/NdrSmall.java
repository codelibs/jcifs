/* org.codelibs.jcifs.smb msrpc client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Eric Glass" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb.dcerpc.ndr;

/**
 * Represents an NDR small integer (1 byte unsigned) for DCE/RPC communication.
 * This class encapsulates a single byte value (0-255) in NDR format.
 */
public class NdrSmall extends NdrObject {

    /**
     * The small integer value (0-255)
     */
    public int value;

    /**
     * Constructs an NdrSmall with the specified value
     * @param value the small integer value (will be masked to 0-255 range)
     */
    public NdrSmall(final int value) {
        this.value = value & 0xFF;
    }

    @Override
    public void encode(final NdrBuffer dst) throws NdrException {
        dst.enc_ndr_small(this.value);
    }

    @Override
    public void decode(final NdrBuffer src) throws NdrException {
        this.value = src.dec_ndr_small();
    }
}
