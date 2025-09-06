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
 * Base class for NDR (Network Data Representation) objects used in DCE/RPC communication.
 * This abstract class defines the interface for encoding and decoding NDR data types.
 */
public abstract class NdrObject {

    /**
     * Default constructor for NDR object
     */
    public NdrObject() {
        // Default constructor
    }

    /**
     * Encodes this NDR object into the specified buffer
     * @param dst the destination buffer for encoding
     * @throws NdrException if encoding fails
     */
    public abstract void encode(NdrBuffer dst) throws NdrException;

    /**
     * Decodes this NDR object from the specified buffer
     * @param src the source buffer for decoding
     * @throws NdrException if decoding fails
     */
    public abstract void decode(NdrBuffer src) throws NdrException;
}
