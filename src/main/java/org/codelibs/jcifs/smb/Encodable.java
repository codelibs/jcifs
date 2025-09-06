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
package org.codelibs.jcifs.smb;

/**
 * Interface for objects that can be encoded to a byte buffer.
 * This interface provides methods for serializing data to SMB protocol messages.
 *
 * @author mbechler
 */
public interface Encodable {

    /**
     * Encodes this object into the specified byte array.
     *
     * @param dst the destination byte array to encode into
     * @param dstIndex the starting index in the destination array
     * @return encoded length
     */
    int encode(byte[] dst, int dstIndex);

    /**
     * Returns the size in bytes that this object will occupy when encoded.
     *
     * @return the encoded size
     */
    int size();

}
