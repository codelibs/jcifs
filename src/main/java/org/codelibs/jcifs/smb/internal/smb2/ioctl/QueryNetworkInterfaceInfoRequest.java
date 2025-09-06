/*
 * © 2025 CodeLibs, Inc.
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
package org.codelibs.jcifs.smb.internal.smb2.ioctl;

/**
 * Request data for FSCTL_QUERY_NETWORK_INTERFACE_INFO
 *
 * This IOCTL has no input data - the request is empty
 */
public class QueryNetworkInterfaceInfoRequest {

    /**
     * Create query network interface info request
     */
    public QueryNetworkInterfaceInfoRequest() {
        // No input data required for this IOCTL
    }

    /**
     * Get the size of this request (always 0)
     *
     * @return size in bytes
     */
    public int size() {
        return 0;
    }

    /**
     * Encode this request (no-op since there's no data)
     *
     * @param dst destination buffer
     * @param dstIndex starting offset
     * @return number of bytes written (always 0)
     */
    public int encode(byte[] dst, int dstIndex) {
        // No data to encode
        return 0;
    }
}
