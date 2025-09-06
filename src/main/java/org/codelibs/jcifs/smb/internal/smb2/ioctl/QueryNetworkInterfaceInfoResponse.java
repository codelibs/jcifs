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

import java.util.ArrayList;
import java.util.List;

import org.codelibs.jcifs.smb.Decodable;
import org.codelibs.jcifs.smb.internal.smb2.multichannel.NetworkInterfaceInfo;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * Response data for FSCTL_QUERY_NETWORK_INTERFACE_INFO
 */
public class QueryNetworkInterfaceInfoResponse implements Decodable {

    private List<NetworkInterfaceInfo> interfaces;

    /**
     * Create query network interface info response
     */
    public QueryNetworkInterfaceInfoResponse() {
        this.interfaces = new ArrayList<>();
    }

    /**
     * Get the list of network interfaces
     *
     * @return list of network interface information
     */
    public List<NetworkInterfaceInfo> getInterfaces() {
        return interfaces;
    }

    /**
     * Set the list of network interfaces
     *
     * @param interfaces list of network interface information
     */
    public void setInterfaces(List<NetworkInterfaceInfo> interfaces) {
        this.interfaces = interfaces;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode(byte[] buffer, int bufferIndex, int len) {
        int start = bufferIndex;
        int end = start + len;
        interfaces.clear();

        while (bufferIndex < end && (bufferIndex + 152) <= end) {
            // Read Next field to determine if there are more entries
            int next = SMBUtil.readInt4(buffer, bufferIndex);

            NetworkInterfaceInfo info = NetworkInterfaceInfo.decode(buffer, bufferIndex);
            if (info != null) {
                interfaces.add(info);
            }

            if (next == 0) {
                // Last entry - advance by the full structure size
                bufferIndex += 152;
                break;
            }

            // Move to next entry based on Next offset
            bufferIndex += next;
        }

        return bufferIndex - start;
    }
}
