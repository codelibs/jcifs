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
package org.codelibs.jcifs.smb.internal.smb2.multichannel;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * Information about a network interface for SMB3 Multi-Channel
 */
public class NetworkInterfaceInfo {

    private int interfaceIndex;
    private int capability;
    private int linkSpeed; // In units of 1 Mbps
    private byte[] sockaddrStorage;
    private InetAddress address;
    private boolean ipv6;
    private boolean rssCapable; // Receive Side Scaling
    private boolean rdmaCapable;

    /**
     * Create network interface info
     *
     * @param address interface address
     * @param linkSpeed link speed in Mbps
     */
    public NetworkInterfaceInfo(InetAddress address, int linkSpeed) {
        this.address = address;
        this.linkSpeed = linkSpeed;
        this.ipv6 = address.getAddress().length == 16;
        this.capability = 0;

        // Check for RSS capability
        this.rssCapable = checkRSSCapability();
        if (rssCapable) {
            this.capability |= Smb2ChannelCapabilities.NETWORK_INTERFACE_CAP_RSS;
        }

        // RDMA capability would require OS-specific detection
        this.rdmaCapable = false;
    }

    /**
     * Get the interface index
     *
     * @return interface index
     */
    public int getInterfaceIndex() {
        return interfaceIndex;
    }

    /**
     * Set the interface index
     *
     * @param interfaceIndex interface index
     */
    public void setInterfaceIndex(int interfaceIndex) {
        this.interfaceIndex = interfaceIndex;
    }

    /**
     * Get interface capabilities
     *
     * @return capability flags
     */
    public int getCapability() {
        return capability;
    }

    /**
     * Set interface capabilities
     *
     * @param capability capability flags
     */
    public void setCapability(int capability) {
        this.capability = capability;
        // Update capability flags based on bitmask
        this.rssCapable = (capability & Smb2ChannelCapabilities.NETWORK_INTERFACE_CAP_RSS) != 0;
        this.rdmaCapable = (capability & Smb2ChannelCapabilities.NETWORK_INTERFACE_CAP_RDMA) != 0;
    }

    /**
     * Get link speed in Mbps
     *
     * @return link speed
     */
    public int getLinkSpeed() {
        return linkSpeed;
    }

    /**
     * Set link speed in Mbps
     *
     * @param linkSpeed link speed
     */
    public void setLinkSpeed(int linkSpeed) {
        this.linkSpeed = linkSpeed;
    }

    /**
     * Get the IP address
     *
     * @return IP address
     */
    public InetAddress getAddress() {
        return address;
    }

    /**
     * Check if this is an IPv6 address
     *
     * @return true if IPv6, false if IPv4
     */
    public boolean isIpv6() {
        return ipv6;
    }

    /**
     * Check if RSS is supported
     *
     * @return true if RSS capable
     */
    public boolean isRssCapable() {
        return rssCapable;
    }

    /**
     * Check if RDMA is supported
     *
     * @return true if RDMA capable
     */
    public boolean isRdmaCapable() {
        return rdmaCapable;
    }

    /**
     * Check if this interface is usable for multi-channel
     *
     * @return true if usable
     */
    public boolean isUsableForChannel() {
        return address != null && !address.isLoopbackAddress() && !address.isLinkLocalAddress();
    }

    /**
     * Get a score for interface selection (higher is better)
     *
     * @return interface score
     */
    public int getScore() {
        int score = linkSpeed; // Base score is link speed

        if (rssCapable)
            score += 1000; // Prefer RSS-capable
        if (rdmaCapable)
            score += 2000; // Prefer RDMA-capable
        // Note: No IPv4 preference bonus to keep base score equal to link speed

        return score;
    }

    /**
     * Encode this interface info for FSCTL_QUERY_NETWORK_INTERFACE_INFO response
     *
     * @return encoded bytes
     */
    public byte[] encode() {
        // NETWORK_INTERFACE_INFO structure per MS-SMB2 2.2.32.5.1
        // Total size: 152 bytes
        byte[] buffer = new byte[Smb2ChannelCapabilities.NETWORK_INTERFACE_INFO_SIZE];
        ByteBuffer bb = ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN);

        // Next field (4 bytes) - offset to next entry (0 for last entry)
        bb.putInt(0);

        // InterfaceIndex (4 bytes)
        bb.putInt(interfaceIndex);

        // Capability (4 bytes)
        bb.putInt(capability);

        // Reserved (4 bytes) - must be 0
        bb.putInt(0);

        // LinkSpeed (8 bytes) - in bits per second
        bb.putLong((long) linkSpeed * 1000000L);

        // SockAddr_Storage (128 bytes)
        encodeSockaddr(buffer, 24);

        return buffer;
    }

    /**
     * Parse network interface info from encoded bytes
     *
     * @param data encoded data
     * @param offset offset in data
     * @return parsed NetworkInterfaceInfo
     */
    public static NetworkInterfaceInfo decode(byte[] data, int offset) {
        // Ensure we have enough data for the full structure
        if (data.length < offset + Smb2ChannelCapabilities.NETWORK_INTERFACE_INFO_SIZE) {
            return null;
        }

        ByteBuffer bb = ByteBuffer.wrap(data, offset, Smb2ChannelCapabilities.NETWORK_INTERFACE_INFO_SIZE).order(ByteOrder.LITTLE_ENDIAN);

        // Next field (4 bytes) - offset to next entry
        int next = bb.getInt();

        // InterfaceIndex (4 bytes)
        int ifIndex = bb.getInt();

        // Capability (4 bytes)
        int capability = bb.getInt();

        // Reserved (4 bytes) - skip
        bb.getInt();

        // LinkSpeed (8 bytes) - in bits per second
        long linkSpeedBps = bb.getLong();

        // Parse sockaddr structure (starts at offset + 24)
        InetAddress addr = parseSockaddr(data, offset + 24);

        if (addr == null) {
            return null;
        }

        // Convert bits per second to Mbps for internal use
        NetworkInterfaceInfo info = new NetworkInterfaceInfo(addr, (int) (linkSpeedBps / 1000000L));
        info.setInterfaceIndex(ifIndex);
        info.setCapability(capability);

        return info;
    }

    private void encodeSockaddr(byte[] buffer, int offset) {
        // MS-SMB2: SockAddr_Storage field is 128 bytes
        // Clear the entire field first
        for (int i = 0; i < 128; i++) {
            buffer[offset + i] = 0;
        }

        if (ipv6) {
            // IPv6 sockaddr_in6 structure (Windows AF_INET6 = 23)
            SMBUtil.writeInt2(23, buffer, offset); // sa_family: AF_INET6
            SMBUtil.writeInt2(445, buffer, offset + 2); // sin6_port
            SMBUtil.writeInt4(0, buffer, offset + 4); // sin6_flowinfo
            System.arraycopy(address.getAddress(), 0, buffer, offset + 8, 16); // sin6_addr
            SMBUtil.writeInt4(0, buffer, offset + 24); // sin6_scope_id
        } else {
            // IPv4 sockaddr_in structure (Windows AF_INET = 2)
            SMBUtil.writeInt2(2, buffer, offset); // sa_family: AF_INET
            SMBUtil.writeInt2(445, buffer, offset + 2); // sin_port
            System.arraycopy(address.getAddress(), 0, buffer, offset + 4, 4); // sin_addr
            // Remaining bytes stay zero-filled
        }
    }

    private static InetAddress parseSockaddr(byte[] data, int offset) {
        try {
            int family = SMBUtil.readInt2(data, offset);
            if (family == 2) { // AF_INET
                byte[] addr = new byte[4];
                System.arraycopy(data, offset + 4, addr, 0, 4);
                return InetAddress.getByAddress(addr);
            } else if (family == 23) { // AF_INET6
                byte[] addr = new byte[16];
                System.arraycopy(data, offset + 8, addr, 0, 16);
                return InetAddress.getByAddress(addr);
            }
        } catch (Exception e) {
            // Ignore parsing errors
        }
        return null;
    }

    private boolean checkRSSCapability() {
        // Platform-specific RSS detection - simplified implementation
        try {
            NetworkInterface ni = NetworkInterface.getByInetAddress(address);
            return ni != null && ni.supportsMulticast();
        } catch (SocketException e) {
            return false;
        }
    }

    @Override
    public String toString() {
        return "NetworkInterfaceInfo{" + "address=" + address + ", linkSpeed=" + linkSpeed + " Mbps" + ", capability=0x"
                + Integer.toHexString(capability) + ", rssCapable=" + rssCapable + ", rdmaCapable=" + rdmaCapable + '}';
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null || getClass() != obj.getClass())
            return false;
        NetworkInterfaceInfo that = (NetworkInterfaceInfo) obj;
        return interfaceIndex == that.interfaceIndex && address != null ? address.equals(that.address) : that.address == null;
    }

    @Override
    public int hashCode() {
        int result = interfaceIndex;
        result = 31 * result + (address != null ? address.hashCode() : 0);
        return result;
    }
}
