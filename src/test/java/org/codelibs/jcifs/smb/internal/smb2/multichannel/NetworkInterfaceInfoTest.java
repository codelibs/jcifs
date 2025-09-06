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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for NetworkInterfaceInfo
 */
@ExtendWith(MockitoExtension.class)
class NetworkInterfaceInfoTest {

    private InetAddress testAddress;
    private InetAddress loopbackAddress;

    @BeforeEach
    void setUp() throws UnknownHostException {
        testAddress = InetAddress.getByName("192.168.1.100");
        loopbackAddress = InetAddress.getLoopbackAddress();
    }

    @Test
    void testConstructor() {
        NetworkInterfaceInfo info = new NetworkInterfaceInfo(testAddress, 1000);

        assertEquals(testAddress, info.getAddress());
        assertEquals(1000, info.getLinkSpeed());
        assertFalse(info.isIpv6());
        assertEquals(0, info.getCapability());
    }

    @Test
    void testIPv6Constructor() throws UnknownHostException {
        InetAddress ipv6Address = InetAddress.getByName("2001:db8::1");
        NetworkInterfaceInfo info = new NetworkInterfaceInfo(ipv6Address, 1000);

        assertEquals(ipv6Address, info.getAddress());
        assertTrue(info.isIpv6());
    }

    @Test
    void testIsUsableForChannel() {
        NetworkInterfaceInfo usable = new NetworkInterfaceInfo(testAddress, 1000);
        assertTrue(usable.isUsableForChannel());

        NetworkInterfaceInfo loopback = new NetworkInterfaceInfo(loopbackAddress, 1000);
        assertFalse(loopback.isUsableForChannel());
    }

    @Test
    void testGetScore() {
        NetworkInterfaceInfo basic = new NetworkInterfaceInfo(testAddress, 1000);
        assertEquals(1000, basic.getScore()); // Base score is link speed

        NetworkInterfaceInfo fast = new NetworkInterfaceInfo(testAddress, 10000);
        assertTrue(fast.getScore() > basic.getScore());
    }

    @Test
    void testCapabilitySettings() {
        NetworkInterfaceInfo info = new NetworkInterfaceInfo(testAddress, 1000);

        info.setCapability(Smb2ChannelCapabilities.NETWORK_INTERFACE_CAP_RSS);
        assertEquals(Smb2ChannelCapabilities.NETWORK_INTERFACE_CAP_RSS, info.getCapability());
        assertTrue(info.isRssCapable());
    }

    @Test
    void testEncodeDecode() {
        NetworkInterfaceInfo original = new NetworkInterfaceInfo(testAddress, 1000);
        original.setInterfaceIndex(1);
        original.setCapability(Smb2ChannelCapabilities.NETWORK_INTERFACE_CAP_RSS);

        byte[] encoded = original.encode();
        assertEquals(Smb2ChannelCapabilities.NETWORK_INTERFACE_INFO_SIZE, encoded.length);

        NetworkInterfaceInfo decoded = NetworkInterfaceInfo.decode(encoded, 0);
        assertNotNull(decoded);
        assertEquals(original.getAddress(), decoded.getAddress());
        assertEquals(original.getLinkSpeed(), decoded.getLinkSpeed());
        assertEquals(original.getInterfaceIndex(), decoded.getInterfaceIndex());
        assertEquals(original.getCapability(), decoded.getCapability());
    }

    @Test
    void testEquals() {
        NetworkInterfaceInfo info1 = new NetworkInterfaceInfo(testAddress, 1000);
        info1.setInterfaceIndex(1);

        NetworkInterfaceInfo info2 = new NetworkInterfaceInfo(testAddress, 1000);
        info2.setInterfaceIndex(1);

        NetworkInterfaceInfo info3 = new NetworkInterfaceInfo(testAddress, 1000);
        info3.setInterfaceIndex(2);

        assertEquals(info1, info2);
        assertNotEquals(info1, info3);
        assertEquals(info1.hashCode(), info2.hashCode());
    }

    @Test
    void testToString() {
        NetworkInterfaceInfo info = new NetworkInterfaceInfo(testAddress, 1000);
        String str = info.toString();

        assertNotNull(str);
        assertTrue(str.contains(testAddress.toString()));
        assertTrue(str.contains("1000"));
    }
}
