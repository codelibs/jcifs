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
package jcifs.internal.witness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for WitnessNotification class.
 */
public class WitnessNotificationTest {

    private WitnessNotification notification;

    @BeforeEach
    void setUp() {
        notification = new WitnessNotification(WitnessEventType.CLIENT_MOVE, "TestResource");
    }

    @Test
    void testNotificationCreation() {
        assertEquals(WitnessEventType.CLIENT_MOVE, notification.getEventType());
        assertEquals("TestResource", notification.getResourceName());
        assertTrue(notification.getTimestamp() <= System.currentTimeMillis());
        assertTrue(notification.getNewIPAddresses().isEmpty());
        assertTrue(notification.getOldIPAddresses().isEmpty());
        assertEquals(WitnessNotification.WITNESS_RESOURCE_STATE_UNKNOWN, notification.getFlags());
    }

    @Test
    void testAddIPAddresses() throws Exception {
        InetAddress ipv4 = InetAddress.getByName("192.168.1.100");
        InetAddress ipv6 = InetAddress.getByName("2001:db8::1");

        notification.addNewIPAddress(ipv4);
        notification.addNewIPAddress(ipv6);
        notification.addOldIPAddress(ipv4);

        List<WitnessNotification.WitnessIPAddress> newAddresses = notification.getNewIPAddresses();
        List<WitnessNotification.WitnessIPAddress> oldAddresses = notification.getOldIPAddresses();

        assertEquals(2, newAddresses.size());
        assertEquals(1, oldAddresses.size());

        // Check IPv4 address
        WitnessNotification.WitnessIPAddress newIPv4 = newAddresses.get(0);
        assertEquals(ipv4, newIPv4.getAddress());
        assertTrue(newIPv4.isIPv4());
        assertFalse(newIPv4.isIPv6());
        assertEquals(WitnessNotification.WitnessIPAddress.IPV4, newIPv4.getFlags());

        // Check IPv6 address
        WitnessNotification.WitnessIPAddress newIPv6 = newAddresses.get(1);
        assertEquals(ipv6, newIPv6.getAddress());
        assertFalse(newIPv6.isIPv4());
        assertTrue(newIPv6.isIPv6());
        assertEquals(WitnessNotification.WitnessIPAddress.IPV6, newIPv6.getFlags());
    }

    @Test
    void testWitnessIPAddressFlags() throws Exception {
        InetAddress ipv4 = InetAddress.getByName("10.0.0.1");
        InetAddress ipv6 = InetAddress.getByName("fe80::1");

        WitnessNotification.WitnessIPAddress addr4 = new WitnessNotification.WitnessIPAddress(ipv4);
        WitnessNotification.WitnessIPAddress addr6 = new WitnessNotification.WitnessIPAddress(ipv6);

        // IPv4 tests
        assertTrue(addr4.isIPv4());
        assertFalse(addr4.isIPv6());
        assertEquals(WitnessNotification.WitnessIPAddress.IPV4, addr4.getFlags());

        // IPv6 tests
        assertFalse(addr6.isIPv4());
        assertTrue(addr6.isIPv6());
        assertEquals(WitnessNotification.WitnessIPAddress.IPV6, addr6.getFlags());
    }

    @Test
    void testDifferentEventTypes() {
        for (WitnessEventType eventType : WitnessEventType.values()) {
            WitnessNotification testNotification = new WitnessNotification(eventType, "Resource" + eventType.getValue());
            assertEquals(eventType, testNotification.getEventType());
            assertEquals("Resource" + eventType.getValue(), testNotification.getResourceName());
        }
    }

    @Test
    void testTimestampConsistency() {
        long beforeCreation = System.currentTimeMillis();
        WitnessNotification newNotification = new WitnessNotification(WitnessEventType.RESOURCE_CHANGE, "TestResource");
        long afterCreation = System.currentTimeMillis();

        assertTrue(newNotification.getTimestamp() >= beforeCreation);
        assertTrue(newNotification.getTimestamp() <= afterCreation);
    }

    @Test
    void testResourceStateConstants() {
        assertEquals(0x00000000, WitnessNotification.WITNESS_RESOURCE_STATE_UNKNOWN);
        assertEquals(0x00000001, WitnessNotification.WITNESS_RESOURCE_STATE_AVAILABLE);
        assertEquals(0x000000FF, WitnessNotification.WITNESS_RESOURCE_STATE_UNAVAILABLE);
    }
}
