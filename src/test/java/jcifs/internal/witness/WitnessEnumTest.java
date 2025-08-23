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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for witness protocol enumerations.
 */
public class WitnessEnumTest {

    @Test
    void testWitnessServiceTypes() {
        assertEquals(4, WitnessServiceType.values().length);

        // Verify all expected types are present
        assertNotNull(WitnessServiceType.CLUSTER_WITNESS);
        assertNotNull(WitnessServiceType.FILE_SERVER_WITNESS);
        assertNotNull(WitnessServiceType.SCALE_OUT_WITNESS);
        assertNotNull(WitnessServiceType.DFS_WITNESS);
    }

    @Test
    void testWitnessVersions() {
        assertEquals(2, WitnessVersion.values().length);

        WitnessVersion v1 = WitnessVersion.VERSION_1;
        WitnessVersion v2 = WitnessVersion.VERSION_2;

        assertEquals(0x00010001, v1.getValue());
        assertEquals(0x00020000, v2.getValue());

        // Verify version ordering
        assertTrue(v2.getValue() > v1.getValue());
    }

    @Test
    void testWitnessEventTypes() {
        assertEquals(7, WitnessEventType.values().length);

        WitnessEventType[] events = WitnessEventType.values();

        // Verify all expected event types with correct values
        assertEquals(1, WitnessEventType.RESOURCE_CHANGE.getValue());
        assertEquals(2, WitnessEventType.CLIENT_MOVE.getValue());
        assertEquals(3, WitnessEventType.SHARE_MOVE.getValue());
        assertEquals(4, WitnessEventType.IP_CHANGE.getValue());
        assertEquals(5, WitnessEventType.SHARE_DELETE.getValue());
        assertEquals(6, WitnessEventType.NODE_UNAVAILABLE.getValue());
        assertEquals(7, WitnessEventType.NODE_AVAILABLE.getValue());

        // Verify all values are unique
        for (int i = 0; i < events.length; i++) {
            for (int j = i + 1; j < events.length; j++) {
                assertNotEquals(events[i].getValue(), events[j].getValue(),
                        "Event types " + events[i] + " and " + events[j] + " have the same value");
            }
        }
    }

    @Test
    void testWitnessRegistrationStates() {
        assertEquals(5, WitnessRegistration.WitnessRegistrationState.values().length);

        // Verify all expected states are present
        assertNotNull(WitnessRegistration.WitnessRegistrationState.REGISTERING);
        assertNotNull(WitnessRegistration.WitnessRegistrationState.REGISTERED);
        assertNotNull(WitnessRegistration.WitnessRegistrationState.UNREGISTERING);
        assertNotNull(WitnessRegistration.WitnessRegistrationState.FAILED);
        assertNotNull(WitnessRegistration.WitnessRegistrationState.EXPIRED);
    }

    @Test
    void testEnumToStringConversions() {
        // Test that enum toString methods work properly
        assertEquals("CLUSTER_WITNESS", WitnessServiceType.CLUSTER_WITNESS.toString());
        assertEquals("FILE_SERVER_WITNESS", WitnessServiceType.FILE_SERVER_WITNESS.toString());
        assertEquals("SCALE_OUT_WITNESS", WitnessServiceType.SCALE_OUT_WITNESS.toString());
        assertEquals("DFS_WITNESS", WitnessServiceType.DFS_WITNESS.toString());

        assertEquals("VERSION_1", WitnessVersion.VERSION_1.toString());
        assertEquals("VERSION_2", WitnessVersion.VERSION_2.toString());

        assertEquals("RESOURCE_CHANGE", WitnessEventType.RESOURCE_CHANGE.toString());
        assertEquals("CLIENT_MOVE", WitnessEventType.CLIENT_MOVE.toString());
        assertEquals("SHARE_MOVE", WitnessEventType.SHARE_MOVE.toString());
        assertEquals("IP_CHANGE", WitnessEventType.IP_CHANGE.toString());
        assertEquals("SHARE_DELETE", WitnessEventType.SHARE_DELETE.toString());
        assertEquals("NODE_UNAVAILABLE", WitnessEventType.NODE_UNAVAILABLE.toString());
        assertEquals("NODE_AVAILABLE", WitnessEventType.NODE_AVAILABLE.toString());
    }

    @Test
    void testEnumValueOf() {
        // Test that valueOf works correctly
        assertEquals(WitnessServiceType.CLUSTER_WITNESS, WitnessServiceType.valueOf("CLUSTER_WITNESS"));
        assertEquals(WitnessServiceType.FILE_SERVER_WITNESS, WitnessServiceType.valueOf("FILE_SERVER_WITNESS"));
        assertEquals(WitnessServiceType.SCALE_OUT_WITNESS, WitnessServiceType.valueOf("SCALE_OUT_WITNESS"));
        assertEquals(WitnessServiceType.DFS_WITNESS, WitnessServiceType.valueOf("DFS_WITNESS"));

        assertEquals(WitnessVersion.VERSION_1, WitnessVersion.valueOf("VERSION_1"));
        assertEquals(WitnessVersion.VERSION_2, WitnessVersion.valueOf("VERSION_2"));

        assertEquals(WitnessEventType.RESOURCE_CHANGE, WitnessEventType.valueOf("RESOURCE_CHANGE"));
        assertEquals(WitnessEventType.CLIENT_MOVE, WitnessEventType.valueOf("CLIENT_MOVE"));
    }

    @Test
    void testInvalidEnumValueOf() {
        // Test that invalid valueOf throws exception
        assertThrows(IllegalArgumentException.class, () -> {
            WitnessServiceType.valueOf("INVALID_TYPE");
        });

        assertThrows(IllegalArgumentException.class, () -> {
            WitnessVersion.valueOf("INVALID_VERSION");
        });

        assertThrows(IllegalArgumentException.class, () -> {
            WitnessEventType.valueOf("INVALID_EVENT");
        });
    }
}
