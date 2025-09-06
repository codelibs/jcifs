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
package org.codelibs.jcifs.smb.internal.witness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;

import org.codelibs.jcifs.smb.internal.witness.WitnessRegistration.WitnessRegistrationState;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for WitnessRegistration class.
 */
public class WitnessRegistrationTest {

    private WitnessRegistration registration;
    private InetAddress serverAddress;

    @BeforeEach
    void setUp() throws Exception {
        serverAddress = InetAddress.getByName("192.168.1.100");
        registration = new WitnessRegistration("\\\\server\\share", serverAddress, WitnessServiceType.FILE_SERVER_WITNESS);
    }

    @Test
    void testRegistrationCreation() {
        assertNotNull(registration.getRegistrationId());
        assertEquals("\\\\server\\share", registration.getShareName());
        assertEquals(serverAddress, registration.getServerAddress());
        assertEquals(WitnessServiceType.FILE_SERVER_WITNESS, registration.getServiceType());
        assertEquals(WitnessVersion.VERSION_2, registration.getVersion());
        assertEquals(WitnessRegistrationState.REGISTERING, registration.getState());
        assertEquals(WitnessRegistration.WITNESS_REGISTER_IP_NOTIFICATION, registration.getFlags());
    }

    @Test
    void testSequenceNumbers() {
        long seq1 = registration.getNextSequenceNumber();
        long seq2 = registration.getNextSequenceNumber();
        long seq3 = registration.getNextSequenceNumber();

        assertEquals(1, seq1);
        assertEquals(2, seq2);
        assertEquals(3, seq3);
        assertTrue(seq2 > seq1);
        assertTrue(seq3 > seq2);
    }

    @Test
    void testHeartbeatUpdate() throws InterruptedException {
        long initialTime = registration.getLastHeartbeat();

        Thread.sleep(50); // Ensure sufficient time difference
        registration.updateHeartbeat();

        // After update, should not be expired with long timeout
        assertFalse(registration.isExpired(60000));

        // Verify heartbeat was actually updated
        assertTrue(registration.getLastHeartbeat() > initialTime);
    }

    @Test
    void testExpiration() throws InterruptedException {
        // Registration should not be expired initially with long timeout
        assertFalse(registration.isExpired(60000));

        // Wait a bit to ensure some time has passed
        Thread.sleep(50);
        // Should be expired with very short timeout (shorter than sleep time)
        assertTrue(registration.isExpired(10));
    }

    @Test
    void testStateTransitions() {
        assertEquals(WitnessRegistrationState.REGISTERING, registration.getState());

        registration.setState(WitnessRegistrationState.REGISTERED);
        assertEquals(WitnessRegistrationState.REGISTERED, registration.getState());

        registration.setState(WitnessRegistrationState.UNREGISTERING);
        assertEquals(WitnessRegistrationState.UNREGISTERING, registration.getState());

        registration.setState(WitnessRegistrationState.FAILED);
        assertEquals(WitnessRegistrationState.FAILED, registration.getState());

        registration.setState(WitnessRegistrationState.EXPIRED);
        assertEquals(WitnessRegistrationState.EXPIRED, registration.getState());
    }

    @Test
    void testRegistrationIdUniqueness() throws Exception {
        WitnessRegistration registration2 =
                new WitnessRegistration("\\\\server\\share2", InetAddress.getByName("192.168.1.101"), WitnessServiceType.CLUSTER_WITNESS);

        assertNotEquals(registration.getRegistrationId(), registration2.getRegistrationId());
    }

    @Test
    void testFlagsModification() {
        assertEquals(WitnessRegistration.WITNESS_REGISTER_IP_NOTIFICATION, registration.getFlags());

        registration.setFlags(WitnessRegistration.WITNESS_REGISTER_NONE);
        assertEquals(WitnessRegistration.WITNESS_REGISTER_NONE, registration.getFlags());

        registration.setFlags(WitnessRegistration.WITNESS_REGISTER_IP_NOTIFICATION);
        assertEquals(WitnessRegistration.WITNESS_REGISTER_IP_NOTIFICATION, registration.getFlags());
    }
}
