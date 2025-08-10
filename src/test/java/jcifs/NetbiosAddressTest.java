/*
 * Copyright 2021 Shinsuke
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jcifs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.netbios.NbtAddress;

/**
 * Tests for NetbiosAddress interface and NbtAddress implementation.
 * This test focuses on verifying constants and basic functionality.
 */
@ExtendWith(MockitoExtension.class)
class NetbiosAddressTest {

    @Test
    void testConstantValues() {
        // Test that constants are properly defined
        assertEquals("*\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000", NbtAddress.ANY_HOSTS_NAME);
        assertEquals("\u0001\u0002__MSBROWSE__\u0002", NbtAddress.MASTER_BROWSER_NAME);
        assertEquals("*SMBSERVER     ", NbtAddress.SMBSERVER_NAME);
        
        // Test node type constants
        assertEquals(0, NbtAddress.B_NODE);
        assertEquals(1, NbtAddress.P_NODE);
        assertEquals(2, NbtAddress.M_NODE);
        assertEquals(3, NbtAddress.H_NODE);
        
        // Test unknown MAC address constant
        assertNotNull(NbtAddress.UNKNOWN_MAC_ADDRESS);
        assertEquals(6, NbtAddress.UNKNOWN_MAC_ADDRESS.length);
    }

    @Test
    void testConstantsAreImmutable() {
        // Ensure constants are properly defined as final
        // This test just verifies the constants exist and are accessible
        String anyHosts = NbtAddress.ANY_HOSTS_NAME;
        String masterBrowser = NbtAddress.MASTER_BROWSER_NAME;
        String smbServer = NbtAddress.SMBSERVER_NAME;
        
        assertNotNull(anyHosts);
        assertNotNull(masterBrowser);
        assertNotNull(smbServer);
        
        // Test that they have expected lengths
        assertEquals(16, anyHosts.length());
        assertEquals(15, masterBrowser.length());
        assertEquals(15, smbServer.length());
    }
}