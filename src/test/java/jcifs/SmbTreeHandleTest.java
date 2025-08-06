/*
 * © 2025 shinsuke
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
package jcifs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for SmbTreeHandle interface.
 * This test class uses Mockito to create a mock implementation of the SmbTreeHandle interface.
 * Each method of the interface is tested to ensure it behaves as expected.
 */
@ExtendWith(MockitoExtension.class)
class SmbTreeHandleTest {

    @Mock
    private SmbTreeHandle smbTreeHandle;

    @Mock
    private Configuration mockConfig;

    /**
     * Set up mock behavior before each test.
     * @throws CIFSException
     */
    @BeforeEach
    void setUp() throws CIFSException {
        // Basic setup for methods that don't throw exceptions by default
        when(smbTreeHandle.getConfig()).thenReturn(mockConfig);
        when(smbTreeHandle.isConnected()).thenReturn(true);
        when(smbTreeHandle.getServerTimeZoneOffset()).thenReturn(0L);
        when(smbTreeHandle.getOEMDomainName()).thenReturn("TEST_DOMAIN");
        when(smbTreeHandle.getConnectedShare()).thenReturn("TEST_SHARE");
        when(smbTreeHandle.isSMB2()).thenReturn(true);
        when(smbTreeHandle.getRemoteHostName()).thenReturn("test-server");
        when(smbTreeHandle.getTreeType()).thenReturn(SmbConstants.TREE_TYPE_DISK);
    }

    /**
     * Test for getConfig() method.
     * Verifies that the method returns the expected Configuration object.
     */
    @Test
    void testGetConfig() {
        Configuration config = smbTreeHandle.getConfig();
        assertNotNull(config, "Configuration should not be null");
        assertEquals(mockConfig, config, "Should return the mock Configuration object");
    }

    /**
     * Test for close() method.
     * Verifies that the close method can be called without throwing an exception.
     * @throws CIFSException
     */
    @Test
    void testClose() throws CIFSException {
        smbTreeHandle.close();
        // Verify that close() was called on the mock
        verify(smbTreeHandle).close();
    }

    /**
     * Test for close() method throwing CIFSException.
     * Verifies that the method correctly throws a CIFSException when configured to do so.
     * @throws CIFSException
     */
    @Test
    void testClose_throwsCIFSException() throws CIFSException {
        doThrow(new CIFSException("Test Exception")).when(smbTreeHandle).close();
        assertThrows(CIFSException.class, () -> smbTreeHandle.close(), "close() should throw CIFSException");
    }

    /**
     * Test for isConnected() method.
     * Verifies that the method returns the correct connected status.
     */
    @Test
    void testIsConnected() {
        assertTrue(smbTreeHandle.isConnected(), "isConnected() should return true");
        when(smbTreeHandle.isConnected()).thenReturn(false);
        assertFalse(smbTreeHandle.isConnected(), "isConnected() should return false after status change");
    }

    /**
     * Test for getServerTimeZoneOffset() method.
     * Verifies that the method returns the correct time zone offset.
     * @throws CIFSException
     */
    @Test
    void testGetServerTimeZoneOffset() throws CIFSException {
        assertEquals(0L, smbTreeHandle.getServerTimeZoneOffset(), "Server time zone offset should be 0");
        when(smbTreeHandle.getServerTimeZoneOffset()).thenReturn(3600000L);
        assertEquals(3600000L, smbTreeHandle.getServerTimeZoneOffset(), "Server time zone offset should be 3600000");
    }

    /**
     * Test for getServerTimeZoneOffset() method throwing CIFSException.
     * @throws CIFSException
     */
    @Test
    void testGetServerTimeZoneOffset_throwsCIFSException() throws CIFSException {
        when(smbTreeHandle.getServerTimeZoneOffset()).thenThrow(new CIFSException("Test Exception"));
        assertThrows(CIFSException.class, () -> smbTreeHandle.getServerTimeZoneOffset(), "getServerTimeZoneOffset() should throw CIFSException");
    }

    /**
     * Test for getOEMDomainName() method.
     * Verifies that the method returns the correct OEM domain name.
     * @throws CIFSException
     */
    @Test
    void testGetOEMDomainName() throws CIFSException {
        assertEquals("TEST_DOMAIN", smbTreeHandle.getOEMDomainName(), "OEM domain name should be TEST_DOMAIN");
    }

    /**
     * Test for getOEMDomainName() method throwing CIFSException.
     * @throws CIFSException
     */
    @Test
    void testGetOEMDomainName_throwsCIFSException() throws CIFSException {
        when(smbTreeHandle.getOEMDomainName()).thenThrow(new CIFSException("Test Exception"));
        assertThrows(CIFSException.class, () -> smbTreeHandle.getOEMDomainName(), "getOEMDomainName() should throw CIFSException");
    }

    /**
     * Test for getConnectedShare() method.
     * Verifies that the method returns the correct connected share name.
     */
    @Test
    void testGetConnectedShare() {
        assertEquals("TEST_SHARE", smbTreeHandle.getConnectedShare(), "Connected share should be TEST_SHARE");
    }

    /**
     * Test for isSameTree() method.
     * Verifies that the method correctly identifies if two handles refer to the same tree.
     */
    @Test
    void testIsSameTree() {
        SmbTreeHandle anotherHandle = mock(SmbTreeHandle.class);
        when(smbTreeHandle.isSameTree(smbTreeHandle)).thenReturn(true);
        when(smbTreeHandle.isSameTree(anotherHandle)).thenReturn(false);

        assertTrue(smbTreeHandle.isSameTree(smbTreeHandle), "isSameTree should return true for the same handle");
        assertFalse(smbTreeHandle.isSameTree(anotherHandle), "isSameTree should return false for a different handle");
    }

    /**
     * Test for isSMB2() method.
     * Verifies that the method returns the correct SMB protocol version status.
     */
    @Test
    void testIsSMB2() {
        assertTrue(smbTreeHandle.isSMB2(), "isSMB2() should return true");
        when(smbTreeHandle.isSMB2()).thenReturn(false);
        assertFalse(smbTreeHandle.isSMB2(), "isSMB2() should return false after status change");
    }

    /**
     * Test for getRemoteHostName() method.
     * Verifies that the method returns the correct remote host name.
     */
    @Test
    void testGetRemoteHostName() {
        assertEquals("test-server", smbTreeHandle.getRemoteHostName(), "Remote host name should be test-server");
    }

    /**
     * Test for getTreeType() method.
     * Verifies that the method returns the correct tree type.
     */
    @Test
    void testGetTreeType() {
        assertEquals(SmbConstants.TREE_TYPE_DISK, smbTreeHandle.getTreeType(), "Tree type should be TREE_TYPE_DISK");
        when(smbTreeHandle.getTreeType()).thenReturn(SmbConstants.TREE_TYPE_PRINTER);
        assertEquals(SmbConstants.TREE_TYPE_PRINTER, smbTreeHandle.getTreeType(), "Tree type should be TREE_TYPE_PRINTER");
    }
}