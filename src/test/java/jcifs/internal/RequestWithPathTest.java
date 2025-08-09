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
package jcifs.internal;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Test class for RequestWithPath interface
 * 
 * @author test
 */
@ExtendWith(MockitoExtension.class)
class RequestWithPathTest {

    @Mock
    private RequestWithPath requestWithPath;

    private TestRequestWithPath testImplementation;

    @BeforeEach
    void setUp() {
        testImplementation = new TestRequestWithPath();
    }

    @Test
    @DisplayName("Test getPath returns correct path")
    void testGetPath() {
        // Test with mock
        String expectedPath = "/share/folder/file.txt";
        when(requestWithPath.getPath()).thenReturn(expectedPath);
        
        assertEquals(expectedPath, requestWithPath.getPath());
        verify(requestWithPath, times(1)).getPath();

        // Test with implementation
        testImplementation.setPath(expectedPath);
        assertEquals(expectedPath, testImplementation.getPath());
    }

    @Test
    @DisplayName("Test setPath updates path correctly")
    void testSetPath() {
        // Test with mock
        String newPath = "/new/path/file.txt";
        doNothing().when(requestWithPath).setPath(newPath);
        
        requestWithPath.setPath(newPath);
        verify(requestWithPath, times(1)).setPath(newPath);

        // Test with implementation
        testImplementation.setPath(newPath);
        assertEquals(newPath, testImplementation.getPath());
    }

    @Test
    @DisplayName("Test getServer returns correct server name")
    void testGetServer() {
        // Test with mock
        String expectedServer = "server.example.com";
        when(requestWithPath.getServer()).thenReturn(expectedServer);
        
        assertEquals(expectedServer, requestWithPath.getServer());
        verify(requestWithPath, times(1)).getServer();

        // Test with implementation
        testImplementation.setFullUNCPath("DOMAIN", expectedServer, "\\\\server\\share\\path");
        assertEquals(expectedServer, testImplementation.getServer());
    }

    @Test
    @DisplayName("Test getDomain returns correct domain")
    void testGetDomain() {
        // Test with mock
        String expectedDomain = "WORKGROUP";
        when(requestWithPath.getDomain()).thenReturn(expectedDomain);
        
        assertEquals(expectedDomain, requestWithPath.getDomain());
        verify(requestWithPath, times(1)).getDomain();

        // Test with implementation
        testImplementation.setFullUNCPath(expectedDomain, "server", "\\\\server\\share\\path");
        assertEquals(expectedDomain, testImplementation.getDomain());
    }

    @Test
    @DisplayName("Test getFullUNCPath returns complete UNC path")
    void testGetFullUNCPath() {
        // Test with mock
        String expectedUNCPath = "\\\\server\\share\\folder\\file.txt";
        when(requestWithPath.getFullUNCPath()).thenReturn(expectedUNCPath);
        
        assertEquals(expectedUNCPath, requestWithPath.getFullUNCPath());
        verify(requestWithPath, times(1)).getFullUNCPath();

        // Test with implementation
        testImplementation.setFullUNCPath("DOMAIN", "server", expectedUNCPath);
        assertEquals(expectedUNCPath, testImplementation.getFullUNCPath());
    }

    @Test
    @DisplayName("Test setFullUNCPath with all parameters")
    void testSetFullUNCPath() {
        // Test with mock
        String domain = "TESTDOMAIN";
        String server = "testserver";
        String fullPath = "\\\\testserver\\share\\test";
        
        doNothing().when(requestWithPath).setFullUNCPath(domain, server, fullPath);
        requestWithPath.setFullUNCPath(domain, server, fullPath);
        
        verify(requestWithPath, times(1)).setFullUNCPath(domain, server, fullPath);

        // Test with implementation
        testImplementation.setFullUNCPath(domain, server, fullPath);
        assertEquals(domain, testImplementation.getDomain());
        assertEquals(server, testImplementation.getServer());
        assertEquals(fullPath, testImplementation.getFullUNCPath());
    }

    @Test
    @DisplayName("Test setResolveInDfs sets flag correctly")
    void testSetResolveInDfs() {
        // Test with mock
        doNothing().when(requestWithPath).setResolveInDfs(true);
        requestWithPath.setResolveInDfs(true);
        verify(requestWithPath, times(1)).setResolveInDfs(true);
        
        doNothing().when(requestWithPath).setResolveInDfs(false);
        requestWithPath.setResolveInDfs(false);
        verify(requestWithPath, times(1)).setResolveInDfs(false);

        // Test with implementation
        testImplementation.setResolveInDfs(true);
        assertTrue(testImplementation.isResolveInDfs());
        
        testImplementation.setResolveInDfs(false);
        assertFalse(testImplementation.isResolveInDfs());
    }

    @Test
    @DisplayName("Test isResolveInDfs returns correct value")
    void testIsResolveInDfs() {
        // Test with mock
        when(requestWithPath.isResolveInDfs()).thenReturn(true);
        assertTrue(requestWithPath.isResolveInDfs());
        verify(requestWithPath, times(1)).isResolveInDfs();
        
        when(requestWithPath.isResolveInDfs()).thenReturn(false);
        assertFalse(requestWithPath.isResolveInDfs());
        verify(requestWithPath, times(2)).isResolveInDfs();

        // Test with implementation
        testImplementation.setResolveInDfs(true);
        assertTrue(testImplementation.isResolveInDfs());
        
        testImplementation.setResolveInDfs(false);
        assertFalse(testImplementation.isResolveInDfs());
    }

    @Test
    @DisplayName("Test with null values")
    void testWithNullValues() {
        // Test null path
        testImplementation.setPath(null);
        assertNull(testImplementation.getPath());
        
        // Test null UNC path components
        testImplementation.setFullUNCPath(null, null, null);
        assertNull(testImplementation.getDomain());
        assertNull(testImplementation.getServer());
        assertNull(testImplementation.getFullUNCPath());
    }

    @Test
    @DisplayName("Test with empty strings")
    void testWithEmptyStrings() {
        // Test empty path
        testImplementation.setPath("");
        assertEquals("", testImplementation.getPath());
        
        // Test empty UNC path components
        testImplementation.setFullUNCPath("", "", "");
        assertEquals("", testImplementation.getDomain());
        assertEquals("", testImplementation.getServer());
        assertEquals("", testImplementation.getFullUNCPath());
    }

    @Test
    @DisplayName("Test with special characters in paths")
    void testWithSpecialCharacters() {
        // Test path with spaces and special characters
        String specialPath = "/share/folder name/file with spaces & special!@#$%.txt";
        testImplementation.setPath(specialPath);
        assertEquals(specialPath, testImplementation.getPath());
        
        // Test UNC path with special characters
        String specialUNCPath = "\\\\server\\share\\folder with spaces\\file!@#$.txt";
        testImplementation.setFullUNCPath("DOMAIN", "server", specialUNCPath);
        assertEquals(specialUNCPath, testImplementation.getFullUNCPath());
    }

    @Test
    @DisplayName("Test with various UNC path formats")
    void testVariousUNCPathFormats() {
        // Standard UNC path
        String standardUNC = "\\\\server\\share\\folder\\file.txt";
        testImplementation.setFullUNCPath("DOMAIN", "server", standardUNC);
        assertEquals(standardUNC, testImplementation.getFullUNCPath());
        
        // UNC path with IP address
        String ipUNC = "\\\\192.168.1.100\\share\\folder\\file.txt";
        testImplementation.setFullUNCPath("WORKGROUP", "192.168.1.100", ipUNC);
        assertEquals(ipUNC, testImplementation.getFullUNCPath());
        assertEquals("192.168.1.100", testImplementation.getServer());
        
        // UNC path with FQDN
        String fqdnUNC = "\\\\server.example.com\\share\\folder\\file.txt";
        testImplementation.setFullUNCPath("EXAMPLE", "server.example.com", fqdnUNC);
        assertEquals(fqdnUNC, testImplementation.getFullUNCPath());
        assertEquals("server.example.com", testImplementation.getServer());
    }

    @Test
    @DisplayName("Test resolve in DFS flag toggles")
    void testResolveInDfsToggle() {
        // Initial state should be false
        assertFalse(testImplementation.isResolveInDfs());
        
        // Toggle to true
        testImplementation.setResolveInDfs(true);
        assertTrue(testImplementation.isResolveInDfs());
        
        // Toggle back to false
        testImplementation.setResolveInDfs(false);
        assertFalse(testImplementation.isResolveInDfs());
        
        // Multiple toggles
        for (int i = 0; i < 10; i++) {
            boolean expectedValue = (i % 2 == 0);
            testImplementation.setResolveInDfs(expectedValue);
            assertEquals(expectedValue, testImplementation.isResolveInDfs());
        }
    }

    /**
     * Test implementation of RequestWithPath interface for testing purposes
     */
    private static class TestRequestWithPath implements RequestWithPath {
        private String path;
        private String server;
        private String domain;
        private String fullUNCPath;
        private boolean resolveInDfs;

        @Override
        public String getPath() {
            return path;
        }

        @Override
        public void setPath(String path) {
            this.path = path;
        }

        @Override
        public String getServer() {
            return server;
        }

        @Override
        public String getDomain() {
            return domain;
        }

        @Override
        public String getFullUNCPath() {
            return fullUNCPath;
        }

        @Override
        public void setFullUNCPath(String domain, String server, String fullPath) {
            this.domain = domain;
            this.server = server;
            this.fullUNCPath = fullPath;
        }

        @Override
        public void setResolveInDfs(boolean resolve) {
            this.resolveInDfs = resolve;
        }

        @Override
        public boolean isResolveInDfs() {
            return resolveInDfs;
        }

        // CommonServerMessageBlock interface methods (stubbed for testing)
        @Override
        public int decode(byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
            return 0;
        }

        @Override
        public int encode(byte[] dst, int dstIndex) {
            return 0;
        }

        @Override
        public void setDigest(SMBSigningDigest digest) {
        }

        @Override
        public SMBSigningDigest getDigest() {
            return null;
        }

        @Override
        public CommonServerMessageBlockResponse getResponse() {
            return null;
        }

        @Override
        public void setResponse(CommonServerMessageBlockResponse msg) {
        }

        @Override
        public long getMid() {
            return 0;
        }

        @Override
        public void setMid(long mid) {
        }

        @Override
        public int getCommand() {
            return 0;
        }

        @Override
        public void setCommand(int command) {
        }

        @Override
        public void setUid(int uid) {
        }

        @Override
        public void setExtendedSecurity(boolean extendedSecurity) {
        }

        @Override
        public void setSessionId(long sessionId) {
        }

        @Override
        public void reset() {
        }

        // Message interface methods (from jcifs.util.transport.Message)
        @Override
        public void retainPayload() {
        }

        @Override
        public boolean isRetainPayload() {
            return false;
        }

        @Override
        public byte[] getRawPayload() {
            return null;
        }

        @Override
        public void setRawPayload(byte[] rawPayload) {
        }
    }
}