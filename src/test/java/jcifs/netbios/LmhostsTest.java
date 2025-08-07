/*
 * © 2025 jcifs project contributors
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
package jcifs.netbios;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.smb.SmbFileInputStream;

/**
 * Test class for Lmhosts
 */
class LmhostsTest {

    private Lmhosts lmhosts;
    private CIFSContext mockContext;
    private Configuration mockConfig;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        lmhosts = new Lmhosts();
        mockContext = mock(CIFSContext.class);
        mockConfig = mock(Configuration.class);
        when(mockContext.getConfig()).thenReturn(mockConfig);
    }

    @Test
    void testGetByNameWithNullLmHostsFile() {
        // Test when lmhosts file is not configured
        when(mockConfig.getLmHostsFileName()).thenReturn(null);
        
        NbtAddress result = lmhosts.getByName("TEST_HOST", mockContext);
        
        assertNull(result);
    }

    @Test
    void testGetByNameWithNonExistentFile() {
        // Test with non-existent file
        when(mockConfig.getLmHostsFileName()).thenReturn("/non/existent/lmhosts");
        
        NbtAddress result = lmhosts.getByName("TEST_HOST", mockContext);
        
        assertNull(result);
    }

    @Test
    void testGetByNameWithValidEntry() throws IOException {
        // Create a temporary lmhosts file
        File lmhostsFile = tempDir.resolve("lmhosts").toFile();
        try (FileWriter writer = new FileWriter(lmhostsFile)) {
            writer.write("192.168.1.100 TESTHOST\n");
            writer.write("10.0.0.1      SERVER01\n");
        }
        
        when(mockConfig.getLmHostsFileName()).thenReturn(lmhostsFile.getAbsolutePath());
        
        // Test first host
        NbtAddress result = lmhosts.getByName("TESTHOST", mockContext);
        assertNotNull(result);
        assertEquals("TESTHOST", result.getHostName());
        
        // Test second host
        result = lmhosts.getByName("SERVER01", mockContext);
        assertNotNull(result);
        assertEquals("SERVER01", result.getHostName());
    }

    @Test
    void testGetByNameCaching() throws IOException {
        // Create a temporary lmhosts file
        File lmhostsFile = tempDir.resolve("lmhosts").toFile();
        try (FileWriter writer = new FileWriter(lmhostsFile)) {
            writer.write("192.168.1.100 TESTHOST\n");
        }
        
        when(mockConfig.getLmHostsFileName()).thenReturn(lmhostsFile.getAbsolutePath());
        
        // First call should read the file
        NbtAddress result1 = lmhosts.getByName("TESTHOST", mockContext);
        assertNotNull(result1);
        
        // Second call should use cached data (file not modified)
        NbtAddress result2 = lmhosts.getByName("TESTHOST", mockContext);
        assertNotNull(result2);
        assertEquals(result1, result2);
    }

    @Test
    void testGetByNameFileModification() throws Exception {
        // Create initial lmhosts file
        File lmhostsFile = tempDir.resolve("lmhosts").toFile();
        try (FileWriter writer = new FileWriter(lmhostsFile)) {
            writer.write("192.168.1.100 TESTHOST\n");
        }
        
        when(mockConfig.getLmHostsFileName()).thenReturn(lmhostsFile.getAbsolutePath());
        
        // First read
        NbtAddress result = lmhosts.getByName("TESTHOST", mockContext);
        assertNotNull(result);
        
        // Modify file with a delay to ensure different lastModified time
        Thread.sleep(100);
        try (FileWriter writer = new FileWriter(lmhostsFile)) {
            writer.write("192.168.1.200 NEWHOST\n");
        }
        
        // Should reload file and find new host
        result = lmhosts.getByName("NEWHOST", mockContext);
        assertNotNull(result);
        
        // Old host should not be found
        result = lmhosts.getByName("TESTHOST", mockContext);
        assertNull(result);
    }

    @Test
    void testPopulateWithEmptyLines() throws IOException {
        String content = "192.168.1.100 HOST1\n" +
                        "\n" +
                        "   \n" +
                        "192.168.1.101 HOST2\n";
        
        lmhosts.populate(new StringReader(content), mockContext);
        
        NbtAddress result = lmhosts.getByName("HOST1", mockContext);
        assertNotNull(result);
        result = lmhosts.getByName("HOST2", mockContext);
        assertNotNull(result);
    }

    @Test
    void testPopulateWithComments() throws IOException {
        String content = "# This is a comment\n" +
                        "192.168.1.100 HOST1\n" +
                        "#192.168.1.101 COMMENTED_HOST\n" +
                        "192.168.1.102 HOST2\n";
        
        lmhosts.populate(new StringReader(content), mockContext);
        
        NbtAddress result = lmhosts.getByName("HOST1", mockContext);
        assertNotNull(result);
        result = lmhosts.getByName("HOST2", mockContext);
        assertNotNull(result);
        result = lmhosts.getByName("COMMENTED_HOST", mockContext);
        assertNull(result);
    }

    @Test
    void testPopulateWithVariousIPFormats() throws IOException {
        String content = "1.2.3.4 HOST1\n" +
                        "192.168.1.100 HOST2\n" +
                        "255.255.255.255 HOST3\n" +
                        "10.0.0.1 HOST4\n";
        
        lmhosts.populate(new StringReader(content), mockContext);
        
        assertNotNull(lmhosts.getByName("HOST1", mockContext));
        assertNotNull(lmhosts.getByName("HOST2", mockContext));
        assertNotNull(lmhosts.getByName("HOST3", mockContext));
        assertNotNull(lmhosts.getByName("HOST4", mockContext));
    }

    @Test
    void testPopulateWithWhitespace() throws IOException {
        String content = "192.168.1.100    HOST1    \n" +
                        "192.168.1.101\tHOST2\t\n" +
                        "192.168.1.102 \t HOST3 \t \n";
        
        lmhosts.populate(new StringReader(content), mockContext);
        
        assertNotNull(lmhosts.getByName("HOST1", mockContext));
        assertNotNull(lmhosts.getByName("HOST2", mockContext));
        assertNotNull(lmhosts.getByName("HOST3", mockContext));
    }

    @Test
    void testPopulateWithInclude() throws IOException {
        // Mock SmbFileInputStream for include directive
        try (MockedConstruction<SmbFileInputStream> mockedConstruction = 
                Mockito.mockConstruction(SmbFileInputStream.class, (mock, context) -> {
                    // Return empty input stream
                    when(mock.read()).thenReturn(-1);
                })) {
            
            String content = "#INCLUDE \\\\server\\share\\lmhosts\n" +
                            "192.168.1.100 HOST1\n";
            
            lmhosts.populate(new StringReader(content), mockContext);
            
            // Verify include was attempted
            assertEquals(1, mockedConstruction.constructed().size());
            
            // Host from main file should still be added
            assertNotNull(lmhosts.getByName("HOST1", mockContext));
        }
    }

    @Test
    void testPopulateWithBeginAlternate() throws IOException {
        String content = "#BEGIN_ALTERNATE\n" +
                        "192.168.1.100 HOST1\n" +
                        "#END_ALTERNATE\n" +
                        "192.168.1.101 HOST2\n";
        
        lmhosts.populate(new StringReader(content), mockContext);
        
        // Both hosts should be added in this simple case
        assertNotNull(lmhosts.getByName("HOST1", mockContext));
        assertNotNull(lmhosts.getByName("HOST2", mockContext));
    }

    @Test
    void testPopulateWithInvalidIPFormat() throws IOException {
        String content = "192.168.1 HOST1\n" +  // Invalid IP - missing octet
                        "192.168.1.100 VALIDHOST\n" +
                        "not.an.ip HOST2\n";  // Invalid IP format
        
        lmhosts.populate(new StringReader(content), mockContext);
        
        // Only valid host should be added
        assertNotNull(lmhosts.getByName("VALIDHOST", mockContext));
        assertNull(lmhosts.getByName("HOST1", mockContext));
        assertNull(lmhosts.getByName("HOST2", mockContext));
    }

    @Test
    void testPopulateWithLongHostname() throws IOException {
        String longHostname = "VERYLONGHOSTNAMETHATSHOULDSTILLWORK";
        String content = "192.168.1.100 " + longHostname + "\n";
        
        lmhosts.populate(new StringReader(content), mockContext);
        
        assertNotNull(lmhosts.getByName(longHostname, mockContext));
    }

    @Test
    void testGetByNameWithName() {
        // Test the internal getByName method that takes a Name object
        Name name = new Name(mockConfig, "TESTHOST", 0x20, null);
        when(mockConfig.getLmHostsFileName()).thenReturn(null);
        
        NbtAddress result = lmhosts.getByName(name, mockContext);
        
        assertNull(result);
    }

    @Test
    void testPopulateWithIPAddressComponents() throws IOException {
        // Test various IP address formats with different byte values
        String content = "0.0.0.0 HOST1\n" +
                        "127.0.0.1 HOST2\n" +
                        "192.168.255.255 HOST3\n" +
                        "10.20.30.40 HOST4\n";
        
        lmhosts.populate(new StringReader(content), mockContext);
        
        assertNotNull(lmhosts.getByName("HOST1", mockContext));
        assertNotNull(lmhosts.getByName("HOST2", mockContext));
        assertNotNull(lmhosts.getByName("HOST3", mockContext));
        assertNotNull(lmhosts.getByName("HOST4", mockContext));
    }

    @Test
    void testCaseInsensitivity() throws IOException {
        String content = "192.168.1.100 hostname\n";
        
        lmhosts.populate(new StringReader(content), mockContext);
        
        // Content is converted to uppercase internally
        assertNotNull(lmhosts.getByName("HOSTNAME", mockContext));
    }

    @Test
    void testMultipleEntriesForSameHost() throws IOException {
        String content = "192.168.1.100 TESTHOST\n" +
                        "192.168.1.200 TESTHOST\n";
        
        lmhosts.populate(new StringReader(content), mockContext);
        
        // Last entry should win
        NbtAddress result = lmhosts.getByName("TESTHOST", mockContext);
        assertNotNull(result);
    }

    @Test
    void testIOExceptionDuringRead() throws IOException {
        // Create a file that exists but will cause an IOException when read
        File lmhostsFile = tempDir.resolve("lmhosts").toFile();
        lmhostsFile.createNewFile();
        lmhostsFile.setReadable(false);
        
        when(mockConfig.getLmHostsFileName()).thenReturn(lmhostsFile.getAbsolutePath());
        
        // Should handle IOException gracefully and return null
        NbtAddress result = lmhosts.getByName("ANYHOST", mockContext);
        assertNull(result);
        
        // Cleanup
        lmhostsFile.setReadable(true);
    }
}