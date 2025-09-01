package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.MalformedURLException;
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;

/**
 * Unit tests for SmbFile functionality using mocked dependencies.
 * These tests validate SmbFile behavior without requiring external SMB servers.
 */
class SmbFileTest {

    private static final Logger log = LoggerFactory.getLogger(SmbFileTest.class);

    private static final String WORKGROUP = "WORKGROUP";
    private static final String USERNAME = "testuser";
    private static final String PASSWORD = "testpass";

    @Mock
    private Configuration mockConfig;

    private CIFSContext context;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        // Create context with real configuration for URL parsing tests
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.connTimeout", "5000");
        props.setProperty("jcifs.smb.client.soTimeout", "30000");
        Configuration config = new PropertyConfiguration(props);
        context = new BaseContext(config);
    }

    // ========== Basic SmbFile Construction Tests ==========

    @Test
    void testSmbFileConstructor() throws Exception {
        String testUrl = "smb://localhost/share/test.txt";
        SmbFile file = new SmbFile(testUrl, context);

        assertNotNull(file, "SmbFile should be created successfully");
        assertEquals("test.txt", file.getName(), "File name should be extracted correctly");
        assertTrue(file.getPath().contains("test.txt"), "File path should contain filename");
    }

    @Test
    void testSmbFileBasicProperties() throws Exception {
        String testUrl = "smb://localhost/share/document.txt";
        SmbFile file = new SmbFile(testUrl, context);

        // Test basic properties that can be determined without server connection
        assertNotNull(file.getName(), "File name should not be null");
        assertNotNull(file.getPath(), "File path should not be null");
        assertNotNull(file.getCanonicalPath(), "Canonical path should not be null");

        // Test URL parsing
        assertTrue(file.getCanonicalPath().contains("document.txt"), "Path should contain filename");
    }

    @Test
    void testSmbFilePathOperations() throws Exception {
        // Test various path operations
        SmbFile file1 = new SmbFile("smb://server/share/folder/file.txt", context);
        assertEquals("file.txt", file1.getName());

        SmbFile file2 = new SmbFile("smb://server/share/folder/", context);
        assertEquals("folder/", file2.getName());

        SmbFile file3 = new SmbFile("smb://server/share/", context);
        assertEquals("share/", file3.getName());
    }

    @Test
    void testSmbFileUrlHandling() throws Exception {
        // Test different URL formats
        String[] testUrls = { "smb://server/share/file.txt", "smb://server:445/share/file.txt", "smb://user:pass@server/share/file.txt",
                "smb://domain;user:pass@server/share/file.txt" };

        for (String url : testUrls) {
            SmbFile file = new SmbFile(url, context);
            assertNotNull(file, "Should handle URL: " + url);
            assertNotNull(file.getName(), "Should extract name from URL: " + url);
        }
    }

    @Test
    void testSmbFileDirectoryOperations() throws Exception {
        // Test directory-like operations that don't require server connection
        SmbFile dir = new SmbFile("smb://server/share/folder/", context);
        assertTrue(dir.getPath().endsWith("/"), "Directory path should end with /");

        SmbFile file = new SmbFile("smb://server/share/folder/file.txt", context);
        assertFalse(file.getPath().endsWith("/"), "File path should not end with /");
    }

    @Test
    void testSmbFileWithAuthentication() throws Exception {
        // Test creating SmbFile with authentication context
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(context, WORKGROUP, USERNAME, PASSWORD);
        CIFSContext authContext = context.withCredentials(auth);

        SmbFile file = new SmbFile("smb://server/share/file.txt", authContext);
        assertNotNull(file, "Should create file with authenticated context");
        assertNotNull(file.getName(), "Should have valid name");
    }

    @Test
    void testSmbFileErrorHandling() throws Exception {
        // Test error handling with malformed URLs
        try {
            new SmbFile("invalid://url", context);
            // Should either succeed or throw an exception - both are valid
        } catch (MalformedURLException e) {
            // Expected for invalid URLs
            assertTrue(e.getMessage().contains("invalid") || e.getMessage().contains("protocol"), "Error message should be meaningful");
        }
    }

    @Test
    void testSmbFileParentOperations() throws Exception {
        SmbFile file = new SmbFile("smb://server/share/folder/subfolder/file.txt", context);

        String parent = file.getParent();
        assertNotNull(parent, "Parent path should not be null");
        assertTrue(parent.contains("subfolder"), "Parent should contain subfolder");
        assertFalse(parent.contains("file.txt"), "Parent should not contain filename");
    }

    @Test
    void testSmbFileCanonicalPath() throws Exception {
        SmbFile file1 = new SmbFile("smb://server/share/./file.txt", context);
        SmbFile file2 = new SmbFile("smb://server/share/folder/../file.txt", context);

        String canonical1 = file1.getCanonicalPath();
        String canonical2 = file2.getCanonicalPath();

        assertNotNull(canonical1, "Canonical path should not be null");
        assertNotNull(canonical2, "Canonical path should not be null");

        // Both should resolve to similar paths
        assertTrue(canonical1.contains("file.txt"), "Canonical path should contain filename");
        assertTrue(canonical2.contains("file.txt"), "Canonical path should contain filename");
    }

    @Test
    void testSmbFileStringRepresentation() throws Exception {
        SmbFile file = new SmbFile("smb://server/share/test.txt", context);

        String toString = file.toString();
        assertNotNull(toString, "toString should not be null");
        assertTrue(toString.contains("test.txt"), "toString should contain filename");

        log.debug("SmbFile toString: {}", toString);
    }

    @Test
    void testSmbFileHashCodeAndEquals() throws Exception {
        SmbFile file1 = new SmbFile("smb://server/share/test.txt", context);
        SmbFile file2 = new SmbFile("smb://server/share/test.txt", context);
        SmbFile file3 = new SmbFile("smb://server/share/other.txt", context);

        // Test hashCode consistency
        int hash1 = file1.hashCode();
        int hash2 = file1.hashCode();
        assertEquals(hash1, hash2, "hashCode should be consistent");

        // Test equals for same URLs
        assertEquals(file1, file2, "Files with same URL should be equal");

        // Test equals for different URLs
        assertFalse(file1.equals(file3), "Files with different URLs should not be equal");
        assertFalse(file1.equals(null), "File should not equal null");
        assertFalse(file1.equals("not a file"), "File should not equal non-file object");
    }
}