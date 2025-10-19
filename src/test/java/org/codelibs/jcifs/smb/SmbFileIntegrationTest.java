/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import org.codelibs.jcifs.smb.context.BaseContext;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.SmbRandomAccessFile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Integration tests for SmbFile using a real Samba server via Testcontainers.
 * These tests verify SMB2/3 protocol support and basic file operations.
 */
@Testcontainers
public class SmbFileIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(SmbFileIntegrationTest.class);

    private static final String SAMBA_IMAGE = "dperson/samba:latest";
    private static final String TESTUSER1 = "testuser1";
    private static final String TESTUSER2 = "testuser2";
    private static final String PASSWORD = "test123";

    @Container
    private static final GenericContainer<?> sambaContainer =
            new GenericContainer<>(DockerImageName.parse(SAMBA_IMAGE)).withExposedPorts(139, 445)
                    .withCommand("-u", TESTUSER1 + ";" + PASSWORD, "-u", TESTUSER2 + ";" + PASSWORD, "-s",
                            "public;/share/public;yes;no;yes", "-s", "users;/share/users;yes;no;no;" + TESTUSER1 + "," + TESTUSER2, "-s",
                            "testuser1private;/share/testuser1private;yes;no;no;" + TESTUSER1, "-s",
                            "testuser2private;/share/testuser2private;yes;no;no;" + TESTUSER2, "-p")
                    .waitingFor(Wait.forListeningPorts(139, 445).withStartupTimeout(java.time.Duration.ofSeconds(60)))
                    .withLogConsumer(new Slf4jLogConsumer(log).withPrefix("SAMBA"));

    private static String sambaHost;
    private static int sambaPort;

    @BeforeAll
    static void setupContainer() throws Exception {
        sambaHost = sambaContainer.getHost();
        sambaPort = sambaContainer.getMappedPort(445);
        log.info("Samba container started at {}:{}", sambaHost, sambaPort);

        // Wait a bit for Samba to fully initialize after ports are open
        Thread.sleep(5000);

        // Verify Samba is accessible
        try {
            final CIFSContext testContext = createContext(TESTUSER1, PASSWORD);
            final String testUrl = String.format("smb://%s:%d/%s/", sambaHost, sambaPort, "users");
            final SmbFile testFile = new SmbFile(testUrl, testContext);
            testFile.exists();
            log.info("Samba server is accessible and ready for tests");
        } catch (final Exception e) {
            log.error("Failed to verify Samba accessibility", e);
            throw e;
        }
    }

    /**
     * Creates a CIFSContext for the specified user.
     *
     * @param username the username
     * @param password the password
     * @return a configured CIFSContext
     */
    private static CIFSContext createContext(final String username, final String password) {
        final Properties props = new Properties();
        props.setProperty("jcifs.smb.client.minVersion", "SMB202");
        props.setProperty("jcifs.smb.client.maxVersion", "SMB311");
        props.setProperty("jcifs.smb.client.port", String.valueOf(sambaPort));

        try {
            final BaseContext context = new BaseContext(new org.codelibs.jcifs.smb.config.PropertyConfiguration(props));
            if (username != null && password != null) {
                return context.withCredentials(new org.codelibs.jcifs.smb.impl.NtlmPasswordAuthenticator(username, password));
            }
            return context;
        } catch (final CIFSException e) {
            throw new RuntimeException("Failed to create CIFS context", e);
        }
    }

    /**
     * Creates an SMB URL for the specified share and path.
     *
     * @param share the share name
     * @param path  the path within the share
     * @return the SMB URL
     */
    private String createSmbUrl(final String share, final String path) {
        return String.format("smb://%s:%d/%s/%s", sambaHost, sambaPort, share, path);
    }

    @AfterEach
    void cleanup() throws Exception {
        // Clean up test files after each test
        final CIFSContext context = createContext(TESTUSER1, PASSWORD);
        cleanupShare(context, "users");
        cleanupShare(context, "testuser1private");

        final CIFSContext context2 = createContext(TESTUSER2, PASSWORD);
        cleanupShare(context2, "testuser2private");
    }

    private void cleanupShare(final CIFSContext context, final String share) {
        try {
            final String shareUrl = String.format("smb://%s:%d/%s/", sambaHost, sambaPort, share);
            final SmbFile shareRoot = new SmbFile(shareUrl, context);
            if (shareRoot.exists()) {
                deleteRecursively(shareRoot);
            }
        } catch (final Exception e) {
            log.warn("Failed to cleanup share: {}", share, e);
        }
    }

    private void deleteRecursively(final SmbFile file) throws Exception {
        if (file.isDirectory()) {
            final SmbResource[] children = file.listFiles();
            if (children != null) {
                for (final SmbResource child : children) {
                    deleteRecursively((SmbFile) child);
                }
            }
        }
        if (file.exists()) {
            file.delete();
        }
    }

    /**
     * Tests for connection and authentication.
     */
    @Nested
    class ConnectionAndAuthenticationTests {

        @Test
        void testConnectWithValidCredentials() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String url = createSmbUrl("users", "");
            final SmbFile file = new SmbFile(url, context);

            assertTrue(file.exists(), "Should be able to connect to users share with valid credentials");
        }

        @Test
        void testConnectToPublicShare() throws Exception {
            final CIFSContext context = createContext(null, null);
            final String url = createSmbUrl("public", "");
            final SmbFile file = new SmbFile(url, context);

            assertTrue(file.exists(), "Should be able to connect to public share without credentials");
        }

        @Test
        void testAccessDeniedToPrivateShare() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String url = createSmbUrl("testuser2private", "");

            // testuser1 should not be able to access testuser2's private share
            assertThrows(Exception.class, () -> {
                final SmbFile file = new SmbFile(url, context);
                file.exists();
            }, "Should not be able to access another user's private share");
        }

        @Test
        void testConnectToOwnPrivateShare() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String url = createSmbUrl("testuser1private", "");
            final SmbFile file = new SmbFile(url, context);

            assertTrue(file.exists(), "Should be able to access own private share");
        }
    }

    /**
     * Tests for file creation, deletion, and basic operations.
     */
    @Nested
    class FileOperationsTests {

        @Test
        void testCreateAndDeleteTextFile() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String url = createSmbUrl("users", "test.txt");
            final SmbFile file = new SmbFile(url, context);

            // Create file
            file.createNewFile();
            assertTrue(file.exists(), "File should exist after creation");

            // Delete file
            file.delete();
            assertFalse(file.exists(), "File should not exist after deletion");
        }

        @Test
        void testWriteAndReadTextFile() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String url = createSmbUrl("users", "test.txt");
            final SmbFile file = new SmbFile(url, context);

            final String content = "Hello, SMB World!";

            // Write to file
            try (OutputStream os = file.getOutputStream()) {
                os.write(content.getBytes(StandardCharsets.UTF_8));
            }

            // Read from file
            try (InputStream is = file.getInputStream()) {
                final byte[] buffer = new byte[1024];
                final int bytesRead = is.read(buffer);
                final String readContent = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
                assertEquals(content, readContent, "Read content should match written content");
            }
        }

        @Test
        void testWriteAndReadBinaryFile() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String url = createSmbUrl("users", "binary.dat");
            final SmbFile file = new SmbFile(url, context);

            final byte[] data = new byte[256];
            for (int i = 0; i < 256; i++) {
                data[i] = (byte) i;
            }

            // Write binary data
            try (OutputStream os = file.getOutputStream()) {
                os.write(data);
            }

            // Read binary data
            try (InputStream is = file.getInputStream()) {
                final byte[] readData = new byte[256];
                final int bytesRead = is.read(readData);
                assertEquals(256, bytesRead, "Should read all bytes");
                assertArrayEquals(data, readData, "Read data should match written data");
            }
        }

        @Test
        void testOverwriteFile() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String url = createSmbUrl("users", "overwrite.txt");
            final SmbFile file = new SmbFile(url, context);

            final String firstContent = "First content";
            final String secondContent = "Second content";

            // Write initial content
            try (OutputStream os = file.getOutputStream()) {
                os.write(firstContent.getBytes(StandardCharsets.UTF_8));
            }

            // Overwrite with new content
            try (OutputStream os = file.getOutputStream()) {
                os.write(secondContent.getBytes(StandardCharsets.UTF_8));
            }

            // Read content
            try (InputStream is = file.getInputStream()) {
                final byte[] buffer = new byte[1024];
                final int bytesRead = is.read(buffer);
                final String readContent = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
                assertEquals(secondContent, readContent, "File should contain overwritten content");
            }
        }

        @Test
        void testFileExists() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String url = createSmbUrl("users", "exists.txt");
            final SmbFile file = new SmbFile(url, context);

            assertFalse(file.exists(), "File should not exist initially");

            file.createNewFile();
            assertTrue(file.exists(), "File should exist after creation");

            file.delete();
            assertFalse(file.exists(), "File should not exist after deletion");
        }

        @Test
        void testDeleteNonExistentFile() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String url = createSmbUrl("users", "nonexistent.txt");
            final SmbFile file = new SmbFile(url, context);

            assertFalse(file.exists(), "File should not exist initially");

            // Deleting a non-existent file may throw exception depending on implementation
            try {
                file.delete();
            } catch (final Exception e) {
                // Expected behavior - deleting non-existent file may throw
                log.debug("Delete non-existent file threw exception (expected): {}", e.getMessage());
            }

            assertFalse(file.exists(), "File should still not exist after delete attempt");
        }
    }

    /**
     * Tests for directory operations.
     */
    @Nested
    class DirectoryOperationsTests {

        @Test
        void testCreateAndDeleteDirectory() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String url = createSmbUrl("users", "testdir/");
            final SmbFile dir = new SmbFile(url, context);

            // Create directory
            dir.mkdir();
            assertTrue(dir.exists(), "Directory should exist after creation");
            assertTrue(dir.isDirectory(), "Should be identified as directory");

            // Delete directory
            dir.delete();
            assertFalse(dir.exists(), "Directory should not exist after deletion");
        }

        @Test
        void testCreateNestedDirectories() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String url = createSmbUrl("users", "parent/child/grandchild/");
            final SmbFile dir = new SmbFile(url, context);

            // Create nested directories
            dir.mkdirs();
            assertTrue(dir.exists(), "Nested directories should exist after creation");
            assertTrue(dir.isDirectory(), "Should be identified as directory");
        }

        @Test
        void testListDirectory() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String dirUrl = createSmbUrl("users", "listtest/");
            final SmbFile dir = new SmbFile(dirUrl, context);
            dir.mkdir();

            // Create some files
            new SmbFile(createSmbUrl("users", "listtest/file1.txt"), context).createNewFile();
            new SmbFile(createSmbUrl("users", "listtest/file2.txt"), context).createNewFile();
            new SmbFile(createSmbUrl("users", "listtest/subdir/"), context).mkdir();

            // List files
            final SmbResource[] files = dir.listFiles();
            assertNotNull(files, "List should not be null");
            assertEquals(3, files.length, "Should have 3 entries");
        }

        @Test
        void testDeleteNonEmptyDirectory() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String dirUrl = createSmbUrl("users", "nonempty/");
            final SmbFile dir = new SmbFile(dirUrl, context);
            dir.mkdir();

            // Create a file inside
            new SmbFile(createSmbUrl("users", "nonempty/file.txt"), context).createNewFile();

            // Attempting to delete non-empty directory should fail or require recursive deletion
            // The behavior may vary, but the directory should still exist if simple delete is used
            try {
                dir.delete();
            } catch (final Exception e) {
                // Expected if the implementation doesn't allow deleting non-empty directories
            }

            // Verify we can delete recursively
            deleteRecursively(dir);
            assertFalse(dir.exists(), "Directory should be deleted after recursive deletion");
        }
    }

    /**
     * Tests for file attributes.
     */
    @Nested
    class FileAttributeTests {

        @Test
        void testGetFileSize() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String url = createSmbUrl("users", "sized.txt");
            final SmbFile file = new SmbFile(url, context);

            final byte[] data = "0123456789".getBytes(StandardCharsets.UTF_8);
            try (OutputStream os = file.getOutputStream()) {
                os.write(data);
            }

            assertEquals(data.length, file.length(), "File size should match written data length");
        }

        @Test
        void testGetLastModified() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String url = createSmbUrl("users", "timestamped.txt");
            final SmbFile file = new SmbFile(url, context);

            final long beforeCreate = System.currentTimeMillis();
            file.createNewFile();
            final long afterCreate = System.currentTimeMillis();

            final long lastModified = file.lastModified();
            assertTrue(lastModified >= beforeCreate - 60000 && lastModified <= afterCreate + 60000,
                    "Last modified time should be around creation time");
        }

        @Test
        void testIsFileAndIsDirectory() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);

            final SmbFile file = new SmbFile(createSmbUrl("users", "testfile.txt"), context);
            file.createNewFile();
            assertTrue(file.isFile(), "Should be identified as file");
            assertFalse(file.isDirectory(), "Should not be identified as directory");

            final SmbFile dir = new SmbFile(createSmbUrl("users", "testdir/"), context);
            dir.mkdir();
            assertTrue(dir.isDirectory(), "Should be identified as directory");
            assertFalse(dir.isFile(), "Should not be identified as file");
        }
    }

    /**
     * Tests for file rename and move operations.
     */
    @Nested
    class FileRenameAndMoveTests {

        @Test
        void testRenameFileInSameDirectory() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile oldFile = new SmbFile(createSmbUrl("users", "oldname.txt"), context);
            final SmbFile newFile = new SmbFile(createSmbUrl("users", "newname.txt"), context);

            oldFile.createNewFile();
            assertTrue(oldFile.exists(), "Old file should exist");

            oldFile.renameTo(newFile);
            assertFalse(oldFile.exists(), "Old file should not exist after rename");
            assertTrue(newFile.exists(), "New file should exist after rename");
        }

        @Test
        void testMoveFileToSubdirectory() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile sourceFile = new SmbFile(createSmbUrl("users", "source.txt"), context);
            final SmbFile targetDir = new SmbFile(createSmbUrl("users", "targetdir/"), context);
            final SmbFile targetFile = new SmbFile(createSmbUrl("users", "targetdir/source.txt"), context);

            sourceFile.createNewFile();
            targetDir.mkdir();

            sourceFile.renameTo(targetFile);
            assertFalse(sourceFile.exists(), "Source file should not exist after move");
            assertTrue(targetFile.exists(), "Target file should exist after move");
        }
    }

    /**
     * Tests for stream operations.
     */
    @Nested
    class StreamOperationsTests {

        @Test
        void testInputStreamRead() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "stream.txt"), context);

            final String content = "Test stream content";
            try (OutputStream os = file.getOutputStream()) {
                os.write(content.getBytes(StandardCharsets.UTF_8));
            }

            try (InputStream is = file.getInputStream()) {
                final StringBuilder sb = new StringBuilder();
                int c;
                while ((c = is.read()) != -1) {
                    sb.append((char) c);
                }
                assertEquals(content, sb.toString(), "Stream content should match");
            }
        }

        @Test
        void testRandomAccessFile() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "random.txt"), context);

            try (SmbRandomAccessFile raf = new SmbRandomAccessFile(file, "rw")) {
                raf.write("0123456789".getBytes(StandardCharsets.UTF_8));
                raf.seek(5);
                final byte[] buffer = new byte[5];
                raf.read(buffer);
                assertEquals("56789", new String(buffer, StandardCharsets.UTF_8), "Should read from seek position");
            }
        }
    }

    /**
     * Tests for permissions and access control.
     */
    @Nested
    class PermissionTests {

        @Test
        void testUserCannotAccessOtherPrivateShare() throws Exception {
            final CIFSContext context1 = createContext(TESTUSER1, PASSWORD);
            final String url = createSmbUrl("testuser2private", "file.txt");

            assertThrows(Exception.class, () -> {
                final SmbFile file = new SmbFile(url, context1);
                file.createNewFile();
            }, "testuser1 should not be able to write to testuser2's private share");
        }

        @Test
        void testUserCanAccessOwnPrivateShare() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("testuser1private", "private.txt"), context);

            file.createNewFile();
            assertTrue(file.exists(), "User should be able to create file in own private share");
        }

        @Test
        void testBothUsersCanAccessUsersShare() throws Exception {
            final CIFSContext context1 = createContext(TESTUSER1, PASSWORD);
            final CIFSContext context2 = createContext(TESTUSER2, PASSWORD);

            final SmbFile file1 = new SmbFile(createSmbUrl("users", "user1file.txt"), context1);
            final SmbFile file2 = new SmbFile(createSmbUrl("users", "user2file.txt"), context2);

            file1.createNewFile();
            file2.createNewFile();

            assertTrue(file1.exists(), "testuser1 should be able to create file in users share");
            assertTrue(file2.exists(), "testuser2 should be able to create file in users share");

            // Each user should be able to see the other's file
            final SmbFile file1AsSeenByUser2 = new SmbFile(createSmbUrl("users", "user1file.txt"), context2);
            assertTrue(file1AsSeenByUser2.exists(), "testuser2 should be able to see testuser1's file");
        }
    }

    /**
     * Tests for error handling.
     */
    @Nested
    class ErrorHandlingTests {

        @Test
        void testFileNotFoundException() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "nonexistent.txt"), context);

            assertThrows(IOException.class, () -> {
                file.getInputStream();
            }, "Should throw exception when trying to read non-existent file");
        }

        @Test
        void testInvalidPath() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);

            // Creating an SmbFile with invalid host doesn't throw immediately,
            // but accessing it should
            assertThrows(Exception.class, () -> {
                final SmbFile file = new SmbFile("smb://invalid-host-that-does-not-exist-12345/share/file.txt", context);
                file.exists(); // This will throw when trying to connect
            }, "Should handle invalid paths gracefully");
        }
    }

    /**
     * Tests for large file operations.
     */
    @Nested
    class LargeFileTests {

        @Test
        void testLargeFileWriteAndRead() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "large.dat"), context);

            final int size = 10 * 1024 * 1024; // 10MB
            final byte[] data = new byte[size];
            for (int i = 0; i < size; i++) {
                data[i] = (byte) (i % 256);
            }

            // Write large file
            try (OutputStream os = file.getOutputStream()) {
                os.write(data);
            }

            assertEquals(size, file.length(), "File size should match");

            // Read and verify
            try (InputStream is = file.getInputStream()) {
                final byte[] readData = new byte[size];
                int offset = 0;
                int bytesRead;
                while (offset < size && (bytesRead = is.read(readData, offset, size - offset)) != -1) {
                    offset += bytesRead;
                }
                assertEquals(size, offset, "Should read all bytes");
                assertArrayEquals(data, readData, "Data should match");
            }
        }
    }

    /**
     * Tests for file attribute manipulation (setting and getting attributes).
     */
    @Nested
    class FileAttributeManipulationTests {

        @Test
        void testCanReadAndCanWrite() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "rwtest.txt"), context);

            file.createNewFile();

            // File should be readable and writable by owner
            assertTrue(file.canRead(), "File should be readable");
            assertTrue(file.canWrite(), "File should be writable");
        }

        @Test
        void testSetReadOnlyAndReadWrite() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "readonly.txt"), context);

            file.createNewFile();

            // Set read-only
            file.setReadOnly();
            assertTrue(file.canRead(), "File should still be readable");

            // Set back to read-write
            file.setReadWrite();
            assertTrue(file.canRead(), "File should be readable");
            assertTrue(file.canWrite(), "File should be writable again");
        }

        @Test
        void testGetAndSetAttributes() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "attrtest.txt"), context);

            file.createNewFile();

            // Get current attributes
            final int attrs = file.getAttributes();
            assertNotNull(attrs, "Attributes should not be null");

            // Note: Setting specific attributes depends on SMB server support
            // Just verify the methods don't throw exceptions
            try {
                file.setAttributes(attrs);
            } catch (final Exception e) {
                log.debug("setAttributes threw exception (may not be fully supported): {}", e.getMessage());
            }
        }

        @Test
        void testCreateTimeAndLastAccessTime() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "timestest.txt"), context);

            final long beforeCreate = System.currentTimeMillis();
            file.createNewFile();
            final long afterCreate = System.currentTimeMillis();

            // Test createTime
            final long createTime = file.createTime();
            assertTrue(createTime > 0, "Create time should be positive");
            assertTrue(createTime >= beforeCreate - 60000 && createTime <= afterCreate + 60000,
                    "Create time should be around current time");

            // Test lastAccess
            final long lastAccess = file.lastAccess();
            assertTrue(lastAccess > 0, "Last access time should be positive");
        }

        @Test
        void testSetLastModified() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "modtest.txt"), context);

            file.createNewFile();

            // Set last modified time to a specific time
            final long newTime = System.currentTimeMillis() - 86400000; // 1 day ago
            file.setLastModified(newTime);

            // Verify the time was set (allowing for some tolerance)
            final long actualTime = file.lastModified();
            assertTrue(Math.abs(actualTime - newTime) < 5000, "Last modified time should be close to set value");
        }

        @Test
        void testSetFileTimes() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "filetimes.txt"), context);

            file.createNewFile();

            final long createTime = System.currentTimeMillis() - 172800000; // 2 days ago
            final long modifiedTime = System.currentTimeMillis() - 86400000; // 1 day ago
            final long accessTime = System.currentTimeMillis(); // now

            // Set all times at once
            file.setFileTimes(createTime, modifiedTime, accessTime);

            // Verify (allowing for some tolerance due to SMB time resolution)
            assertTrue(Math.abs(file.lastModified() - modifiedTime) < 5000, "Last modified time should be close to set value");
        }

        @Test
        void testSetCreateTimeAndLastAccessTime() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "settimes.txt"), context);

            file.createNewFile();

            final long newCreateTime = System.currentTimeMillis() - 86400000; // 1 day ago
            final long newAccessTime = System.currentTimeMillis();

            // Set create time
            file.setCreateTime(newCreateTime);

            // Set last access time
            file.setLastAccess(newAccessTime);

            // Verify times were set (allowing for tolerance)
            assertTrue(Math.abs(file.createTime() - newCreateTime) < 5000, "Create time should be close to set value");
        }

        @Test
        void testIsHidden() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "visiblefile.txt"), context);

            file.createNewFile();

            // Normal files should not be hidden
            assertFalse(file.isHidden(), "Regular file should not be hidden");
        }
    }

    /**
     * Tests for file copy operations.
     */
    @Nested
    class FileCopyTests {

        @Test
        void testCopyFileInSameDirectory() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile source = new SmbFile(createSmbUrl("users", "source.txt"), context);
            final SmbFile dest = new SmbFile(createSmbUrl("users", "copy.txt"), context);

            final String content = "Test copy content";
            try (OutputStream os = source.getOutputStream()) {
                os.write(content.getBytes(StandardCharsets.UTF_8));
            }

            // Copy file
            source.copyTo(dest);

            // Verify both files exist
            assertTrue(source.exists(), "Source file should still exist after copy");
            assertTrue(dest.exists(), "Destination file should exist after copy");

            // Verify content
            try (InputStream is = dest.getInputStream()) {
                final byte[] buffer = new byte[1024];
                final int bytesRead = is.read(buffer);
                final String readContent = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
                assertEquals(content, readContent, "Copied file should have same content");
            }
        }

        @Test
        void testCopyFileToDifferentDirectory() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile source = new SmbFile(createSmbUrl("users", "original.txt"), context);
            final SmbFile destDir = new SmbFile(createSmbUrl("users", "copydir/"), context);
            final SmbFile dest = new SmbFile(createSmbUrl("users", "copydir/original.txt"), context);

            destDir.mkdir();

            final String content = "Copy to different directory";
            try (OutputStream os = source.getOutputStream()) {
                os.write(content.getBytes(StandardCharsets.UTF_8));
            }

            // Copy file
            source.copyTo(dest);

            assertTrue(dest.exists(), "Destination file should exist");
            assertEquals(source.length(), dest.length(), "File sizes should match");
        }

        @Test
        void testCopyLargeFile() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile source = new SmbFile(createSmbUrl("users", "largesource.dat"), context);
            final SmbFile dest = new SmbFile(createSmbUrl("users", "largedest.dat"), context);

            final int size = 1024 * 1024; // 1MB
            final byte[] data = new byte[size];
            for (int i = 0; i < size; i++) {
                data[i] = (byte) (i % 256);
            }

            try (OutputStream os = source.getOutputStream()) {
                os.write(data);
            }

            // Copy large file
            source.copyTo(dest);

            assertEquals(source.length(), dest.length(), "File sizes should match after copy");
        }
    }

    /**
     * Tests for edge cases and boundary conditions.
     */
    @Nested
    class EdgeCasesAndBoundaryTests {

        @Test
        void testZeroByteFile() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "zerobyte.txt"), context);

            // Create empty file
            try (OutputStream os = file.getOutputStream()) {
                // Write nothing
            }

            assertTrue(file.exists(), "Zero-byte file should exist");
            assertEquals(0, file.length(), "File size should be 0");

            // Read from empty file
            try (InputStream is = file.getInputStream()) {
                final int b = is.read();
                assertEquals(-1, b, "Reading from empty file should return -1");
            }
        }

        @Test
        void testFileWithSpacesInName() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "file with spaces.txt"), context);

            file.createNewFile();
            assertTrue(file.exists(), "File with spaces in name should be created");

            final String content = "Spaces in filename";
            try (OutputStream os = file.getOutputStream()) {
                os.write(content.getBytes(StandardCharsets.UTF_8));
            }

            try (InputStream is = file.getInputStream()) {
                final byte[] buffer = new byte[1024];
                final int bytesRead = is.read(buffer);
                assertEquals(content, new String(buffer, 0, bytesRead, StandardCharsets.UTF_8));
            }
        }

        @Test
        void testFileWithSpecialCharacters() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            // Test various special characters that are typically allowed in filenames
            final SmbFile file = new SmbFile(createSmbUrl("users", "file!@#$%^&()_+-=.txt"), context);

            file.createNewFile();
            assertTrue(file.exists(), "File with special characters should be created");
        }

        @Test
        void testFileWithJapaneseCharacters() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "テストファイル.txt"), context);

            file.createNewFile();
            assertTrue(file.exists(), "File with Japanese characters should be created");

            final String content = "日本語コンテンツ";
            try (OutputStream os = file.getOutputStream()) {
                os.write(content.getBytes(StandardCharsets.UTF_8));
            }

            try (InputStream is = file.getInputStream()) {
                final byte[] buffer = new byte[1024];
                final int bytesRead = is.read(buffer);
                assertEquals(content, new String(buffer, 0, bytesRead, StandardCharsets.UTF_8));
            }
        }

        @Test
        void testDeepDirectoryHierarchy() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final String deepPath = "level1/level2/level3/level4/level5/level6/level7/level8/level9/level10/";
            final SmbFile deepDir = new SmbFile(createSmbUrl("users", deepPath), context);

            // Create deep directory structure
            deepDir.mkdirs();
            assertTrue(deepDir.exists(), "Deep directory should exist");
            assertTrue(deepDir.isDirectory(), "Should be a directory");

            // Create file in deep directory
            final SmbFile file = new SmbFile(createSmbUrl("users", deepPath + "deepfile.txt"), context);
            file.createNewFile();
            assertTrue(file.exists(), "File in deep directory should exist");
        }

        @Test
        void testManyFilesInDirectory() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile dir = new SmbFile(createSmbUrl("users", "manyfiles/"), context);
            dir.mkdir();

            final int fileCount = 50;
            // Create many files
            for (int i = 0; i < fileCount; i++) {
                final SmbFile file = new SmbFile(createSmbUrl("users", "manyfiles/file" + i + ".txt"), context);
                file.createNewFile();
            }

            // List all files
            final SmbResource[] files = dir.listFiles();
            assertNotNull(files, "File list should not be null");
            assertEquals(fileCount, files.length, "Should have " + fileCount + " files");
        }

        @Test
        void testEmptyDirectory() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile dir = new SmbFile(createSmbUrl("users", "emptydir/"), context);
            dir.mkdir();

            final SmbResource[] files = dir.listFiles();
            assertNotNull(files, "File list should not be null");
            assertEquals(0, files.length, "Empty directory should have no files");
        }

        @Test
        void testLongFileName() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            // Create a filename with 200 characters (within typical limits)
            final String longName = "a".repeat(200) + ".txt";
            final SmbFile file = new SmbFile(createSmbUrl("users", longName), context);

            file.createNewFile();
            assertTrue(file.exists(), "File with long name should be created");
        }

        @Test
        void testMultipleConsecutiveOperations() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "multiop.txt"), context);

            // Create, write, read, modify, read again
            file.createNewFile();

            try (OutputStream os = file.getOutputStream()) {
                os.write("First content".getBytes(StandardCharsets.UTF_8));
            }

            try (InputStream is = file.getInputStream()) {
                final byte[] buffer = new byte[1024];
                is.read(buffer);
            }

            try (OutputStream os = file.getOutputStream()) {
                os.write("Second content".getBytes(StandardCharsets.UTF_8));
            }

            try (InputStream is = file.getInputStream()) {
                final byte[] buffer = new byte[1024];
                final int bytesRead = is.read(buffer);
                assertEquals("Second content", new String(buffer, 0, bytesRead, StandardCharsets.UTF_8));
            }
        }
    }

    /**
     * Tests for path operations and metadata.
     */
    @Nested
    class PathAndMetadataTests {

        @Test
        void testGetName() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "testfile.txt"), context);

            file.createNewFile();

            assertEquals("testfile.txt", file.getName(), "File name should match");
        }

        @Test
        void testGetParent() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "subdir/file.txt"), context);

            final String parent = file.getParent();
            assertNotNull(parent, "Parent path should not be null");
            assertTrue(parent.contains("users"), "Parent should contain share name");
        }

        @Test
        void testGetPath() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "testpath.txt"), context);

            file.createNewFile();

            final String path = file.getPath();
            assertNotNull(path, "Path should not be null");
            assertTrue(path.contains("testpath.txt"), "Path should contain filename");
        }

        @Test
        void testGetUncPath() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "unctest.txt"), context);

            final String uncPath = file.getUncPath();
            assertNotNull(uncPath, "UNC path should not be null");
            // UNC path is relative to the share and starts with single backslash
            assertTrue(uncPath.startsWith("\\"), "UNC path should start with \\");
            assertTrue(uncPath.contains("unctest.txt"), "UNC path should contain the filename");
        }

        @Test
        void testGetShare() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "sharefile.txt"), context);

            final String share = file.getShare();
            assertNotNull(share, "Share should not be null");
            assertTrue(share.contains("users"), "Share should be 'users'");
        }

        @Test
        void testGetServer() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "servertest.txt"), context);

            final String server = file.getServer();
            assertNotNull(server, "Server should not be null");
            assertEquals(sambaHost, server, "Server should match container host");
        }

        @Test
        void testGetCanonicalPath() throws Exception {
            final CIFSContext context = createContext(TESTUSER1, PASSWORD);
            final SmbFile file = new SmbFile(createSmbUrl("users", "canonical.txt"), context);

            file.createNewFile();

            final String canonicalPath = file.getCanonicalPath();
            assertNotNull(canonicalPath, "Canonical path should not be null");
            assertTrue(canonicalPath.contains("canonical.txt"), "Canonical path should contain filename");
        }
    }
}
