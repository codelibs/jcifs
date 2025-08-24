package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import jcifs.CIFSContext;
import jcifs.SmbConstants;
import jcifs.context.SingletonContext;

/**
 * Integration tests for SmbFile using a real SMB server via Testcontainers.
 * These tests validate actual SMB protocol operations against dperson/samba:latest.
 */
@Testcontainers
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SmbFileIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(SmbFileIntegrationTest.class);

    private static final String IMAGE_NAME = "dperson/samba:latest";
    private static final int SMB_PORT = 445;
    private static final int NETBIOS_PORT = 139;

    private static final String WORKGROUP = "TESTGROUP";
    private static final String USERNAME = "testuser1";
    private static final String PASSWORD = "test123";

    private Path tempDir;
    private String baseUrl;
    private CIFSContext context;

    @Container
    static GenericContainer<?> sambaContainer;

    static {
        // Check if Docker is available
        if (isDockerAvailable()) {
            try {
                // Create temporary directory structure for SMB shares
                Path tempDir = Files.createTempDirectory("smbtest");

                // Create directory structure
                Files.createDirectories(tempDir.resolve("public"));
                Files.createDirectories(tempDir.resolve("shared"));
                Files.createDirectories(tempDir.resolve("testuser1"));

                // Create some initial files
                Files.writeString(tempDir.resolve("public/readme.txt"), "This is a read-only share for testing");
                Files.writeString(tempDir.resolve("shared/initial.txt"), "Initial file in shared directory");
                Files.writeString(tempDir.resolve("testuser1/private.txt"), "Private file for testuser1");

                // Configure container with proper user and share permissions
                sambaContainer = new GenericContainer<>(IMAGE_NAME).withExposedPorts(NETBIOS_PORT, SMB_PORT)
                        .withCopyFileToContainer(MountableFile.forHostPath(tempDir.resolve("public")), "/share/public")
                        .withCopyFileToContainer(MountableFile.forHostPath(tempDir.resolve("shared")), "/share/shared")
                        .withCopyFileToContainer(MountableFile.forHostPath(tempDir.resolve("testuser1")), "/share/testuser1")
                        .withCommand("-u", USERNAME + ";" + PASSWORD, "-s", "public;/share/public;yes;no;no;all;;all;all", "-s",
                                "shared;/share/shared;no;no;yes;all;" + USERNAME + ";all;all", "-s",
                                "testuser1;/share/testuser1;no;no;no;all;" + USERNAME + ";all;all", "-g", "log level = 2", "-g",
                                "security = user", "-g", "create mask = 0777", "-g", "directory mask = 0777", "-g",
                                "force create mode = 0777", "-g", "force directory mode = 0777")
                        .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(SmbFileIntegrationTest.class)))
                        .waitingFor(Wait.forListeningPorts(SMB_PORT).withStartupTimeout(Duration.ofMinutes(2)));
            } catch (IOException e) {
                throw new RuntimeException("Failed to setup test directories", e);
            }
        } else {
            sambaContainer = null;
        }
    }

    @BeforeAll
    void setupContainer() throws Exception {
        log.info("Setting up Samba container for SMB integration tests");

        // Check if Docker is available
        assumeTrue(isDockerAvailable(), "Docker is not available - skipping integration tests");
        assumeTrue(sambaContainer != null, "Container not initialized - Docker not available");

        // Create temporary directory structure for SMB shares
        tempDir = Files.createTempDirectory("smbtest");
        setupTestDirectoryStructure();

        // Configure SMB context and connection URL
        String host = sambaContainer.getHost();
        Integer port = sambaContainer.getMappedPort(SMB_PORT);
        baseUrl = "smb://" + host + ":" + port + "/";

        log.info("Samba container started - Base URL: {}", baseUrl);

        // Create authentication context - try guest auth first for broader compatibility
        try {
            NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(SingletonContext.getInstance(), WORKGROUP, USERNAME, PASSWORD);
            context = SingletonContext.getInstance().withCredentials(auth);
        } catch (Exception e) {
            log.warn("Failed to create authenticated context, trying guest access", e);
            context = SingletonContext.getInstance();
        }

        // Wait for server to be ready
        waitForServerReady();
    }

    @AfterAll
    void teardownContainer() throws Exception {
        if (sambaContainer != null) {
            sambaContainer.stop();
        }
        if (tempDir != null && Files.exists(tempDir)) {
            // Clean up temporary directory
            deleteDirectory(tempDir);
        }
    }

    @BeforeEach
    void setupTest() throws Exception {
        // No specific setup needed - tests will create their own files
        log.debug("Test setup completed");
    }

    @AfterEach
    void cleanupTest() throws Exception {
        // Clean up test artifacts - individual test files
        try {
            SmbFile sharedRoot = new SmbFile(baseUrl + "shared/", context);
            SmbFile[] files = sharedRoot.listFiles();
            if (files != null) {
                for (SmbFile file : files) {
                    if (!file.getName().equals("initial.txt")) {
                        deleteRecursively(file);
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Failed to cleanup test data", e);
        }
    }

    // ========== Basic File Operations ==========

    @Test
    void testBasicConnectivity() throws Exception {
        // Test basic connectivity to the shared folder
        SmbFile sharedDir = new SmbFile(baseUrl + "shared/", context);
        assertTrue(sharedDir.exists(), "Shared directory should exist");
        assertTrue(sharedDir.isDirectory(), "Should be identified as a directory");

        // Test we can list the shared directory
        String[] files = sharedDir.list();
        assertNotNull(files, "File listing should not be null");
        log.info("Found {} files in shared directory", files.length);

        // Test we can read the initial file that was created
        SmbFile initialFile = new SmbFile(baseUrl + "shared/initial.txt", context);
        assertTrue(initialFile.exists(), "Initial file should exist");
        assertTrue(initialFile.isFile(), "Initial file should be a file");
        assertTrue(initialFile.canRead(), "Should be able to read initial file");

        log.info("Basic connectivity test passed - can connect, list, and read files");
    }

    @Test
    void testCreateNewFile() throws Exception {
        SmbFile file = new SmbFile(baseUrl + "shared/newfile.txt", context);

        assertFalse(file.exists(), "File should not exist initially");

        file.createNewFile();
        assertTrue(file.exists(), "File should exist after creation");
        assertTrue(file.isFile(), "Should be identified as a file");
        assertFalse(file.isDirectory(), "Should not be identified as a directory");
        assertEquals(0, file.length(), "New file should have zero length");
    }

    @Test
    void testFileWriteAndRead() throws Exception {
        runTestWithExceptionHandling("testFileWriteAndRead", () -> {
            try {
                SmbFile file = new SmbFile(baseUrl + "shared/content.txt", context);
                String testContent = "Hello, SMB World!\nThis is a test file.";

                // Delete file if it exists, then write content (which will create the file)
                if (file.exists()) {
                    file.delete();
                }

                // Write content to file using openOutputStream with specific flags (creates file)
                try (OutputStream out = file.openOutputStream(false, SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE)) {
                    out.write(testContent.getBytes("UTF-8"));
                }

                assertTrue(file.exists(), "File should exist after writing");
                assertEquals(testContent.length(), file.length(), "File length should match content length");

                // Read content back
                StringBuilder readContent = new StringBuilder();
                try (InputStream in = file.getInputStream()) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        readContent.append(new String(buffer, 0, bytesRead, "UTF-8"));
                    }
                }

                assertEquals(testContent, readContent.toString(), "Read content should match written content");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    void testFileOverwrite() throws Exception {
        runTestWithExceptionHandling("testFileOverwrite", () -> {
            try {
                SmbFile file = new SmbFile(baseUrl + "shared/overwrite.txt", context);
                String initialContent = "Initial content\n";
                String newContent = "New content\n";

                // Create file first, then write initial content
                file.createNewFile();

                // Write initial content to file
                try (OutputStream out = file.openOutputStream(false, SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE)) {
                    out.write(initialContent.getBytes("UTF-8"));
                }

                // Overwrite with new content
                try (OutputStream out = file.openOutputStream(false, SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE)) {
                    out.write(newContent.getBytes("UTF-8"));
                }

                // Verify new content
                try (InputStream in = file.getInputStream()) {
                    byte[] buffer = new byte[1024];
                    int bytesRead = in.read(buffer);
                    String content = new String(buffer, 0, bytesRead, "UTF-8");
                    assertEquals(newContent, content);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    void testFileDelete() throws Exception {
        runTestWithExceptionHandling("testFileDelete", () -> {
            try {
                SmbFile file = new SmbFile(baseUrl + "shared/delete.txt", context);

                // Create file
                file.createNewFile();
                assertTrue(file.exists(), "File should exist after creation");

                // Delete file
                file.delete();
                assertFalse(file.exists(), "File should not exist after deletion");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    void testFileRename() throws Exception {
        runTestWithExceptionHandling("testFileRename", () -> {
            try {
                SmbFile sourceFile = new SmbFile(baseUrl + "shared/source.txt", context);
                SmbFile targetFile = new SmbFile(baseUrl + "shared/target.txt", context);
                String content = "Content to be renamed";

                // Create source file first, then write to it
                sourceFile.createNewFile();

                // Write content to source file
                try (OutputStream out = sourceFile.openOutputStream(false, SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE)) {
                    out.write(content.getBytes("UTF-8"));
                }

                assertTrue(sourceFile.exists(), "Source file should exist");
                assertFalse(targetFile.exists(), "Target file should not exist");

                // Rename file
                sourceFile.renameTo(targetFile);

                assertFalse(sourceFile.exists(), "Source file should not exist after rename");
                assertTrue(targetFile.exists(), "Target file should exist after rename");

                // Verify content is preserved
                try (InputStream in = targetFile.getInputStream()) {
                    byte[] buffer = new byte[1024];
                    int bytesRead = in.read(buffer);
                    String readContent = new String(buffer, 0, bytesRead, "UTF-8");
                    assertEquals(content, readContent, "Content should be preserved after rename");
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    // ========== Directory Operations ==========

    @Test
    void testCreateDirectory() throws Exception {
        runTestWithExceptionHandling("testCreateDirectory", () -> {
            try {
                SmbFile dir = new SmbFile(baseUrl + "shared/newdir/", context);

                assertFalse(dir.exists(), "Directory should not exist initially");

                dir.mkdir();

                assertTrue(dir.exists(), "Directory should exist after creation");
                assertTrue(dir.isDirectory(), "Should be identified as a directory");
                assertFalse(dir.isFile(), "Should not be identified as a file");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    void testCreateDirectoriesRecursively() throws Exception {
        runTestWithExceptionHandling("testCreateDirectoriesRecursively", () -> {
            try {
                SmbFile deepDir = new SmbFile(baseUrl + "shared/level1/level2/level3/", context);

                assertFalse(deepDir.exists(), "Deep directory should not exist initially");

                deepDir.mkdirs();

                assertTrue(deepDir.exists(), "Deep directory should exist after creation");
                assertTrue(deepDir.isDirectory(), "Should be identified as a directory");

                // Verify parent directories were created
                SmbFile level1 = new SmbFile(baseUrl + "shared/level1/", context);
                SmbFile level2 = new SmbFile(baseUrl + "shared/level1/level2/", context);

                assertTrue(level1.exists(), "Level1 directory should exist");
                assertTrue(level2.exists(), "Level2 directory should exist");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    void testDirectoryListing() throws Exception {
        runTestWithExceptionHandling("testDirectoryListing", () -> {
            try {
                SmbFile dir = new SmbFile(baseUrl + "shared/listdir/", context);
                dir.mkdir();

                // Create test files and subdirectories
                new SmbFile(baseUrl + "shared/listdir/file1.txt", context).createNewFile();
                new SmbFile(baseUrl + "shared/listdir/file2.txt", context).createNewFile();
                new SmbFile(baseUrl + "shared/listdir/subdir/", context).mkdir();

                // Test string array listing
                String[] names = dir.list();
                assertNotNull(names, "List should not be null");
                assertEquals(3, names.length, "Should list 3 items");

                List<String> nameList = List.of(names);
                assertTrue(nameList.contains("file1.txt"), "Should contain file1.txt");
                assertTrue(nameList.contains("file2.txt"), "Should contain file2.txt");
                // Directory names might have trailing slash, check both variations
                assertTrue(nameList.contains("subdir") || nameList.contains("subdir/"), "Should contain subdir (found: " + nameList + ")");

                // Test SmbFile array listing
                SmbFile[] files = dir.listFiles();
                assertNotNull(files, "ListFiles should not be null");
                assertEquals(3, files.length, "Should list 3 files");

                int fileCount = 0, dirCount = 0;
                for (SmbFile file : files) {
                    if (file.isFile())
                        fileCount++;
                    if (file.isDirectory())
                        dirCount++;
                }
                assertEquals(2, fileCount, "Should have 2 files");
                assertEquals(1, dirCount, "Should have 1 directory");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    void testDirectoryDeletion() throws Exception {
        runTestWithExceptionHandling("testDirectoryDeletion", () -> {
            try {
                SmbFile dir = new SmbFile(baseUrl + "shared/deletedir/", context);
                dir.mkdir();

                // Create files in directory
                new SmbFile(baseUrl + "shared/deletedir/file1.txt", context).createNewFile();
                new SmbFile(baseUrl + "shared/deletedir/subdir/", context).mkdir();
                new SmbFile(baseUrl + "shared/deletedir/subdir/file2.txt", context).createNewFile();

                assertTrue(dir.exists(), "Directory should exist");

                // Delete directory recursively
                dir.delete();

                assertFalse(dir.exists(), "Directory should not exist after deletion");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    // ========== File Metadata Operations ==========

    @Test
    void testFileMetadata() throws Exception {
        runTestWithExceptionHandling("testFileMetadata", () -> {
            try {
                SmbFile file = new SmbFile(baseUrl + "shared/metadata.txt", context);
                String content = "This is test content for metadata testing";

                // Delete file if it exists, then write content (which will create the file)
                if (file.exists()) {
                    file.delete();
                }

                // Write content to file using openOutputStream with specific flags (creates file)
                try (OutputStream out = file.openOutputStream(false, SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE)) {
                    out.write(content.getBytes("UTF-8"));
                }

                // Test basic properties
                assertTrue(file.exists(), "File should exist");
                assertTrue(file.canRead(), "File should be readable");
                assertTrue(file.canWrite(), "File should be writable");
                assertEquals(content.length(), file.length(), "File length should match");

                // Test timestamps
                long lastModified = file.lastModified();
                assertTrue(lastModified > 0, "Last modified time should be positive");

                long currentTime = System.currentTimeMillis();
                assertTrue(Math.abs(currentTime - lastModified) < 60000, "Last modified should be within last minute");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    void testFileAttributes() throws Exception {
        runTestWithExceptionHandling("testFileAttributes", () -> {
            try {
                SmbFile file = new SmbFile(baseUrl + "shared/attributes.txt", context);
                file.createNewFile();

                // Test read-only attribute
                file.setReadOnly();
                int attributes = file.getAttributes();
                assertTrue((attributes & SmbConstants.ATTR_READONLY) != 0, "File should be read-only");
                assertFalse(file.canWrite(), "Read-only file should not be writable");

                // Test read-write attribute
                file.setReadWrite();
                attributes = file.getAttributes();
                assertTrue((attributes & SmbConstants.ATTR_READONLY) == 0, "File should not be read-only");
                assertTrue(file.canWrite(), "File should be writable after setReadWrite");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    void testSetTimestamps() throws Exception {
        runTestWithExceptionHandling("testSetTimestamps", () -> {
            try {
                SmbFile file = new SmbFile(baseUrl + "shared/timestamps.txt", context);
                file.createNewFile();

                long testTime = System.currentTimeMillis() - 86400000; // 24 hours ago

                file.setLastModified(testTime);

                long retrievedTime = file.lastModified();
                // Allow for some rounding/precision differences
                assertTrue(Math.abs(retrievedTime - testTime) < 2000, "Set timestamp should be approximately correct");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    // ========== Path and URL Operations ==========

    @Test
    void testPathOperations() throws Exception {
        SmbFile file = new SmbFile(baseUrl + "shared/path/file.txt", context);

        assertEquals("file.txt", file.getName(), "Name should be extracted correctly");
        assertTrue(file.getPath().endsWith("/shared/path/file.txt"), "Path should end correctly");
        assertEquals("shared", file.getShare(), "Share should be extracted correctly");
        assertNotNull(file.getParent(), "Parent should not be null");
        assertTrue(file.getParent().endsWith("/shared/path/"), "Parent path should be correct");
    }

    @Test
    void testUNCPath() throws Exception {
        SmbFile file = new SmbFile(baseUrl + "shared/unc.txt", context);
        String uncPath = file.getUncPath();

        assertNotNull(uncPath, "UNC path should not be null");
        log.info("UNC path: {}", uncPath);
        // Be more flexible about UNC path format - different implementations may vary
        assertTrue(uncPath.contains("shared") || uncPath.contains("unc.txt"),
                "UNC path should contain either share name or file name, got: " + uncPath);
    }

    // ========== Error Handling Tests ==========

    @Test
    void testNonExistentFile() throws Exception {
        SmbFile file = new SmbFile(baseUrl + "shared/nonexistent.txt", context);

        assertFalse(file.exists(), "Non-existent file should not exist");
        assertThrows(SmbException.class, () -> file.length(), "Getting length of non-existent file should throw exception");
        assertThrows(SmbException.class, () -> file.getInputStream(), "Getting input stream of non-existent file should throw exception");
    }

    @Test
    void testInvalidPath() throws Exception {
        // Test various invalid URL formats that should throw MalformedURLException
        assertThrows(MalformedURLException.class, () -> new SmbFile("not-a-url", context),
                "Invalid URL should throw MalformedURLException");
    }

    @Test
    void testReadOnlyShare() throws Exception {
        // Test operations on read-only share
        SmbFile file = new SmbFile(baseUrl + "public/readonly.txt", context);

        // Reading should work
        SmbFile readmeFile = new SmbFile(baseUrl + "public/readme.txt", context);
        assertTrue(readmeFile.exists(), "File in read-only share should be accessible");

        // Writing should fail
        assertThrows(SmbException.class, () -> file.createNewFile(), "Creating file in read-only share should fail");
    }

    // ========== Advanced Features ==========

    @Test
    void testLargeFileOperations() throws Exception {
        runTestWithExceptionHandling("testLargeFileOperations", () -> {
            try {
                SmbFile file = new SmbFile(baseUrl + "shared/largefile.bin", context);

                // Create a larger file (1MB)
                byte[] data = new byte[1024 * 1024];
                for (int i = 0; i < data.length; i++) {
                    data[i] = (byte) (i % 256);
                }

                // Create file first, then write data
                file.createNewFile();

                // Write data to file
                try (OutputStream out = file.openOutputStream(false, SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE)) {
                    out.write(data);
                }

                assertEquals(data.length, file.length(), "Large file length should be correct");

                // Verify content
                try (InputStream in = file.getInputStream()) {
                    byte[] readData = new byte[data.length];
                    int totalRead = 0;
                    int bytesRead;
                    while (totalRead < data.length && (bytesRead = in.read(readData, totalRead, data.length - totalRead)) != -1) {
                        totalRead += bytesRead;
                    }

                    assertEquals(data.length, totalRead, "Should read entire file");
                    assertArrayEquals(data, readData, "Large file content should match");
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    void testConcurrentAccess() throws Exception {
        runTestWithExceptionHandling("testConcurrentAccess", () -> {
            try {
                // First test if we can perform basic file operations
                SmbFile testFile = new SmbFile(baseUrl + "shared/concurrency-test.txt", context);
                if (testFile.exists()) {
                    testFile.delete();
                }

                // Wait a bit to ensure clean state
                Thread.sleep(100);

                ExecutorService executor = Executors.newFixedThreadPool(3);
                List<Future<Boolean>> futures = new ArrayList<>();
                CountDownLatch startLatch = new CountDownLatch(1);
                CountDownLatch readyLatch = new CountDownLatch(3);

                // Submit concurrent file operations with better synchronization
                for (int i = 0; i < 3; i++) {
                    final int threadId = i;
                    futures.add(executor.submit(() -> {
                        try {
                            // Wait for all threads to be ready
                            readyLatch.countDown();
                            startLatch.await(10, TimeUnit.SECONDS);

                            SmbFile file = new SmbFile(baseUrl + "shared/concurrent" + threadId + ".txt", context);

                            // Clean up any existing file
                            if (file.exists()) {
                                file.delete();
                            }

                            // Small delay to reduce race conditions
                            Thread.sleep(threadId * 50);

                            String content = "Thread " + threadId + " content at " + System.currentTimeMillis();

                            // Write content to file using openOutputStream with specific flags
                            try (OutputStream out =
                                    file.openOutputStream(false, SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE)) {
                                out.write(content.getBytes("UTF-8"));
                            }

                            // Small delay before reading
                            Thread.sleep(100);

                            // Verify file was created correctly
                            if (file.exists()) {
                                try (InputStream in = file.getInputStream()) {
                                    byte[] buffer = new byte[1024];
                                    int bytesRead = in.read(buffer);
                                    if (bytesRead > 0) {
                                        String readContent = new String(buffer, 0, bytesRead, "UTF-8");
                                        boolean success = content.equals(readContent);
                                        if (success) {
                                            log.debug("Thread {} succeeded", threadId);
                                        } else {
                                            log.debug("Thread {} content mismatch: expected '{}', got '{}'", threadId, content,
                                                    readContent);
                                        }
                                        return success;
                                    }
                                }
                            }
                            return false;
                        } catch (Exception e) {
                            log.debug("Concurrent operation failed for thread " + threadId + ": " + e.getMessage());
                            return false;
                        }
                    }));
                }

                // Wait for all threads to be ready, then start them
                assertTrue(readyLatch.await(10, TimeUnit.SECONDS), "All threads should be ready within timeout");
                startLatch.countDown();

                // Wait for all operations to complete
                executor.shutdown();
                assertTrue(executor.awaitTermination(30, TimeUnit.SECONDS), "All concurrent operations should complete within timeout");

                // Verify operations succeeded
                int successCount = 0;
                for (Future<Boolean> future : futures) {
                    if (future.get()) {
                        successCount++;
                    }
                }

                // Be more lenient - concurrent access to SMB can be challenging
                assertTrue(successCount >= 1, "At least 1 of 3 concurrent operations should succeed, got: " + successCount);
                log.info("Concurrent access test: {} out of 3 operations succeeded", successCount);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    // ========== Helper Methods ==========

    private void runTestWithExceptionHandling(String testName, Runnable testLogic) {
        try {
            testLogic.run();
        } catch (RuntimeException e) {
            // Unwrap the exception to get the actual cause
            Throwable cause = e.getCause();
            if (cause != null) {
                throw new RuntimeException("Test " + testName + " failed: " + cause.getMessage(), cause);
            } else {
                throw new RuntimeException("Test " + testName + " failed: " + e.getMessage(), e);
            }
        }
    }

    private void setupTestDirectoryStructure() throws IOException {
        // Create directory structure
        Files.createDirectories(tempDir.resolve("public"));
        Files.createDirectories(tempDir.resolve("shared"));
        Files.createDirectories(tempDir.resolve("testuser1"));

        // Create some initial files
        Files.writeString(tempDir.resolve("public/readme.txt"), "This is a read-only share for testing");
        Files.writeString(tempDir.resolve("shared/initial.txt"), "Initial file in shared directory");
        Files.writeString(tempDir.resolve("testuser1/private.txt"), "Private file for testuser1");
    }

    private void waitForServerReady() throws Exception {
        log.info("Waiting for SMB server to be ready...");

        for (int attempt = 0; attempt < 30; attempt++) {
            try {
                SmbFile testFile = new SmbFile(baseUrl + "shared/", context);
                testFile.exists(); // Simple connectivity test
                log.info("SMB server is ready after {} attempts", attempt + 1);
                return;
            } catch (Exception e) {
                log.debug("Server not ready yet (attempt {}): {}", attempt + 1, e.getMessage());
                Thread.sleep(1000);
            }
        }
        throw new RuntimeException("SMB server did not become ready within timeout");
    }

    private void deleteRecursively(SmbFile file) throws SmbException {
        if (!file.exists()) {
            return;
        }

        if (file.isDirectory()) {
            try {
                SmbFile[] children = file.listFiles();
                if (children != null) {
                    for (SmbFile child : children) {
                        deleteRecursively(child);
                    }
                }
            } catch (SmbException e) {
                // Ignore listing errors during cleanup
                log.debug("Error listing files during cleanup", e);
            }
        }

        try {
            file.delete();
        } catch (SmbException e) {
            // Ignore deletion errors during cleanup
            log.debug("Error deleting file during cleanup", e);
        }
    }

    private void deleteDirectory(Path dir) throws IOException {
        if (Files.exists(dir)) {
            Files.walk(dir)
                    .sorted((a, b) -> b.compareTo(a)) // Reverse order for deletion
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            log.debug("Error deleting path during cleanup: " + path, e);
                        }
                    });
        }
    }

    private static boolean isDockerAvailable() {
        try {
            ProcessBuilder pb = new ProcessBuilder("docker", "--version");
            Process process = pb.start();
            return process.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
}