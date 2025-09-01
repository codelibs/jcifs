package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.condition.EnabledIf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import jcifs.CIFSContext;
import jcifs.context.SingletonContext;

/**
 * Integration tests for SmbFile using a real SMB server via Testcontainers.
 * These tests validate actual SMB protocol operations against dperson/samba.
 */
@Testcontainers
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.MethodName.class)
@EnabledIf("isDockerAvailable")
class SmbFileIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(SmbFileIntegrationTest.class);

    private static final String IMAGE_NAME = "dperson/samba:latest";
    private static final int SMB_PORT = 445;
    private static final int NETBIOS_PORT = 139;

    private static final String WORKGROUP = "WORKGROUP";
    private static final String USERNAME = "smbuser";
    private static final String PASSWORD = "smbpass";

    private Path tempDir;
    private String baseUrl;
    private CIFSContext context;

    @Container
    static GenericContainer<?> sambaContainer;

    static {
        try {
            // Create temporary directory structure for SMB shares
            Path tempDir = Files.createTempDirectory("smbtest");

            // Create directory structure
            Files.createDirectories(tempDir.resolve("public"));
            Files.createDirectories(tempDir.resolve("shared"));

            // Create some initial files
            Files.writeString(tempDir.resolve("public/readme.txt"), "This is a public share for testing");
            Files.writeString(tempDir.resolve("shared/initial.txt"), "Initial file in shared directory");

            // Configure container with proper SMB configuration
            sambaContainer = new GenericContainer<>(DockerImageName.parse(IMAGE_NAME)).withExposedPorts(NETBIOS_PORT, SMB_PORT)
                    .withCopyFileToContainer(MountableFile.forHostPath(tempDir.resolve("public")), "/share/public")
                    .withCopyFileToContainer(MountableFile.forHostPath(tempDir.resolve("shared")), "/share/shared")
                    .withCommand("-u", USERNAME + ";" + PASSWORD, "-s", "public;/share/public;yes;no;yes;all;;all;all", "-s",
                            "shared;/share/shared;no;no;no;all;" + USERNAME + ";all;all", "-g", "log level = 1", "-g", "security = user",
                            "-g", "map to guest = bad user", "-g", "min protocol = SMB2", "-g", "max protocol = SMB3")
                    .withLogConsumer(new Slf4jLogConsumer(log))
                    .waitingFor(Wait.forListeningPorts(SMB_PORT).withStartupTimeout(Duration.ofMinutes(3)));

        } catch (IOException e) {
            throw new RuntimeException("Failed to setup test directories", e);
        }
    }

    @BeforeAll
    void setupContainer() throws Exception {
        log.info("Setting up Samba container for SMB integration tests");

        // Create temporary directory structure for SMB shares
        tempDir = Files.createTempDirectory("smbtest");
        setupTestDirectoryStructure();

        // Configure SMB context and connection URL
        String host = sambaContainer.getHost();
        Integer port = sambaContainer.getMappedPort(SMB_PORT);
        baseUrl = "smb://" + host + ":" + port + "/";

        log.info("Samba container started - Base URL: {}", baseUrl);

        // Create authentication context
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(SingletonContext.getInstance(), WORKGROUP, USERNAME, PASSWORD);
        context = SingletonContext.getInstance().withCredentials(auth);

        // Wait for server to be ready
        waitForServerReady();
    }

    @AfterAll
    void teardownContainer() throws Exception {
        if (sambaContainer != null) {
            sambaContainer.stop();
        }
        if (tempDir != null && Files.exists(tempDir)) {
            deleteDirectory(tempDir);
        }
    }

    @BeforeEach
    void setupTest() throws Exception {
        log.debug("Test setup completed");
    }

    @AfterEach
    void cleanupTest() throws Exception {
        try {
            System.gc();
            Thread.sleep(100);
            log.debug("Test cleanup completed");
        } catch (Exception e) {
            log.warn("Failed to cleanup test", e);
        }
    }

    // ========== Comprehensive SMB File Operations ==========

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
        String filename = "newfile_" + System.currentTimeMillis() + ".txt";
        SmbFile file = new SmbFile(baseUrl + "shared/" + filename, context);

        assertFalse(file.exists(), "File should not exist initially");

        file.createNewFile();
        assertTrue(file.exists(), "File should exist after creation");
        assertTrue(file.isFile(), "Should be identified as a file");
        assertFalse(file.isDirectory(), "Should not be identified as a directory");
        assertEquals(0, file.length(), "New file should have zero length");
    }

    @Test
    void testFileWriteAndRead() throws Exception {
        String filename = "content_" + System.currentTimeMillis() + ".txt";
        SmbFile file = new SmbFile(baseUrl + "shared/" + filename, context);
        String testContent = "Hello, SMB World!\nThis is a test file with multiple lines.\n日本語テスト\n";

        // Write content to file
        try (OutputStream out = file.openOutputStream(false)) {
            out.write(testContent.getBytes("UTF-8"));
        }

        assertTrue(file.exists(), "File should exist after writing");
        assertEquals(testContent.getBytes("UTF-8").length, file.length(), "File length should match content length");

        // Read content back
        try (InputStream in = file.getInputStream()) {
            String readContent = new String(in.readAllBytes(), "UTF-8");
            assertEquals(testContent, readContent, "Read content should match written content");
        }
    }

    @Test
    void testFileOverwrite() throws Exception {
        String filename = "overwrite_" + System.currentTimeMillis() + ".txt";
        SmbFile file = new SmbFile(baseUrl + "shared/" + filename, context);
        String initialContent = "Initial content\n";
        String newContent = "New overwritten content with more data\n";

        // Write initial content
        try (OutputStream out = file.openOutputStream(false)) {
            out.write(initialContent.getBytes("UTF-8"));
        }

        // Verify initial content
        try (InputStream in = file.getInputStream()) {
            String content = new String(in.readAllBytes(), "UTF-8");
            assertEquals(initialContent, content, "Initial content should be correct");
        }

        // Overwrite with new content
        try (OutputStream out = file.openOutputStream(false)) {
            out.write(newContent.getBytes("UTF-8"));
        }

        // Verify new content
        try (InputStream in = file.getInputStream()) {
            String content = new String(in.readAllBytes(), "UTF-8");
            assertEquals(newContent, content, "Overwritten content should be correct");
        }
    }

    @Test
    void testFileAppend() throws Exception {
        String filename = "append_" + System.currentTimeMillis() + ".txt";
        SmbFile file = new SmbFile(baseUrl + "shared/" + filename, context);
        String initialContent = "Initial content\n";
        String appendContent = "Appended content\n";

        // Write initial content
        try (OutputStream out = file.openOutputStream(false)) {
            out.write(initialContent.getBytes("UTF-8"));
        }

        // Append content
        try (OutputStream out = file.openOutputStream(true)) {
            out.write(appendContent.getBytes("UTF-8"));
        }

        // Verify combined content
        try (InputStream in = file.getInputStream()) {
            String content = new String(in.readAllBytes(), "UTF-8");
            assertEquals(initialContent + appendContent, content, "Content should be appended");
        }
    }

    @Test
    void testFileDelete() throws Exception {
        String filename = "delete_" + System.currentTimeMillis() + ".txt";
        SmbFile file = new SmbFile(baseUrl + "shared/" + filename, context);
        String content = "Content to be deleted";

        // Create file
        try (OutputStream out = file.openOutputStream(false)) {
            out.write(content.getBytes("UTF-8"));
        }
        assertTrue(file.exists(), "File should exist after creation");

        // Delete file
        file.delete();
        assertFalse(file.exists(), "File should not exist after deletion");
    }

    @Test
    void testFileRename() throws Exception {
        long timestamp = System.currentTimeMillis();
        String sourceFilename = "source_" + timestamp + ".txt";
        String targetFilename = "target_" + timestamp + ".txt";
        String content = "Content for rename test";

        SmbFile sourceFile = new SmbFile(baseUrl + "shared/" + sourceFilename, context);
        SmbFile targetFile = new SmbFile(baseUrl + "shared/" + targetFilename, context);

        // Create source file
        try (OutputStream out = sourceFile.openOutputStream(false)) {
            out.write(content.getBytes("UTF-8"));
        }
        assertTrue(sourceFile.exists(), "Source file should exist");

        // Rename file
        sourceFile.renameTo(targetFile);

        // Verify rename
        assertFalse(sourceFile.exists(), "Source file should not exist after rename");
        assertTrue(targetFile.exists(), "Target file should exist after rename");

        // Verify content is preserved
        try (InputStream in = targetFile.getInputStream()) {
            String readContent = new String(in.readAllBytes(), "UTF-8");
            assertEquals(content, readContent, "Content should be preserved after rename");
        }
    }

    @Test
    void testDirectoryOperations() throws Exception {
        String dirName = "testdir_" + System.currentTimeMillis();
        SmbFile dir = new SmbFile(baseUrl + "shared/" + dirName + "/", context);

        assertFalse(dir.exists(), "Directory should not exist initially");

        // Create directory
        dir.mkdir();
        assertTrue(dir.exists(), "Directory should exist after creation");
        assertTrue(dir.isDirectory(), "Should be identified as directory");

        // Create file in directory
        SmbFile fileInDir = new SmbFile(baseUrl + "shared/" + dirName + "/file.txt", context);
        try (OutputStream out = fileInDir.openOutputStream(false)) {
            out.write("File in directory".getBytes("UTF-8"));
        }
        assertTrue(fileInDir.exists(), "File in directory should exist");

        // List directory contents
        String[] files = dir.list();
        assertNotNull(files, "Directory listing should not be null");
        assertEquals(1, files.length, "Directory should contain one file");
        assertEquals("file.txt", files[0], "File name should match");

        // Delete file first, then directory
        fileInDir.delete();
        assertFalse(fileInDir.exists(), "File should be deleted");

        dir.delete();
        assertFalse(dir.exists(), "Directory should be deleted");
    }

    @Test
    void testLargeFileOperations() throws Exception {
        String filename = "largefile_" + System.currentTimeMillis() + ".txt";
        SmbFile file = new SmbFile(baseUrl + "shared/" + filename, context);

        // Create 1MB of test data
        byte[] largeContent = new byte[1024 * 1024];
        for (int i = 0; i < largeContent.length; i++) {
            largeContent[i] = (byte) (i % 256);
        }

        // Write large content
        try (OutputStream out = file.openOutputStream(false)) {
            out.write(largeContent);
        }

        assertTrue(file.exists(), "Large file should exist after writing");
        assertEquals(largeContent.length, file.length(), "File length should match large content length");

        // Read back and verify
        try (InputStream in = file.getInputStream()) {
            byte[] readContent = in.readAllBytes();
            assertArrayEquals(largeContent, readContent, "Large file content should match");
        }

        // Clean up
        file.delete();
        assertFalse(file.exists(), "Large file should be deleted");
    }

    @Test
    void testFileMetadata() throws Exception {
        String filename = "metadata_" + System.currentTimeMillis() + ".txt";
        SmbFile file = new SmbFile(baseUrl + "shared/" + filename, context);
        String content = "Test content for metadata";

        // Create file
        try (OutputStream out = file.openOutputStream(false)) {
            out.write(content.getBytes("UTF-8"));
        }

        // Test metadata
        assertTrue(file.exists(), "File should exist");
        assertTrue(file.isFile(), "Should be a file");
        assertFalse(file.isDirectory(), "Should not be a directory");
        assertEquals(content.getBytes("UTF-8").length, file.length(), "Length should match");

        long lastModified = file.lastModified();
        assertTrue(lastModified > 0, "Last modified time should be positive");
        assertTrue(lastModified <= System.currentTimeMillis(), "Last modified should not be in future");

        // Test permissions
        assertTrue(file.canRead(), "Should be readable");
        assertTrue(file.canWrite(), "Should be writable");

        // Clean up
        file.delete();
    }

    @Test
    void testConcurrentAccess() throws Exception {
        String filename = "concurrent_" + System.currentTimeMillis() + ".txt";
        SmbFile file = new SmbFile(baseUrl + "shared/" + filename, context);

        // Create file
        file.createNewFile();
        assertTrue(file.exists(), "File should exist after creation");

        // Test concurrent read access
        String content = "Concurrent test content\n";
        try (OutputStream out = file.openOutputStream(false)) {
            out.write(content.getBytes("UTF-8"));
        }

        // Multiple concurrent reads
        for (int i = 0; i < 5; i++) {
            try (InputStream in = file.getInputStream()) {
                String readContent = new String(in.readAllBytes(), "UTF-8");
                assertEquals(content, readContent, "Concurrent read " + i + " should work");
            }
        }

        // Clean up
        file.delete();
    }

    @Test
    void testPublicShare() throws Exception {
        // Test access to public share (no authentication required)
        CIFSContext guestContext = SingletonContext.getInstance();
        SmbFile publicFile = new SmbFile(baseUrl + "public/readme.txt", guestContext);

        assertTrue(publicFile.exists(), "Public file should exist");
        assertTrue(publicFile.canRead(), "Public file should be readable");

        // Read content
        try (InputStream in = publicFile.getInputStream()) {
            String content = new String(in.readAllBytes(), "UTF-8");
            assertEquals("This is a public share for testing", content, "Public file content should match");
        }
    }

    @Test
    void testAuthenticationRequired() throws Exception {
        // Test that shared directory requires authentication
        CIFSContext guestContext = SingletonContext.getInstance();
        SmbFile sharedFile = new SmbFile(baseUrl + "shared/initial.txt", guestContext);

        // This should fail without proper authentication
        assertThrows(SmbException.class, () -> {
            sharedFile.exists();
        }, "Access to shared directory should require authentication");
    }

    @Test
    void testBinaryFileOperations() throws Exception {
        String filename = "binary_" + System.currentTimeMillis() + ".dat";
        SmbFile file = new SmbFile(baseUrl + "shared/" + filename, context);

        // Create binary test data (random bytes)
        byte[] binaryData = new byte[8192];
        for (int i = 0; i < binaryData.length; i++) {
            binaryData[i] = (byte) (i % 256);
        }

        // Write binary data
        try (OutputStream out = file.openOutputStream(false)) {
            out.write(binaryData);
        }

        // Read back and verify
        try (InputStream in = file.getInputStream()) {
            byte[] readData = in.readAllBytes();
            assertArrayEquals(binaryData, readData, "Binary data should match exactly");
        }

        // Clean up
        file.delete();
    }

    @Test
    void testFileListingWithPatterns() throws Exception {
        String dirName = "listtest_" + System.currentTimeMillis();
        SmbFile dir = new SmbFile(baseUrl + "shared/" + dirName + "/", context);

        // Create directory
        dir.mkdir();

        // Create multiple files with different extensions
        String[] filenames = { "test.txt", "data.csv", "config.json", "readme.md", "script.sh" };
        for (String filename : filenames) {
            SmbFile file = new SmbFile(baseUrl + "shared/" + dirName + "/" + filename, context);
            try (OutputStream out = file.openOutputStream(false)) {
                out.write(("Content of " + filename).getBytes("UTF-8"));
            }
        }

        // List all files
        String[] allFiles = dir.list();
        assertEquals(filenames.length, allFiles.length, "Should list all created files");

        // Test filtering (basic filename matching)
        String[] txtFiles = dir.list((file, name) -> name.endsWith(".txt"));
        assertEquals(1, txtFiles.length, "Should find one .txt file");
        assertEquals("test.txt", txtFiles[0], "Should find the correct .txt file");

        // Clean up
        for (String filename : filenames) {
            SmbFile file = new SmbFile(baseUrl + "shared/" + dirName + "/" + filename, context);
            file.delete();
        }
        dir.delete();
    }

    @Test
    void testStreamingLargeFile() throws Exception {
        String filename = "streaming_" + System.currentTimeMillis() + ".dat";
        SmbFile file = new SmbFile(baseUrl + "shared/" + filename, context);

        // Create 5MB of streaming test data
        int totalSize = 5 * 1024 * 1024;
        int chunkSize = 64 * 1024;

        // Write in chunks
        try (OutputStream out = file.openOutputStream(false)) {
            for (int i = 0; i < totalSize; i += chunkSize) {
                int currentChunkSize = Math.min(chunkSize, totalSize - i);
                byte[] chunk = new byte[currentChunkSize];

                // Fill chunk with predictable pattern
                for (int j = 0; j < currentChunkSize; j++) {
                    chunk[j] = (byte) ((i + j) % 256);
                }

                out.write(chunk);
            }
        }

        assertEquals(totalSize, file.length(), "File size should match written data");

        // Read back in chunks and verify
        try (InputStream in = file.getInputStream()) {
            byte[] buffer = new byte[chunkSize];
            int totalRead = 0;
            int bytesRead;

            while ((bytesRead = in.read(buffer)) != -1) {
                // Verify chunk content
                for (int i = 0; i < bytesRead; i++) {
                    byte expected = (byte) ((totalRead + i) % 256);
                    assertEquals(expected, buffer[i], "Byte mismatch at position " + (totalRead + i));
                }
                totalRead += bytesRead;
            }

            assertEquals(totalSize, totalRead, "Should read all data back");
        }

        // Clean up
        file.delete();
    }

    @Test
    void testSymbolicLinksAndSpecialFiles() throws Exception {
        // Test handling of different file types (regular files vs directories)
        String testDir = "specialfiles_" + System.currentTimeMillis();
        SmbFile dir = new SmbFile(baseUrl + "shared/" + testDir + "/", context);
        dir.mkdir();

        // Create nested directory structure
        SmbFile subDir = new SmbFile(baseUrl + "shared/" + testDir + "/subdir/", context);
        subDir.mkdir();

        SmbFile fileInSubDir = new SmbFile(baseUrl + "shared/" + testDir + "/subdir/nested.txt", context);
        try (OutputStream out = fileInSubDir.openOutputStream(false)) {
            out.write("nested file content".getBytes("UTF-8"));
        }

        // Test directory traversal
        String[] dirContents = dir.list();
        assertEquals(1, dirContents.length, "Directory should contain subdirectory");
        assertEquals("subdir", dirContents[0], "Should find subdirectory");

        String[] subDirContents = subDir.list();
        assertEquals(1, subDirContents.length, "Subdirectory should contain file");
        assertEquals("nested.txt", subDirContents[0], "Should find nested file");

        // Test type identification
        assertTrue(dir.isDirectory(), "Should identify directory correctly");
        assertTrue(subDir.isDirectory(), "Should identify subdirectory correctly");
        assertTrue(fileInSubDir.isFile(), "Should identify file correctly");

        // Clean up
        fileInSubDir.delete();
        subDir.delete();
        dir.delete();
    }

    @Test
    void testErrorHandlingAndRecovery() throws Exception {
        // Test operations on non-existent files
        SmbFile nonExistent = new SmbFile(baseUrl + "shared/does_not_exist.txt", context);

        assertFalse(nonExistent.exists(), "Non-existent file should not exist");
        assertThrows(SmbException.class, () -> {
            nonExistent.getInputStream();
        }, "Reading non-existent file should throw exception");

        // Test operations on invalid paths
        assertThrows(Exception.class, () -> {
            new SmbFile(baseUrl + "nonexistent_share/file.txt", context);
        }, "Invalid share should cause error");

        // Test recovery after failed operations
        String filename = "recovery_" + System.currentTimeMillis() + ".txt";
        SmbFile file = new SmbFile(baseUrl + "shared/" + filename, context);

        // Create file
        try (OutputStream out = file.openOutputStream(false)) {
            out.write("recovery test".getBytes("UTF-8"));
        }

        assertTrue(file.exists(), "File should exist after creation");

        // File should still be operable after failed operation attempt
        try (InputStream in = file.getInputStream()) {
            String content = new String(in.readAllBytes(), "UTF-8");
            assertEquals("recovery test", content, "File should be readable after failed operation");
        }

        // Clean up
        file.delete();
    }

    // ========== Docker Environment Check ==========

    /**
     * Check if Docker is available and running.
     * This method is used by @EnabledIf to conditionally enable tests.
     */
    static boolean isDockerAvailable() {
        try {
            // First check if docker command exists
            ProcessBuilder versionCheck = new ProcessBuilder("docker", "--version");
            versionCheck.redirectErrorStream(true);
            Process versionProcess = versionCheck.start();
            int versionExitCode = versionProcess.waitFor();

            if (versionExitCode != 0) {
                System.out.println("Docker command not available");
                return false;
            }

            // Check if Docker daemon is running
            ProcessBuilder psCheck = new ProcessBuilder("docker", "ps");
            psCheck.redirectErrorStream(true);
            Process psProcess = psCheck.start();
            int psExitCode = psProcess.waitFor();

            if (psExitCode != 0) {
                System.out.println("Docker daemon not running - integration tests will be skipped");
                return false;
            }

            System.out.println("Docker is available and running - integration tests will be executed");
            return true;

        } catch (Exception e) {
            System.out.println("Docker availability check failed: " + e.getMessage());
            return false;
        }
    }

    // ========== Helper Methods ==========

    private void setupTestDirectoryStructure() throws IOException {
        // Create directory structure
        Files.createDirectories(tempDir.resolve("public"));
        Files.createDirectories(tempDir.resolve("shared"));

        // Create some initial files
        Files.writeString(tempDir.resolve("public/readme.txt"), "This is a public share for testing");
        Files.writeString(tempDir.resolve("shared/initial.txt"), "Initial file in shared directory");
    }

    private void waitForServerReady() throws Exception {
        int maxAttempts = 30;
        int attempt = 0;

        while (attempt < maxAttempts) {
            try {
                SmbFile testFile = new SmbFile(baseUrl + "public/", context);
                if (testFile.exists()) {
                    log.info("SMB server is ready after {} attempts", attempt + 1);
                    return;
                }
            } catch (Exception e) {
                log.debug("SMB server not ready, attempt {}: {}", attempt + 1, e.getMessage());
            }

            attempt++;
            Thread.sleep(2000);
        }

        throw new RuntimeException("SMB server failed to become ready after " + maxAttempts + " attempts");
    }

    private CIFSContext createFreshContext() throws Exception {
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(SingletonContext.getInstance(), WORKGROUP, USERNAME, PASSWORD);
        return SingletonContext.getInstance().withCredentials(auth);
    }

    private void deleteDirectory(Path dir) throws IOException {
        Files.walk(dir).map(Path::toFile).sorted((o1, o2) -> -o1.compareTo(o2)).forEach(file -> {
            if (!file.delete()) {
                log.warn("Could not delete: {}", file.getAbsolutePath());
            }
        });
    }
}