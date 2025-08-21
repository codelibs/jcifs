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
package jcifs.internal.smb2.multichannel;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.config.PropertyConfiguration;
import jcifs.context.SingletonContext;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.context.BaseContext;

/**
 * Integration tests for SMB3 Multi-Channel functionality
 *
 * These tests require a real SMB server with multi-channel support.
 * Run with -Djcifs.test.integration=true and provide server details.
 */
@EnabledIfSystemProperty(named = "jcifs.test.integration", matches = "true")
class MultiChannelIntegrationTest {

    private static final String TEST_SERVER = System.getProperty("jcifs.test.server", "localhost");
    private static final String TEST_SHARE = System.getProperty("jcifs.test.share", "test");
    private static final String TEST_USER = System.getProperty("jcifs.test.user", "test");
    private static final String TEST_PASSWORD = System.getProperty("jcifs.test.password", "test");

    private CIFSContext context;

    @BeforeEach
    void setUp() throws CIFSException {
        Properties props = new Properties();

        // Enable multi-channel
        props.setProperty("jcifs.smb.client.useMultiChannel", "true");
        props.setProperty("jcifs.smb.client.maxChannels", "4");
        props.setProperty("jcifs.smb.client.loadBalancingStrategy", "adaptive");
        props.setProperty("jcifs.smb.client.channelHealthCheckInterval", "5");

        // Use SMB3 for multi-channel support
        props.setProperty("jcifs.smb.client.minVersion", "SMB300");
        props.setProperty("jcifs.smb.client.maxVersion", "SMB311");

        // Authentication
        props.setProperty("jcifs.smb.client.username", TEST_USER);
        props.setProperty("jcifs.smb.client.password", TEST_PASSWORD);

        PropertyConfiguration config = new PropertyConfiguration(props);
        context = new BaseContext(config);
    }

    @Test
    void testMultiChannelConnection() throws Exception {
        assumeServerAvailable();

        try (SmbFile testDir = new SmbFile("smb://" + TEST_SERVER + "/" + TEST_SHARE + "/", context)) {
            assertTrue(testDir.exists(), "Test share should be accessible");

            // Check if multi-channel was negotiated
            // This would require access to session internals
            // For now, just verify the connection works
            SmbFile[] files = testDir.listFiles();
            assertNotNull(files, "Should be able to list files");
        }
    }

    @Test
    void testLargeFileTransferWithMultiChannel() throws Exception {
        assumeServerAvailable();

        String testFileName = "multichannel-test-" + System.currentTimeMillis() + ".dat";
        try (SmbFile testFile = new SmbFile("smb://" + TEST_SERVER + "/" + TEST_SHARE + "/" + testFileName, context)) {

            // Create a large test file (10MB)
            byte[] testData = new byte[10 * 1024 * 1024];
            for (int i = 0; i < testData.length; i++) {
                testData[i] = (byte) (i % 256);
            }

            // Write the file
            long startWrite = System.currentTimeMillis();
            try (OutputStream out = testFile.getOutputStream()) {
                out.write(testData);
                out.flush();
            }
            long writeTime = System.currentTimeMillis() - startWrite;

            // Read the file back
            long startRead = System.currentTimeMillis();
            byte[] readData = new byte[testData.length];
            try (InputStream in = testFile.getInputStream()) {
                int totalRead = 0;
                while (totalRead < readData.length) {
                    int read = in.read(readData, totalRead, readData.length - totalRead);
                    if (read == -1)
                        break;
                    totalRead += read;
                }
                assertEquals(testData.length, totalRead);
            }
            long readTime = System.currentTimeMillis() - startRead;

            // Verify data integrity
            assertArrayEquals(testData, readData, "Data should be identical after round-trip");

            System.out.println("Write time: " + writeTime + "ms, Read time: " + readTime + "ms");

            // Clean up
            testFile.delete();
        }
    }

    @Test
    void testConcurrentOperations() throws Exception {
        assumeServerAvailable();

        int numThreads = 4;
        int numOperations = 10;
        CompletableFuture<Void>[] futures = new CompletableFuture[numThreads];

        for (int t = 0; t < numThreads; t++) {
            final int threadId = t;
            futures[t] = CompletableFuture.runAsync(() -> {
                try {
                    for (int i = 0; i < numOperations; i++) {
                        String fileName = "concurrent-test-" + threadId + "-" + i + ".txt";
                        try (SmbFile file = new SmbFile("smb://" + TEST_SERVER + "/" + TEST_SHARE + "/" + fileName, context)) {

                            // Write operation
                            String content = "Thread " + threadId + " operation " + i;
                            try (OutputStream out = file.getOutputStream()) {
                                out.write(content.getBytes());
                            }

                            // Read operation
                            try (InputStream in = file.getInputStream()) {
                                byte[] buffer = new byte[1024];
                                int read = in.read(buffer);
                                String readContent = new String(buffer, 0, read);
                                assertEquals(content, readContent);
                            }

                            // Delete operation
                            file.delete();
                        }
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }

        // Wait for all operations to complete
        CompletableFuture.allOf(futures).get(30, TimeUnit.SECONDS);

        System.out.println("Successfully completed " + (numThreads * numOperations) + " concurrent operations");
    }

    @Test
    void testChannelFailureRecovery() throws Exception {
        assumeServerAvailable();

        try (SmbFile testDir = new SmbFile("smb://" + TEST_SERVER + "/" + TEST_SHARE + "/", context)) {

            // Perform initial operation
            assertTrue(testDir.exists());
            SmbFile[] initialFiles = testDir.listFiles();
            assertNotNull(initialFiles);

            // Simulate network disruption by creating many concurrent operations
            // This might trigger channel failures and recovery
            CompletableFuture<Void>[] futures = new CompletableFuture[20];

            for (int i = 0; i < futures.length; i++) {
                final int opId = i;
                futures[i] = CompletableFuture.runAsync(() -> {
                    try {
                        Thread.sleep(opId * 10); // Stagger operations

                        try (SmbFile testFile =
                                new SmbFile("smb://" + TEST_SERVER + "/" + TEST_SHARE + "/recovery-test-" + opId + ".tmp", context)) {
                            testFile.createNewFile();
                            assertTrue(testFile.exists());
                            testFile.delete();
                        }
                    } catch (Exception e) {
                        // Some operations might fail due to simulated disruption
                        System.out.println("Operation " + opId + " failed: " + e.getMessage());
                    }
                });
            }

            // Wait for operations to complete
            CompletableFuture.allOf(futures).get(60, TimeUnit.SECONDS);

            // Verify we can still perform operations after potential failures
            SmbFile[] finalFiles = testDir.listFiles();
            assertNotNull(finalFiles, "Should still be able to list files after recovery");
        }
    }

    @Test
    void testLoadBalancingStrategies() throws Exception {
        assumeServerAvailable();

        // Test different load balancing strategies
        String[] strategies = { "ROUND_ROBIN", "LEAST_LOADED", "WEIGHTED_RANDOM", "ADAPTIVE" };

        for (String strategy : strategies) {
            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.useMultiChannel", "true");
            props.setProperty("jcifs.smb.client.loadBalancingStrategy", strategy);
            props.setProperty("jcifs.smb.client.username", TEST_USER);
            props.setProperty("jcifs.smb.client.password", TEST_PASSWORD);

            PropertyConfiguration config = new PropertyConfiguration(props);
            CIFSContext strategyContext = new BaseContext(config);

            try (SmbFile testDir = new SmbFile("smb://" + TEST_SERVER + "/" + TEST_SHARE + "/", strategyContext)) {
                assertTrue(testDir.exists(), "Connection should work with " + strategy + " strategy");

                // Perform a few operations to exercise the load balancer
                for (int i = 0; i < 5; i++) {
                    SmbFile[] files = testDir.listFiles();
                    assertNotNull(files, "List operation should work with " + strategy);
                }
            }
        }
    }

    private void assumeServerAvailable() {
        try {
            InetAddress.getByName(TEST_SERVER);
        } catch (UnknownHostException e) {
            assumeTrue(false, "Test server " + TEST_SERVER + " is not available: " + e.getMessage());
        }
    }
}
