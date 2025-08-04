package jcifs.context;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.net.URLStreamHandler;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import jcifs.BaseTest;
import jcifs.BufferCache;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.DfsResolver;
import jcifs.NameServiceClient;
import jcifs.SidResolver;
import jcifs.SmbPipeResource;
import jcifs.SmbResource;
import jcifs.SmbTransportPool;
import jcifs.config.BaseConfiguration;

/**
 * Comprehensive test suite for BaseContext class.
 * Tests CIFS context implementation and component integration.
 */
@DisplayName("BaseContext Tests")
class BaseContextTest extends BaseTest {

    @Mock
    private Configuration mockConfig;

    private BaseContext context;

    @BeforeEach
    void setUp() throws CIFSException {
        // Setup mock configuration with required methods
        when(mockConfig.getDefaultUsername()).thenReturn(null);
        when(mockConfig.getDefaultPassword()).thenReturn(null);
        when(mockConfig.getDefaultDomain()).thenReturn(null);
        when(mockConfig.getBufferCacheSize()).thenReturn(16);
        when(mockConfig.getMaximumBufferSize()).thenReturn(65536);

        context = new BaseContext(mockConfig);
    }

    @Test
    @DisplayName("Constructor should initialize all components")
    void testConstructorInitialization() {
        // Then
        assertNotNull(context, "Context should be created");
        assertNotNull(context.getConfig(), "Configuration should be initialized");
        assertNotNull(context.getDfs(), "DFS resolver should be initialized");
        assertNotNull(context.getSIDResolver(), "SID resolver should be initialized");
        assertNotNull(context.getUrlHandler(), "URL handler should be initialized");
        assertNotNull(context.getNameServiceClient(), "Name service client should be initialized");
        assertNotNull(context.getBufferCache(), "Buffer cache should be initialized");
        assertNotNull(context.getTransportPool(), "Transport pool should be initialized");
    }

    @Test
    @DisplayName("Constructor should use provided configuration")
    void testConstructorUsesConfiguration() {
        // Then
        assertSame(mockConfig, context.getConfig(), "Should use provided configuration");
        verify(mockConfig).getDefaultUsername();
        verify(mockConfig).getDefaultPassword();
        verify(mockConfig).getDefaultDomain();
    }

    @Test
    @DisplayName("Constructor should handle credentials from configuration")
    void testConstructorWithCredentials() throws CIFSException {
        // Given
        Configuration configWithCreds = mock(Configuration.class);
        when(configWithCreds.getDefaultUsername()).thenReturn("testuser");
        when(configWithCreds.getDefaultPassword()).thenReturn("testpass");
        when(configWithCreds.getDefaultDomain()).thenReturn("TESTDOMAIN");
        when(configWithCreds.getBufferCacheSize()).thenReturn(16);
        when(configWithCreds.getMaximumBufferSize()).thenReturn(65536);

        // When
        BaseContext contextWithCreds = new BaseContext(configWithCreds);

        // Then
        assertNotNull(contextWithCreds, "Context with credentials should be created");
        verify(configWithCreds).getDefaultUsername();
        verify(configWithCreds).getDefaultPassword();
        verify(configWithCreds).getDefaultDomain();
    }

    @Test
    @DisplayName("get method should create SmbResource from URL")
    void testGetSmbResource() throws CIFSException {
        // When
        SmbResource resource = context.get("smb://server/share/file.txt");

        // Then
        assertNotNull(resource, "Should create SMB resource");
        assertTrue(resource.getLocator().getURL().toString().contains("server/share/file.txt"), "Resource should contain URL path");
    }

    @Test
    @DisplayName("get method should handle malformed URLs")
    void testGetSmbResourceWithMalformedURL() {
        // When & Then
        CIFSException exception = assertThrows(CIFSException.class, () -> {
            context.get("invalid://url");
        });

        assertTrue(exception.getMessage().contains("Invalid URL"), "Exception should indicate invalid URL");
        assertTrue(exception.getCause() instanceof MalformedURLException, "Cause should be MalformedURLException");
    }

    @Test
    @DisplayName("get method should handle various URL formats")
    void testGetSmbResourceWithVariousURLs() throws CIFSException {
        // Test different valid URL formats
        String[] validUrls = { "smb://server/share/", "smb://server/share/file.txt", "smb://user:pass@server/share/file.txt",
                "smb://domain;user:pass@server/share/file.txt" };

        for (String url : validUrls) {
            // When
            SmbResource resource = context.get(url);

            // Then
            assertNotNull(resource, "Should create resource for URL: " + url);
        }
    }

    @Test
    @DisplayName("getPipe method should create SmbPipeResource")
    void testGetPipeResource() throws CIFSException {
        // When
        SmbPipeResource pipe = context.getPipe("smb://server/IPC$/pipe", 0);

        // Then
        assertNotNull(pipe, "Should create pipe resource");
        assertTrue(pipe.getLocator().getURL().toString().contains("pipe"), "Pipe resource should contain pipe path");
    }

    @Test
    @DisplayName("getPipe method should handle malformed URLs")
    void testGetPipeResourceWithMalformedURL() {
        // When & Then
        CIFSException exception = assertThrows(CIFSException.class, () -> {
            context.getPipe("invalid://url", 0);
        });

        assertTrue(exception.getMessage().contains("Invalid URL"), "Exception should indicate invalid URL");
        assertTrue(exception.getCause() instanceof MalformedURLException, "Cause should be MalformedURLException");
    }

    @Test
    @DisplayName("getPipe method should handle different pipe types")
    void testGetPipeResourceWithDifferentTypes() throws CIFSException {
        // Test different pipe types
        int[] pipeTypes = { 0, 1, 2 };

        for (int pipeType : pipeTypes) {
            // When
            SmbPipeResource pipe = context.getPipe("smb://server/IPC$/pipe", pipeType);

            // Then
            assertNotNull(pipe, "Should create pipe resource for type: " + pipeType);
        }
    }

    @Test
    @DisplayName("getTransportPool should return initialized transport pool")
    void testGetTransportPool() {
        // When
        SmbTransportPool transportPool = context.getTransportPool();

        // Then
        assertNotNull(transportPool, "Transport pool should not be null");
        assertSame(transportPool, context.getTransportPool(), "Should return same instance on multiple calls");
    }

    @Test
    @DisplayName("getConfig should return the provided configuration")
    void testGetConfig() {
        // When
        Configuration config = context.getConfig();

        // Then
        assertSame(mockConfig, config, "Should return the same configuration instance");
    }

    @Test
    @DisplayName("getDfs should return initialized DFS resolver")
    void testGetDfs() {
        // When
        DfsResolver dfs = context.getDfs();

        // Then
        assertNotNull(dfs, "DFS resolver should not be null");
        assertSame(dfs, context.getDfs(), "Should return same instance on multiple calls");
    }

    @Test
    @DisplayName("getNameServiceClient should return initialized name service client")
    void testGetNameServiceClient() {
        // When
        NameServiceClient nameServiceClient = context.getNameServiceClient();

        // Then
        assertNotNull(nameServiceClient, "Name service client should not be null");
        assertSame(nameServiceClient, context.getNameServiceClient(), "Should return same instance on multiple calls");
    }

    @Test
    @DisplayName("getBufferCache should return initialized buffer cache")
    void testGetBufferCache() {
        // When
        BufferCache bufferCache = context.getBufferCache();

        // Then
        assertNotNull(bufferCache, "Buffer cache should not be null");
        assertSame(bufferCache, context.getBufferCache(), "Should return same instance on multiple calls");
    }

    @Test
    @DisplayName("getUrlHandler should return initialized URL handler")
    void testGetUrlHandler() {
        // When
        URLStreamHandler urlHandler = context.getUrlHandler();

        // Then
        assertNotNull(urlHandler, "URL handler should not be null");
        assertSame(urlHandler, context.getUrlHandler(), "Should return same instance on multiple calls");
    }

    @Test
    @DisplayName("getSIDResolver should return initialized SID resolver")
    void testGetSIDResolver() {
        // When
        SidResolver sidResolver = context.getSIDResolver();

        // Then
        assertNotNull(sidResolver, "SID resolver should not be null");
        assertSame(sidResolver, context.getSIDResolver(), "Should return same instance on multiple calls");
    }

    @Test
    @DisplayName("Context should implement CIFSContext interface")
    void testInterfaceImplementation() {
        // Then
        assertTrue(context instanceof jcifs.CIFSContext, "BaseContext should implement CIFSContext interface");
    }

    @Test
    @DisplayName("Context should extend AbstractCIFSContext")
    void testInheritanceHierarchy() {
        // Then
        assertTrue(context instanceof AbstractCIFSContext, "BaseContext should extend AbstractCIFSContext");
    }

    @Test
    @DisplayName("Context should handle concurrent access safely")
    void testConcurrentAccess() throws InterruptedException {
        // Given
        final int threadCount = 10;
        final Thread[] threads = new Thread[threadCount];
        final boolean[] results = new boolean[threadCount];

        // When
        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                try {
                    // Multiple threads accessing context simultaneously
                    for (int j = 0; j < 50; j++) {
                        context.getConfig();
                        context.getBufferCache();
                        context.getDfs();
                        context.getNameServiceClient();
                        context.getSIDResolver();
                        context.getTransportPool();
                        context.getUrlHandler();

                        // Try creating resources
                        context.get("smb://server" + index + "/share/file" + j + ".txt");
                    }
                    results[index] = true;
                } catch (Exception e) {
                    logger.error("Thread {} failed", index, e);
                    results[index] = false;
                }
            });
            threads[i].start();
        }

        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }

        // Then
        for (int i = 0; i < threadCount; i++) {
            assertTrue(results[i], "Thread " + i + " should have completed successfully");
        }
    }

    @Test
    @DisplayName("Context should work with real configuration")
    void testWithRealConfiguration() throws CIFSException {
        // Given
        BaseConfiguration realConfig = new BaseConfiguration(true);

        // When
        BaseContext realContext = new BaseContext(realConfig);

        // Then
        assertNotNull(realContext, "Context should work with real configuration");
        assertSame(realConfig, realContext.getConfig(), "Should use provided real configuration");

        // Verify all components are initialized
        assertNotNull(realContext.getDfs(), "DFS should be initialized");
        assertNotNull(realContext.getSIDResolver(), "SID resolver should be initialized");
        assertNotNull(realContext.getUrlHandler(), "URL handler should be initialized");
        assertNotNull(realContext.getNameServiceClient(), "Name service client should be initialized");
        assertNotNull(realContext.getBufferCache(), "Buffer cache should be initialized");
        assertNotNull(realContext.getTransportPool(), "Transport pool should be initialized");
    }

    @Test
    @DisplayName("Context should handle resource creation errors gracefully")
    void testResourceCreationErrorHandling() {
        // Test various malformed URLs
        String[] malformedUrls = { "", "not-a-url", "ftp://wrong-protocol/path", "smb://", // Too short
                "smb:///", // Missing server
                "http://server/path" // Wrong protocol
        };

        for (String malformedUrl : malformedUrls) {
            // When & Then
            assertThrows(CIFSException.class, () -> {
                context.get(malformedUrl);
            }, "Should throw CIFSException for malformed URL: " + malformedUrl);

            assertThrows(CIFSException.class, () -> {
                context.getPipe(malformedUrl, 0);
            }, "Should throw CIFSException for malformed pipe URL: " + malformedUrl);
        }
    }

    @Test
    @DisplayName("Context components should maintain consistent state")
    void testComponentStateConsistency() {
        // When - get components multiple times
        Configuration config1 = context.getConfig();
        Configuration config2 = context.getConfig();
        DfsResolver dfs1 = context.getDfs();
        DfsResolver dfs2 = context.getDfs();
        BufferCache cache1 = context.getBufferCache();
        BufferCache cache2 = context.getBufferCache();

        // Then - should be same instances
        assertSame(config1, config2, "Configuration should be consistent");
        assertSame(dfs1, dfs2, "DFS resolver should be consistent");
        assertSame(cache1, cache2, "Buffer cache should be consistent");
    }

    @Test
    @DisplayName("Context should provide working resource creation")
    void testWorkingResourceCreation() throws CIFSException {
        // When
        SmbResource resource1 = context.get("smb://server1/share1/file1.txt");
        SmbResource resource2 = context.get("smb://server2/share2/file2.txt");
        SmbPipeResource pipe1 = context.getPipe("smb://server1/IPC$/pipe1", 1);
        SmbPipeResource pipe2 = context.getPipe("smb://server2/IPC$/pipe2", 2);

        // Then
        assertNotNull(resource1, "First resource should be created");
        assertNotNull(resource2, "Second resource should be created");
        assertNotNull(pipe1, "First pipe should be created");
        assertNotNull(pipe2, "Second pipe should be created");

        assertNotSame(resource1, resource2, "Different resources should be different instances");
        assertNotSame(pipe1, pipe2, "Different pipes should be different instances");

        assertTrue(resource1.getLocator().getURL().toString().contains("server1"), "First resource should contain server1");
        assertTrue(resource2.getLocator().getURL().toString().contains("server2"), "Second resource should contain server2");
    }
}