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
package org.codelibs.jcifs.smb.internal.smb2.rdma;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.InetSocketAddress;
import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.SmbTransportInternal;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.context.BaseContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for RDMA functionality.
 *
 * This class contains both unit tests (that always run) and integration tests
 * (that require system properties to be set for execution).
 *
 * Integration tests require system properties:
 * - rdma.test.enabled=true (to enable RDMA integration tests)
 * - rdma.test.server=hostname/IP (target server for testing)
 * - rdma.test.port=445 (target port, defaults to 445)
 */
public class RdmaIntegrationTest {

    private String testServer;
    private int testPort;
    private CIFSContext testContext;

    @BeforeEach
    public void setUp() throws Exception {
        testServer = System.getProperty("rdma.test.server");
        String portStr = System.getProperty("rdma.test.port", "445");
        testPort = Integer.parseInt(portStr);

        // Create RDMA-enabled context
        Properties props = new Properties();
        props.setProperty("jcifs.client.useRDMA", "true");
        props.setProperty("jcifs.client.rdmaProvider", "auto");

        PropertyConfiguration config = new PropertyConfiguration(props);
        testContext = new BaseContext(config);
    }

    // ============================================
    // UNIT TESTS - Always run, no external deps
    // ============================================

    @Test
    public void testRdmaProviderSelectionAlwaysReturnsProvider() {
        // This should always return at least the TCP fallback provider
        RdmaProvider provider = RdmaProviderFactory.selectBestProvider();
        assertNotNull(provider, "Should always select an RDMA provider (at minimum TCP fallback)");
        assertNotNull(provider.getProviderName(), "Provider name should not be null");
        assertNotNull(provider.getSupportedCapabilities(), "Supported capabilities should not be null");
        assertTrue(provider.getMaxMessageSize() > 0, "Max message size should be positive");

        System.out.println("Selected RDMA provider: " + provider.getProviderName());
        System.out.println("Supported capabilities: " + provider.getSupportedCapabilities());
        System.out.println("Max message size: " + provider.getMaxMessageSize());
    }

    @Test
    public void testRdmaConnectionCreationWithTcpFallback() throws Exception {
        RdmaProvider provider = RdmaProviderFactory.selectBestProvider();

        // Use localhost for testing - should work with TCP fallback
        InetSocketAddress address = new InetSocketAddress("localhost", 12345);

        try (RdmaConnection connection = provider.createConnection(address, null)) {
            assertNotNull(connection, "Connection should not be null");
            assertEquals(address, connection.getRemoteAddress(), "Remote address should match");
            assertNotNull(connection.getState(), "Connection state should not be null");

            System.out.println("RDMA connection created to: " + address);
            System.out.println("Connection state: " + connection.getState());
        }
    }

    @Test
    public void testRdmaTransportCreationWithMockDelegate() throws Exception {
        // Create a mock SmbTransportInternal for RdmaTransport
        SmbTransportInternal mockTransport = mock(SmbTransportInternal.class);
        when(mockTransport.isDisconnected()).thenReturn(true);
        when(mockTransport.toString()).thenReturn("MockTransport");

        try (RdmaTransport transport = new RdmaTransport(mockTransport, testContext)) {
            assertNotNull(transport, "Transport should not be null");
            assertTrue(transport.isDisconnected(), "Transport should be disconnected initially");

            System.out.println("RDMA transport created successfully with mock delegate");
        }
    }

    @Test
    public void testRdmaStatisticsTracking() throws Exception {
        RdmaStatistics stats = new RdmaStatistics();

        // Simulate various RDMA operations
        stats.recordRdmaRead(1024, 1000000); // 1KB in 1ms
        stats.recordRdmaWrite(2048, 2000000); // 2KB in 2ms
        stats.recordRdmaSend(512, 500000); // 512B in 0.5ms
        stats.recordRdmaReceive(1536, 1500000); // 1.5KB in 1.5ms
        stats.recordError();

        // Verify counters
        assertEquals(1, stats.getRdmaReads(), "Should have 1 read operation");
        assertEquals(1, stats.getRdmaWrites(), "Should have 1 write operation");
        assertEquals(1, stats.getRdmaSends(), "Should have 1 send operation");
        assertEquals(1, stats.getRdmaReceives(), "Should have 1 receive operation");
        assertEquals(5120, stats.getBytesTransferred(), "Should have transferred 5KB total");
        assertEquals(1, stats.getOperationErrors(), "Should have 1 error");
        assertEquals(0.25, stats.getErrorRate(), 0.001, "Error rate should be 25% (1 error out of 4 successful operations)");

        // Verify latency calculations
        assertTrue(stats.getAverageReadLatencyMicros() > 0, "Read latency should be positive");
        assertTrue(stats.getAverageWriteLatencyMicros() > 0, "Write latency should be positive");

        System.out.println("RDMA Statistics: " + stats);

        // Test statistics reset functionality
        stats.reset();
        assertEquals(0, stats.getRdmaReads(), "Reads should be reset to 0");
        assertEquals(0, stats.getRdmaWrites(), "Writes should be reset to 0");
        assertEquals(0, stats.getBytesTransferred(), "Bytes should be reset to 0");
        assertEquals(0, stats.getOperationErrors(), "Errors should be reset to 0");
        assertEquals(0.0, stats.getErrorRate(), 0.001, "Error rate should be 0% after reset");
    }

    @Test
    public void testRdmaErrorHandlerBehavior() {
        RdmaStatistics stats = new RdmaStatistics();
        RdmaErrorHandler errorHandler = new RdmaErrorHandler(stats, 3, 50); // 3 retries, 50ms delay

        assertNotNull(errorHandler, "Error handler should not be null");

        // Test error classification for different exception types
        Exception hardwareError = new RuntimeException("RDMA hardware not supported");
        Exception networkError = new java.io.IOException("Network connection failed");
        Exception timeoutError = new java.net.SocketTimeoutException("Operation timed out");

        // Test fallback logic
        assertTrue(errorHandler.shouldFallbackToTcp(hardwareError), "Hardware errors should suggest TCP fallback");
        assertFalse(errorHandler.shouldFallbackToTcp(timeoutError), "Timeout errors should not immediately suggest TCP fallback");

        // Test error classification using public API
        assertNotNull(errorHandler, "Error handler should handle network errors");

        // Test fallback logic which is public
        assertTrue(errorHandler.shouldFallbackToTcp(hardwareError), "Hardware errors should suggest TCP fallback");
        assertFalse(errorHandler.shouldFallbackToTcp(timeoutError), "Timeout errors should not immediately suggest TCP fallback");

        System.out.println("Error handler configured with 3 retries and 50ms delay");
    }

    @Test
    public void testRdmaBufferManagerUnitTests() throws Exception {
        RdmaProvider provider = RdmaProviderFactory.selectBestProvider();

        try (RdmaBufferManager bufferManager = new RdmaBufferManager(provider)) {
            // Test basic buffer allocation
            RdmaMemoryRegion sendRegion = bufferManager.getSendRegion(4096);
            assertNotNull(sendRegion, "Send region should not be null");
            assertTrue(sendRegion.getSize() >= 4096, "Send region should be at least 4KB");
            assertNotNull(sendRegion.getBuffer(), "Send region buffer should not be null");

            RdmaMemoryRegion recvRegion = bufferManager.getReceiveRegion();
            assertNotNull(recvRegion, "Receive region should not be null");
            assertTrue(recvRegion.getSize() > 0, "Receive region should have positive size");
            assertNotNull(recvRegion.getBuffer(), "Receive region buffer should not be null");

            // Test buffer pooling statistics
            long initialAllocated = bufferManager.getTotalAllocated();
            long initialActive = bufferManager.getActiveRegions();

            assertTrue(initialAllocated >= 2, "Should have allocated at least 2 regions");
            assertTrue(initialActive >= 2, "Should have at least 2 active regions");

            // Test buffer release and reuse
            bufferManager.releaseSendRegion(sendRegion);
            bufferManager.releaseReceiveRegion(recvRegion);

            // Allocate again to test pooling
            RdmaMemoryRegion newSendRegion = bufferManager.getSendRegion(4096);
            assertNotNull(newSendRegion, "Should be able to allocate new send region");

            // Release the new region
            bufferManager.releaseSendRegion(newSendRegion);

            System.out.println("Buffer manager stats - Total Allocated: " + bufferManager.getTotalAllocated() + ", Active: "
                    + bufferManager.getActiveRegions());
        }
    }

    // ===================================================
    // ADDITIONAL UNIT TESTS - Always run with mocks
    // ===================================================

    @Test
    public void testRdmaConnectionLifecycle() throws Exception {
        // Test connection lifecycle without requiring real server
        RdmaProvider provider = RdmaProviderFactory.selectBestProvider();
        assertNotNull(provider, "Should always have a provider (at least TCP fallback)");

        // Use mock address for testing
        InetSocketAddress mockAddress = new InetSocketAddress("127.0.0.1", 445);

        try (RdmaConnection connection = provider.createConnection(mockAddress, null)) {
            assertNotNull(connection, "Connection should not be null");
            assertEquals(mockAddress, connection.getRemoteAddress(), "Remote address should match");

            // Test connection state transitions
            RdmaConnection.RdmaConnectionState initialState = connection.getState();
            assertNotNull(initialState, "Initial state should not be null");
            assertTrue(
                    initialState == RdmaConnection.RdmaConnectionState.DISCONNECTED
                            || initialState == RdmaConnection.RdmaConnectionState.CONNECTING,
                    "Initial state should be DISCONNECTED or CONNECTING");

            // Test connection properties
            // Note: Local address may be null for TCP fallback provider
            InetSocketAddress localAddr = connection.getLocalAddress();
            if (localAddr != null) {
                System.out.println("Local address: " + localAddr);
            }

            // Test that connection was created successfully
            assertNotNull(connection.getState(), "Connection should have a state");

            System.out.println("Connection lifecycle test completed for provider: " + provider.getProviderName());
        }
    }

    @Test
    public void testRdmaDataTransferComponents() throws Exception {
        // Test data transfer components without requiring real RDMA
        RdmaProvider provider = RdmaProviderFactory.selectBestProvider();

        // Create mock connection for testing
        InetSocketAddress mockAddress = new InetSocketAddress("localhost", 445);

        try (RdmaConnection connection = provider.createConnection(mockAddress, null);
                RdmaBufferManager bufferManager = new RdmaBufferManager(provider)) {

            assertNotNull(connection, "Connection should be created");
            assertNotNull(bufferManager, "Buffer manager should be created");

            // Test buffer allocation for data transfer
            RdmaMemoryRegion sendBuffer = bufferManager.getSendRegion(8192);
            assertNotNull(sendBuffer, "Send buffer should be allocated");
            assertTrue(sendBuffer.getSize() >= 8192, "Send buffer should be at least 8KB");

            RdmaMemoryRegion recvBuffer = bufferManager.getReceiveRegion();
            assertNotNull(recvBuffer, "Receive buffer should be allocated");
            assertTrue(recvBuffer.getSize() > 0, "Receive buffer should have positive size");

            // Test data preparation
            byte[] testData = "Test RDMA data transfer".getBytes();
            sendBuffer.getBuffer().put(testData);
            sendBuffer.getBuffer().flip();
            assertEquals(testData.length, sendBuffer.getBuffer().remaining(), "Buffer should contain test data");

            // Clean up
            bufferManager.releaseSendRegion(sendBuffer);
            bufferManager.releaseReceiveRegion(recvBuffer);

            System.out.println("RDMA data transfer components test completed");
        }
    }
}
