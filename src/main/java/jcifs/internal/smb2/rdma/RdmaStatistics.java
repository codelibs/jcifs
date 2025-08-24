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
package jcifs.internal.smb2.rdma;

import java.util.concurrent.atomic.AtomicLong;

/**
 * RDMA performance statistics and monitoring.
 *
 * This class tracks various RDMA operation metrics for performance
 * monitoring and troubleshooting purposes.
 */
public class RdmaStatistics {

    /**
     * Creates a new RDMA statistics tracker
     */
    public RdmaStatistics() {
        // Default constructor
    }

    private final AtomicLong rdmaReads = new AtomicLong();
    private final AtomicLong rdmaWrites = new AtomicLong();
    private final AtomicLong rdmaSends = new AtomicLong();
    private final AtomicLong rdmaReceives = new AtomicLong();
    private final AtomicLong bytesTransferred = new AtomicLong();
    private final AtomicLong operationErrors = new AtomicLong();
    private final AtomicLong connectionsCreated = new AtomicLong();
    private final AtomicLong connectionsActive = new AtomicLong();
    private final AtomicLong memoryRegionsAllocated = new AtomicLong();
    private final AtomicLong memoryRegionsActive = new AtomicLong();

    // Timing statistics (in nanoseconds)
    private final AtomicLong totalReadTime = new AtomicLong();
    private final AtomicLong totalWriteTime = new AtomicLong();
    private final AtomicLong totalSendTime = new AtomicLong();
    private final AtomicLong totalReceiveTime = new AtomicLong();

    /**
     * Record an RDMA read operation
     *
     * @param bytes number of bytes read
     * @param durationNanos operation duration in nanoseconds
     */
    public void recordRdmaRead(int bytes, long durationNanos) {
        rdmaReads.incrementAndGet();
        bytesTransferred.addAndGet(bytes);
        totalReadTime.addAndGet(durationNanos);
    }

    /**
     * Record an RDMA write operation
     *
     * @param bytes number of bytes written
     * @param durationNanos operation duration in nanoseconds
     */
    public void recordRdmaWrite(int bytes, long durationNanos) {
        rdmaWrites.incrementAndGet();
        bytesTransferred.addAndGet(bytes);
        totalWriteTime.addAndGet(durationNanos);
    }

    /**
     * Record an RDMA send operation
     *
     * @param bytes number of bytes sent
     * @param durationNanos operation duration in nanoseconds
     */
    public void recordRdmaSend(int bytes, long durationNanos) {
        rdmaSends.incrementAndGet();
        bytesTransferred.addAndGet(bytes);
        totalSendTime.addAndGet(durationNanos);
    }

    /**
     * Record an RDMA receive operation
     *
     * @param bytes number of bytes received
     * @param durationNanos operation duration in nanoseconds
     */
    public void recordRdmaReceive(int bytes, long durationNanos) {
        rdmaReceives.incrementAndGet();
        bytesTransferred.addAndGet(bytes);
        totalReceiveTime.addAndGet(durationNanos);
    }

    /**
     * Record an RDMA operation error
     */
    public void recordError() {
        operationErrors.incrementAndGet();
    }

    /**
     * Record a new RDMA connection creation
     */
    public void recordConnectionCreated() {
        connectionsCreated.incrementAndGet();
        connectionsActive.incrementAndGet();
    }

    /**
     * Record RDMA connection closure
     */
    public void recordConnectionClosed() {
        connectionsActive.decrementAndGet();
    }

    /**
     * Record memory region allocation
     */
    public void recordMemoryRegionAllocated() {
        memoryRegionsAllocated.incrementAndGet();
        memoryRegionsActive.incrementAndGet();
    }

    /**
     * Record memory region deallocation
     */
    public void recordMemoryRegionReleased() {
        memoryRegionsActive.decrementAndGet();
    }

    /**
     * Get total number of RDMA read operations
     *
     * @return read operation count
     */
    public long getRdmaReads() {
        return rdmaReads.get();
    }

    /**
     * Get total number of RDMA write operations
     *
     * @return write operation count
     */
    public long getRdmaWrites() {
        return rdmaWrites.get();
    }

    /**
     * Get total number of RDMA send operations
     *
     * @return send operation count
     */
    public long getRdmaSends() {
        return rdmaSends.get();
    }

    /**
     * Get total number of RDMA receive operations
     *
     * @return receive operation count
     */
    public long getRdmaReceives() {
        return rdmaReceives.get();
    }

    /**
     * Get total bytes transferred via RDMA
     *
     * @return total bytes
     */
    public long getBytesTransferred() {
        return bytesTransferred.get();
    }

    /**
     * Get total number of operation errors
     *
     * @return error count
     */
    public long getOperationErrors() {
        return operationErrors.get();
    }

    /**
     * Get total number of connections created
     *
     * @return connection count
     */
    public long getConnectionsCreated() {
        return connectionsCreated.get();
    }

    /**
     * Get number of currently active connections
     *
     * @return active connection count
     */
    public long getConnectionsActive() {
        return connectionsActive.get();
    }

    /**
     * Get total number of memory regions allocated
     *
     * @return memory region count
     */
    public long getMemoryRegionsAllocated() {
        return memoryRegionsAllocated.get();
    }

    /**
     * Get number of currently active memory regions
     *
     * @return active memory region count
     */
    public long getMemoryRegionsActive() {
        return memoryRegionsActive.get();
    }

    /**
     * Calculate error rate as percentage of total operations
     *
     * @return error rate (0.0 to 1.0)
     */
    public double getErrorRate() {
        long total = rdmaReads.get() + rdmaWrites.get() + rdmaSends.get() + rdmaReceives.get();
        if (total == 0) {
            return 0.0;
        }
        return (double) operationErrors.get() / total;
    }

    /**
     * Calculate average read latency in microseconds
     *
     * @return average read latency
     */
    public double getAverageReadLatencyMicros() {
        long reads = rdmaReads.get();
        if (reads == 0) {
            return 0.0;
        }
        return totalReadTime.get() / (double) reads / 1000.0; // Convert to microseconds
    }

    /**
     * Calculate average write latency in microseconds
     *
     * @return average write latency
     */
    public double getAverageWriteLatencyMicros() {
        long writes = rdmaWrites.get();
        if (writes == 0) {
            return 0.0;
        }
        return totalWriteTime.get() / (double) writes / 1000.0; // Convert to microseconds
    }

    /**
     * Calculate average send latency in microseconds
     *
     * @return average send latency
     */
    public double getAverageSendLatencyMicros() {
        long sends = rdmaSends.get();
        if (sends == 0) {
            return 0.0;
        }
        return totalSendTime.get() / (double) sends / 1000.0; // Convert to microseconds
    }

    /**
     * Calculate average receive latency in microseconds
     *
     * @return average receive latency
     */
    public double getAverageReceiveLatencyMicros() {
        long receives = rdmaReceives.get();
        if (receives == 0) {
            return 0.0;
        }
        return totalReceiveTime.get() / (double) receives / 1000.0; // Convert to microseconds
    }

    /**
     * Calculate total throughput in MB/s based on total time
     *
     * @param totalTimeSeconds total elapsed time in seconds
     * @return throughput in MB/s
     */
    public double getThroughputMBps(double totalTimeSeconds) {
        if (totalTimeSeconds <= 0.0) {
            return 0.0;
        }
        return (bytesTransferred.get() / 1024.0 / 1024.0) / totalTimeSeconds;
    }

    /**
     * Reset all statistics
     */
    public void reset() {
        rdmaReads.set(0);
        rdmaWrites.set(0);
        rdmaSends.set(0);
        rdmaReceives.set(0);
        bytesTransferred.set(0);
        operationErrors.set(0);
        connectionsCreated.set(0);
        connectionsActive.set(0);
        memoryRegionsAllocated.set(0);
        memoryRegionsActive.set(0);
        totalReadTime.set(0);
        totalWriteTime.set(0);
        totalSendTime.set(0);
        totalReceiveTime.set(0);
    }

    /**
     * Record start of a read request
     *
     * @param bytes number of bytes being requested
     */
    public void recordReadRequest(int bytes) {
        // Track that a read was requested
        rdmaReads.incrementAndGet();
    }

    /**
     * Record successful completion of a read request
     *
     * @param bytes number of bytes successfully read
     * @param durationNanos operation duration in nanoseconds
     */
    public void recordReadSuccess(int bytes, long durationNanos) {
        recordRdmaRead(bytes, durationNanos);
    }

    /**
     * Record a read operation error
     */
    public void recordReadError() {
        recordError();
    }

    /**
     * Record start of a write request
     *
     * @param bytes number of bytes being written
     */
    public void recordWriteRequest(int bytes) {
        // Track that a write was requested
        rdmaWrites.incrementAndGet();
    }

    /**
     * Record successful completion of a write request
     *
     * @param bytes number of bytes successfully written
     * @param durationNanos operation duration in nanoseconds
     */
    public void recordWriteSuccess(int bytes, long durationNanos) {
        recordRdmaWrite(bytes, durationNanos);
    }

    /**
     * Record a write operation error
     */
    public void recordWriteError() {
        recordError();
    }

    @Override
    public String toString() {
        return String.format(
                "RdmaStatistics[reads=%d, writes=%d, sends=%d, receives=%d, "
                        + "bytes=%d, errors=%d, errorRate=%.3f, activeConnections=%d, activeMemRegions=%d]",
                rdmaReads.get(), rdmaWrites.get(), rdmaSends.get(), rdmaReceives.get(), bytesTransferred.get(), operationErrors.get(),
                getErrorRate(), connectionsActive.get(), memoryRegionsActive.get());
    }
}
