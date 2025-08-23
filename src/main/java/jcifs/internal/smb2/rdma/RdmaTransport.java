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

import java.io.IOException;
import java.nio.ByteBuffer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.DfsReferralData;
import jcifs.SmbSession;
import jcifs.SmbTransport;
import jcifs.smb.SmbException;
import jcifs.smb.SmbTransportInternal;

/**
 * RDMA-enabled SMB transport that wraps existing SMB transport
 * and adds RDMA capabilities for direct memory access operations.
 */
public class RdmaTransport implements SmbTransportInternal {
    private static final Logger log = LoggerFactory.getLogger(RdmaTransport.class);

    private final SmbTransportInternal delegate;
    private final RdmaProvider rdmaProvider;
    private final RdmaBufferManager bufferManager;
    private final RdmaStatistics statistics;
    private RdmaConnection rdmaConnection;
    private final Object connectionLock = new Object();

    /**
     * Creates a new RDMA transport wrapping the given delegate transport.
     *
     * @param delegate the underlying SMB transport to wrap
     * @param context the CIFS context for configuration
     */
    public RdmaTransport(SmbTransportInternal delegate, CIFSContext context) {
        this.delegate = delegate;
        this.rdmaProvider = RdmaProviderFactory.getProvider(context.getConfig());
        this.bufferManager = new RdmaBufferManager(rdmaProvider);
        this.statistics = new RdmaStatistics();

        log.debug("Created RDMA transport with provider: {}", rdmaProvider.getClass().getSimpleName());
    }

    /**
     * Establishes RDMA connection to the remote server.
     *
     * @throws IOException if connection fails
     */
    public void connectRdma() throws IOException {
        synchronized (connectionLock) {
            if (rdmaConnection != null && rdmaConnection.isConnected()) {
                return;
            }

            try {
                rdmaConnection =
                        rdmaProvider.connect(delegate.getRemoteAddress().getHostAddress(), delegate.getContext().getConfig().getRdmaPort());
                log.info("RDMA connection established to {}", delegate.getRemoteAddress());
            } catch (IOException e) {
                log.warn("Failed to establish RDMA connection: {}", e.getMessage());
                throw e;
            }
        }
    }

    /**
     * Checks if RDMA connection is available.
     *
     * @return true if RDMA connection is active
     */
    public boolean isRdmaConnected() {
        synchronized (connectionLock) {
            return rdmaConnection != null && rdmaConnection.isConnected();
        }
    }

    /**
     * Performs RDMA read operation.
     *
     * @param buffer the buffer to read into
     * @param remoteAddress remote memory address
     * @param remoteKey remote access key
     * @param length number of bytes to read
     * @return number of bytes read
     * @throws IOException if operation fails
     */
    public int rdmaRead(ByteBuffer buffer, long remoteAddress, int remoteKey, int length) throws IOException {
        if (!isRdmaConnected()) {
            throw new IOException("RDMA connection not available");
        }

        try {
            statistics.recordReadRequest(length);
            long startTime = System.nanoTime();

            int bytesRead = rdmaConnection.read(buffer, remoteAddress, remoteKey, length);

            long duration = System.nanoTime() - startTime;
            statistics.recordReadSuccess(bytesRead, duration);

            return bytesRead;
        } catch (IOException e) {
            statistics.recordReadError();
            throw e;
        }
    }

    /**
     * Performs RDMA write operation.
     *
     * @param buffer the buffer to write from
     * @param remoteAddress remote memory address
     * @param remoteKey remote access key
     * @param length number of bytes to write
     * @return number of bytes written
     * @throws IOException if operation fails
     */
    public int rdmaWrite(ByteBuffer buffer, long remoteAddress, int remoteKey, int length) throws IOException {
        if (!isRdmaConnected()) {
            throw new IOException("RDMA connection not available");
        }

        try {
            statistics.recordWriteRequest(length);
            long startTime = System.nanoTime();

            int bytesWritten = rdmaConnection.write(buffer, remoteAddress, remoteKey, length);

            long duration = System.nanoTime() - startTime;
            statistics.recordWriteSuccess(bytesWritten, duration);

            return bytesWritten;
        } catch (IOException e) {
            statistics.recordWriteError();
            throw e;
        }
    }

    /**
     * Gets the RDMA buffer manager for memory operations.
     *
     * @return buffer manager instance
     */
    public RdmaBufferManager getBufferManager() {
        return bufferManager;
    }

    /**
     * Gets RDMA statistics.
     *
     * @return statistics instance
     */
    public RdmaStatistics getStatistics() {
        return statistics;
    }

    // Delegate all SmbTransportInternal methods to the wrapped transport

    @Override
    public boolean hasCapability(int cap) throws SmbException {
        return delegate.hasCapability(cap);
    }

    @Override
    public boolean isDisconnected() {
        return delegate.isDisconnected();
    }

    @Override
    public boolean disconnect(boolean hard, boolean inuse) throws IOException {
        synchronized (connectionLock) {
            if (rdmaConnection != null) {
                try {
                    rdmaConnection.close();
                } catch (Exception e) {
                    log.warn("Error closing RDMA connection: {}", e.getMessage());
                }
                rdmaConnection = null;
            }
        }
        return delegate.disconnect(hard, inuse);
    }

    @Override
    public boolean ensureConnected() throws IOException {
        boolean result = delegate.ensureConnected();

        // Try to establish RDMA connection if configured
        if (result && delegate.getContext().getConfig().isRdmaEnabled()) {
            try {
                connectRdma();
            } catch (IOException e) {
                log.warn("RDMA connection failed, continuing with regular transport: {}", e.getMessage());
            }
        }

        return result;
    }

    @Override
    public DfsReferralData getDfsReferrals(CIFSContext ctx, String name, String targetHost, String targetDomain, int rn)
            throws CIFSException {
        return delegate.getDfsReferrals(ctx, name, targetHost, targetDomain, rn);
    }

    @Override
    public boolean isSigningOptional() throws SmbException {
        return delegate.isSigningOptional();
    }

    @Override
    public boolean isSigningEnforced() throws SmbException {
        return delegate.isSigningEnforced();
    }

    @Override
    public byte[] getServerEncryptionKey() {
        return delegate.getServerEncryptionKey();
    }

    @Override
    public SmbSession getSmbSession(CIFSContext ctx) {
        return delegate.getSmbSession(ctx);
    }

    @Override
    public SmbSession getSmbSession(CIFSContext tf, String targetHost, String targetDomain) {
        return delegate.getSmbSession(tf, targetHost, targetDomain);
    }

    @Override
    public boolean isSMB2() throws SmbException {
        return delegate.isSMB2();
    }

    @Override
    public int getInflightRequests() {
        return delegate.getInflightRequests();
    }

    @Override
    public CIFSContext getContext() {
        return delegate.getContext();
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T extends SmbTransport> T unwrap(Class<T> type) {
        if (type.isAssignableFrom(this.getClass())) {
            return (T) this;
        }
        return delegate.unwrap(type);
    }

    @Override
    public void close() {
        try {
            disconnect(true, false);
        } catch (IOException e) {
            log.warn("Error during RDMA transport close: {}", e.getMessage());
        }
        delegate.close();
    }

    @Override
    public Address getRemoteAddress() {
        return delegate.getRemoteAddress();
    }

    @Override
    public String getRemoteHostName() {
        return delegate.getRemoteHostName();
    }
}
