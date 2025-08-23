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
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Abstract base class for RDMA connections.
 *
 * Manages connection state, credit flow control, and provides
 * abstract methods for RDMA operations that must be implemented
 * by specific provider implementations.
 */
public abstract class RdmaConnection implements AutoCloseable {

    /**
     * RDMA connection state enumeration
     */
    public enum RdmaConnectionState {
        DISCONNECTED, CONNECTING, CONNECTED, ESTABLISHED, ERROR, CLOSING, CLOSED
    }

    protected final InetSocketAddress remoteAddress;
    protected final InetSocketAddress localAddress;
    protected final AtomicInteger sendCredits;
    protected final AtomicInteger receiveCredits;
    protected final BlockingQueue<RdmaWorkRequest> pendingRequests;

    // Connection state
    protected volatile RdmaConnectionState state;
    protected RdmaCredits credits;
    protected int maxFragmentedSize;
    protected int maxReadWriteSize;

    /**
     * Create new RDMA connection
     *
     * @param remote remote socket address
     * @param local local socket address, may be null
     */
    public RdmaConnection(InetSocketAddress remote, InetSocketAddress local) {
        this.remoteAddress = remote;
        this.localAddress = local;
        this.sendCredits = new AtomicInteger(0);
        this.receiveCredits = new AtomicInteger(RdmaCapabilities.DEFAULT_RECEIVE_CREDIT_MAX);
        this.pendingRequests = new LinkedBlockingQueue<>();
        this.state = RdmaConnectionState.DISCONNECTED;
        this.maxFragmentedSize = RdmaCapabilities.DEFAULT_MAX_FRAGMENTED_SIZE;
        this.maxReadWriteSize = RdmaCapabilities.DEFAULT_MAX_READ_WRITE_SIZE;
    }

    /**
     * Establish RDMA connection
     *
     * @throws IOException if connection fails
     */
    public abstract void connect() throws IOException;

    /**
     * Send data using RDMA
     *
     * @param data data buffer to send
     * @param region registered memory region for the data
     * @throws IOException if send fails
     */
    public abstract void send(ByteBuffer data, RdmaMemoryRegion region) throws IOException;

    /**
     * Receive data using RDMA
     *
     * @param timeout timeout in milliseconds
     * @return received data buffer, or null if timeout
     * @throws IOException if receive fails
     */
    public abstract ByteBuffer receive(int timeout) throws IOException;

    /**
     * Perform RDMA read operation
     *
     * @param localRegion local memory region to read into
     * @param remoteAddress remote memory address
     * @param remoteKey remote memory key
     * @param length number of bytes to read
     * @throws IOException if read fails
     */
    public abstract void rdmaRead(RdmaMemoryRegion localRegion, long remoteAddress, int remoteKey, int length) throws IOException;

    /**
     * Perform RDMA write operation
     *
     * @param localRegion local memory region to write from
     * @param remoteAddress remote memory address
     * @param remoteKey remote memory key
     * @param length number of bytes to write
     * @throws IOException if write fails
     */
    public abstract void rdmaWrite(RdmaMemoryRegion localRegion, long remoteAddress, int remoteKey, int length) throws IOException;

    /**
     * Negotiate RDMA parameters
     *
     * @param request negotiation request parameters
     * @return negotiation response
     * @throws IOException if negotiation fails
     */
    public abstract RdmaNegotiateResponse negotiate(RdmaNegotiateRequest request) throws IOException;

    /**
     * Reset connection after recoverable error
     *
     * @throws IOException if reset fails
     */
    public abstract void reset() throws IOException;

    /**
     * Check if connection can send data (has send credits and is established)
     *
     * @return true if can send, false otherwise
     */
    public boolean canSend() {
        return sendCredits.get() > 0 && state == RdmaConnectionState.ESTABLISHED;
    }

    /**
     * Consume a send credit
     */
    public void consumeSendCredit() {
        sendCredits.decrementAndGet();
    }

    /**
     * Grant a send credit
     */
    public void grantSendCredit() {
        sendCredits.incrementAndGet();
    }

    /**
     * Grant a receive credit
     */
    public void grantReceiveCredit() {
        receiveCredits.incrementAndGet();
    }

    /**
     * Get number of available send credits
     *
     * @return available send credits
     */
    public int getAvailableSendCredits() {
        return sendCredits.get();
    }

    /**
     * Get number of available receive credits
     *
     * @return available receive credits
     */
    public int getAvailableReceiveCredits() {
        return receiveCredits.get();
    }

    /**
     * Get connection state
     *
     * @return current connection state
     */
    public RdmaConnectionState getState() {
        return state;
    }

    /**
     * Get remote address
     *
     * @return remote socket address
     */
    public InetSocketAddress getRemoteAddress() {
        return remoteAddress;
    }

    /**
     * Get local address
     *
     * @return local socket address
     */
    public InetSocketAddress getLocalAddress() {
        return localAddress;
    }

    /**
     * Check if connection is established and ready for use
     *
     * @return true if connection is connected/established, false otherwise
     */
    public boolean isConnected() {
        return state == RdmaConnectionState.CONNECTED || state == RdmaConnectionState.ESTABLISHED;
    }

    /**
     * Read data from RDMA connection
     *
     * @param buffer buffer to read data into
     * @param remoteAddress remote memory address for RDMA read
     * @param remoteKey remote memory key
     * @param length number of bytes to read
     * @return number of bytes actually read
     * @throws IOException if read operation fails
     */
    public abstract int read(ByteBuffer buffer, long remoteAddress, int remoteKey, int length) throws IOException;

    /**
     * Write data to RDMA connection
     *
     * @param buffer buffer containing data to write
     * @param remoteAddress remote memory address for RDMA write
     * @param remoteKey remote memory key
     * @param length number of bytes to write
     * @return number of bytes actually written
     * @throws IOException if write operation fails
     */
    public abstract int write(ByteBuffer buffer, long remoteAddress, int remoteKey, int length) throws IOException;
}
