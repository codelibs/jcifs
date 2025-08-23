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
package jcifs.internal.smb2.rdma.tcp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.internal.smb2.rdma.RdmaConnection;
import jcifs.internal.smb2.rdma.RdmaMemoryRegion;
import jcifs.internal.smb2.rdma.RdmaNegotiateRequest;
import jcifs.internal.smb2.rdma.RdmaNegotiateResponse;

/**
 * TCP-based RDMA connection implementation.
 *
 * Uses regular TCP sockets to simulate RDMA operations.
 * This provides a fallback when real RDMA hardware is not available.
 */
public class TcpRdmaConnection extends RdmaConnection {

    private static final Logger log = LoggerFactory.getLogger(TcpRdmaConnection.class);

    private SocketChannel socketChannel;
    private Socket socket;

    /**
     * Create new TCP RDMA connection
     *
     * @param remote remote socket address
     * @param local local socket address, may be null
     */
    public TcpRdmaConnection(InetSocketAddress remote, InetSocketAddress local) {
        super(remote, local);
    }

    @Override
    public void connect() throws IOException {
        try {
            socketChannel = SocketChannel.open();
            if (localAddress != null) {
                socketChannel.bind(localAddress);
            }

            socketChannel.connect(remoteAddress);
            socket = socketChannel.socket();
            socket.setTcpNoDelay(true);
            socket.setKeepAlive(true);

            state = RdmaConnectionState.CONNECTED;
            log.debug("TCP RDMA connection established to {}", remoteAddress);

        } catch (IOException e) {
            state = RdmaConnectionState.ERROR;
            throw new IOException("TCP RDMA connection failed", e);
        }
    }

    @Override
    public void send(ByteBuffer data, RdmaMemoryRegion region) throws IOException {
        if (state != RdmaConnectionState.ESTABLISHED && state != RdmaConnectionState.CONNECTED) {
            throw new IOException("Connection not established");
        }

        try {
            while (data.hasRemaining()) {
                socketChannel.write(data);
            }
        } catch (IOException e) {
            state = RdmaConnectionState.ERROR;
            throw new IOException("TCP RDMA send failed", e);
        }
    }

    @Override
    public ByteBuffer receive(int timeout) throws IOException {
        if (state != RdmaConnectionState.ESTABLISHED && state != RdmaConnectionState.CONNECTED) {
            throw new IOException("Connection not established");
        }

        try {
            socket.setSoTimeout(timeout);

            // First, read the header to determine message size
            ByteBuffer headerBuffer = ByteBuffer.allocate(4);
            while (headerBuffer.hasRemaining()) {
                int read = socketChannel.read(headerBuffer);
                if (read < 0) {
                    throw new IOException("Connection closed by peer");
                }
            }

            headerBuffer.flip();
            int messageSize = headerBuffer.getInt();

            // Now read the message body
            ByteBuffer messageBuffer = ByteBuffer.allocate(messageSize);
            while (messageBuffer.hasRemaining()) {
                int read = socketChannel.read(messageBuffer);
                if (read < 0) {
                    throw new IOException("Connection closed by peer");
                }
            }

            messageBuffer.flip();
            return messageBuffer;

        } catch (SocketTimeoutException e) {
            return null; // Timeout
        } catch (IOException e) {
            state = RdmaConnectionState.ERROR;
            throw new IOException("TCP RDMA receive failed", e);
        }
    }

    @Override
    public void rdmaRead(RdmaMemoryRegion localRegion, long remoteAddress, int remoteKey, int length) throws IOException {
        // TCP fallback doesn't support real RDMA read
        throw new UnsupportedOperationException("RDMA read not supported by TCP fallback");
    }

    @Override
    public void rdmaWrite(RdmaMemoryRegion localRegion, long remoteAddress, int remoteKey, int length) throws IOException {
        // TCP fallback doesn't support real RDMA write
        throw new UnsupportedOperationException("RDMA write not supported by TCP fallback");
    }

    @Override
    public RdmaNegotiateResponse negotiate(RdmaNegotiateRequest request) throws IOException {
        // For TCP fallback, we simulate successful negotiation
        RdmaNegotiateResponse response = new RdmaNegotiateResponse();
        response.setStatus(0); // Success
        response.setSelectedVersion(request.getMaxVersion());
        response.setCreditsGranted(request.getCreditsRequested());
        response.setMaxReceiveSize(Math.min(request.getMaxReceiveSize(), 65536));
        response.setMaxReadWriteSize(0); // No RDMA read/write support
        response.setMaxFragmentedSize(request.getMaxFragmentedSize());

        state = RdmaConnectionState.ESTABLISHED;

        // Initialize credits
        sendCredits.set(response.getCreditsGranted());

        log.debug("TCP RDMA negotiation completed with {} credits", response.getCreditsGranted());
        return response;
    }

    @Override
    public void reset() throws IOException {
        if (socketChannel != null && socketChannel.isOpen()) {
            socketChannel.close();
        }
        connect();
    }

    @Override
    public int read(ByteBuffer buffer, long remoteAddress, int remoteKey, int length) throws IOException {
        if (state != RdmaConnectionState.ESTABLISHED && state != RdmaConnectionState.CONNECTED) {
            throw new IOException("Connection not established");
        }

        try {
            // For TCP fallback, simulate reading data through the TCP socket
            int bytesToRead = Math.min(length, buffer.remaining());
            ByteBuffer tempBuffer = ByteBuffer.allocate(bytesToRead);

            int totalRead = 0;
            while (tempBuffer.hasRemaining() && totalRead < bytesToRead) {
                int read = socketChannel.read(tempBuffer);
                if (read < 0) {
                    break;
                }
                totalRead += read;
            }

            tempBuffer.flip();
            buffer.put(tempBuffer);

            log.debug("TCP RDMA read completed: {} bytes", totalRead);
            return totalRead;

        } catch (IOException e) {
            state = RdmaConnectionState.ERROR;
            throw new IOException("TCP RDMA read failed", e);
        }
    }

    @Override
    public int write(ByteBuffer buffer, long remoteAddress, int remoteKey, int length) throws IOException {
        if (state != RdmaConnectionState.ESTABLISHED && state != RdmaConnectionState.CONNECTED) {
            throw new IOException("Connection not established");
        }

        try {
            // For TCP fallback, simulate writing data through the TCP socket
            int bytesToWrite = Math.min(length, buffer.remaining());

            ByteBuffer writeBuffer = buffer.duplicate();
            writeBuffer.limit(writeBuffer.position() + bytesToWrite);

            int totalWritten = 0;
            while (writeBuffer.hasRemaining()) {
                int written = socketChannel.write(writeBuffer);
                totalWritten += written;
            }

            // Update original buffer position
            buffer.position(buffer.position() + totalWritten);

            log.debug("TCP RDMA write completed: {} bytes", totalWritten);
            return totalWritten;

        } catch (IOException e) {
            state = RdmaConnectionState.ERROR;
            throw new IOException("TCP RDMA write failed", e);
        }
    }

    @Override
    public void close() throws IOException {
        state = RdmaConnectionState.CLOSING;

        try {
            if (socketChannel != null) {
                socketChannel.close();
            }
        } finally {
            state = RdmaConnectionState.CLOSED;
        }

        log.debug("TCP RDMA connection closed");
    }
}
