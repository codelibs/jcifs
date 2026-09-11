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
package org.codelibs.jcifs.smb.it.env;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A TCP relay the tests can put in front of the SMB server so a connection can
 * be dropped on demand.
 *
 * <p>
 * Connecting a client through the relay and calling {@link #dropConnections()}
 * reproduces what an idle firewall or a restarted server does to a live SMB
 * connection: both ends go away without a protocol-level goodbye. Nothing else
 * in the harness can produce that, because the server itself has to stay up for
 * the client to reconnect to.
 * </p>
 *
 * <p>
 * It listens on the loopback interface only, on a port the operating system
 * picks, so it never collides with the SMB port the backends use.
 * </p>
 */
public final class TcpRelay implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(TcpRelay.class);

    private static final int BUFFER_BYTES = 8192;

    private final ServerSocket listener;
    private final String targetHost;
    private final int targetPort;

    /**
     * Every socket of every connection relayed so far. Sockets that close on their own are left in the list, which
     * costs nothing for a relay that lives for one test and keeps {@link #dropConnections()} free of bookkeeping.
     */
    private final List<Socket> relayed = Collections.synchronizedList(new ArrayList<>());

    private volatile boolean closed;

    private TcpRelay(final String targetHost, final int targetPort) throws IOException {
        this.targetHost = targetHost;
        this.targetPort = targetPort;
        this.listener = new ServerSocket(0, 0, InetAddress.getLoopbackAddress());
    }

    /**
     * Starts a relay forwarding to the given server.
     *
     * @param host the server to forward to
     * @param port the port to forward to
     * @return the running relay, which the caller closes
     * @throws IOException if the listening socket cannot be opened
     */
    public static TcpRelay to(final String host, final int port) throws IOException {
        final TcpRelay relay = new TcpRelay(host, port);
        final Thread accepting = new Thread(relay::acceptLoop, "smb-it-relay-accept");
        accepting.setDaemon(true);
        accepting.start();
        return relay;
    }

    /**
     * The loopback address clients connect to, ready to put in a URL.
     *
     * <p>
     * Taken from the socket rather than written out as a literal, because a JVM
     * that prefers IPv6 binds {@code ::1} where another binds {@code 127.0.0.1}.
     * </p>
     *
     * @return the address, bracketed if it is an IPv6 one
     */
    public String host() {
        final String address = this.listener.getInetAddress().getHostAddress();
        return address.indexOf(':') >= 0 ? "[" + address + "]" : address;
    }

    /**
     * @return the loopback port clients connect to
     */
    public int port() {
        return this.listener.getLocalPort();
    }

    /**
     * Closes every connection currently relayed, in both directions.
     *
     * <p>
     * The relay keeps listening, so a client that reconnects is served again.
     * </p>
     */
    public void dropConnections() {
        final List<Socket> live;
        synchronized (this.relayed) {
            live = new ArrayList<>(this.relayed);
            this.relayed.clear();
        }
        live.forEach(TcpRelay::closeQuietly);
    }

    @Override
    public void close() {
        this.closed = true;
        closeQuietly(this.listener);
        dropConnections();
    }

    private void acceptLoop() {
        while (!this.closed) {
            Socket client = null;
            Socket server = null;
            try {
                client = this.listener.accept();
                server = new Socket(this.targetHost, this.targetPort);
                this.relayed.add(client);
                this.relayed.add(server);
                pump(client, server);
                pump(server, client);
            } catch (final IOException e) {
                closeQuietly(client);
                closeQuietly(server);
                if (this.closed) {
                    return;
                }
                // Failing to reach the server is transient. Giving up here would leave the listener accepting
                // connections that are never forwarded, and the client would then wait out its response timeout
                // instead of failing, turning a blip into a test that hangs.
                log.debug("Relay could not establish a connection", e);
            }
        }
    }

    private void pump(final Socket from, final Socket to) {
        final Thread pumping = new Thread(() -> {
            final byte[] buffer = new byte[BUFFER_BYTES];
            try {
                final InputStream in = from.getInputStream();
                final OutputStream out = to.getOutputStream();
                int read;
                while ((read = in.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                    out.flush();
                }
            } catch (final IOException e) {
                log.trace("Relayed connection ended", e);
            } finally {
                closeQuietly(from);
                closeQuietly(to);
            }
        }, "smb-it-relay-pump-" + port());
        pumping.setDaemon(true);
        pumping.start();
    }

    private static void closeQuietly(final ServerSocket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (final IOException e) {
                log.trace("Failed to close the relay listener", e);
            }
        }
    }

    private static void closeQuietly(final Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (final IOException e) {
                log.trace("Failed to close a relayed socket", e);
            }
        }
    }
}
