/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.smb1.netbios;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;

import jcifs.smb1.Config;
import jcifs.smb1.util.LogStream;

/**
Do not use this class. Writing to the OutputStream of this type of socket
requires leaving a 4 byte prefix for the NBT header. IOW you must call
write( buf, 4, len ). Calling write( buf, 0, len ) will generate an error.
 */

public class NbtSocket extends Socket {

    private static final int SSN_SRVC_PORT = 139;
    private static final int BUFFER_SIZE = 512;
    private static final int DEFAULT_SO_TIMEOUT = 5000;

    private static LogStream log = LogStream.getInstance();

    private NbtAddress address;
    private Name calledName;
    private int soTimeout;

    /**
     * Constructs an unconnected NbtSocket.
     */
    public NbtSocket() {
    }

    /**
     * Constructs an NbtSocket and connects it to the specified NetBIOS address and port.
     *
     * @param address the NetBIOS address to connect to
     * @param port the port number, or 0 for the default NetBIOS session service port
     * @throws IOException if an I/O error occurs while creating the socket
     */
    public NbtSocket(final NbtAddress address, final int port) throws IOException {
        this(address, port, null, 0);
    }

    /**
     * Constructs an NbtSocket with specified local and remote addresses.
     *
     * @param address the NetBIOS address to connect to
     * @param port the remote port number, or 0 for the default NetBIOS session service port
     * @param localAddr the local address to bind to
     * @param localPort the local port to bind to
     * @throws IOException if an I/O error occurs while creating the socket
     */
    public NbtSocket(final NbtAddress address, final int port, final InetAddress localAddr, final int localPort) throws IOException {
        this(address, null, port, localAddr, localPort);
    }

    /**
     * Creates a new NetBIOS socket with the specified parameters.
     *
     * @param address the NetBIOS address to connect to
     * @param calledName the called NetBIOS name (optional)
     * @param port the port number (0 for default)
     * @param localAddr the local address to bind to
     * @param localPort the local port to bind to
     * @throws IOException if an I/O error occurs while creating the socket
     */
    public NbtSocket(final NbtAddress address, final String calledName, final int port, final InetAddress localAddr, final int localPort)
            throws IOException {
        super(address.getInetAddress(), port == 0 ? SSN_SRVC_PORT : port, localAddr, localPort);
        this.address = address;
        if (calledName == null) {
            this.calledName = address.hostName;
        } else {
            this.calledName = new Name(calledName, 0x20, null);
        }
        soTimeout = Config.getInt("jcifs.smb1.netbios.soTimeout", DEFAULT_SO_TIMEOUT);
        connect();
    }

    /**
     * Returns the NetBIOS address associated with this socket.
     *
     * @return the NetBIOS address
     */
    public NbtAddress getNbtAddress() {
        return address;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return new SocketInputStream(super.getInputStream());
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return new SocketOutputStream(super.getOutputStream());
    }

    @Override
    public int getPort() {
        return super.getPort();
    }

    @Override
    public InetAddress getLocalAddress() {
        return super.getLocalAddress();
    }

    @Override
    public int getLocalPort() {
        return super.getLocalPort();
    }

    @Override
    public String toString() {
        return "NbtSocket[addr=" + address + ",port=" + super.getPort() + ",localport=" + super.getLocalPort() + "]";
    }

    private void connect() throws IOException {
        final byte[] buffer = new byte[BUFFER_SIZE];
        int type;
        InputStream in;

        try {
            in = super.getInputStream();
            final OutputStream out = super.getOutputStream();

            final SessionServicePacket ssp0 = new SessionRequestPacket(calledName, NbtAddress.localhost.hostName);
            out.write(buffer, 0, ssp0.writeWireFormat(buffer, 0));

            setSoTimeout(soTimeout);
            type = SessionServicePacket.readPacketType(in, buffer, 0);
        } catch (final IOException ioe) {
            close();
            throw ioe;
        }

        switch (type) {
        case SessionServicePacket.POSITIVE_SESSION_RESPONSE:
            if (LogStream.level > 2) {
                log.println("session established ok with " + address);
            }
            return;
        case SessionServicePacket.NEGATIVE_SESSION_RESPONSE:
            final int errorCode = in.read() & 0xFF;
            close();
            throw new NbtException(NbtException.ERR_SSN_SRVC, errorCode);
        case -1:
            throw new NbtException(NbtException.ERR_SSN_SRVC, NbtException.CONNECTION_REFUSED);
        default:
            close();
            throw new NbtException(NbtException.ERR_SSN_SRVC, 0);
        }
    }

    @Override
    public void close() throws IOException {
        if (LogStream.level > 3) {
            log.println("close: " + this);
        }
        super.close();
    }
}
