/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
package jcifs;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * This is an internal API for managing pools of SMB connections
 *
 * @author mbechler
 *
 * <p>This interface is intended for internal use.</p>
 */
public interface SmbTransportPool {

    /**
     * Gets an SMB transport connection to the specified server.
     *
     * @param tf the CIFS context to use
     * @param name the server name or address
     * @param port the port number
     * @param exclusive whether to acquire an unshared connection
     * @param forceSigning whether to enforce SMB signing
     * @return a connected transport
     * @throws UnknownHostException if the host cannot be resolved
     * @throws IOException if an I/O error occurs
     */
    SmbTransport getSmbTransport(CIFSContext tf, String name, int port, boolean exclusive, boolean forceSigning)
            throws UnknownHostException, IOException;

    /**
     * Get transport connection
     *
     * @param tc
     *            context to use
     * @param address the server address
     * @param port the port number
     * @param exclusive
     *            whether to acquire an unshared connection
     * @return a transport connection to the target
     */
    SmbTransport getSmbTransport(CIFSContext tc, Address address, int port, boolean exclusive);

    /**
     * Get transport connection
     *
     * @param tc
     *            context to use
     * @param address the server address
     * @param port the port number
     * @param exclusive
     *            whether to acquire an unshared connection
     * @param forceSigning
     *            whether to enforce SMB signing on this connection
     * @return a transport connection to the target
     */
    SmbTransport getSmbTransport(CIFSContext tc, Address address, int port, boolean exclusive, boolean forceSigning);

    /**
     * Get transport connection, with local binding
     *
     * @param tc
     *            context to use
     * @param address the server address
     * @param port the port number
     * @param localAddr the local address to bind to
     * @param localPort the local port to bind to
     * @param hostName the server host name
     * @param exclusive
     *            whether to acquire an unshared connection
     * @return a transport connection to the target
     */
    SmbTransport getSmbTransport(CIFSContext tc, Address address, int port, InetAddress localAddr, int localPort, String hostName,
            boolean exclusive);

    /**
     * Gets or creates an SMB transport for the given context.
     *
     * @param tc
     *            context to use
     * @param address the server address
     * @param port the port number
     * @param localAddr the local address to bind to
     * @param localPort the local port to bind to
     * @param hostName the server host name
     * @param exclusive
     *            whether to acquire an unshared connection
     * @param forceSigning
     *            whether to enforce SMB signing on this connection
     * @return a transport connection to the target
     */
    SmbTransport getSmbTransport(CIFSContext tc, Address address, int port, InetAddress localAddr, int localPort, String hostName,
            boolean exclusive, boolean forceSigning);

    /**
     * Removes a transport from the pool.
     *
     * @param trans the transport to remove
     */
    void removeTransport(SmbTransport trans);

    /**
     * Closes the pool and all connections in it
     *
     * @return whether any transport was still in use
     *
     * @throws CIFSException if an error occurs during authentication
     *
     */
    boolean close() throws CIFSException;

    /**
     * Authenticate arbitrary credentials represented by the
     * <code>NtlmPasswordAuthentication</code> object against the domain controller
     * specified by the <code>UniAddress</code> parameter. If the credentials are
     * not accepted, an <code>SmbAuthException</code> will be thrown. If an error
     * occurs an <code>SmbException</code> will be thrown. If the credentials are
     * valid, the method will return without throwing an exception. See the
     * last <a href="../../../faq.html">FAQ</a> question.
     * <p>
     * See also the <code>jcifs.smb.client.logonShare</code> property.
     *
     * @param dc the domain controller address
     * @param tc the CIFS context containing credentials
     * @throws CIFSException if an error occurs during authentication
     * @deprecated functionality is broken and will be removed at some point,
     *             use actual Active Directory authentication instead
     */
    @Deprecated
    void logon(CIFSContext tc, Address dc) throws CIFSException;

    /**
     * Authenticate arbitrary credentials represented by the
     * <code>NtlmPasswordAuthentication</code> object against the domain controller
     * specified by the <code>UniAddress</code> parameter. If the credentials are
     * not accepted, an <code>SmbAuthException</code> will be thrown. If an error
     * occurs an <code>SmbException</code> will be thrown. If the credentials are
     * valid, the method will return without throwing an exception. See the
     * last <a href="../../../faq.html">FAQ</a> question.
     * <p>
     * See also the <code>jcifs.smb.client.logonShare</code> property.
     *
     * @param dc the domain controller address
     * @param port the port number
     * @param tc the CIFS context containing credentials
     * @throws CIFSException if an error occurs during authentication
     * @deprecated functionality is broken and will be removed at some point,
     *             use actual Active Directory authentication instead
     */
    @Deprecated
    void logon(CIFSContext tc, Address dc, int port) throws CIFSException;

    /**
     * Get NTLM challenge from a server
     *
     * @param dc the domain controller address
     * @param tc the CIFS context containing credentials
     * @return NTLM challenge
     * @throws CIFSException if an error occurs during authentication
     * @deprecated functionality is broken and will be removed at some point,
     *             use actual Active Directory authentication instead
     */
    @Deprecated
    byte[] getChallenge(CIFSContext tc, Address dc) throws CIFSException;

    /**
     * Get NTLM challenge from a server
     *
     * @param dc the domain controller address
     * @param port the port number
     * @param tc the CIFS context containing credentials
     * @return NTLM challenge
     * @throws CIFSException if an error occurs during authentication
     * @deprecated functionality is broken and will be removed at some point,
     *             use actual Active Directory authentication instead
     */
    @Deprecated
    byte[] getChallenge(CIFSContext tc, Address dc, int port) throws CIFSException;

}