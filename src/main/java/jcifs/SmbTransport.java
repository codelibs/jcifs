/*
 * © 2017 AgNO3 Gmbh & Co. KG
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

/**
 * Opaque reference to a SMB transport
 *
 * @author mbechler
 * @internal
 */
public interface SmbTransport extends AutoCloseable {

    /**
     * @return the context this transport is attached to
     */
    CIFSContext getContext();

    /**
     *
     * @param type
     * @return transport instance with the given type
     */
    <T extends SmbTransport> T unwrap(Class<T> type);

    /**
     *
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    void close();

    /**
     * @return the connected address
     */
    Address getRemoteAddress();

    /**
     * @return the connected host name
     */
    String getRemoteHostName();

}