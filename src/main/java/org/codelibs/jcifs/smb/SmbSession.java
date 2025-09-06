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
package org.codelibs.jcifs.smb;

/**
 * Opaque reference to a SMB session
 *
 * @author mbechler
 */
public interface SmbSession extends AutoCloseable {

    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    void close();

    /**
     * Returns the configuration object used by this SMB session.
     *
     * @return the configuration used by this session
     */
    Configuration getConfig();

    /**
     * Unwraps this session to the specified type, allowing access to implementation-specific functionality.
     *
     * @param <T> the type to unwrap to
     * @param type the class of the type to unwrap to
     * @return session instance with the given type
     */
    <T extends SmbSession> T unwrap(Class<T> type);

    /**
     * Returns the CIFS context that this session is attached to.
     *
     * @return the context this session is attached to
     */
    CIFSContext getContext();

}
