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
 * Handle to an open file
 *
 * @author mbechler
 *
 */
public interface SmbFileHandle extends AutoCloseable {

    /**
     * Returns the tree handle associated with this file handle
     *
     * @return the tree
     */
    SmbTreeHandle getTree();

    /**
     * Checks if this file handle is still valid
     *
     * @return whether the file descriptor is valid
     */
    boolean isValid();

    /**
     * Closes this file handle and optionally sets the last write time
     *
     * @param lastWriteTime the last write time to set, or 0 to leave unchanged
     * @throws CIFSException if an error occurs while closing the file
     */
    void close(long lastWriteTime) throws CIFSException;

    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    void close() throws CIFSException;

    /**
     * Releases this file handle without closing it
     *
     * @throws CIFSException if an error occurs while releasing the handle
     */
    void release() throws CIFSException;

    /**
     * Returns the initial size of the file when it was opened
     *
     * @return the file size when it was opened
     */
    long getInitialSize();

}