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
package org.codelibs.jcifs.smb.impl;

import org.codelibs.jcifs.smb.CIFSException;

/**
 * Test-only access to the transfer sizes a connection negotiated.
 *
 * <p>
 * The sizes live on the negotiate response, which is reachable only through {@code SmbTreeHandleImpl} - a package
 * private class - so this has to sit in the implementation package the way {@code SmbOplockProbe} does.
 * </p>
 */
public final class SmbBufferSizeProbe {

    private SmbBufferSizeProbe() {
    }

    /**
     * The read size the connection settled on.
     *
     * @param file any file on the connection to measure
     * @return the negotiated maximum read size in bytes
     * @throws CIFSException if the connection cannot be established
     */
    public static int readSize(final SmbFile file) throws CIFSException {
        try (SmbTreeHandleImpl th = (SmbTreeHandleImpl) file.getTreeHandle()) {
            return th.getReceiveBufferSize();
        }
    }

    /**
     * The write size the connection settled on.
     *
     * @param file any file on the connection to measure
     * @return the negotiated maximum write size in bytes
     * @throws CIFSException if the connection cannot be established
     */
    public static int writeSize(final SmbFile file) throws CIFSException {
        try (SmbTreeHandleImpl th = (SmbTreeHandleImpl) file.getTreeHandle()) {
            return th.getSendBufferSize();
        }
    }

    /**
     * The transact size the connection settled on.
     *
     * @param file any file on the connection to measure
     * @return the negotiated maximum transact size in bytes
     * @throws CIFSException if the connection cannot be established
     */
    public static int transactSize(final SmbFile file) throws CIFSException {
        try (SmbTreeHandleImpl th = (SmbTreeHandleImpl) file.getTreeHandle()) {
            return th.getMaximumBufferSize();
        }
    }
}
