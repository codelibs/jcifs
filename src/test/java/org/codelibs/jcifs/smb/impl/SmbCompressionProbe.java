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
 * Test-only access to whether a connection negotiated compression.
 *
 * <p>
 * Without this a test cannot tell a server that compressed the reply from one
 * that quietly did not, and an assertion that only checks the bytes would pass
 * either way. It sits in the implementation package because the state hangs off
 * {@code SmbTreeHandleImpl}, which is package private, the same way
 * {@code SmbBufferSizeProbe} does.
 * </p>
 */
public final class SmbCompressionProbe {

    private SmbCompressionProbe() {
    }

    /**
     * Whether the connection this file is reached through negotiated compression.
     *
     * @param file any file on the connection to ask about
     * @return true when the server agreed to at least one compression algorithm
     * @throws CIFSException if the connection cannot be established
     */
    public static boolean negotiated(final SmbFile file) throws CIFSException {
        try (SmbTreeHandleImpl th = (SmbTreeHandleImpl) file.getTreeHandle()) {
            return th.isCompressionNegotiated();
        }
    }
}
