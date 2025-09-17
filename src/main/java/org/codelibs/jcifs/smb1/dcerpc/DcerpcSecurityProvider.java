/* org.codelibs.jcifs.smb msrpc client library in Java
 * Copyright (C) 2009  "Michael B. Allen" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb1.dcerpc;

import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrBuffer;

/**
 * Interface for DCERPC security providers that handle message protection
 */
public interface DcerpcSecurityProvider {
    /**
     * Wraps outgoing DCERPC message data for security protection
     * @param outgoing the buffer containing data to be wrapped
     * @throws DcerpcException if the wrapping operation fails
     */
    void wrap(NdrBuffer outgoing) throws DcerpcException;

    /**
     * Unwraps incoming DCERPC message data after security processing
     * @param incoming the buffer containing data to be unwrapped
     * @throws DcerpcException if the unwrapping operation fails
     */
    void unwrap(NdrBuffer incoming) throws DcerpcException;
}
