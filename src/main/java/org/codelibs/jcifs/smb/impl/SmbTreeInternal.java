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
package org.codelibs.jcifs.smb.impl;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.SmbTree;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockResponse;
import org.codelibs.jcifs.smb.internal.Request;

/**
 * Internal SMB tree connection interface providing extended tree management capabilities.
 * Defines methods for internal tree operations and resource management.
 *
 * @author mbechler
 *
 * <p>This interface is intended for internal use.</p>
 */
public interface SmbTreeInternal extends SmbTree {

    /**
     * Connects and performs logon to the tree using the specified context
     * @param tf the CIFS context to use for connection
     * @throws SmbException if an SMB error occurs during connection
     */
    @Deprecated
    void connectLogon(CIFSContext tf) throws SmbException;

    /**
     * Sends an SMB request and returns the response
     * @param <T> the response type
     * @param request the request to send
     * @param params optional request parameters
     * @return response message
     * @throws CIFSException if an error occurs sending the request
     */
    <T extends CommonServerMessageBlockResponse> T send(Request<T> request, RequestParam... params) throws CIFSException;
}
