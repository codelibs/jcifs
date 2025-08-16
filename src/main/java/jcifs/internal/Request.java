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
package jcifs.internal;

import jcifs.CIFSContext;

/**
 * Generic interface for typed SMB request messages.
 * Extends the common request interface with type-safe response handling,
 * allowing requests to specify their expected response type.
 *
 * @author mbechler
 * @param <T> response type
 */
public interface Request<T extends CommonServerMessageBlockResponse> extends CommonServerMessageBlockRequest {

    /**
     * Initializes and returns a response object for this request.
     *
     * @param tc the CIFS context
     * @return the initialized response
     */
    T initResponse(CIFSContext tc);

    /**
     *
     * @return the response message
     */
    @Override
    T getResponse();

    /**
     * Marks this request to ignore disconnection errors.
     *
     * @return this request
     *
     */
    CommonServerMessageBlock ignoreDisconnect();

}
