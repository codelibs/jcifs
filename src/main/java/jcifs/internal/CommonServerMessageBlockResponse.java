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

import jcifs.util.transport.Response;

/**
 * Interface for SMB response messages received from server.
 * Extends the common SMB message block with response-specific functionality including
 * asynchronous response handling and response chaining capabilities.
 *
 * @author mbechler
 */
public interface CommonServerMessageBlockResponse extends CommonServerMessageBlock, Response {

    /**
     * Checks if this is an asynchronous response.
     *
     * @return is an async response
     */
    boolean isAsync();

    /**
     *
     * @return the next response
     */
    @Override
    CommonServerMessageBlockResponse getNextResponse();

    /**
     * Prepares this response for the next request.
     *
     * @param next the next request to prepare for
     */
    void prepare(CommonServerMessageBlockRequest next);
}
