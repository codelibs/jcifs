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

import jcifs.util.transport.Request;

/**
 * Interface for SMB request messages sent from client to server.
 * Extends the common SMB message block with request-specific functionality including
 * asynchronous handling, message chaining, cancellation, and timeout management.
 *
 * @author mbechler
 */
public interface CommonServerMessageBlockRequest extends CommonServerMessageBlock, Request {

    /**
     * Checks if the request will be handled asynchronously.
     *
     * @return request was handled asynchronously
     */
    boolean isResponseAsync();

    /**
     *
     * @return next chained message
     */
    @Override
    CommonServerMessageBlockRequest getNext();

    /**
     * Splits this request for processing.
     *
     * @return the following message
     */
    CommonServerMessageBlockRequest split();

    /**
     * Gets the size of this message.
     *
     * @return the size of this message
     */
    int size();

    /**
     * Creates a cancel request for this request.
     *
     * @return create cancel request
     */
    CommonServerMessageBlockRequest createCancel();

    /**
     * Checks if chaining is allowed with the next request.
     *
     * @param next the next request in the chain
     * @return whether to allow chaining
     */
    boolean allowChain(CommonServerMessageBlockRequest next);

    /**
     * Sets the tree ID.
     *
     * @param t the tree ID to set
     */
    void setTid(int t);

    /**
     * Gets the custom response timeout for this request.
     *
     * @return custom response timeout for this request
     */
    Integer getOverrideTimeout();

}
