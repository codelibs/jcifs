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
package jcifs.util.transport;

/**
 * Exception thrown when a request times out during SMB communication.
 * Indicates that a request could not be completed within the specified timeout period.
 *
 * @author mbechler
 */
public class RequestTimeoutException extends TransportException {

    /**
     *
     */
    private static final long serialVersionUID = -8825922797594232534L;

    /**
     *
     */
    public RequestTimeoutException() {
    }

    /**
     * @param msg
     * @param rootCause
     */
    public RequestTimeoutException(final String msg, final Throwable rootCause) {
        super(msg, rootCause);
    }

    /**
     * @param msg
     */
    public RequestTimeoutException(final String msg) {
        super(msg);
    }

    /**
     * @param rootCause
     */
    public RequestTimeoutException(final Throwable rootCause) {
        super(rootCause);
    }

}
