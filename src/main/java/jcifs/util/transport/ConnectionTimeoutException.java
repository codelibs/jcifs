/*
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
 * Exception thrown when a network connection times out during SMB communication.
 * Indicates that the connection could not be established within the specified timeout period.
 *
 * @author mbechler
 */
public class ConnectionTimeoutException extends TransportException {

    /**
     *
     */
    private static final long serialVersionUID = 7327198103204592731L;

    /**
     * Constructs a new ConnectionTimeoutException with no detail message.
     */
    public ConnectionTimeoutException() {
    }

    /**
     * Constructs a new ConnectionTimeoutException with the specified detail message.
     * @param msg the detail message
     */
    public ConnectionTimeoutException(final String msg) {
        super(msg);
    }

    /**
     * Constructs a new ConnectionTimeoutException with the specified cause.
     * @param rootCause the cause of this exception
     */
    public ConnectionTimeoutException(final Throwable rootCause) {
        super(rootCause);
    }

    /**
     * Constructs a new ConnectionTimeoutException with the specified detail message and cause.
     * @param msg the detail message
     * @param rootCause the cause of this exception
     */
    public ConnectionTimeoutException(final String msg, final Throwable rootCause) {
        super(msg, rootCause);
    }

}
