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
package org.codelibs.jcifs.smb.util.transport;

import org.codelibs.jcifs.smb.CIFSException;

/**
 * Exception class for transport layer errors.
 * This exception is thrown when transport-related communication errors occur.
 */
public class TransportException extends CIFSException {

    /**
     *
     */
    private static final long serialVersionUID = 3743631204022885618L;

    /**
     * Constructs a new TransportException with no detail message.
     */
    public TransportException() {
    }

    /**
     * Constructs a new TransportException with the specified detail message.
     * @param msg the detail message
     */
    public TransportException(final String msg) {
        super(msg);
    }

    /**
     * Constructs a new TransportException with the specified cause.
     * @param rootCause the cause of this exception
     */
    public TransportException(final Throwable rootCause) {
        super(rootCause);
    }

    /**
     * Constructs a new TransportException with the specified detail message and cause.
     * @param msg the detail message
     * @param rootCause the cause of this exception
     */
    public TransportException(final String msg, final Throwable rootCause) {
        super(msg, rootCause);
    }

    /**
     * Gets the root cause of this exception.
     * @return root cause of this exception
     */
    @Deprecated
    public Throwable getRootCause() {
        return getCause();
    }
}
