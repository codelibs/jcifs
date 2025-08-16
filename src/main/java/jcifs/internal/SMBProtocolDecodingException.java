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

import jcifs.CIFSException;

/**
 * Exception thrown when errors occur during SMB protocol message decoding.
 * Indicates that an SMB message could not be properly parsed or decoded due to
 * malformed data, protocol violations, or unsupported message formats.
 *
 * @author mbechler
 */
public class SMBProtocolDecodingException extends CIFSException {

    /**
     *
     */
    private static final long serialVersionUID = 4862398838709265475L;

    /**
     * Constructs a new SMBProtocolDecodingException with no detail message.
     */
    public SMBProtocolDecodingException() {
    }

    /**
     * Constructs a new SMBProtocolDecodingException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public SMBProtocolDecodingException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new SMBProtocolDecodingException with the specified detail message.
     *
     * @param message the detail message
     */
    public SMBProtocolDecodingException(final String message) {
        super(message);
    }

    /**
     * Constructs a new SMBProtocolDecodingException with the specified cause.
     *
     * @param cause the cause of the exception
     */
    public SMBProtocolDecodingException(final Throwable cause) {
        super(cause);
    }

}
