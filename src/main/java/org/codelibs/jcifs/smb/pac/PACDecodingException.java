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
package org.codelibs.jcifs.smb.pac;

import org.codelibs.jcifs.smb.CIFSException;

/**
 * Exception thrown when PAC (Privilege Attribute Certificate) data cannot be decoded.
 * Indicates malformed or invalid PAC structures in Kerberos tickets.
 */
public class PACDecodingException extends CIFSException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new PAC decoding exception with no detail message.
     */
    public PACDecodingException() {
        this(null, null);
    }

    /**
     * Constructs a new PAC decoding exception with the specified detail message.
     * @param message the detail message
     */
    public PACDecodingException(final String message) {
        this(message, null);
    }

    /**
     * Constructs a new PAC decoding exception with the specified cause.
     * @param cause the cause of the exception
     */
    public PACDecodingException(final Throwable cause) {
        this(null, cause);
    }

    /**
     * Constructs a new PAC decoding exception with the specified detail message and cause.
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public PACDecodingException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
