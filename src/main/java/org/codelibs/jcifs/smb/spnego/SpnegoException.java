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
package org.codelibs.jcifs.smb.spnego;

import org.codelibs.jcifs.smb.CIFSException;

/**
 * Exception thrown during SPNEGO authentication processing.
 *
 * This exception indicates an error in SPNEGO token processing,
 * negotiation, or authentication flow.
 *
 * @author mbechler
 */
public class SpnegoException extends CIFSException {

    /**
     *
     */
    private static final long serialVersionUID = -4591854684249021395L;

    /**
     * Constructs a new SpnegoException with no detail message
     */
    public SpnegoException() {
    }

    /**
     * Constructs a new SpnegoException with the specified detail message and cause
     * @param message the detail message
     * @param cause the cause of this exception
     */
    public SpnegoException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new SpnegoException with the specified detail message
     * @param message the detail message
     */
    public SpnegoException(final String message) {
        super(message);
    }

    /**
     * Constructs a new SpnegoException with the specified cause
     * @param cause the cause of this exception
     */
    public SpnegoException(final Throwable cause) {
        super(cause);
    }

}
