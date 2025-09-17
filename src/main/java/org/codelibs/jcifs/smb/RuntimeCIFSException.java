/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
package org.codelibs.jcifs.smb;

/**
 * Base for all checked exceptions used by this library
 *
 *
 * These should only occur under very rare circumstances.
 *
 * @author mbechler
 *
 */
public class RuntimeCIFSException extends RuntimeException {

    /**
     *
     */
    private static final long serialVersionUID = -2611196678846438579L;

    /**
     * Constructs a runtime CIFS exception with no detail message.
     */
    public RuntimeCIFSException() {
    }

    /**
     * Constructs a runtime CIFS exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of this exception
     */
    public RuntimeCIFSException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a runtime CIFS exception with the specified detail message.
     *
     * @param message the detail message
     */
    public RuntimeCIFSException(final String message) {
        super(message);
    }

    /**
     * Constructs a runtime CIFS exception with the specified cause.
     *
     * @param cause the cause of this exception
     */
    public RuntimeCIFSException(final Throwable cause) {
        super(cause);
    }

}
