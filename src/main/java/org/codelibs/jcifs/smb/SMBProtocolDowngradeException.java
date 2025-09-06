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
package org.codelibs.jcifs.smb;

/**
 * Exception thrown when an SMB protocol downgrade attack is detected.
 * Indicates that the negotiated protocol version is lower than expected or required.
 *
 * @author mbechler
 *
 */
public class SMBProtocolDowngradeException extends CIFSException {

    /**
     * Serial version UID for serialization compatibility.
     */
    private static final long serialVersionUID = 1913365058349456689L;

    /**
     * Creates a new SMBProtocolDowngradeException with no message.
     */
    public SMBProtocolDowngradeException() {
    }

    /**
     * Creates a new SMBProtocolDowngradeException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public SMBProtocolDowngradeException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Creates a new SMBProtocolDowngradeException with the specified detail message.
     *
     * @param message the detail message
     */
    public SMBProtocolDowngradeException(final String message) {
        super(message);
    }

    /**
     * Creates a new SMBProtocolDowngradeException with the specified cause.
     *
     * @param cause the cause of the exception
     */
    public SMBProtocolDowngradeException(final Throwable cause) {
        super(cause);
    }

}
