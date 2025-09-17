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
package org.codelibs.jcifs.smb.impl;

/**
 * Exception thrown when SMB message signature validation fails.
 * Indicates that the integrity of an SMB message could not be verified.
 *
 * @author mbechler
 *
 */
public class SMBSignatureValidationException extends SmbException {

    /**
     * Default constructor for SMB signature validation exception.
     */
    public SMBSignatureValidationException() {
    }

    /**
     * Constructs an SMB signature validation exception with message and cause.
     *
     * @param msg the detail message describing the validation failure
     * @param rootCause the underlying cause of the validation failure
     */
    public SMBSignatureValidationException(final String msg, final Throwable rootCause) {
        super(msg, rootCause);
    }

    /**
     * Constructs an SMB signature validation exception with a detail message.
     *
     * @param msg the detail message describing the validation failure
     */
    public SMBSignatureValidationException(final String msg) {
        super(msg);
    }

    /**
     *
     */
    private static final long serialVersionUID = 2283323396289696982L;

}
