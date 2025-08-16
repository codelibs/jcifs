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
package jcifs;

import java.io.IOException;

/**
 * Base for all checked exceptions used by this library
 *
 * @author mbechler
 *
 */
public class CIFSException extends IOException {

    /**
     *
     */
    private static final long serialVersionUID = 7806460518865806784L;

    /**
     * Constructs a CIFS exception with no detail message.
     */
    public CIFSException() {
    }

    /**
     * Constructs a CIFS exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of this exception
     */
    public CIFSException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a CIFS exception with the specified detail message.
     *
     * @param message the detail message
     */
    public CIFSException(final String message) {
        super(message);
    }

    /**
     * Constructs a CIFS exception with the specified cause.
     *
     * @param cause the cause of this exception
     */
    public CIFSException(final Throwable cause) {
        super(cause);
    }

}
