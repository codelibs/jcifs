/* jcifs msrpc client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Eric Glass" <jcifs at samba dot org>
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

package jcifs.dcerpc.ndr;

import jcifs.CIFSException;

/**
 * Exception thrown when an error occurs during NDR encoding or decoding operations.
 */
public class NdrException extends CIFSException {

    /**
     *
     */
    private static final long serialVersionUID = 7621650016319792189L;
    /**
     * Error message for null reference pointers.
     */
    public static final String NO_NULL_REF = "ref pointer cannot be null";

    /**
     * Error message for invalid array conformance.
     */
    public static final String INVALID_CONFORMANCE = "invalid array conformance";

    /**
     * Constructs an NdrException with the specified error message.
     *
     * @param msg the error message
     */
    public NdrException(final String msg) {
        super(msg);
    }
}
