/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.codelibs.jcifs.smb.internal.smb2.lock;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;

/**
 * Test-only way to build a decoded break notification from its body alone.
 *
 * <p>
 * A test of what the transport does with a break needs the transport, which is package private in the
 * implementation package, and the notification's decoder, which is protected here. No single package sees both, so
 * this exposes the decode without making a test hand-build a whole SMB2 header to reach the public one.
 * </p>
 */
public final class Smb2BreakNotifications {

    private Smb2BreakNotifications() {
    }

    /**
     * Decodes a break notification body - 24 bytes for an oplock break, 44 for a lease break.
     *
     * @param config the configuration to build it with
     * @param body   the notification body, starting at its structure size
     * @return the decoded notification
     * @throws SMBProtocolDecodingException if the body is neither shape
     */
    public static Smb2OplockBreakNotification decodeBody(final Configuration config, final byte[] body)
            throws SMBProtocolDecodingException {
        final Smb2OplockBreakNotification notification = new Smb2OplockBreakNotification(config);
        notification.readBytesWireFormat(body, 0);
        return notification;
    }
}
