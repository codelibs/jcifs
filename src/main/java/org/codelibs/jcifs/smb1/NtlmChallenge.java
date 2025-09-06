/*
 * Copyright (C) 2004  "Michael B. Allen" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb1;

import java.io.Serializable;

import org.codelibs.jcifs.smb1.util.Hexdump;

/**
 * Represents an NTLM authentication challenge in SMB1 protocol.
 */
public final class NtlmChallenge implements Serializable {

    /**
     * The NTLM challenge bytes received from the server.
     */
    public byte[] challenge;
    /**
     * The domain controller address that issued the challenge.
     */
    public UniAddress dc;

    NtlmChallenge(final byte[] challenge, final UniAddress dc) {
        this.challenge = challenge;
        this.dc = dc;
    }

    @Override
    public String toString() {
        return "NtlmChallenge[challenge=0x" + Hexdump.toHexString(challenge, 0, challenge.length * 2) + ",dc=" + dc.toString() + "]";
    }
}
