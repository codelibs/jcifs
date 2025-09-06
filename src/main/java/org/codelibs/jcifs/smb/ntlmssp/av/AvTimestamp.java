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
package org.codelibs.jcifs.smb.ntlmssp.av;

import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * NTLMSSP AV pair representing timestamp information in NTLM authentication.
 * Contains time-based data used to prevent replay attacks and ensure message freshness.
 *
 * @author mbechler
 */
public class AvTimestamp extends AvPair {

    /**
     * Constructs an AvTimestamp from raw byte data
     *
     * @param raw the raw byte data for the timestamp AV pair
     */
    public AvTimestamp(final byte[] raw) {
        super(AvPair.MsvAvTimestamp, raw);
    }

    /**
     * Constructs an AvTimestamp with the specified timestamp value
     *
     * @param ts the timestamp value in Windows FILETIME format
     */
    public AvTimestamp(final long ts) {
        this(encode(ts));
    }

    /**
     * @param ts
     * @return
     */
    private static byte[] encode(final long ts) {
        final byte[] data = new byte[8];
        SMBUtil.writeInt8(ts, data, 0);
        return data;
    }

    /**
     * Gets the timestamp value from this AV pair
     *
     * @return the timestamp
     */
    public long getTimestamp() {
        return SMBUtil.readInt8(getRaw(), 0);
    }

}
