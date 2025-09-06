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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * NTLMSSP AV pair representing target name information in NTLM authentication.
 * Contains the name of the target server or service being authenticated against.
 *
 * @author mbechler
 */
public class AvTargetName extends AvPair {

    /**
     *
     */
    private static final Charset UTF16LE = StandardCharsets.UTF_16LE;

    /**
     * Constructs an AvTargetName from raw byte data
     *
     * @param raw the raw byte data for the target name AV pair
     */
    public AvTargetName(final byte[] raw) {
        super(AvPair.MsvAvTargetName, raw);
    }

    /**
     * Constructs an AvTargetName with the specified target name
     *
     * @param targetName the target name string to encode
     */
    public AvTargetName(final String targetName) {
        this(encode(targetName));
    }

    /**
     * Gets the target name from this AV pair
     *
     * @return the target name
     */
    public String getTargetName() {
        return new String(getRaw(), UTF16LE);
    }

    /**
     * @param targetName
     * @return
     */
    private static byte[] encode(final String targetName) {
        return targetName.getBytes(UTF16LE);
    }

}
