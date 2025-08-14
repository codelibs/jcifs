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
package jcifs.ntlmssp.av;

import jcifs.Configuration;
import jcifs.internal.util.SMBUtil;

/**
 * NTLMSSP AV pair representing single host information in NTLM authentication.
 * Contains host-specific data used during the NTLM challenge-response process.
 *
 * @author mbechler
 */
public class AvSingleHost extends AvPair {

    /**
     * Constructs an AvSingleHost from raw byte data
     *
     * @param raw the raw byte data for the single host AV pair
     */
    public AvSingleHost(final byte[] raw) {
        super(AvPair.MsvAvSingleHost, raw);
    }

    /**
     * Constructs an AvSingleHost using configuration settings
     *
     * @param cfg the configuration containing machine ID
     */
    public AvSingleHost(final Configuration cfg) {
        this(new byte[8], cfg.getMachineId());
    }

    /**
     * Constructs an AvSingleHost with custom data and machine ID
     *
     * @param customData custom data for the single host (8 bytes)
     * @param machineId the machine identifier (32 bytes)
     */
    public AvSingleHost(final byte[] customData, final byte[] machineId) {
        this(encode(customData, machineId));
    }

    private static byte[] encode(final byte[] customData, final byte[] machineId) {
        final int size = 8 + 8 + 32;
        final byte[] enc = new byte[size];
        SMBUtil.writeInt4(size, enc, 0);
        SMBUtil.writeInt4(0, enc, 4);
        System.arraycopy(customData, 0, enc, 8, 8);
        System.arraycopy(machineId, 0, enc, 16, 32);
        return enc;
    }

}
