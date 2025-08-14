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
package jcifs.internal.smb2.nego;

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

/**
 * SMB2 Encryption Negotiate Context.
 *
 * This negotiate context is used in SMB 3.x to negotiate
 * encryption capabilities and cipher suites.
 *
 * @author mbechler
 */
public class EncryptionNegotiateContext implements NegotiateContextRequest, NegotiateContextResponse {

    /**
     * Context type
     */
    public static final int NEGO_CTX_ENC_TYPE = 0x2;

    /**
     * AES 128 CCM
     */
    public static final int CIPHER_AES128_CCM = 0x1;

    /**
     * AES 128 GCM
     */
    public static final int CIPHER_AES128_GCM = 0x2;

    private int[] ciphers;

    /**
     * Constructs an encryption negotiate context.
     *
     * @param config the configuration (currently unused)
     * @param ciphers array of encryption cipher IDs to negotiate
     */
    public EncryptionNegotiateContext(final Configuration config, final int ciphers[]) {
        this.ciphers = ciphers;
    }

    /**
     * Default constructor for decoding.
     */
    public EncryptionNegotiateContext() {
    }

    /**
     * Gets the supported encryption ciphers.
     *
     * @return array of encryption cipher IDs
     */
    public int[] getCiphers() {
        return this.ciphers;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.nego.NegotiateContextRequest#getContextType()
     */
    @Override
    public int getContextType() {
        return NEGO_CTX_ENC_TYPE;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#encode(byte[], int)
     */
    @Override
    public int encode(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt2(this.ciphers != null ? this.ciphers.length : 0, dst, dstIndex);
        dstIndex += 2;

        if (this.ciphers != null) {
            for (final int cipher : this.ciphers) {
                SMBUtil.writeInt2(cipher, dst, dstIndex);
                dstIndex += 2;
            }
        }
        return dstIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode(final byte[] buffer, int bufferIndex, final int len) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        final int nciphers = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        this.ciphers = new int[nciphers];
        for (int i = 0; i < nciphers; i++) {
            this.ciphers[i] = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
        }

        return bufferIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.Encodable#size()
     */
    @Override
    public int size() {
        return 4 + (this.ciphers != null ? 2 * this.ciphers.length : 0);
    }

}
