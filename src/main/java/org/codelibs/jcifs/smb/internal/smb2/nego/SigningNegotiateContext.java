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
package org.codelibs.jcifs.smb.internal.smb2.nego;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Signing Capabilities Negotiate Context.
 *
 * <p>
 * Used in SMB 3.1.1 to negotiate which algorithm signs messages (MS-SMB2 2.2.3.1.7). The data is a count followed
 * by that many 16-bit algorithm ids, ordered with the client's most preferred first. Only SMB 3.1.1 negotiates
 * this: SMB 3.0 and 3.0.2 always sign with AES-128-CMAC, and SMB 2.x with HMAC-SHA256.
 * </p>
 */
public class SigningNegotiateContext implements NegotiateContextRequest, NegotiateContextResponse {

    /**
     * Context type
     */
    public static final int NEGO_CTX_SIGNING_TYPE = 0x8;

    /**
     * HMAC-SHA256, the SMB 2.x signing algorithm
     */
    public static final int SIGNING_ALGO_HMAC_SHA256 = 0x0;

    /**
     * AES-128-CMAC, the SMB 3.x default
     */
    public static final int SIGNING_ALGO_AES128_CMAC = 0x1;

    /**
     * AES-128-GMAC (SMB 3.1.1 only)
     */
    public static final int SIGNING_ALGO_AES128_GMAC = 0x2;

    private int[] signingAlgos;

    /**
     * Constructs a signing capabilities negotiate context.
     *
     * @param config the configuration (currently unused)
     * @param signingAlgos the signing algorithm ids to negotiate, most preferred first
     */
    public SigningNegotiateContext(final Configuration config, final int[] signingAlgos) {
        this.signingAlgos = signingAlgos;
    }

    /**
     * Default constructor for decoding.
     */
    public SigningNegotiateContext() {
    }

    /**
     * Gets the signing algorithms.
     *
     * @return array of signing algorithm ids
     */
    public int[] getSigningAlgos() {
        return this.signingAlgos;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.nego.NegotiateContextRequest#getContextType()
     */
    @Override
    public int getContextType() {
        return NEGO_CTX_SIGNING_TYPE;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Encodable#encode(byte[], int)
     */
    @Override
    public int encode(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt2(this.signingAlgos != null ? this.signingAlgos.length : 0, dst, dstIndex);
        dstIndex += 2;

        if (this.signingAlgos != null) {
            for (final int algo : this.signingAlgos) {
                SMBUtil.writeInt2(algo, dst, dstIndex);
                dstIndex += 2;
            }
        }
        return dstIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Decodable#decode(byte[], int, int)
     */
    @Override
    public int decode(final byte[] buffer, int bufferIndex, final int len) throws SMBProtocolDecodingException {
        final int start = bufferIndex;
        final int nalgos = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        if ((long) bufferIndex + 2L * nalgos > buffer.length) {
            throw new SMBProtocolDecodingException("Invalid signing negotiate context");
        }

        this.signingAlgos = new int[nalgos];
        for (int i = 0; i < nalgos; i++) {
            this.signingAlgos[i] = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
        }

        return bufferIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Encodable#size()
     */
    @Override
    public int size() {
        // Deliberately the number of bytes encode() writes, and no more. EncryptionNegotiateContext reports two
        // bytes more than it writes, which is harmless there only because the wire length comes from encode's
        // return value rather than from size().
        return 2 + (this.signingAlgos != null ? 2 * this.signingAlgos.length : 0);
    }

}
