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
package org.codelibs.jcifs.smb.internal.smb2.nego;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Pre-authentication Integrity Negotiate Context.
 *
 * This negotiate context is used in SMB 3.1.1 to establish
 * pre-authentication integrity protection against downgrade attacks.
 *
 * @author mbechler
 */
public class PreauthIntegrityNegotiateContext implements NegotiateContextRequest, NegotiateContextResponse {

    /**
     * Context type
     */
    public static final int NEGO_CTX_PREAUTH_TYPE = 0x1;

    /**
     * SHA-512
     */
    public static final int HASH_ALGO_SHA512 = 0x1;

    private int[] hashAlgos;
    private byte[] salt;

    /**
     * Constructs a preauth integrity negotiate context with the specified parameters.
     *
     * @param config the SMB configuration
     * @param hashAlgos the supported hash algorithms
     * @param salt the salt value for preauth integrity
     */
    public PreauthIntegrityNegotiateContext(final Configuration config, final int[] hashAlgos, final byte[] salt) {
        this.hashAlgos = hashAlgos;
        this.salt = salt;
    }

    /**
     * Default constructor for deserialization.
     */
    public PreauthIntegrityNegotiateContext() {
    }

    /**
     * Gets the salt value used for preauth integrity.
     *
     * @return the salt
     */
    public byte[] getSalt() {
        return this.salt;
    }

    /**
     * Gets the supported hash algorithms for preauth integrity.
     *
     * @return the hashAlgos
     */
    public int[] getHashAlgos() {
        return this.hashAlgos;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.nego.NegotiateContextRequest#getContextType()
     */
    @Override
    public int getContextType() {
        return NEGO_CTX_PREAUTH_TYPE;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Encodable#encode(byte[], int)
     */
    @Override
    public int encode(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        SMBUtil.writeInt2(this.hashAlgos != null ? this.hashAlgos.length : 0, dst, dstIndex);
        SMBUtil.writeInt2(this.salt != null ? this.salt.length : 0, dst, dstIndex + 2);
        dstIndex += 4;

        if (this.hashAlgos != null) {
            for (final int hashAlgo : this.hashAlgos) {
                SMBUtil.writeInt2(hashAlgo, dst, dstIndex);
                dstIndex += 2;
            }
        }

        if (this.salt != null) {
            System.arraycopy(this.salt, 0, dst, dstIndex, this.salt.length);
            dstIndex += this.salt.length;
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
        final int nsalt = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;

        this.hashAlgos = new int[nalgos];
        for (int i = 0; i < nalgos; i++) {
            this.hashAlgos[i] = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
        }

        this.salt = new byte[nsalt];
        System.arraycopy(buffer, bufferIndex, this.salt, 0, nsalt);
        bufferIndex += nsalt;

        return bufferIndex - start;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Encodable#size()
     */
    @Override
    public int size() {
        return 4 + (this.hashAlgos != null ? 2 * this.hashAlgos.length : 0) + (this.salt != null ? this.salt.length : 0);
    }

}
