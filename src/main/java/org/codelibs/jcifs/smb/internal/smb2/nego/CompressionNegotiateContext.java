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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.codelibs.jcifs.smb.internal.smb2.nego;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2_COMPRESSION_CAPABILITIES, MS-SMB2 2.2.3.1.3 and 2.2.4.1.3.
 *
 * <p>
 * The request names the algorithms the client can handle, in order of
 * preference. The response takes the same shape and names what the server
 * picked from them - which is a selection rather than a statement of what the
 * server supports: Windows Server 2025 answers an offer of all five algorithms
 * with two of them, and answers an offer of one with that one.
 * </p>
 *
 * <p>
 * That is why a client offers only what it can actually decompress. MS-SMB2
 * 3.2.5.2 requires the connection to fail if the server names an algorithm the
 * client did not offer, so the offer is a promise, not a wish.
 * </p>
 */
public class CompressionNegotiateContext implements NegotiateContextRequest, NegotiateContextResponse {

    /**
     * Context type
     */
    public static final int NEGO_CTX_COMPRESSION_TYPE = 0x3;

    /**
     * No compression
     */
    public static final int COMPRESSION_NONE = 0x0;

    /**
     * LZNT1, the NTFS compression format
     */
    public static final int COMPRESSION_LZNT1 = 0x1;

    /**
     * Plain LZ77, also called XPRESS
     */
    public static final int COMPRESSION_LZ77 = 0x2;

    /**
     * LZ77 with Huffman coding, also called XPRESS Huffman
     */
    public static final int COMPRESSION_LZ77_HUFFMAN = 0x3;

    /**
     * A run of one repeated byte, only meaningful inside a chained message
     */
    public static final int COMPRESSION_PATTERN_V1 = 0x4;

    /**
     * LZ4, added in Windows Server 2025
     */
    public static final int COMPRESSION_LZ4 = 0x5;

    /**
     * Chained compression is not supported
     */
    public static final int FLAG_NONE = 0x0;

    /**
     * Chained compression is supported on this connection
     */
    public static final int FLAG_CHAINED = 0x1;

    /**
     * An algorithm identifier at or above this value is invalid (MS-SMB2 3.2.5.2).
     */
    private static final int ALGORITHM_LIMIT = 32;

    /** CompressionAlgorithmCount, Padding and Flags, ahead of the identifiers. */
    private static final int PREAMBLE_SIZE = 8;

    private int[] algorithms;
    private int flags;

    /**
     * Constructs a compression negotiate context.
     *
     * @param config     the configuration (currently unused)
     * @param algorithms the compression algorithm identifiers to offer, in preference order
     */
    public CompressionNegotiateContext(final Configuration config, final int[] algorithms) {
        this.algorithms = algorithms;
        this.flags = FLAG_NONE;
    }

    /**
     * Default constructor for decoding.
     */
    public CompressionNegotiateContext() {
    }

    /**
     * Gets the compression algorithms.
     *
     * @return the algorithm identifiers, in the order they appeared
     */
    public int[] getAlgorithms() {
        return this.algorithms;
    }

    /**
     * Gets the context flags.
     *
     * @return {@link #FLAG_CHAINED} when chained compression is supported, otherwise {@link #FLAG_NONE}
     */
    public int getFlags() {
        return this.flags;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.nego.NegotiateContextRequest#getContextType()
     */
    @Override
    public int getContextType() {
        return NEGO_CTX_COMPRESSION_TYPE;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Encodable#encode(byte[], int)
     */
    @Override
    public int encode(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        final int count = this.algorithms != null ? this.algorithms.length : 0;
        SMBUtil.writeInt2(count, dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(0, dst, dstIndex); // Padding, the sender must set this to zero
        dstIndex += 2;
        SMBUtil.writeInt4(this.flags, dst, dstIndex);
        dstIndex += 4;

        if (this.algorithms != null) {
            for (final int algorithm : this.algorithms) {
                SMBUtil.writeInt2(algorithm, dst, dstIndex);
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
        if (len < PREAMBLE_SIZE) {
            throw new SMBProtocolDecodingException("Compression negotiate context is shorter than its own header");
        }
        final int start = bufferIndex;
        final int count = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        bufferIndex += 2; // Padding, ignored on receipt
        this.flags = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        if (count == 0) {
            throw new SMBProtocolDecodingException("Compression negotiate context names no algorithm");
        }
        if (PREAMBLE_SIZE + 2 * count > len || (long) bufferIndex + 2L * count > buffer.length) {
            throw new SMBProtocolDecodingException("Compression negotiate context runs past its own length");
        }

        this.algorithms = new int[count];
        for (int i = 0; i < count; i++) {
            this.algorithms[i] = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            if (this.algorithms[i] >= ALGORITHM_LIMIT) {
                throw new SMBProtocolDecodingException("Invalid compression algorithm " + this.algorithms[i]);
            }
            for (int j = 0; j < i; j++) {
                if (this.algorithms[j] == this.algorithms[i]) {
                    throw new SMBProtocolDecodingException("Duplicate compression algorithm " + this.algorithms[i]);
                }
            }
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
        return PREAMBLE_SIZE + (this.algorithms != null ? 2 * this.algorithms.length : 0);
    }
}
