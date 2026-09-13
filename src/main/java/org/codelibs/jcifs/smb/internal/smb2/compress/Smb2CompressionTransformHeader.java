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
package org.codelibs.jcifs.smb.internal.smb2.compress;

import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2_COMPRESSION_TRANSFORM_HEADER_UNCHAINED, MS-SMB2 2.2.42.1.
 *
 * <p>
 * Reading only. This client never compresses what it sends, so the header is
 * parsed and never written. The chained form, 2.2.42.2, is not read either: it
 * only arrives when both ends set the chained flag, and this client does not.
 * </p>
 */
public final class Smb2CompressionTransformHeader {

    /** The header is a fixed sixteen bytes. */
    public static final int HEADER_SIZE = 16;

    /** ProtocolId, 0xFC 'S' 'M' 'B' on the wire. */
    public static final int PROTOCOL_ID = 0x424D53FC;

    /** Flags value for the unchained form. */
    public static final int FLAG_NONE = 0x0;

    /** Flags value that makes the header the chained form instead. */
    public static final int FLAG_CHAINED = 0x1;

    private final int originalSize;
    private final int algorithm;
    private final int flags;
    private final int offset;

    private Smb2CompressionTransformHeader(final int originalSize, final int algorithm, final int flags, final int offset) {
        this.originalSize = originalSize;
        this.algorithm = algorithm;
        this.flags = flags;
        this.offset = offset;
    }

    /**
     * The size the sender says the decompressed segment has.
     *
     * @return the declared decompressed size in bytes
     */
    public int getOriginalSize() {
        return this.originalSize;
    }

    /**
     * The algorithm the segment was compressed with, never NONE.
     *
     * @return the compression algorithm identifier
     */
    public int getAlgorithm() {
        return this.algorithm;
    }

    /**
     * The header flags, which decide whether this is the chained form.
     *
     * @return {@link #FLAG_NONE} or {@link #FLAG_CHAINED}
     */
    public int getFlags() {
        return this.flags;
    }

    /**
     * How far past the end of this header the compressed segment starts. What lies
     * in between is carried uncompressed.
     *
     * @return the offset in bytes from the end of the header
     */
    public int getOffset() {
        return this.offset;
    }

    /**
     * Whether this is the chained form, which this client does not negotiate and
     * cannot read.
     *
     * @return true when the chained flag is set
     */
    public boolean isChained() {
        return (this.flags & FLAG_CHAINED) != 0;
    }

    /**
     * Parses a compression transform header.
     *
     * @param buffer      the message
     * @param bufferIndex where the header starts
     * @param len         how many bytes of the message are available from there
     * @return the parsed header
     * @throws SMBProtocolDecodingException if the header is truncated or is not one
     */
    public static Smb2CompressionTransformHeader decode(final byte[] buffer, final int bufferIndex, final int len)
            throws SMBProtocolDecodingException {
        if (len < HEADER_SIZE || bufferIndex < 0 || (long) bufferIndex + HEADER_SIZE > buffer.length) {
            throw new SMBProtocolDecodingException("Message is shorter than a compression transform header");
        }
        if (SMBUtil.readInt4(buffer, bufferIndex) != PROTOCOL_ID) {
            throw new SMBProtocolDecodingException("Not a compression transform header");
        }
        final int originalSize = SMBUtil.readInt4(buffer, bufferIndex + 4);
        final int algorithm = SMBUtil.readInt2(buffer, bufferIndex + 8);
        final int flags = SMBUtil.readInt2(buffer, bufferIndex + 10);
        final int offset = SMBUtil.readInt4(buffer, bufferIndex + 12);

        if (originalSize < 0) {
            throw new SMBProtocolDecodingException("Compressed segment declares a negative decompressed size");
        }
        if (offset < 0 || (long) HEADER_SIZE + offset > len) {
            throw new SMBProtocolDecodingException("Compressed segment starts past the end of the message");
        }
        return new Smb2CompressionTransformHeader(originalSize, algorithm, flags, offset);
    }
}
