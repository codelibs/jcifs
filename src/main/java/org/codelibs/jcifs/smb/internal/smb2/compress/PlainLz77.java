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
 * Plain LZ77 (XPRESS) decompression, MS-XCA 2.4.
 *
 * <p>
 * Decompression only. A client is never obliged to compress what it sends, and
 * this one does not, so only the reading half of the format is implemented.
 * </p>
 *
 * <p>
 * The format: a 32-bit little-endian indicator word whose bits are consumed from
 * the top down, a zero bit meaning a literal byte and a one bit meaning a match.
 * A match is a 16-bit little-endian word holding a 13-bit distance and a 3-bit
 * length, each biased. A length of 7 escapes to a 4-bit nibble, 15 to a byte, 255
 * to 16 bits and 0 to 32 bits.
 * </p>
 *
 * <p>
 * The nibble is the part worth reading twice: one byte carries the nibbles of two
 * consecutive matches, the first taking its low half and the second the high half
 * of that same byte, which is why the position is remembered rather than the
 * value. Deriving the arithmetic from the specification's worked examples instead
 * gets this right for those examples and wrong for a long match.
 * </p>
 */
public final class PlainLz77 {

    /** A match is at least this long, and the encoded length is the excess over it. */
    private static final int MIN_MATCH = 3;

    /** The 3-bit length field escapes to a nibble at this value. */
    private static final int LENGTH_ESCAPE = 7;

    /** The nibble escapes to a byte at this value. */
    private static final int NIBBLE_ESCAPE = 15;

    /** The byte escapes to sixteen bits at this value. */
    private static final int BYTE_ESCAPE = 255;

    private PlainLz77() {
    }

    /**
     * Decompresses a plain LZ77 segment.
     *
     * @param input            the compressed bytes
     * @param inputIndex       where the compressed data starts
     * @param inputLength      how many compressed bytes there are
     * @param originalSize     the decompressed size the sender declared
     * @return the decompressed bytes, exactly {@code originalSize} of them
     * @throws SMBProtocolDecodingException if the data is malformed or does not produce that size
     */
    public static byte[] decompress(final byte[] input, final int inputIndex, final int inputLength, final int originalSize)
            throws SMBProtocolDecodingException {
        if (inputIndex < 0 || inputLength < 0 || originalSize < 0 || (long) inputIndex + inputLength > input.length) {
            throw new SMBProtocolDecodingException("Compressed segment lies outside the message");
        }

        final byte[] output = new byte[originalSize];
        final int inputEnd = inputIndex + inputLength;
        int in = inputIndex;
        int out = 0;
        int indicator = 0;
        int indicatorBit = 0;
        // The position of the byte holding a pending high nibble, or 0 for none. A
        // position is kept rather than the value because the byte is shared with the
        // next match, which reads its high half.
        int nibbleIndex = 0;

        while (out < originalSize && in < inputEnd) {
            if (indicatorBit == 0) {
                if (in + 4 > inputEnd) {
                    throw new SMBProtocolDecodingException("Truncated indicator word");
                }
                indicator = SMBUtil.readInt4(input, in);
                in += 4;
                if (in == inputEnd) {
                    // Flags written for data that was never emitted.
                    break;
                }
                indicatorBit = 32;
            }
            indicatorBit--;

            if ((indicator >>> indicatorBit & 1) == 0) {
                if (in + 1 > inputEnd || out + 1 > originalSize) {
                    throw new SMBProtocolDecodingException("Truncated literal");
                }
                output[out] = input[in];
                in++;
                out++;
                continue;
            }

            if (in + 2 > inputEnd) {
                throw new SMBProtocolDecodingException("Truncated match");
            }
            final int match = SMBUtil.readInt2(input, in);
            in += 2;
            final int distance = (match >>> 3) + 1;
            int length = match & 7;

            if (length == LENGTH_ESCAPE) {
                if (nibbleIndex == 0) {
                    if (in + 1 > inputEnd) {
                        throw new SMBProtocolDecodingException("Truncated match length nibble");
                    }
                    nibbleIndex = in;
                    length = input[in] & 0x0F;
                    in++;
                } else {
                    length = (input[nibbleIndex] & 0xFF) >>> 4;
                    nibbleIndex = 0;
                }

                if (length == NIBBLE_ESCAPE) {
                    if (in + 1 > inputEnd) {
                        throw new SMBProtocolDecodingException("Truncated match length byte");
                    }
                    length = input[in] & 0xFF;
                    in++;
                    if (length == BYTE_ESCAPE) {
                        if (in + 2 > inputEnd) {
                            throw new SMBProtocolDecodingException("Truncated match length word");
                        }
                        length = SMBUtil.readInt2(input, in);
                        in += 2;
                        if (length == 0) {
                            if (in + 4 > inputEnd) {
                                throw new SMBProtocolDecodingException("Truncated match length long word");
                            }
                            length = SMBUtil.readInt4(input, in);
                            in += 4;
                        }
                        if (length < NIBBLE_ESCAPE + LENGTH_ESCAPE) {
                            throw new SMBProtocolDecodingException("Match length " + length + " is below its own encoding");
                        }
                        length -= NIBBLE_ESCAPE + LENGTH_ESCAPE;
                    }
                    length += NIBBLE_ESCAPE;
                }
                length += LENGTH_ESCAPE;
            }
            length += MIN_MATCH;

            if (distance > out) {
                throw new SMBProtocolDecodingException("Match reaches back past the start of the data");
            }
            if (length < 0 || out + length > originalSize) {
                throw new SMBProtocolDecodingException("Match runs past the declared decompressed size");
            }
            // One byte at a time on purpose: the length may exceed the distance, which
            // is how a run is encoded, and a bulk copy would read bytes it has not
            // written yet.
            for (int i = 0; i < length; i++) {
                output[out] = output[out - distance];
                out++;
            }
        }

        if (out != originalSize) {
            throw new SMBProtocolDecodingException("Decompressed " + out + " bytes, the sender declared " + originalSize);
        }
        return output;
    }
}
