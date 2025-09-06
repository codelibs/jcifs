/*
 * © 2025 CodeLibs, Inc.
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
package org.codelibs.jcifs.smb.compression;

import org.codelibs.jcifs.smb.CIFSException;

/**
 * Interface for SMB3 compression services.
 *
 * Provides compression and decompression functionality for SMB3 protocol
 * data transfers with support for multiple compression algorithms.
 */
public interface CompressionService {

    /**
     * Compression algorithm constants matching SMB3 specification.
     */
    /** No compression algorithm */
    public static final int COMPRESSION_NONE = 0x0;
    /** LZ77 compression algorithm */
    public static final int COMPRESSION_LZ77 = 0x1;
    /** LZ77 with Huffman encoding compression algorithm */
    public static final int COMPRESSION_LZ77_HUFFMAN = 0x2;
    /** LZNT1 compression algorithm */
    public static final int COMPRESSION_LZNT1 = 0x3;
    /** Pattern V1 compression algorithm */
    public static final int COMPRESSION_PATTERN_V1 = 0x4;

    /**
     * Compresses data using the specified algorithm.
     *
     * @param data the data to compress
     * @param algorithm the compression algorithm to use
     * @return the compressed data
     * @throws CIFSException if compression fails
     */
    byte[] compress(byte[] data, int algorithm) throws CIFSException;

    /**
     * Compresses data using the specified algorithm with offset and length.
     *
     * @param data the data buffer
     * @param offset the offset in the buffer
     * @param length the length of data to compress
     * @param algorithm the compression algorithm to use
     * @return the compressed data
     * @throws CIFSException if compression fails
     */
    byte[] compress(byte[] data, int offset, int length, int algorithm) throws CIFSException;

    /**
     * Decompresses data that was compressed with the specified algorithm.
     *
     * @param compressedData the compressed data
     * @param algorithm the compression algorithm that was used
     * @return the decompressed data
     * @throws CIFSException if decompression fails
     */
    byte[] decompress(byte[] compressedData, int algorithm) throws CIFSException;

    /**
     * Decompresses data with offset and length parameters.
     *
     * @param compressedData the compressed data buffer
     * @param offset the offset in the buffer
     * @param length the length of compressed data
     * @param algorithm the compression algorithm that was used
     * @return the decompressed data
     * @throws CIFSException if decompression fails
     */
    byte[] decompress(byte[] compressedData, int offset, int length, int algorithm) throws CIFSException;

    /**
     * Decompresses data into a provided buffer.
     *
     * @param compressedData the compressed data buffer
     * @param offset the offset in the compressed data buffer
     * @param length the length of compressed data
     * @param outputBuffer the output buffer for decompressed data
     * @param outputOffset the offset in the output buffer
     * @param algorithm the compression algorithm that was used
     * @return the number of bytes written to the output buffer
     * @throws CIFSException if decompression fails
     */
    int decompress(byte[] compressedData, int offset, int length, byte[] outputBuffer, int outputOffset, int algorithm)
            throws CIFSException;

    /**
     * Checks if the specified compression algorithm is supported.
     *
     * @param algorithm the compression algorithm to check
     * @return true if the algorithm is supported
     */
    boolean isAlgorithmSupported(int algorithm);

    /**
     * Gets the list of supported compression algorithms.
     *
     * @return array of supported algorithm constants
     */
    int[] getSupportedAlgorithms();

    /**
     * Estimates the compression ratio for the given data and algorithm.
     * This can be used to decide whether compression is worthwhile.
     *
     * @param data the data to analyze
     * @param algorithm the compression algorithm
     * @return estimated compression ratio (0.0 to 1.0, where 0.5 means 50% size reduction)
     */
    double estimateCompressionRatio(byte[] data, int algorithm);

    /**
     * Gets the minimum data size threshold for compression.
     * Data smaller than this threshold should not be compressed.
     *
     * @return minimum size in bytes for compression to be beneficial
     */
    int getMinCompressionSize();

    /**
     * Gets the maximum data size that can be compressed in a single operation.
     *
     * @return maximum size in bytes that can be compressed
     */
    int getMaxCompressionSize();

    /**
     * Gets a human-readable name for the compression algorithm.
     *
     * @param algorithm the algorithm constant
     * @return the algorithm name
     */
    String getAlgorithmName(int algorithm);
}
