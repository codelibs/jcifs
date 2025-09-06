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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import org.codelibs.jcifs.smb.CIFSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of SMB3 compression service.
 *
 * Provides compression using Java's built-in deflate algorithm as a base
 * for LZ77-based compression. For production use, more specialized
 * implementations of LZNT1 and Pattern_V1 algorithms would be needed.
 */
public class DefaultCompressionService implements CompressionService {

    /**
     * Creates a default compression service
     */
    public DefaultCompressionService() {
        // Default constructor
    }

    private static final Logger log = LoggerFactory.getLogger(DefaultCompressionService.class);

    // Configuration constants
    private static final int MIN_COMPRESSION_SIZE = 512; // 512 bytes minimum
    private static final int MAX_COMPRESSION_SIZE = 1024 * 1024; // 1MB maximum
    private static final int COMPRESSION_LEVEL = Deflater.DEFAULT_COMPRESSION;

    // Supported algorithms
    private static final int[] SUPPORTED_ALGORITHMS = { COMPRESSION_NONE, COMPRESSION_LZ77, COMPRESSION_LZ77_HUFFMAN };

    @Override
    public byte[] compress(byte[] data, int algorithm) throws CIFSException {
        if (data == null) {
            throw new CIFSException("Data cannot be null");
        }
        return compress(data, 0, data.length, algorithm);
    }

    @Override
    public byte[] compress(byte[] data, int offset, int length, int algorithm) throws CIFSException {
        if (data == null) {
            throw new CIFSException("Data cannot be null");
        }
        if (offset < 0 || length < 0 || offset + length > data.length) {
            throw new CIFSException("Invalid offset or length");
        }
        if (!isAlgorithmSupported(algorithm)) {
            throw new CIFSException("Unsupported compression algorithm: " + algorithm);
        }
        if (length < MIN_COMPRESSION_SIZE) {
            log.debug("Data too small for compression ({} bytes), returning uncompressed", length);
            byte[] result = new byte[length];
            System.arraycopy(data, offset, result, 0, length);
            return result;
        }
        if (length > MAX_COMPRESSION_SIZE) {
            throw new CIFSException("Data too large for compression: " + length + " bytes");
        }

        switch (algorithm) {
        case COMPRESSION_NONE:
            byte[] uncompressed = new byte[length];
            System.arraycopy(data, offset, uncompressed, 0, length);
            return uncompressed;

        case COMPRESSION_LZ77:
            return compressLZ77(data, offset, length);

        case COMPRESSION_LZ77_HUFFMAN:
            return compressLZ77Huffman(data, offset, length);

        case COMPRESSION_LZNT1:
            throw new CIFSException("LZNT1 compression not yet implemented");

        case COMPRESSION_PATTERN_V1:
            throw new CIFSException("Pattern_V1 compression not yet implemented");

        default:
            throw new CIFSException("Unknown compression algorithm: " + algorithm);
        }
    }

    @Override
    public byte[] decompress(byte[] compressedData, int algorithm) throws CIFSException {
        if (compressedData == null) {
            throw new CIFSException("Compressed data cannot be null");
        }
        return decompress(compressedData, 0, compressedData.length, algorithm);
    }

    @Override
    public byte[] decompress(byte[] compressedData, int offset, int length, int algorithm) throws CIFSException {
        if (compressedData == null) {
            throw new CIFSException("Compressed data cannot be null");
        }
        if (offset < 0 || length < 0 || offset + length > compressedData.length) {
            throw new CIFSException("Invalid offset or length");
        }
        if (!isAlgorithmSupported(algorithm)) {
            throw new CIFSException("Unsupported compression algorithm: " + algorithm);
        }

        switch (algorithm) {
        case COMPRESSION_NONE:
            byte[] result = new byte[length];
            System.arraycopy(compressedData, offset, result, 0, length);
            return result;

        case COMPRESSION_LZ77:
            return decompressLZ77(compressedData, offset, length);

        case COMPRESSION_LZ77_HUFFMAN:
            return decompressLZ77Huffman(compressedData, offset, length);

        case COMPRESSION_LZNT1:
            throw new CIFSException("LZNT1 decompression not yet implemented");

        case COMPRESSION_PATTERN_V1:
            throw new CIFSException("Pattern_V1 decompression not yet implemented");

        default:
            throw new CIFSException("Unknown compression algorithm: " + algorithm);
        }
    }

    @Override
    public int decompress(byte[] compressedData, int offset, int length, byte[] outputBuffer, int outputOffset, int algorithm)
            throws CIFSException {
        byte[] decompressed = decompress(compressedData, offset, length, algorithm);
        if (outputBuffer.length - outputOffset < decompressed.length) {
            throw new CIFSException("Output buffer too small");
        }
        System.arraycopy(decompressed, 0, outputBuffer, outputOffset, decompressed.length);
        return decompressed.length;
    }

    @Override
    public boolean isAlgorithmSupported(int algorithm) {
        for (int supported : SUPPORTED_ALGORITHMS) {
            if (supported == algorithm) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int[] getSupportedAlgorithms() {
        return SUPPORTED_ALGORITHMS.clone();
    }

    @Override
    public double estimateCompressionRatio(byte[] data, int algorithm) {
        if (data == null || data.length == 0) {
            return 1.0;
        }
        if (algorithm == COMPRESSION_NONE) {
            return 1.0;
        }

        // Simple heuristic based on data entropy
        // In practice, this would be more sophisticated
        int uniqueBytes = countUniqueBytes(data);
        double entropy = (double) uniqueBytes / 256.0;

        // Estimate compression ratio based on entropy
        // Lower entropy = better compression
        return 0.3 + (entropy * 0.6); // Range from 30% to 90%
    }

    @Override
    public int getMinCompressionSize() {
        return MIN_COMPRESSION_SIZE;
    }

    @Override
    public int getMaxCompressionSize() {
        return MAX_COMPRESSION_SIZE;
    }

    @Override
    public String getAlgorithmName(int algorithm) {
        switch (algorithm) {
        case COMPRESSION_NONE:
            return "None";
        case COMPRESSION_LZ77:
            return "LZ77";
        case COMPRESSION_LZ77_HUFFMAN:
            return "LZ77+Huffman";
        case COMPRESSION_LZNT1:
            return "LZNT1";
        case COMPRESSION_PATTERN_V1:
            return "Pattern_V1";
        default:
            return "Unknown(0x" + Integer.toHexString(algorithm) + ")";
        }
    }

    /**
     * Compresses data using LZ77 algorithm (implemented using Java's Deflater).
     */
    private byte[] compressLZ77(byte[] data, int offset, int length) throws CIFSException {
        try {
            Deflater deflater = new Deflater(COMPRESSION_LEVEL, false);
            deflater.setInput(data, offset, length);
            deflater.finish();

            ByteArrayOutputStream baos = new ByteArrayOutputStream(length);
            byte[] buffer = new byte[1024];

            while (!deflater.finished()) {
                int compressedSize = deflater.deflate(buffer);
                baos.write(buffer, 0, compressedSize);
            }

            deflater.end();
            return baos.toByteArray();
        } catch (Exception e) {
            throw new CIFSException("LZ77 compression failed", e);
        }
    }

    /**
     * Decompresses LZ77 data.
     */
    private byte[] decompressLZ77(byte[] compressedData, int offset, int length) throws CIFSException {
        try {
            Inflater inflater = new Inflater(false);
            inflater.setInput(compressedData, offset, length);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];

            while (!inflater.finished()) {
                int decompressedSize = inflater.inflate(buffer);
                if (decompressedSize == 0) {
                    break;
                }
                baos.write(buffer, 0, decompressedSize);
            }

            inflater.end();
            return baos.toByteArray();
        } catch (Exception e) {
            throw new CIFSException("LZ77 decompression failed", e);
        }
    }

    /**
     * Compresses data using LZ77+Huffman algorithm.
     */
    private byte[] compressLZ77Huffman(byte[] data, int offset, int length) throws CIFSException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DeflaterOutputStream deflaterStream = new DeflaterOutputStream(baos, new Deflater(COMPRESSION_LEVEL, false));

            deflaterStream.write(data, offset, length);
            deflaterStream.close();

            return baos.toByteArray();
        } catch (IOException e) {
            throw new CIFSException("LZ77+Huffman compression failed", e);
        }
    }

    /**
     * Decompresses LZ77+Huffman data.
     */
    private byte[] decompressLZ77Huffman(byte[] compressedData, int offset, int length) throws CIFSException {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(compressedData, offset, length);
            InflaterInputStream inflaterStream = new InflaterInputStream(bais);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int bytesRead;

            while ((bytesRead = inflaterStream.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }

            inflaterStream.close();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new CIFSException("LZ77+Huffman decompression failed", e);
        }
    }

    /**
     * Counts the number of unique bytes in the data (for entropy estimation).
     */
    private int countUniqueBytes(byte[] data) {
        boolean[] seen = new boolean[256];
        int count = 0;

        for (byte b : data) {
            int index = b & 0xFF;
            if (!seen[index]) {
                seen[index] = true;
                count++;
            }
        }

        return count;
    }
}
