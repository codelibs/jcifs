package org.codelibs.jcifs.smb.internal.smb2.nego;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SMB 3.1.1 Compression Capabilities negotiate context.
 *
 * This context is used during SMB2 negotiation to negotiate compression
 * algorithms for SMB3 data compression support.
 */
public class CompressionNegotiateContext implements NegotiateContextRequest, NegotiateContextResponse {

    private static final Logger log = LoggerFactory.getLogger(CompressionNegotiateContext.class);

    // Context type
    /** Context ID for compression capabilities */
    public static final int NEGO_CTX_COMPRESSION_TYPE = 0x3;

    // SMB3 Compression Algorithms
    /** No compression */
    public static final int COMPRESSION_NONE = 0x0;
    /** LZ77 compression */
    public static final int COMPRESSION_LZ77 = 0x1;
    /** LZ77 + Huffman compression */
    public static final int COMPRESSION_LZ77_HUFFMAN = 0x2;
    /** LZNT1 compression (Windows standard) */
    public static final int COMPRESSION_LZNT1 = 0x3;
    /** Pattern V1 compression */
    public static final int COMPRESSION_PATTERN_V1 = 0x4;

    private int[] compressionAlgorithms;
    private int flags;

    /**
     * Constructs a compression negotiate context with the specified algorithms.
     *
     * @param config the configuration
     * @param compressionAlgorithms the supported compression algorithms
     */
    public CompressionNegotiateContext(final Configuration config, final int[] compressionAlgorithms) {
        this(config, compressionAlgorithms, 0);
    }

    /**
     * Constructs a compression negotiate context with the specified algorithms and flags.
     *
     * @param config the configuration
     * @param compressionAlgorithms the supported compression algorithms
     * @param flags compression flags (reserved, should be 0)
     */
    public CompressionNegotiateContext(final Configuration config, final int[] compressionAlgorithms, final int flags) {
        this.compressionAlgorithms = compressionAlgorithms != null ? compressionAlgorithms.clone() : new int[0];
        this.flags = flags;
    }

    /**
     * Default constructor for response parsing.
     */
    public CompressionNegotiateContext() {
        this.compressionAlgorithms = new int[0];
        this.flags = 0;
    }

    @Override
    public int getContextType() {
        return NEGO_CTX_COMPRESSION_TYPE;
    }

    /**
     * Gets the supported compression algorithms.
     *
     * @return the supported compression algorithms
     */
    public int[] getCompressionAlgorithms() {
        return this.compressionAlgorithms != null ? this.compressionAlgorithms.clone() : new int[0];
    }

    /**
     * Gets the compression flags.
     *
     * @return the compression flags
     */
    public int getFlags() {
        return this.flags;
    }

    /**
     * Checks if a specific compression algorithm is supported.
     *
     * @param algorithm the algorithm to check
     * @return true if the algorithm is supported
     */
    public boolean supportsAlgorithm(int algorithm) {
        if (this.compressionAlgorithms == null) {
            return false;
        }
        for (int algo : this.compressionAlgorithms) {
            if (algo == algorithm) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int encode(byte[] dst, int dstIndex) {
        if (this.compressionAlgorithms == null) {
            return 0;
        }

        int start = dstIndex;

        // Compression count (2 bytes)
        SMBUtil.writeInt2(this.compressionAlgorithms.length, dst, dstIndex);
        dstIndex += 2;

        // Padding (2 bytes)
        SMBUtil.writeInt2(0, dst, dstIndex);
        dstIndex += 2;

        // Flags (4 bytes)
        SMBUtil.writeInt4(this.flags, dst, dstIndex);
        dstIndex += 4;

        // Compression algorithms (2 bytes each)
        for (int algo : this.compressionAlgorithms) {
            SMBUtil.writeInt2(algo, dst, dstIndex);
            dstIndex += 2;
        }

        return dstIndex - start;
    }

    @Override
    public int decode(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
        if (len < 8) {
            throw new SMBProtocolDecodingException("Invalid compression context length: " + len);
        }

        int start = bufferIndex;

        // Read compression count
        int compressionCount = SMBUtil.readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        // Validate compression count
        if (compressionCount < 0 || compressionCount > 16) {
            throw new SMBProtocolDecodingException("Invalid compression count: " + compressionCount);
        }

        // Skip padding
        bufferIndex += 2;

        // Read flags
        this.flags = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        // Validate remaining buffer size for algorithms
        if (len < 8 + (compressionCount * 2)) {
            throw new SMBProtocolDecodingException("Buffer too small for compression algorithms");
        }

        // Read compression algorithms
        this.compressionAlgorithms = new int[compressionCount];
        for (int i = 0; i < compressionCount; i++) {
            this.compressionAlgorithms[i] = SMBUtil.readInt2(buffer, bufferIndex);
            bufferIndex += 2;

            // Validate known algorithms
            if (!isValidCompressionAlgorithm(this.compressionAlgorithms[i])) {
                log.warn("Unknown compression algorithm: 0x{}", Integer.toHexString(this.compressionAlgorithms[i]));
            }
        }

        return bufferIndex - start;
    }

    @Override
    public int size() {
        if (this.compressionAlgorithms == null) {
            return 8; // Minimum size: count + padding + flags
        }
        return 8 + (this.compressionAlgorithms.length * 2);
    }

    /**
     * Validates if the compression algorithm is known.
     *
     * @param algorithm the algorithm to validate
     * @return true if the algorithm is known
     */
    private boolean isValidCompressionAlgorithm(int algorithm) {
        return algorithm == COMPRESSION_NONE || algorithm == COMPRESSION_LZ77 || algorithm == COMPRESSION_LZ77_HUFFMAN
                || algorithm == COMPRESSION_LZNT1 || algorithm == COMPRESSION_PATTERN_V1;
    }

    /**
     * Gets a human-readable name for the compression algorithm.
     *
     * @param algorithm the algorithm constant
     * @return the algorithm name
     */
    public static String getAlgorithmName(int algorithm) {
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

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("CompressionNegotiateContext{");
        sb.append("flags=0x").append(Integer.toHexString(flags));
        sb.append(", algorithms=[");
        if (compressionAlgorithms != null) {
            for (int i = 0; i < compressionAlgorithms.length; i++) {
                if (i > 0)
                    sb.append(", ");
                sb.append(getAlgorithmName(compressionAlgorithms[i]));
            }
        }
        sb.append("]}");
        return sb.toString();
    }
}
