package jcifs.smb.compression;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.Configuration;
import jcifs.config.PropertyConfiguration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb2.nego.CompressionNegotiateContext;

/**
 * Comprehensive tests for SMB3 compression negotiate context.
 */
public class CompressionNegotiateContextTest {

    private Configuration config;
    private CompressionNegotiateContext context;

    @BeforeEach
    public void setUp() throws Exception {
        Properties props = new Properties();
        config = new PropertyConfiguration(props);
        context = new CompressionNegotiateContext(config, new int[] { CompressionNegotiateContext.COMPRESSION_LZ77,
                CompressionNegotiateContext.COMPRESSION_LZ77_HUFFMAN, CompressionNegotiateContext.COMPRESSION_LZNT1 });
    }

    @Test
    @DisplayName("Test compression context type")
    public void testContextType() {
        assertEquals(CompressionNegotiateContext.NEGO_CTX_COMPRESSION_TYPE, context.getContextType());
    }

    @Test
    @DisplayName("Test supported algorithms")
    public void testSupportedAlgorithms() {
        int[] algorithms = context.getCompressionAlgorithms();
        assertNotNull(algorithms);
        assertEquals(3, algorithms.length);
        assertTrue(context.supportsAlgorithm(CompressionNegotiateContext.COMPRESSION_LZ77));
        assertTrue(context.supportsAlgorithm(CompressionNegotiateContext.COMPRESSION_LZ77_HUFFMAN));
        assertTrue(context.supportsAlgorithm(CompressionNegotiateContext.COMPRESSION_LZNT1));
        assertFalse(context.supportsAlgorithm(CompressionNegotiateContext.COMPRESSION_PATTERN_V1));
    }

    @Test
    @DisplayName("Test context encoding")
    public void testEncoding() {
        byte[] buffer = new byte[256];
        int encodedSize = context.encode(buffer, 0);

        assertTrue(encodedSize > 8); // Minimum size: count + padding + flags + algorithms
        assertEquals(context.size(), encodedSize);
    }

    @Test
    @DisplayName("Test context decoding")
    public void testDecoding() throws SMBProtocolDecodingException {
        // Encode first
        byte[] buffer = new byte[256];
        int encodedSize = context.encode(buffer, 0);

        // Create new context for decoding
        CompressionNegotiateContext decodedContext = new CompressionNegotiateContext();
        int decodedSize = decodedContext.decode(buffer, 0, encodedSize);

        assertEquals(encodedSize, decodedSize);
        assertArrayEquals(context.getCompressionAlgorithms(), decodedContext.getCompressionAlgorithms());
        assertEquals(context.getFlags(), decodedContext.getFlags());
    }

    @Test
    @DisplayName("Test invalid buffer size for decoding")
    public void testInvalidBufferSize() {
        byte[] smallBuffer = new byte[4]; // Too small

        assertThrows(SMBProtocolDecodingException.class, () -> {
            context.decode(smallBuffer, 0, smallBuffer.length);
        });
    }

    @Test
    @DisplayName("Test algorithm name resolution")
    public void testAlgorithmNames() {
        assertEquals("None", CompressionNegotiateContext.getAlgorithmName(CompressionNegotiateContext.COMPRESSION_NONE));
        assertEquals("LZ77", CompressionNegotiateContext.getAlgorithmName(CompressionNegotiateContext.COMPRESSION_LZ77));
        assertEquals("LZ77+Huffman", CompressionNegotiateContext.getAlgorithmName(CompressionNegotiateContext.COMPRESSION_LZ77_HUFFMAN));
        assertEquals("LZNT1", CompressionNegotiateContext.getAlgorithmName(CompressionNegotiateContext.COMPRESSION_LZNT1));
        assertEquals("Pattern_V1", CompressionNegotiateContext.getAlgorithmName(CompressionNegotiateContext.COMPRESSION_PATTERN_V1));
        assertTrue(CompressionNegotiateContext.getAlgorithmName(0xFF).startsWith("Unknown"));
    }

    @Test
    @DisplayName("Test empty algorithms context")
    public void testEmptyAlgorithms() {
        CompressionNegotiateContext emptyContext = new CompressionNegotiateContext(config, new int[0]);

        assertEquals(0, emptyContext.getCompressionAlgorithms().length);
        assertEquals(8, emptyContext.size()); // Minimum size
        assertFalse(emptyContext.supportsAlgorithm(CompressionNegotiateContext.COMPRESSION_LZ77));
    }

    @Test
    @DisplayName("Test context size calculation")
    public void testContextSize() {
        int expectedSize = 8 + (3 * 2); // Header + 3 algorithms * 2 bytes each
        assertEquals(expectedSize, context.size());
    }

    @Test
    @DisplayName("Test context with flags")
    public void testContextWithFlags() {
        CompressionNegotiateContext contextWithFlags =
                new CompressionNegotiateContext(config, new int[] { CompressionNegotiateContext.COMPRESSION_LZ77 }, 0x12345678);

        assertEquals(0x12345678, contextWithFlags.getFlags());
    }

    @Test
    @DisplayName("Test toString representation")
    public void testToString() {
        String str = context.toString();
        assertNotNull(str);
        assertTrue(str.contains("CompressionNegotiateContext"));
        assertTrue(str.contains("LZ77"));
        assertTrue(str.contains("LZNT1"));
    }
}