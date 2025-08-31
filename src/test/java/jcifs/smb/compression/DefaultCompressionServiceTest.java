package jcifs.smb.compression;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.CIFSException;

/**
 * Comprehensive tests for default compression service implementation.
 */
public class DefaultCompressionServiceTest {

    private DefaultCompressionService compressionService;
    private byte[] testData;
    private byte[] largeTestData;

    @BeforeEach
    public void setUp() {
        compressionService = new DefaultCompressionService();

        // Create test data with patterns that should compress well
        testData = generateTestData(1024);
        largeTestData = generateTestData(8192);
    }

    @Test
    @DisplayName("Test supported algorithms")
    public void testSupportedAlgorithms() {
        int[] supported = compressionService.getSupportedAlgorithms();
        assertNotNull(supported);
        assertTrue(supported.length > 0);

        assertTrue(compressionService.isAlgorithmSupported(CompressionService.COMPRESSION_NONE));
        assertTrue(compressionService.isAlgorithmSupported(CompressionService.COMPRESSION_LZ77));
        assertTrue(compressionService.isAlgorithmSupported(CompressionService.COMPRESSION_LZ77_HUFFMAN));
        assertFalse(compressionService.isAlgorithmSupported(CompressionService.COMPRESSION_LZNT1));
        assertFalse(compressionService.isAlgorithmSupported(CompressionService.COMPRESSION_PATTERN_V1));
    }

    @Test
    @DisplayName("Test no compression (passthrough)")
    public void testNoCompression() throws CIFSException {
        byte[] compressed = compressionService.compress(testData, CompressionService.COMPRESSION_NONE);
        assertArrayEquals(testData, compressed);

        byte[] decompressed = compressionService.decompress(compressed, CompressionService.COMPRESSION_NONE);
        assertArrayEquals(testData, decompressed);
    }

    @Test
    @DisplayName("Test LZ77 compression and decompression")
    public void testLZ77Compression() throws CIFSException {
        byte[] compressed = compressionService.compress(testData, CompressionService.COMPRESSION_LZ77);
        assertNotNull(compressed);
        assertTrue(compressed.length > 0);
        // Compressed size should typically be smaller (though not guaranteed for all data)

        byte[] decompressed = compressionService.decompress(compressed, CompressionService.COMPRESSION_LZ77);
        assertArrayEquals(testData, decompressed);
    }

    @Test
    @DisplayName("Test LZ77+Huffman compression and decompression")
    public void testLZ77HuffmanCompression() throws CIFSException {
        byte[] compressed = compressionService.compress(testData, CompressionService.COMPRESSION_LZ77_HUFFMAN);
        assertNotNull(compressed);
        assertTrue(compressed.length > 0);

        byte[] decompressed = compressionService.decompress(compressed, CompressionService.COMPRESSION_LZ77_HUFFMAN);
        assertArrayEquals(testData, decompressed);
    }

    @Test
    @DisplayName("Test compression with offset and length")
    public void testCompressionWithOffsetLength() throws CIFSException {
        byte[] paddedData = new byte[testData.length + 200];
        System.arraycopy(testData, 0, paddedData, 100, testData.length);

        byte[] compressed = compressionService.compress(paddedData, 100, testData.length, CompressionService.COMPRESSION_LZ77);
        byte[] decompressed = compressionService.decompress(compressed, CompressionService.COMPRESSION_LZ77);

        assertArrayEquals(testData, decompressed);
    }

    @Test
    @DisplayName("Test decompression into buffer")
    public void testDecompressionIntoBuffer() throws CIFSException {
        byte[] compressed = compressionService.compress(testData, CompressionService.COMPRESSION_LZ77);

        byte[] outputBuffer = new byte[testData.length + 100];
        int writtenBytes =
                compressionService.decompress(compressed, 0, compressed.length, outputBuffer, 50, CompressionService.COMPRESSION_LZ77);

        assertEquals(testData.length, writtenBytes);

        byte[] extracted = new byte[testData.length];
        System.arraycopy(outputBuffer, 50, extracted, 0, testData.length);
        assertArrayEquals(testData, extracted);
    }

    @Test
    @DisplayName("Test small data handling")
    public void testSmallDataHandling() throws CIFSException {
        byte[] smallData = new byte[100]; // Below minimum compression size

        byte[] compressed = compressionService.compress(smallData, CompressionService.COMPRESSION_LZ77);
        // Should return uncompressed data for small inputs
        assertArrayEquals(smallData, compressed);
    }

    @Test
    @DisplayName("Test large data compression")
    public void testLargeDataCompression() throws CIFSException {
        byte[] compressed = compressionService.compress(largeTestData, CompressionService.COMPRESSION_LZ77);
        byte[] decompressed = compressionService.decompress(compressed, CompressionService.COMPRESSION_LZ77);

        assertArrayEquals(largeTestData, decompressed);
    }

    @Test
    @DisplayName("Test compression ratio estimation")
    public void testCompressionRatioEstimation() {
        double ratio = compressionService.estimateCompressionRatio(testData, CompressionService.COMPRESSION_LZ77);
        assertTrue(ratio >= 0.0 && ratio <= 1.0);

        double noneRatio = compressionService.estimateCompressionRatio(testData, CompressionService.COMPRESSION_NONE);
        assertEquals(1.0, noneRatio, 0.001);
    }

    @Test
    @DisplayName("Test configuration limits")
    public void testConfigurationLimits() {
        assertTrue(compressionService.getMinCompressionSize() > 0);
        assertTrue(compressionService.getMaxCompressionSize() > compressionService.getMinCompressionSize());
    }

    @Test
    @DisplayName("Test algorithm names")
    public void testAlgorithmNames() {
        assertEquals("None", compressionService.getAlgorithmName(CompressionService.COMPRESSION_NONE));
        assertEquals("LZ77", compressionService.getAlgorithmName(CompressionService.COMPRESSION_LZ77));
        assertEquals("LZ77+Huffman", compressionService.getAlgorithmName(CompressionService.COMPRESSION_LZ77_HUFFMAN));
        assertEquals("LZNT1", compressionService.getAlgorithmName(CompressionService.COMPRESSION_LZNT1));
        assertEquals("Pattern_V1", compressionService.getAlgorithmName(CompressionService.COMPRESSION_PATTERN_V1));
    }

    @Test
    @DisplayName("Test unsupported algorithm compression")
    public void testUnsupportedAlgorithmCompression() {
        assertThrows(CIFSException.class, () -> {
            compressionService.compress(testData, CompressionService.COMPRESSION_LZNT1);
        });
    }

    @Test
    @DisplayName("Test unsupported algorithm decompression")
    public void testUnsupportedAlgorithmDecompression() {
        assertThrows(CIFSException.class, () -> {
            compressionService.decompress(testData, CompressionService.COMPRESSION_PATTERN_V1);
        });
    }

    @Test
    @DisplayName("Test null data handling")
    public void testNullDataHandling() {
        assertThrows(CIFSException.class, () -> {
            compressionService.compress(null, CompressionService.COMPRESSION_LZ77);
        });

        assertThrows(CIFSException.class, () -> {
            compressionService.decompress(null, CompressionService.COMPRESSION_LZ77);
        });
    }

    @Test
    @DisplayName("Test invalid offset/length handling")
    public void testInvalidOffsetLength() {
        assertThrows(CIFSException.class, () -> {
            compressionService.compress(testData, -1, testData.length, CompressionService.COMPRESSION_LZ77);
        });

        assertThrows(CIFSException.class, () -> {
            compressionService.compress(testData, 0, testData.length + 1, CompressionService.COMPRESSION_LZ77);
        });
    }

    @Test
    @DisplayName("Test output buffer too small")
    public void testOutputBufferTooSmall() throws CIFSException {
        byte[] compressed = compressionService.compress(testData, CompressionService.COMPRESSION_LZ77);
        byte[] smallBuffer = new byte[10]; // Too small

        assertThrows(CIFSException.class, () -> {
            compressionService.decompress(compressed, 0, compressed.length, smallBuffer, 0, CompressionService.COMPRESSION_LZ77);
        });
    }

    /**
     * Generates test data with repeating patterns for good compression.
     */
    private byte[] generateTestData(int size) {
        byte[] data = new byte[size];

        // Create data with repeating patterns
        for (int i = 0; i < size; i++) {
            if (i % 100 < 50) {
                data[i] = (byte) 'A';
            } else if (i % 100 < 75) {
                data[i] = (byte) 'B';
            } else {
                data[i] = (byte) (i % 26 + 'a');
            }
        }

        return data;
    }
}