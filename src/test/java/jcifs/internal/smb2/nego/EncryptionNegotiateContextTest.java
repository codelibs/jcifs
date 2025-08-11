package jcifs.internal.smb2.nego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Arrays;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for EncryptionNegotiateContext
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("EncryptionNegotiateContext Tests")
class EncryptionNegotiateContextTest {

    @Mock
    private Configuration mockConfig;
    
    private static final int BUFFER_SIZE = 1024;
    private byte[] buffer;
    
    @BeforeEach
    void setUp() {
        buffer = new byte[BUFFER_SIZE];
    }
    
    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {
        
        @Test
        @DisplayName("Should create instance with Configuration and ciphers")
        void testConstructorWithConfigAndCiphers() {
            int[] ciphers = {EncryptionNegotiateContext.CIPHER_AES128_CCM, EncryptionNegotiateContext.CIPHER_AES128_GCM};
            
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            assertNotNull(context);
            assertArrayEquals(ciphers, context.getCiphers());
        }
        
        @Test
        @DisplayName("Should create instance with null ciphers")
        void testConstructorWithNullCiphers() {
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, null);
            
            assertNotNull(context);
            assertNull(context.getCiphers());
        }
        
        @Test
        @DisplayName("Should create instance with empty ciphers array")
        void testConstructorWithEmptyCiphers() {
            int[] ciphers = {};
            
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            assertNotNull(context);
            assertArrayEquals(ciphers, context.getCiphers());
            assertEquals(0, context.getCiphers().length);
        }
        
        @Test
        @DisplayName("Should create instance with default constructor")
        void testDefaultConstructor() {
            EncryptionNegotiateContext context = new EncryptionNegotiateContext();
            
            assertNotNull(context);
            assertNull(context.getCiphers());
        }
    }
    
    @Nested
    @DisplayName("Context Type Tests")
    class ContextTypeTests {
        
        @Test
        @DisplayName("Should return correct context type")
        void testGetContextType() {
            EncryptionNegotiateContext context = new EncryptionNegotiateContext();
            
            assertEquals(EncryptionNegotiateContext.NEGO_CTX_ENC_TYPE, context.getContextType());
            assertEquals(0x2, context.getContextType());
        }
    }
    
    @Nested
    @DisplayName("Encoding Tests")
    class EncodingTests {
        
        @Test
        @DisplayName("Should encode single cipher correctly")
        void testEncodeSingleCipher() {
            int[] ciphers = {EncryptionNegotiateContext.CIPHER_AES128_CCM};
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            int bytesWritten = context.encode(buffer, 0);
            
            assertEquals(4, bytesWritten);
            assertEquals(1, SMBUtil.readInt2(buffer, 0));
            assertEquals(EncryptionNegotiateContext.CIPHER_AES128_CCM, SMBUtil.readInt2(buffer, 2));
        }
        
        @Test
        @DisplayName("Should encode multiple ciphers correctly")
        void testEncodeMultipleCiphers() {
            int[] ciphers = {EncryptionNegotiateContext.CIPHER_AES128_CCM, EncryptionNegotiateContext.CIPHER_AES128_GCM};
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            int bytesWritten = context.encode(buffer, 0);
            
            assertEquals(6, bytesWritten);
            assertEquals(2, SMBUtil.readInt2(buffer, 0));
            assertEquals(EncryptionNegotiateContext.CIPHER_AES128_CCM, SMBUtil.readInt2(buffer, 2));
            assertEquals(EncryptionNegotiateContext.CIPHER_AES128_GCM, SMBUtil.readInt2(buffer, 4));
        }
        
        @Test
        @DisplayName("Should encode null ciphers as zero count")
        void testEncodeNullCiphers() {
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, null);
            
            int bytesWritten = context.encode(buffer, 0);
            
            assertEquals(2, bytesWritten);
            assertEquals(0, SMBUtil.readInt2(buffer, 0));
        }
        
        @Test
        @DisplayName("Should encode empty ciphers array")
        void testEncodeEmptyCiphers() {
            int[] ciphers = {};
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            int bytesWritten = context.encode(buffer, 0);
            
            assertEquals(2, bytesWritten);
            assertEquals(0, SMBUtil.readInt2(buffer, 0));
        }
        
        @Test
        @DisplayName("Should encode at non-zero offset")
        void testEncodeWithOffset() {
            int offset = 100;
            int[] ciphers = {EncryptionNegotiateContext.CIPHER_AES128_GCM};
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            int bytesWritten = context.encode(buffer, offset);
            
            assertEquals(4, bytesWritten);
            assertEquals(1, SMBUtil.readInt2(buffer, offset));
            assertEquals(EncryptionNegotiateContext.CIPHER_AES128_GCM, SMBUtil.readInt2(buffer, offset + 2));
        }
        
        @ParameterizedTest
        @ValueSource(ints = {1, 3, 5, 10, 20})
        @DisplayName("Should encode various cipher counts correctly")
        void testEncodeVariousCipherCounts(int cipherCount) {
            int[] ciphers = new int[cipherCount];
            for (int i = 0; i < cipherCount; i++) {
                ciphers[i] = i + 1;
            }
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            int bytesWritten = context.encode(buffer, 0);
            
            assertEquals(2 + (2 * cipherCount), bytesWritten);
            assertEquals(cipherCount, SMBUtil.readInt2(buffer, 0));
            for (int i = 0; i < cipherCount; i++) {
                assertEquals(i + 1, SMBUtil.readInt2(buffer, 2 + (i * 2)));
            }
        }
    }
    
    @Nested
    @DisplayName("Decoding Tests")
    class DecodingTests {
        
        @Test
        @DisplayName("Should decode single cipher correctly")
        void testDecodeSingleCipher() throws SMBProtocolDecodingException {
            SMBUtil.writeInt2(1, buffer, 0);
            SMBUtil.writeInt2(EncryptionNegotiateContext.CIPHER_AES128_CCM, buffer, 2);
            
            EncryptionNegotiateContext context = new EncryptionNegotiateContext();
            int bytesRead = context.decode(buffer, 0, 4);
            
            assertEquals(4, bytesRead);
            assertNotNull(context.getCiphers());
            assertEquals(1, context.getCiphers().length);
            assertEquals(EncryptionNegotiateContext.CIPHER_AES128_CCM, context.getCiphers()[0]);
        }
        
        @Test
        @DisplayName("Should decode multiple ciphers correctly")
        void testDecodeMultipleCiphers() throws SMBProtocolDecodingException {
            SMBUtil.writeInt2(2, buffer, 0);
            SMBUtil.writeInt2(EncryptionNegotiateContext.CIPHER_AES128_CCM, buffer, 2);
            SMBUtil.writeInt2(EncryptionNegotiateContext.CIPHER_AES128_GCM, buffer, 4);
            
            EncryptionNegotiateContext context = new EncryptionNegotiateContext();
            int bytesRead = context.decode(buffer, 0, 6);
            
            assertEquals(6, bytesRead);
            assertNotNull(context.getCiphers());
            assertEquals(2, context.getCiphers().length);
            assertEquals(EncryptionNegotiateContext.CIPHER_AES128_CCM, context.getCiphers()[0]);
            assertEquals(EncryptionNegotiateContext.CIPHER_AES128_GCM, context.getCiphers()[1]);
        }
        
        @Test
        @DisplayName("Should decode zero ciphers correctly")
        void testDecodeZeroCiphers() throws SMBProtocolDecodingException {
            SMBUtil.writeInt2(0, buffer, 0);
            
            EncryptionNegotiateContext context = new EncryptionNegotiateContext();
            int bytesRead = context.decode(buffer, 0, 2);
            
            assertEquals(2, bytesRead);
            assertNotNull(context.getCiphers());
            assertEquals(0, context.getCiphers().length);
        }
        
        @Test
        @DisplayName("Should decode at non-zero offset")
        void testDecodeWithOffset() throws SMBProtocolDecodingException {
            int offset = 50;
            SMBUtil.writeInt2(1, buffer, offset);
            SMBUtil.writeInt2(EncryptionNegotiateContext.CIPHER_AES128_GCM, buffer, offset + 2);
            
            EncryptionNegotiateContext context = new EncryptionNegotiateContext();
            int bytesRead = context.decode(buffer, offset, 4);
            
            assertEquals(4, bytesRead);
            assertNotNull(context.getCiphers());
            assertEquals(1, context.getCiphers().length);
            assertEquals(EncryptionNegotiateContext.CIPHER_AES128_GCM, context.getCiphers()[0]);
        }
        
        @ParameterizedTest
        @ValueSource(ints = {1, 3, 5, 10, 20})
        @DisplayName("Should decode various cipher counts correctly")
        void testDecodeVariousCipherCounts(int cipherCount) throws SMBProtocolDecodingException {
            SMBUtil.writeInt2(cipherCount, buffer, 0);
            for (int i = 0; i < cipherCount; i++) {
                SMBUtil.writeInt2(i + 1, buffer, 2 + (i * 2));
            }
            
            EncryptionNegotiateContext context = new EncryptionNegotiateContext();
            int bytesRead = context.decode(buffer, 0, 2 + (2 * cipherCount));
            
            assertEquals(2 + (2 * cipherCount), bytesRead);
            assertNotNull(context.getCiphers());
            assertEquals(cipherCount, context.getCiphers().length);
            for (int i = 0; i < cipherCount; i++) {
                assertEquals(i + 1, context.getCiphers()[i]);
            }
        }
    }
    
    @Nested
    @DisplayName("Size Calculation Tests")
    class SizeCalculationTests {
        
        @Test
        @DisplayName("Should calculate size for null ciphers")
        void testSizeWithNullCiphers() {
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, null);
            
            assertEquals(4, context.size());
        }
        
        @Test
        @DisplayName("Should calculate size for empty ciphers")
        void testSizeWithEmptyCiphers() {
            int[] ciphers = {};
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            assertEquals(4, context.size());
        }
        
        @Test
        @DisplayName("Should calculate size for single cipher")
        void testSizeWithSingleCipher() {
            int[] ciphers = {EncryptionNegotiateContext.CIPHER_AES128_CCM};
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            assertEquals(6, context.size());
        }
        
        @Test
        @DisplayName("Should calculate size for multiple ciphers")
        void testSizeWithMultipleCiphers() {
            int[] ciphers = {EncryptionNegotiateContext.CIPHER_AES128_CCM, EncryptionNegotiateContext.CIPHER_AES128_GCM};
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            assertEquals(8, context.size());
        }
        
        @ParameterizedTest
        @ValueSource(ints = {1, 2, 3, 5, 10, 20})
        @DisplayName("Should calculate size for various cipher counts")
        void testSizeWithVariousCipherCounts(int cipherCount) {
            int[] ciphers = new int[cipherCount];
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            assertEquals(4 + (2 * cipherCount), context.size());
        }
    }
    
    @Nested
    @DisplayName("Round-trip Tests")
    class RoundTripTests {
        
        @Test
        @DisplayName("Should encode and decode correctly with single cipher")
        void testRoundTripSingleCipher() throws SMBProtocolDecodingException {
            int[] originalCiphers = {EncryptionNegotiateContext.CIPHER_AES128_CCM};
            EncryptionNegotiateContext originalContext = new EncryptionNegotiateContext(mockConfig, originalCiphers);
            
            int encoded = originalContext.encode(buffer, 0);
            
            EncryptionNegotiateContext decodedContext = new EncryptionNegotiateContext();
            int decoded = decodedContext.decode(buffer, 0, encoded);
            
            assertEquals(encoded, decoded);
            assertArrayEquals(originalCiphers, decodedContext.getCiphers());
        }
        
        @Test
        @DisplayName("Should encode and decode correctly with multiple ciphers")
        void testRoundTripMultipleCiphers() throws SMBProtocolDecodingException {
            int[] originalCiphers = {
                EncryptionNegotiateContext.CIPHER_AES128_CCM,
                EncryptionNegotiateContext.CIPHER_AES128_GCM,
                0x3,
                0x4
            };
            EncryptionNegotiateContext originalContext = new EncryptionNegotiateContext(mockConfig, originalCiphers);
            
            int encoded = originalContext.encode(buffer, 0);
            
            EncryptionNegotiateContext decodedContext = new EncryptionNegotiateContext();
            int decoded = decodedContext.decode(buffer, 0, encoded);
            
            assertEquals(encoded, decoded);
            assertArrayEquals(originalCiphers, decodedContext.getCiphers());
        }
        
        @Test
        @DisplayName("Should encode and decode correctly with null ciphers")
        void testRoundTripNullCiphers() throws SMBProtocolDecodingException {
            EncryptionNegotiateContext originalContext = new EncryptionNegotiateContext(mockConfig, null);
            
            int encoded = originalContext.encode(buffer, 0);
            
            EncryptionNegotiateContext decodedContext = new EncryptionNegotiateContext();
            int decoded = decodedContext.decode(buffer, 0, encoded);
            
            assertEquals(encoded, decoded);
            assertNotNull(decodedContext.getCiphers());
            assertEquals(0, decodedContext.getCiphers().length);
        }
        
        @Test
        @DisplayName("Should encode and decode correctly with empty ciphers")
        void testRoundTripEmptyCiphers() throws SMBProtocolDecodingException {
            int[] originalCiphers = {};
            EncryptionNegotiateContext originalContext = new EncryptionNegotiateContext(mockConfig, originalCiphers);
            
            int encoded = originalContext.encode(buffer, 0);
            
            EncryptionNegotiateContext decodedContext = new EncryptionNegotiateContext();
            int decoded = decodedContext.decode(buffer, 0, encoded);
            
            assertEquals(encoded, decoded);
            assertArrayEquals(originalCiphers, decodedContext.getCiphers());
        }
        
        @Test
        @DisplayName("Should handle round-trip at non-zero offset")
        void testRoundTripWithOffset() throws SMBProtocolDecodingException {
            int offset = 100;
            int[] originalCiphers = {EncryptionNegotiateContext.CIPHER_AES128_GCM, EncryptionNegotiateContext.CIPHER_AES128_CCM};
            EncryptionNegotiateContext originalContext = new EncryptionNegotiateContext(mockConfig, originalCiphers);
            
            int encoded = originalContext.encode(buffer, offset);
            
            EncryptionNegotiateContext decodedContext = new EncryptionNegotiateContext();
            int decoded = decodedContext.decode(buffer, offset, encoded);
            
            assertEquals(encoded, decoded);
            assertArrayEquals(originalCiphers, decodedContext.getCiphers());
        }
    }
    
    @Nested
    @DisplayName("Constant Value Tests")
    class ConstantValueTests {
        
        @Test
        @DisplayName("Should have correct constant values")
        void testConstantValues() {
            assertEquals(0x2, EncryptionNegotiateContext.NEGO_CTX_ENC_TYPE);
            assertEquals(0x1, EncryptionNegotiateContext.CIPHER_AES128_CCM);
            assertEquals(0x2, EncryptionNegotiateContext.CIPHER_AES128_GCM);
        }
    }
    
    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {
        
        @Test
        @DisplayName("Should handle maximum supported ciphers")
        void testMaximumCiphers() throws SMBProtocolDecodingException {
            int maxCiphers = 100;
            int[] ciphers = new int[maxCiphers];
            for (int i = 0; i < maxCiphers; i++) {
                ciphers[i] = i;
            }
            
            EncryptionNegotiateContext originalContext = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            int encoded = originalContext.encode(buffer, 0);
            assertEquals(2 + (2 * maxCiphers), encoded);
            
            EncryptionNegotiateContext decodedContext = new EncryptionNegotiateContext();
            int decoded = decodedContext.decode(buffer, 0, encoded);
            
            assertEquals(encoded, decoded);
            assertArrayEquals(ciphers, decodedContext.getCiphers());
        }
        
        @Test
        @DisplayName("Should preserve cipher order")
        void testCipherOrderPreservation() throws SMBProtocolDecodingException {
            int[] ciphers = {5, 3, 1, 4, 2};
            EncryptionNegotiateContext originalContext = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            int encoded = originalContext.encode(buffer, 0);
            
            EncryptionNegotiateContext decodedContext = new EncryptionNegotiateContext();
            decodedContext.decode(buffer, 0, encoded);
            
            assertArrayEquals(ciphers, decodedContext.getCiphers());
        }
        
        @Test
        @DisplayName("Should handle duplicate ciphers")
        void testDuplicateCiphers() throws SMBProtocolDecodingException {
            int[] ciphers = {
                EncryptionNegotiateContext.CIPHER_AES128_CCM,
                EncryptionNegotiateContext.CIPHER_AES128_CCM,
                EncryptionNegotiateContext.CIPHER_AES128_GCM,
                EncryptionNegotiateContext.CIPHER_AES128_GCM
            };
            EncryptionNegotiateContext originalContext = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            int encoded = originalContext.encode(buffer, 0);
            
            EncryptionNegotiateContext decodedContext = new EncryptionNegotiateContext();
            decodedContext.decode(buffer, 0, encoded);
            
            assertArrayEquals(ciphers, decodedContext.getCiphers());
        }
        
        @Test
        @DisplayName("Should handle ciphers with maximum value")
        void testMaximumCipherValues() throws SMBProtocolDecodingException {
            int[] ciphers = {0xFFFF, 0x0000, 0x7FFF};
            EncryptionNegotiateContext originalContext = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            int encoded = originalContext.encode(buffer, 0);
            
            EncryptionNegotiateContext decodedContext = new EncryptionNegotiateContext();
            decodedContext.decode(buffer, 0, encoded);
            
            assertArrayEquals(ciphers, decodedContext.getCiphers());
        }
    }
    
    @Nested
    @DisplayName("Interface Implementation Tests")
    class InterfaceImplementationTests {
        
        @Test
        @DisplayName("Should implement NegotiateContextRequest interface")
        void testImplementsNegotiateContextRequest() {
            EncryptionNegotiateContext context = new EncryptionNegotiateContext();
            
            assertTrue(context instanceof NegotiateContextRequest);
        }
        
        @Test
        @DisplayName("Should implement NegotiateContextResponse interface")
        void testImplementsNegotiateContextResponse() {
            EncryptionNegotiateContext context = new EncryptionNegotiateContext();
            
            assertTrue(context instanceof NegotiateContextResponse);
        }
        
        @Test
        @DisplayName("Should be usable as both request and response")
        void testDualInterfaceUsage() {
            EncryptionNegotiateContext context = new EncryptionNegotiateContext();
            
            NegotiateContextRequest request = context;
            NegotiateContextResponse response = context;
            
            assertEquals(EncryptionNegotiateContext.NEGO_CTX_ENC_TYPE, request.getContextType());
            assertEquals(EncryptionNegotiateContext.NEGO_CTX_ENC_TYPE, response.getContextType());
        }
    }
}
