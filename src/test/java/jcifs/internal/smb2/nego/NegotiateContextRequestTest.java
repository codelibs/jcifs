package jcifs.internal.smb2.nego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;

/**
 * Test class for NegotiateContextRequest interface and its implementations
 */
@ExtendWith(MockitoExtension.class)
class NegotiateContextRequestTest {

    @Mock
    private Configuration mockConfig;
    
    private static final int BUFFER_SIZE = 1024;
    
    /**
     * Test custom implementation of NegotiateContextRequest for interface testing
     */
    static class TestNegotiateContextRequest implements NegotiateContextRequest {
        private final int contextType;
        
        TestNegotiateContextRequest(int contextType) {
            this.contextType = contextType;
        }
        
        @Override
        public int getContextType() {
            return contextType;
        }
        
        @Override
        public int encode(byte[] dst, int dstIndex) {
            return 0;
        }
        
        @Override
        public int size() {
            return 0;
        }
    }
    
    @Nested
    @DisplayName("Interface Tests")
    class InterfaceTests {
        
        @Test
        @DisplayName("Should implement getContextType correctly")
        void testGetContextType() {
            // Test with different context types
            TestNegotiateContextRequest request1 = new TestNegotiateContextRequest(0x1);
            TestNegotiateContextRequest request2 = new TestNegotiateContextRequest(0x2);
            TestNegotiateContextRequest request3 = new TestNegotiateContextRequest(Integer.MAX_VALUE);
            
            assertEquals(0x1, request1.getContextType());
            assertEquals(0x2, request2.getContextType());
            assertEquals(Integer.MAX_VALUE, request3.getContextType());
        }
        
        @Test
        @DisplayName("Should verify interface is Encodable")
        void testEncodableInterface() {
            NegotiateContextRequest request = new TestNegotiateContextRequest(1);
            
            // Verify the interface extends Encodable
            assertNotNull(request);
            assertTrue(request instanceof jcifs.Encodable);
        }
    }
    
    @Nested
    @DisplayName("PreauthIntegrityNegotiateContext Tests")
    class PreauthIntegrityNegotiateContextTests {
        
        private PreauthIntegrityNegotiateContext context;
        private byte[] buffer;
        
        @BeforeEach
        void setUp() {
            buffer = new byte[BUFFER_SIZE];
        }
        
        @Test
        @DisplayName("Should create context with constructor parameters")
        void testConstructorWithParameters() {
            int[] hashAlgos = {PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512};
            byte[] salt = new byte[32];
            new SecureRandom().nextBytes(salt);
            
            context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            assertEquals(PreauthIntegrityNegotiateContext.NEGO_CTX_PREAUTH_TYPE, context.getContextType());
            assertArrayEquals(hashAlgos, context.getHashAlgos());
            assertArrayEquals(salt, context.getSalt());
        }
        
        @Test
        @DisplayName("Should create context with default constructor")
        void testDefaultConstructor() {
            context = new PreauthIntegrityNegotiateContext();
            
            assertEquals(PreauthIntegrityNegotiateContext.NEGO_CTX_PREAUTH_TYPE, context.getContextType());
            assertNull(context.getHashAlgos());
            assertNull(context.getSalt());
        }
        
        @Test
        @DisplayName("Should handle null hash algorithms")
        void testNullHashAlgorithms() {
            context = new PreauthIntegrityNegotiateContext(mockConfig, null, new byte[16]);
            
            assertNull(context.getHashAlgos());
            assertEquals(20, context.size()); // 4 header + 16 salt
        }
        
        @Test
        @DisplayName("Should handle null salt")
        void testNullSalt() {
            int[] hashAlgos = {PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512};
            context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, null);
            
            assertNull(context.getSalt());
            assertEquals(6, context.size()); // 4 header + 2 for one hash algo
        }
        
        @Test
        @DisplayName("Should handle both null parameters")
        void testBothNullParameters() {
            context = new PreauthIntegrityNegotiateContext(mockConfig, null, null);
            
            assertNull(context.getHashAlgos());
            assertNull(context.getSalt());
            assertEquals(4, context.size()); // Only header
        }
        
        @ParameterizedTest
        @DisplayName("Should encode with different hash algorithm counts")
        @ValueSource(ints = {0, 1, 2, 5, 10})
        void testEncodeWithDifferentHashAlgoCounts(int count) {
            int[] hashAlgos = new int[count];
            for (int i = 0; i < count; i++) {
                hashAlgos[i] = i + 1;
            }
            byte[] salt = new byte[16];
            
            context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            int encoded = context.encode(buffer, 0);
            
            assertEquals(4 + (count * 2) + 16, encoded);
            assertEquals(context.size(), encoded);
        }
        
        @Test
        @DisplayName("Should encode and decode correctly")
        void testEncodeAndDecode() throws SMBProtocolDecodingException {
            int[] hashAlgos = {PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512, 2, 3};
            byte[] salt = new byte[32];
            new SecureRandom().nextBytes(salt);
            
            context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            int encodedSize = context.encode(buffer, 0);
            
            PreauthIntegrityNegotiateContext decoded = new PreauthIntegrityNegotiateContext();
            int decodedSize = decoded.decode(buffer, 0, encodedSize);
            
            assertEquals(encodedSize, decodedSize);
            assertArrayEquals(hashAlgos, decoded.getHashAlgos());
            assertArrayEquals(salt, decoded.getSalt());
        }
        
        @Test
        @DisplayName("Should handle empty arrays in encode/decode")
        void testEmptyArraysEncodeDecode() throws SMBProtocolDecodingException {
            context = new PreauthIntegrityNegotiateContext(mockConfig, new int[0], new byte[0]);
            int encodedSize = context.encode(buffer, 0);
            
            PreauthIntegrityNegotiateContext decoded = new PreauthIntegrityNegotiateContext();
            int decodedSize = decoded.decode(buffer, 0, encodedSize);
            
            assertEquals(encodedSize, decodedSize);
            assertEquals(0, decoded.getHashAlgos().length);
            assertEquals(0, decoded.getSalt().length);
        }
        
        @Test
        @DisplayName("Should calculate size correctly")
        void testSizeCalculation() {
            // Test with various combinations
            context = new PreauthIntegrityNegotiateContext(mockConfig, new int[3], new byte[32]);
            assertEquals(4 + 6 + 32, context.size()); // header + 3*2 + 32
            
            context = new PreauthIntegrityNegotiateContext(mockConfig, null, new byte[16]);
            assertEquals(4 + 16, context.size());
            
            context = new PreauthIntegrityNegotiateContext(mockConfig, new int[5], null);
            assertEquals(4 + 10, context.size());
        }
        
        @Test
        @DisplayName("Should encode at different buffer positions")
        void testEncodeAtDifferentPositions() {
            int[] hashAlgos = {1, 2};
            byte[] salt = new byte[8];
            Arrays.fill(salt, (byte) 0xFF);
            
            context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            // Encode at position 100
            int encoded = context.encode(buffer, 100);
            assertEquals(context.size(), encoded);
            
            // Verify salt is at correct position
            for (int i = 0; i < salt.length; i++) {
                assertEquals((byte) 0xFF, buffer[100 + 4 + 4 + i]);
            }
        }
    }
    
    @Nested
    @DisplayName("EncryptionNegotiateContext Tests")
    class EncryptionNegotiateContextTests {
        
        private EncryptionNegotiateContext context;
        private byte[] buffer;
        
        @BeforeEach
        void setUp() {
            buffer = new byte[BUFFER_SIZE];
        }
        
        @Test
        @DisplayName("Should create context with constructor parameters")
        void testConstructorWithParameters() {
            int[] ciphers = {
                EncryptionNegotiateContext.CIPHER_AES128_CCM,
                EncryptionNegotiateContext.CIPHER_AES128_GCM
            };
            
            context = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            assertEquals(EncryptionNegotiateContext.NEGO_CTX_ENC_TYPE, context.getContextType());
            assertArrayEquals(ciphers, context.getCiphers());
        }
        
        @Test
        @DisplayName("Should create context with default constructor")
        void testDefaultConstructor() {
            context = new EncryptionNegotiateContext();
            
            assertEquals(EncryptionNegotiateContext.NEGO_CTX_ENC_TYPE, context.getContextType());
            assertNull(context.getCiphers());
        }
        
        @Test
        @DisplayName("Should handle null ciphers")
        void testNullCiphers() {
            context = new EncryptionNegotiateContext(mockConfig, null);
            
            assertNull(context.getCiphers());
            assertEquals(4, context.size()); // Size returns 4 as base (implementation detail)
        }
        
        @ParameterizedTest
        @DisplayName("Should encode with different cipher counts")
        @ValueSource(ints = {0, 1, 2, 5, 10})
        void testEncodeWithDifferentCipherCounts(int count) {
            int[] ciphers = new int[count];
            for (int i = 0; i < count; i++) {
                ciphers[i] = i + 1;
            }
            
            context = new EncryptionNegotiateContext(mockConfig, ciphers);
            int encoded = context.encode(buffer, 0);
            
            assertEquals(2 + (count * 2), encoded);
            // Note: size() returns 4 + count*2, but encode returns 2 + count*2
            // This is an implementation inconsistency in the original code
            assertNotEquals(context.size(), encoded);
            assertEquals(4 + (count * 2), context.size());
        }
        
        @Test
        @DisplayName("Should encode and decode correctly")
        void testEncodeAndDecode() throws SMBProtocolDecodingException {
            int[] ciphers = {
                EncryptionNegotiateContext.CIPHER_AES128_CCM,
                EncryptionNegotiateContext.CIPHER_AES128_GCM,
                3, 4
            };
            
            context = new EncryptionNegotiateContext(mockConfig, ciphers);
            int encodedSize = context.encode(buffer, 0);
            
            EncryptionNegotiateContext decoded = new EncryptionNegotiateContext();
            int decodedSize = decoded.decode(buffer, 0, encodedSize);
            
            assertEquals(encodedSize, decodedSize);
            assertArrayEquals(ciphers, decoded.getCiphers());
        }
        
        @Test
        @DisplayName("Should handle empty cipher array")
        void testEmptyCipherArray() throws SMBProtocolDecodingException {
            context = new EncryptionNegotiateContext(mockConfig, new int[0]);
            int encodedSize = context.encode(buffer, 0);
            
            EncryptionNegotiateContext decoded = new EncryptionNegotiateContext();
            int decodedSize = decoded.decode(buffer, 0, encodedSize);
            
            assertEquals(encodedSize, decodedSize);
            assertEquals(0, decoded.getCiphers().length);
        }
        
        @Test
        @DisplayName("Should calculate size correctly")
        void testSizeCalculation() {
            // Note: The size() method in EncryptionNegotiateContext returns 4 as base,
            // while encode() only writes 2 bytes for the count field.
            // This appears to be an implementation inconsistency.
            context = new EncryptionNegotiateContext(mockConfig, new int[3]);
            assertEquals(4 + 6, context.size()); // 4 base + 3*2 for ciphers
            
            context = new EncryptionNegotiateContext(mockConfig, null);
            assertEquals(4, context.size()); // 4 base when null
            
            context = new EncryptionNegotiateContext(mockConfig, new int[0]);
            assertEquals(4, context.size()); // 4 base for empty array
        }
        
        @Test
        @DisplayName("Should encode at different buffer positions")
        void testEncodeAtDifferentPositions() {
            int[] ciphers = {0xABCD, 0xEFAB};
            
            context = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            // Encode at position 200
            int encoded = context.encode(buffer, 200);
            assertEquals(2 + 4, encoded); // count + 2 ciphers
            
            // Decode and verify
            EncryptionNegotiateContext decoded = new EncryptionNegotiateContext();
            try {
                decoded.decode(buffer, 200, encoded);
                assertArrayEquals(ciphers, decoded.getCiphers());
            } catch (SMBProtocolDecodingException e) {
                fail("Should not throw exception: " + e.getMessage());
            }
        }
        
        @Test
        @DisplayName("Should verify cipher constants")
        void testCipherConstants() {
            // Verify the cipher constants are correctly defined
            assertEquals(0x1, EncryptionNegotiateContext.CIPHER_AES128_CCM);
            assertEquals(0x2, EncryptionNegotiateContext.CIPHER_AES128_GCM);
            assertEquals(0x2, EncryptionNegotiateContext.NEGO_CTX_ENC_TYPE);
        }
    }
    
    @Nested
    @DisplayName("Cross-Implementation Tests")
    class CrossImplementationTests {
        
        @Test
        @DisplayName("Should have different context types for different implementations")
        void testDifferentContextTypes() {
            PreauthIntegrityNegotiateContext preauth = new PreauthIntegrityNegotiateContext();
            EncryptionNegotiateContext encryption = new EncryptionNegotiateContext();
            
            assertNotEquals(preauth.getContextType(), encryption.getContextType());
            assertEquals(0x1, preauth.getContextType());
            assertEquals(0x2, encryption.getContextType());
        }
        
        @Test
        @DisplayName("Should verify all implementations are NegotiateContextRequest")
        void testAllImplementationsAreNegotiateContextRequest() {
            NegotiateContextRequest preauth = new PreauthIntegrityNegotiateContext();
            NegotiateContextRequest encryption = new EncryptionNegotiateContext();
            
            assertNotNull(preauth);
            assertNotNull(encryption);
            assertTrue(preauth instanceof NegotiateContextRequest);
            assertTrue(encryption instanceof NegotiateContextRequest);
        }
        
        @Test
        @DisplayName("Should verify mock implementation")
        void testMockImplementation() {
            NegotiateContextRequest mockRequest = mock(NegotiateContextRequest.class);
            when(mockRequest.getContextType()).thenReturn(0xFF);
            
            assertEquals(0xFF, mockRequest.getContextType());
            verify(mockRequest).getContextType();
        }
    }
    
    @Nested
    @DisplayName("Edge Cases and Error Conditions")
    class EdgeCasesTests {
        
        @Test
        @DisplayName("Should handle maximum size arrays")
        void testMaximumSizeArrays() {
            // Test with reasonably large arrays
            int[] largeCiphers = new int[100];
            for (int i = 0; i < 100; i++) {
                largeCiphers[i] = i;
            }
            
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, largeCiphers);
            byte[] largeBuffer = new byte[1024];
            
            int encoded = context.encode(largeBuffer, 0);
            assertEquals(2 + 200, encoded); // 2 for count + 100*2 for ciphers
            
            EncryptionNegotiateContext decoded = new EncryptionNegotiateContext();
            try {
                int decodedSize = decoded.decode(largeBuffer, 0, encoded);
                assertEquals(encoded, decodedSize);
                assertArrayEquals(largeCiphers, decoded.getCiphers());
            } catch (SMBProtocolDecodingException e) {
                fail("Should handle large arrays: " + e.getMessage());
            }
        }
        
        @Test
        @DisplayName("Should handle buffer boundaries correctly")
        void testBufferBoundaries() {
            byte[] smallBuffer = new byte[10];
            int[] ciphers = {1, 2};
            
            EncryptionNegotiateContext context = new EncryptionNegotiateContext(mockConfig, ciphers);
            
            // Should encode successfully at the beginning
            int encoded = context.encode(smallBuffer, 0);
            assertEquals(6, encoded);
            
            // Should handle encoding at the end of buffer correctly
            assertDoesNotThrow(() -> context.encode(smallBuffer, 4));
        }
        
        @Test
        @DisplayName("Should preserve data integrity through encode/decode cycle")
        void testDataIntegrity() throws SMBProtocolDecodingException {
            // Create complex test data
            int[] hashAlgos = new int[20];
            byte[] salt = new byte[64];
            SecureRandom random = new SecureRandom();
            
            for (int i = 0; i < hashAlgos.length; i++) {
                hashAlgos[i] = random.nextInt(65536);
            }
            random.nextBytes(salt);
            
            PreauthIntegrityNegotiateContext original = 
                new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            // Encode
            byte[] buffer = new byte[1024];
            int encodedSize = original.encode(buffer, 0);
            
            // Decode
            PreauthIntegrityNegotiateContext decoded = new PreauthIntegrityNegotiateContext();
            int decodedSize = decoded.decode(buffer, 0, encodedSize);
            
            // Verify
            assertEquals(encodedSize, decodedSize);
            assertArrayEquals(hashAlgos, decoded.getHashAlgos());
            assertArrayEquals(salt, decoded.getSalt());
            assertEquals(original.getContextType(), decoded.getContextType());
            assertEquals(original.size(), decoded.size());
        }
    }
}
