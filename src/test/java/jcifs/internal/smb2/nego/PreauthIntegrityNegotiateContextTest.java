/*
 * © 2025 CodeLibs Project
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
package jcifs.internal.smb2.nego;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Arrays;
import java.util.Random;
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
 * Test class for PreauthIntegrityNegotiateContext
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("PreauthIntegrityNegotiateContext Tests")
class PreauthIntegrityNegotiateContextTest {

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
        @DisplayName("Should create instance with Configuration, hash algorithms and salt")
        void testConstructorWithConfigHashAlgosAndSalt() {
            int[] hashAlgos = {PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512};
            byte[] salt = {0x01, 0x02, 0x03, 0x04};
            
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            assertNotNull(context);
            assertArrayEquals(hashAlgos, context.getHashAlgos());
            assertArrayEquals(salt, context.getSalt());
        }
        
        @Test
        @DisplayName("Should create instance with null hash algorithms")
        void testConstructorWithNullHashAlgos() {
            byte[] salt = {0x01, 0x02, 0x03, 0x04};
            
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, null, salt);
            
            assertNotNull(context);
            assertNull(context.getHashAlgos());
            assertArrayEquals(salt, context.getSalt());
        }
        
        @Test
        @DisplayName("Should create instance with null salt")
        void testConstructorWithNullSalt() {
            int[] hashAlgos = {PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512};
            
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, null);
            
            assertNotNull(context);
            assertArrayEquals(hashAlgos, context.getHashAlgos());
            assertNull(context.getSalt());
        }
        
        @Test
        @DisplayName("Should create instance with both null parameters")
        void testConstructorWithNullParameters() {
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, null, null);
            
            assertNotNull(context);
            assertNull(context.getHashAlgos());
            assertNull(context.getSalt());
        }
        
        @Test
        @DisplayName("Should create instance with empty arrays")
        void testConstructorWithEmptyArrays() {
            int[] hashAlgos = {};
            byte[] salt = {};
            
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            assertNotNull(context);
            assertArrayEquals(hashAlgos, context.getHashAlgos());
            assertArrayEquals(salt, context.getSalt());
            assertEquals(0, context.getHashAlgos().length);
            assertEquals(0, context.getSalt().length);
        }
        
        @Test
        @DisplayName("Should create instance with default constructor")
        void testDefaultConstructor() {
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext();
            
            assertNotNull(context);
            assertNull(context.getHashAlgos());
            assertNull(context.getSalt());
        }
    }
    
    @Nested
    @DisplayName("Context Type Tests")
    class ContextTypeTests {
        
        @Test
        @DisplayName("Should return correct context type")
        void testGetContextType() {
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext();
            
            assertEquals(PreauthIntegrityNegotiateContext.NEGO_CTX_PREAUTH_TYPE, context.getContextType());
            assertEquals(0x1, context.getContextType());
        }
    }
    
    @Nested
    @DisplayName("Encoding Tests")
    class EncodingTests {
        
        @Test
        @DisplayName("Should encode single hash algorithm with salt")
        void testEncodeSingleHashAlgoWithSalt() {
            int[] hashAlgos = {PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512};
            byte[] salt = {0x01, 0x02, 0x03, 0x04};
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            int bytesWritten = context.encode(buffer, 0);
            
            assertEquals(10, bytesWritten);
            assertEquals(1, SMBUtil.readInt2(buffer, 0));
            assertEquals(4, SMBUtil.readInt2(buffer, 2));
            assertEquals(PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512, SMBUtil.readInt2(buffer, 4));
            assertArrayEquals(salt, Arrays.copyOfRange(buffer, 6, 10));
        }
        
        @Test
        @DisplayName("Should encode multiple hash algorithms with salt")
        void testEncodeMultipleHashAlgosWithSalt() {
            int[] hashAlgos = {0x01, 0x02, 0x03};
            byte[] salt = {0x0A, 0x0B};
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            int bytesWritten = context.encode(buffer, 0);
            
            assertEquals(12, bytesWritten);
            assertEquals(3, SMBUtil.readInt2(buffer, 0));
            assertEquals(2, SMBUtil.readInt2(buffer, 2));
            assertEquals(0x01, SMBUtil.readInt2(buffer, 4));
            assertEquals(0x02, SMBUtil.readInt2(buffer, 6));
            assertEquals(0x03, SMBUtil.readInt2(buffer, 8));
            assertArrayEquals(salt, Arrays.copyOfRange(buffer, 10, 12));
        }
        
        @Test
        @DisplayName("Should encode null hash algorithms and salt")
        void testEncodeNullHashAlgosAndSalt() {
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, null, null);
            
            int bytesWritten = context.encode(buffer, 0);
            
            assertEquals(4, bytesWritten);
            assertEquals(0, SMBUtil.readInt2(buffer, 0));
            assertEquals(0, SMBUtil.readInt2(buffer, 2));
        }
        
        @Test
        @DisplayName("Should encode empty arrays")
        void testEncodeEmptyArrays() {
            int[] hashAlgos = {};
            byte[] salt = {};
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            int bytesWritten = context.encode(buffer, 0);
            
            assertEquals(4, bytesWritten);
            assertEquals(0, SMBUtil.readInt2(buffer, 0));
            assertEquals(0, SMBUtil.readInt2(buffer, 2));
        }
        
        @Test
        @DisplayName("Should encode at non-zero offset")
        void testEncodeWithOffset() {
            int offset = 100;
            int[] hashAlgos = {PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512};
            byte[] salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            int bytesWritten = context.encode(buffer, offset);
            
            assertEquals(12, bytesWritten);
            assertEquals(1, SMBUtil.readInt2(buffer, offset));
            assertEquals(6, SMBUtil.readInt2(buffer, offset + 2));
            assertEquals(PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512, SMBUtil.readInt2(buffer, offset + 4));
            assertArrayEquals(salt, Arrays.copyOfRange(buffer, offset + 6, offset + 12));
        }
        
        @Test
        @DisplayName("Should encode hash algorithms only (no salt)")
        void testEncodeHashAlgosOnly() {
            int[] hashAlgos = {0x01, 0x02};
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, null);
            
            int bytesWritten = context.encode(buffer, 0);
            
            assertEquals(8, bytesWritten);
            assertEquals(2, SMBUtil.readInt2(buffer, 0));
            assertEquals(0, SMBUtil.readInt2(buffer, 2));
            assertEquals(0x01, SMBUtil.readInt2(buffer, 4));
            assertEquals(0x02, SMBUtil.readInt2(buffer, 6));
        }
        
        @Test
        @DisplayName("Should encode salt only (no hash algorithms)")
        void testEncodeSaltOnly() {
            byte[] salt = {0x0A, 0x0B, 0x0C};
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, null, salt);
            
            int bytesWritten = context.encode(buffer, 0);
            
            assertEquals(7, bytesWritten);
            assertEquals(0, SMBUtil.readInt2(buffer, 0));
            assertEquals(3, SMBUtil.readInt2(buffer, 2));
            assertArrayEquals(salt, Arrays.copyOfRange(buffer, 4, 7));
        }
        
        @ParameterizedTest
        @ValueSource(ints = {1, 3, 5, 10, 20})
        @DisplayName("Should encode various hash algorithm counts correctly")
        void testEncodeVariousHashAlgoCounts(int algoCount) {
            int[] hashAlgos = new int[algoCount];
            for (int i = 0; i < algoCount; i++) {
                hashAlgos[i] = i + 1;
            }
            byte[] salt = {0x01, 0x02};
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            int bytesWritten = context.encode(buffer, 0);
            
            assertEquals(4 + (2 * algoCount) + 2, bytesWritten);
            assertEquals(algoCount, SMBUtil.readInt2(buffer, 0));
            assertEquals(2, SMBUtil.readInt2(buffer, 2));
            for (int i = 0; i < algoCount; i++) {
                assertEquals(i + 1, SMBUtil.readInt2(buffer, 4 + (i * 2)));
            }
            assertArrayEquals(salt, Arrays.copyOfRange(buffer, 4 + (2 * algoCount), 4 + (2 * algoCount) + 2));
        }
    }
    
    @Nested
    @DisplayName("Decoding Tests")
    class DecodingTests {
        
        @Test
        @DisplayName("Should decode single hash algorithm with salt")
        void testDecodeSingleHashAlgoWithSalt() throws SMBProtocolDecodingException {
            SMBUtil.writeInt2(1, buffer, 0);
            SMBUtil.writeInt2(4, buffer, 2);
            SMBUtil.writeInt2(PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512, buffer, 4);
            byte[] salt = {0x01, 0x02, 0x03, 0x04};
            System.arraycopy(salt, 0, buffer, 6, 4);
            
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext();
            int bytesRead = context.decode(buffer, 0, 10);
            
            assertEquals(10, bytesRead);
            assertNotNull(context.getHashAlgos());
            assertEquals(1, context.getHashAlgos().length);
            assertEquals(PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512, context.getHashAlgos()[0]);
            assertArrayEquals(salt, context.getSalt());
        }
        
        @Test
        @DisplayName("Should decode multiple hash algorithms with salt")
        void testDecodeMultipleHashAlgosWithSalt() throws SMBProtocolDecodingException {
            SMBUtil.writeInt2(3, buffer, 0);
            SMBUtil.writeInt2(2, buffer, 2);
            SMBUtil.writeInt2(0x01, buffer, 4);
            SMBUtil.writeInt2(0x02, buffer, 6);
            SMBUtil.writeInt2(0x03, buffer, 8);
            byte[] salt = {0x0A, 0x0B};
            System.arraycopy(salt, 0, buffer, 10, 2);
            
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext();
            int bytesRead = context.decode(buffer, 0, 12);
            
            assertEquals(12, bytesRead);
            assertNotNull(context.getHashAlgos());
            assertEquals(3, context.getHashAlgos().length);
            assertEquals(0x01, context.getHashAlgos()[0]);
            assertEquals(0x02, context.getHashAlgos()[1]);
            assertEquals(0x03, context.getHashAlgos()[2]);
            assertArrayEquals(salt, context.getSalt());
        }
        
        @Test
        @DisplayName("Should decode zero hash algorithms and zero salt")
        void testDecodeZeroHashAlgosAndSalt() throws SMBProtocolDecodingException {
            SMBUtil.writeInt2(0, buffer, 0);
            SMBUtil.writeInt2(0, buffer, 2);
            
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext();
            int bytesRead = context.decode(buffer, 0, 4);
            
            assertEquals(4, bytesRead);
            assertNotNull(context.getHashAlgos());
            assertEquals(0, context.getHashAlgos().length);
            assertNotNull(context.getSalt());
            assertEquals(0, context.getSalt().length);
        }
        
        @Test
        @DisplayName("Should decode at non-zero offset")
        void testDecodeWithOffset() throws SMBProtocolDecodingException {
            int offset = 50;
            SMBUtil.writeInt2(1, buffer, offset);
            SMBUtil.writeInt2(6, buffer, offset + 2);
            SMBUtil.writeInt2(PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512, buffer, offset + 4);
            byte[] salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
            System.arraycopy(salt, 0, buffer, offset + 6, 6);
            
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext();
            int bytesRead = context.decode(buffer, offset, 12);
            
            assertEquals(12, bytesRead);
            assertNotNull(context.getHashAlgos());
            assertEquals(1, context.getHashAlgos().length);
            assertEquals(PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512, context.getHashAlgos()[0]);
            assertArrayEquals(salt, context.getSalt());
        }
        
        @Test
        @DisplayName("Should decode hash algorithms only (no salt)")
        void testDecodeHashAlgosOnly() throws SMBProtocolDecodingException {
            SMBUtil.writeInt2(2, buffer, 0);
            SMBUtil.writeInt2(0, buffer, 2);
            SMBUtil.writeInt2(0x01, buffer, 4);
            SMBUtil.writeInt2(0x02, buffer, 6);
            
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext();
            int bytesRead = context.decode(buffer, 0, 8);
            
            assertEquals(8, bytesRead);
            assertNotNull(context.getHashAlgos());
            assertEquals(2, context.getHashAlgos().length);
            assertEquals(0x01, context.getHashAlgos()[0]);
            assertEquals(0x02, context.getHashAlgos()[1]);
            assertNotNull(context.getSalt());
            assertEquals(0, context.getSalt().length);
        }
        
        @Test
        @DisplayName("Should decode salt only (no hash algorithms)")
        void testDecodeSaltOnly() throws SMBProtocolDecodingException {
            SMBUtil.writeInt2(0, buffer, 0);
            SMBUtil.writeInt2(3, buffer, 2);
            byte[] salt = {0x0A, 0x0B, 0x0C};
            System.arraycopy(salt, 0, buffer, 4, 3);
            
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext();
            int bytesRead = context.decode(buffer, 0, 7);
            
            assertEquals(7, bytesRead);
            assertNotNull(context.getHashAlgos());
            assertEquals(0, context.getHashAlgos().length);
            assertArrayEquals(salt, context.getSalt());
        }
        
        @ParameterizedTest
        @ValueSource(ints = {1, 3, 5, 10, 20})
        @DisplayName("Should decode various hash algorithm counts correctly")
        void testDecodeVariousHashAlgoCounts(int algoCount) throws SMBProtocolDecodingException {
            SMBUtil.writeInt2(algoCount, buffer, 0);
            SMBUtil.writeInt2(2, buffer, 2);
            for (int i = 0; i < algoCount; i++) {
                SMBUtil.writeInt2(i + 1, buffer, 4 + (i * 2));
            }
            byte[] salt = {0x01, 0x02};
            System.arraycopy(salt, 0, buffer, 4 + (algoCount * 2), 2);
            
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext();
            int bytesRead = context.decode(buffer, 0, 4 + (2 * algoCount) + 2);
            
            assertEquals(4 + (2 * algoCount) + 2, bytesRead);
            assertNotNull(context.getHashAlgos());
            assertEquals(algoCount, context.getHashAlgos().length);
            for (int i = 0; i < algoCount; i++) {
                assertEquals(i + 1, context.getHashAlgos()[i]);
            }
            assertArrayEquals(salt, context.getSalt());
        }
    }
    
    @Nested
    @DisplayName("Size Calculation Tests")
    class SizeCalculationTests {
        
        @Test
        @DisplayName("Should calculate size for null hash algorithms and salt")
        void testSizeWithNullHashAlgosAndSalt() {
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, null, null);
            
            assertEquals(4, context.size());
        }
        
        @Test
        @DisplayName("Should calculate size for empty arrays")
        void testSizeWithEmptyArrays() {
            int[] hashAlgos = {};
            byte[] salt = {};
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            assertEquals(4, context.size());
        }
        
        @Test
        @DisplayName("Should calculate size for single hash algorithm with salt")
        void testSizeWithSingleHashAlgoAndSalt() {
            int[] hashAlgos = {PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512};
            byte[] salt = {0x01, 0x02, 0x03, 0x04};
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            assertEquals(10, context.size());
        }
        
        @Test
        @DisplayName("Should calculate size for multiple hash algorithms with salt")
        void testSizeWithMultipleHashAlgosAndSalt() {
            int[] hashAlgos = {0x01, 0x02, 0x03};
            byte[] salt = {0x01, 0x02, 0x03, 0x04, 0x05};
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            assertEquals(15, context.size());
        }
        
        @Test
        @DisplayName("Should calculate size for hash algorithms only")
        void testSizeWithHashAlgosOnly() {
            int[] hashAlgos = {0x01, 0x02};
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, null);
            
            assertEquals(8, context.size());
        }
        
        @Test
        @DisplayName("Should calculate size for salt only")
        void testSizeWithSaltOnly() {
            byte[] salt = {0x01, 0x02, 0x03};
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, null, salt);
            
            assertEquals(7, context.size());
        }
        
        @ParameterizedTest
        @MethodSource("provideSizeTestCases")
        @DisplayName("Should calculate size for various combinations")
        void testSizeWithVariousCombinations(int algoCount, int saltSize, int expectedSize) {
            int[] hashAlgos = algoCount > 0 ? new int[algoCount] : null;
            byte[] salt = saltSize > 0 ? new byte[saltSize] : null;
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            assertEquals(expectedSize, context.size());
        }
        
        static Stream<Arguments> provideSizeTestCases() {
            return Stream.of(
                Arguments.of(0, 0, 4),
                Arguments.of(1, 0, 6),
                Arguments.of(0, 1, 5),
                Arguments.of(1, 1, 7),
                Arguments.of(5, 10, 24),
                Arguments.of(10, 20, 44),
                Arguments.of(20, 32, 76)
            );
        }
    }
    
    @Nested
    @DisplayName("Round-trip Tests")
    class RoundTripTests {
        
        @Test
        @DisplayName("Should encode and decode correctly with single hash algorithm and salt")
        void testRoundTripSingleHashAlgoAndSalt() throws SMBProtocolDecodingException {
            int[] originalHashAlgos = {PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512};
            byte[] originalSalt = {0x01, 0x02, 0x03, 0x04};
            PreauthIntegrityNegotiateContext originalContext = 
                new PreauthIntegrityNegotiateContext(mockConfig, originalHashAlgos, originalSalt);
            
            int encoded = originalContext.encode(buffer, 0);
            
            PreauthIntegrityNegotiateContext decodedContext = new PreauthIntegrityNegotiateContext();
            int decoded = decodedContext.decode(buffer, 0, encoded);
            
            assertEquals(encoded, decoded);
            assertArrayEquals(originalHashAlgos, decodedContext.getHashAlgos());
            assertArrayEquals(originalSalt, decodedContext.getSalt());
        }
        
        @Test
        @DisplayName("Should encode and decode correctly with multiple hash algorithms and large salt")
        void testRoundTripMultipleHashAlgosAndLargeSalt() throws SMBProtocolDecodingException {
            int[] originalHashAlgos = {0x01, 0x02, 0x03, 0x04, 0x05};
            byte[] originalSalt = new byte[32];
            new Random(42).nextBytes(originalSalt);
            PreauthIntegrityNegotiateContext originalContext = 
                new PreauthIntegrityNegotiateContext(mockConfig, originalHashAlgos, originalSalt);
            
            int encoded = originalContext.encode(buffer, 0);
            
            PreauthIntegrityNegotiateContext decodedContext = new PreauthIntegrityNegotiateContext();
            int decoded = decodedContext.decode(buffer, 0, encoded);
            
            assertEquals(encoded, decoded);
            assertArrayEquals(originalHashAlgos, decodedContext.getHashAlgos());
            assertArrayEquals(originalSalt, decodedContext.getSalt());
        }
        
        @Test
        @DisplayName("Should encode and decode correctly with null parameters")
        void testRoundTripNullParameters() throws SMBProtocolDecodingException {
            PreauthIntegrityNegotiateContext originalContext = 
                new PreauthIntegrityNegotiateContext(mockConfig, null, null);
            
            int encoded = originalContext.encode(buffer, 0);
            
            PreauthIntegrityNegotiateContext decodedContext = new PreauthIntegrityNegotiateContext();
            int decoded = decodedContext.decode(buffer, 0, encoded);
            
            assertEquals(encoded, decoded);
            assertNotNull(decodedContext.getHashAlgos());
            assertEquals(0, decodedContext.getHashAlgos().length);
            assertNotNull(decodedContext.getSalt());
            assertEquals(0, decodedContext.getSalt().length);
        }
        
        @Test
        @DisplayName("Should encode and decode correctly with empty arrays")
        void testRoundTripEmptyArrays() throws SMBProtocolDecodingException {
            int[] originalHashAlgos = {};
            byte[] originalSalt = {};
            PreauthIntegrityNegotiateContext originalContext = 
                new PreauthIntegrityNegotiateContext(mockConfig, originalHashAlgos, originalSalt);
            
            int encoded = originalContext.encode(buffer, 0);
            
            PreauthIntegrityNegotiateContext decodedContext = new PreauthIntegrityNegotiateContext();
            int decoded = decodedContext.decode(buffer, 0, encoded);
            
            assertEquals(encoded, decoded);
            assertArrayEquals(originalHashAlgos, decodedContext.getHashAlgos());
            assertArrayEquals(originalSalt, decodedContext.getSalt());
        }
        
        @Test
        @DisplayName("Should handle round-trip at non-zero offset")
        void testRoundTripWithOffset() throws SMBProtocolDecodingException {
            int offset = 100;
            int[] originalHashAlgos = {0x01, 0x02};
            byte[] originalSalt = {0x0A, 0x0B, 0x0C};
            PreauthIntegrityNegotiateContext originalContext = 
                new PreauthIntegrityNegotiateContext(mockConfig, originalHashAlgos, originalSalt);
            
            int encoded = originalContext.encode(buffer, offset);
            
            PreauthIntegrityNegotiateContext decodedContext = new PreauthIntegrityNegotiateContext();
            int decoded = decodedContext.decode(buffer, offset, encoded);
            
            assertEquals(encoded, decoded);
            assertArrayEquals(originalHashAlgos, decodedContext.getHashAlgos());
            assertArrayEquals(originalSalt, decodedContext.getSalt());
        }
        
        @Test
        @DisplayName("Should handle round-trip with hash algorithms only")
        void testRoundTripHashAlgosOnly() throws SMBProtocolDecodingException {
            int[] originalHashAlgos = {0x01, 0x02, 0x03};
            PreauthIntegrityNegotiateContext originalContext = 
                new PreauthIntegrityNegotiateContext(mockConfig, originalHashAlgos, null);
            
            int encoded = originalContext.encode(buffer, 0);
            
            PreauthIntegrityNegotiateContext decodedContext = new PreauthIntegrityNegotiateContext();
            int decoded = decodedContext.decode(buffer, 0, encoded);
            
            assertEquals(encoded, decoded);
            assertArrayEquals(originalHashAlgos, decodedContext.getHashAlgos());
            assertNotNull(decodedContext.getSalt());
            assertEquals(0, decodedContext.getSalt().length);
        }
        
        @Test
        @DisplayName("Should handle round-trip with salt only")
        void testRoundTripSaltOnly() throws SMBProtocolDecodingException {
            byte[] originalSalt = {0x0A, 0x0B, 0x0C, 0x0D};
            PreauthIntegrityNegotiateContext originalContext = 
                new PreauthIntegrityNegotiateContext(mockConfig, null, originalSalt);
            
            int encoded = originalContext.encode(buffer, 0);
            
            PreauthIntegrityNegotiateContext decodedContext = new PreauthIntegrityNegotiateContext();
            int decoded = decodedContext.decode(buffer, 0, encoded);
            
            assertEquals(encoded, decoded);
            assertNotNull(decodedContext.getHashAlgos());
            assertEquals(0, decodedContext.getHashAlgos().length);
            assertArrayEquals(originalSalt, decodedContext.getSalt());
        }
    }
    
    @Nested
    @DisplayName("Constant Value Tests")
    class ConstantValueTests {
        
        @Test
        @DisplayName("Should have correct constant values")
        void testConstantValues() {
            assertEquals(0x1, PreauthIntegrityNegotiateContext.NEGO_CTX_PREAUTH_TYPE);
            assertEquals(0x1, PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512);
        }
    }
    
    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {
        
        @Test
        @DisplayName("Should handle maximum supported hash algorithms and salt")
        void testMaximumHashAlgosAndSalt() throws SMBProtocolDecodingException {
            int maxAlgos = 100;
            int[] hashAlgos = new int[maxAlgos];
            for (int i = 0; i < maxAlgos; i++) {
                hashAlgos[i] = i;
            }
            byte[] salt = new byte[256];
            new Random(123).nextBytes(salt);
            
            PreauthIntegrityNegotiateContext originalContext = 
                new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            byte[] largeBuffer = new byte[4096];
            int encoded = originalContext.encode(largeBuffer, 0);
            assertEquals(4 + (2 * maxAlgos) + salt.length, encoded);
            
            PreauthIntegrityNegotiateContext decodedContext = new PreauthIntegrityNegotiateContext();
            int decoded = decodedContext.decode(largeBuffer, 0, encoded);
            
            assertEquals(encoded, decoded);
            assertArrayEquals(hashAlgos, decodedContext.getHashAlgos());
            assertArrayEquals(salt, decodedContext.getSalt());
        }
        
        @Test
        @DisplayName("Should preserve hash algorithm order")
        void testHashAlgoOrderPreservation() throws SMBProtocolDecodingException {
            int[] hashAlgos = {5, 3, 1, 4, 2};
            byte[] salt = {0x01};
            PreauthIntegrityNegotiateContext originalContext = 
                new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            int encoded = originalContext.encode(buffer, 0);
            
            PreauthIntegrityNegotiateContext decodedContext = new PreauthIntegrityNegotiateContext();
            decodedContext.decode(buffer, 0, encoded);
            
            assertArrayEquals(hashAlgos, decodedContext.getHashAlgos());
            assertArrayEquals(salt, decodedContext.getSalt());
        }
        
        @Test
        @DisplayName("Should handle duplicate hash algorithms")
        void testDuplicateHashAlgos() throws SMBProtocolDecodingException {
            int[] hashAlgos = {
                PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512,
                PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512,
                0x02,
                0x02
            };
            byte[] salt = {0x01, 0x02};
            PreauthIntegrityNegotiateContext originalContext = 
                new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            int encoded = originalContext.encode(buffer, 0);
            
            PreauthIntegrityNegotiateContext decodedContext = new PreauthIntegrityNegotiateContext();
            decodedContext.decode(buffer, 0, encoded);
            
            assertArrayEquals(hashAlgos, decodedContext.getHashAlgos());
            assertArrayEquals(salt, decodedContext.getSalt());
        }
        
        @Test
        @DisplayName("Should handle hash algorithms with maximum value")
        void testMaximumHashAlgoValues() throws SMBProtocolDecodingException {
            int[] hashAlgos = {0xFFFF, 0x0000, 0x7FFF};
            byte[] salt = {(byte)0xFF, 0x00, 0x7F};
            PreauthIntegrityNegotiateContext originalContext = 
                new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            int encoded = originalContext.encode(buffer, 0);
            
            PreauthIntegrityNegotiateContext decodedContext = new PreauthIntegrityNegotiateContext();
            decodedContext.decode(buffer, 0, encoded);
            
            assertArrayEquals(hashAlgos, decodedContext.getHashAlgos());
            assertArrayEquals(salt, decodedContext.getSalt());
        }
        
        @Test
        @DisplayName("Should handle salt with all byte values")
        void testSaltWithAllByteValues() throws SMBProtocolDecodingException {
            int[] hashAlgos = {PreauthIntegrityNegotiateContext.HASH_ALGO_SHA512};
            byte[] salt = new byte[256];
            for (int i = 0; i < 256; i++) {
                salt[i] = (byte)i;
            }
            
            PreauthIntegrityNegotiateContext originalContext = 
                new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            byte[] largeBuffer = new byte[1024];
            int encoded = originalContext.encode(largeBuffer, 0);
            
            PreauthIntegrityNegotiateContext decodedContext = new PreauthIntegrityNegotiateContext();
            decodedContext.decode(largeBuffer, 0, encoded);
            
            assertArrayEquals(hashAlgos, decodedContext.getHashAlgos());
            assertArrayEquals(salt, decodedContext.getSalt());
        }
    }
    
    @Nested
    @DisplayName("Interface Implementation Tests")
    class InterfaceImplementationTests {
        
        @Test
        @DisplayName("Should implement NegotiateContextRequest interface")
        void testImplementsNegotiateContextRequest() {
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext();
            
            assertTrue(context instanceof NegotiateContextRequest);
        }
        
        @Test
        @DisplayName("Should implement NegotiateContextResponse interface")
        void testImplementsNegotiateContextResponse() {
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext();
            
            assertTrue(context instanceof NegotiateContextResponse);
        }
        
        @Test
        @DisplayName("Should be usable as both request and response")
        void testDualInterfaceUsage() {
            PreauthIntegrityNegotiateContext context = new PreauthIntegrityNegotiateContext();
            
            NegotiateContextRequest request = context;
            NegotiateContextResponse response = context;
            
            assertEquals(PreauthIntegrityNegotiateContext.NEGO_CTX_PREAUTH_TYPE, request.getContextType());
            assertEquals(PreauthIntegrityNegotiateContext.NEGO_CTX_PREAUTH_TYPE, response.getContextType());
        }
    }
    
    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {
        
        @Test
        @DisplayName("Should return hash algorithms correctly")
        void testGetHashAlgos() {
            int[] hashAlgos = {0x01, 0x02, 0x03};
            byte[] salt = {0x01};
            PreauthIntegrityNegotiateContext context = 
                new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            assertArrayEquals(hashAlgos, context.getHashAlgos());
            // The implementation returns the same reference, not a defensive copy
            assertSame(hashAlgos, context.getHashAlgos());
        }
        
        @Test
        @DisplayName("Should return salt correctly")
        void testGetSalt() {
            int[] hashAlgos = {0x01};
            byte[] salt = {0x01, 0x02, 0x03, 0x04};
            PreauthIntegrityNegotiateContext context = 
                new PreauthIntegrityNegotiateContext(mockConfig, hashAlgos, salt);
            
            assertArrayEquals(salt, context.getSalt());
            // The implementation returns the same reference, not a defensive copy
            assertSame(salt, context.getSalt());
        }
        
        @Test
        @DisplayName("Should return null when hash algorithms is null")
        void testGetHashAlgosNull() {
            PreauthIntegrityNegotiateContext context = 
                new PreauthIntegrityNegotiateContext(mockConfig, null, new byte[]{0x01});
            
            assertNull(context.getHashAlgos());
        }
        
        @Test
        @DisplayName("Should return null when salt is null")
        void testGetSaltNull() {
            PreauthIntegrityNegotiateContext context = 
                new PreauthIntegrityNegotiateContext(mockConfig, new int[]{0x01}, null);
            
            assertNull(context.getSalt());
        }
    }
}