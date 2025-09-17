package org.codelibs.jcifs.smb.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class HMACT64Test {

    private static final byte[] TEST_KEY = "testkey".getBytes();
    private static final byte[] LONG_TEST_KEY = "thisisalongtestkeythatislongerthan64bytesandshouldbetruncated".getBytes();
    private static final byte[] SHORT_TEST_KEY = "short".getBytes();
    private static final byte[] TEST_DATA = "testdata".getBytes();
    private static final byte[] EMPTY_DATA = new byte[0];

    @Mock
    private MessageDigest mockMd5;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        // Mock Crypto.getMD5() to return our mockMd5 instance
        // This requires Mockito 3.4.0+ for MockedStatic
        // For simplicity, we'll assume Crypto.getMD5() is static and mock it.
        // If it's not static, we'd need to inject it or mock the class that provides it.
        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(mockMd5);
        }
    }

    @Test
    void testConstructorWithNormalKey() throws NoSuchAlgorithmException {
        // Test constructor with a normal length key
        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(mockMd5);
            HMACT64 hmac = new HMACT64(TEST_KEY);
            assertNotNull(hmac);
            verify(mockMd5, times(1)).reset();
            verify(mockMd5, times(1)).update(any(byte[].class)); // Should update with ipad
        }
    }

    @Test
    void testConstructorWithLongKey() throws NoSuchAlgorithmException {
        // Test constructor with a key longer than BLOCK_LENGTH (64 bytes)
        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(mockMd5);
            HMACT64 hmac = new HMACT64(LONG_TEST_KEY);
            assertNotNull(hmac);
            verify(mockMd5, times(1)).reset();
            verify(mockMd5, times(1)).update(any(byte[].class)); // Should update with ipad
        }
    }

    @Test
    void testConstructorWithShortKey() throws NoSuchAlgorithmException {
        // Test constructor with a key shorter than BLOCK_LENGTH (64 bytes)
        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(mockMd5);
            HMACT64 hmac = new HMACT64(SHORT_TEST_KEY);
            assertNotNull(hmac);
            verify(mockMd5, times(1)).reset();
            verify(mockMd5, times(1)).update(any(byte[].class)); // Should update with ipad
        }
    }

    @Test
    void testEngineUpdateByte() throws NoSuchAlgorithmException {
        // Test engineUpdate(byte b)
        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(mockMd5);
            HMACT64 hmac = new HMACT64(TEST_KEY);
            hmac.engineUpdate((byte) 0x01);
            verify(mockMd5, times(1)).update((byte) 0x01);
        }
    }

    @Test
    void testEngineUpdateByteArray() throws NoSuchAlgorithmException {
        // Test engineUpdate(byte[] input, int offset, int len)
        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(mockMd5);
            HMACT64 hmac = new HMACT64(TEST_KEY);
            hmac.engineUpdate(TEST_DATA, 0, TEST_DATA.length);
            verify(mockMd5, times(1)).update(TEST_DATA, 0, TEST_DATA.length);
        }
    }

    @Test
    void testEngineReset() throws NoSuchAlgorithmException {
        // Test engineReset()
        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(mockMd5);
            HMACT64 hmac = new HMACT64(TEST_KEY);
            hmac.engineReset();
            verify(mockMd5, times(2)).reset(); // Once in constructor, once in reset
            verify(mockMd5, times(2)).update(any(byte[].class)); // Once in constructor, once in reset
        }
    }

    @Test
    void testEngineGetDigestLength() throws NoSuchAlgorithmException {
        // Test engineGetDigestLength()
        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(mockMd5);
            when(mockMd5.getDigestLength()).thenReturn(16); // MD5 digest length is 16
            HMACT64 hmac = new HMACT64(TEST_KEY);
            assertEquals(16, hmac.engineGetDigestLength());
            verify(mockMd5, times(1)).getDigestLength();
        }
    }

    @Test
    void testEngineDigest() throws NoSuchAlgorithmException {
        // Test engineDigest()
        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(mockMd5);
            byte[] innerDigest = "inner_digest".getBytes();
            byte[] finalDigest = "final_digest".getBytes();

            when(mockMd5.digest()).thenReturn(innerDigest);
            when(mockMd5.digest(any(byte[].class))).thenReturn(finalDigest);

            HMACT64 hmac = new HMACT64(TEST_KEY);
            byte[] result = hmac.engineDigest();

            assertArrayEquals(finalDigest, result);
            verify(mockMd5, times(1)).digest(); // First call for inner digest
            verify(mockMd5, times(2)).update(any(byte[].class)); // Once in constructor with ipad, once in engineDigest with opad
            verify(mockMd5, times(1)).digest(innerDigest); // Second call for final digest
        }
    }

    @Test
    void testEngineDigestWithBuffer() throws NoSuchAlgorithmException, DigestException {
        // Test engineDigest(byte[] buf, int offset, int len)
        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(mockMd5);
            byte[] innerDigest = "inner_digest".getBytes();
            byte[] expectedOutput = "output_data".getBytes();
            byte[] buffer = new byte[expectedOutput.length + 10]; // Buffer with extra space

            when(mockMd5.digest()).thenReturn(innerDigest);
            when(mockMd5.digest(buffer, 0, expectedOutput.length)).thenAnswer(invocation -> {
                byte[] b = invocation.getArgument(0);
                int off = invocation.getArgument(1);
                int l = invocation.getArgument(2);
                System.arraycopy(expectedOutput, 0, b, off, l);
                return l;
            });

            HMACT64 hmac = new HMACT64(TEST_KEY);
            int bytesWritten = hmac.engineDigest(buffer, 0, expectedOutput.length);

            assertEquals(expectedOutput.length, bytesWritten);
            assertArrayEquals(expectedOutput, Arrays.copyOfRange(buffer, 0, expectedOutput.length));

            verify(mockMd5, times(1)).digest(); // First call for inner digest
            verify(mockMd5, times(3)).update(any(byte[].class)); // Once in constructor with ipad, once with opad, once with innerDigest
            verify(mockMd5, times(1)).digest(buffer, 0, expectedOutput.length); // Final digest into buffer
        }
    }

    @Test
    void testEngineDigestWithBufferException() throws NoSuchAlgorithmException, DigestException {
        // Test engineDigest(byte[] buf, int offset, int len) throws exception
        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(mockMd5);
            byte[] innerDigest = "inner_digest".getBytes();

            when(mockMd5.digest()).thenReturn(innerDigest);
            doThrow(new RuntimeException("Test Exception")).when(mockMd5).digest(any(byte[].class), anyInt(), anyInt());

            HMACT64 hmac = new HMACT64(TEST_KEY);
            assertThrows(IllegalStateException.class, () -> hmac.engineDigest(new byte[10], 0, 10));
        }
    }

    @Test
    void testClone() throws NoSuchAlgorithmException, CloneNotSupportedException {
        // Test clone() method
        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(mockMd5);
            HMACT64 originalHmac = new HMACT64(TEST_KEY);

            // Mock the clone behavior of the internal MessageDigest
            MessageDigest clonedMd5 = mock(MessageDigest.class);
            when(mockMd5.clone()).thenReturn(clonedMd5);

            HMACT64 clonedHmac = (HMACT64) originalHmac.clone();

            assertNotNull(clonedHmac);
            assertNotSame(originalHmac, clonedHmac);
            verify(mockMd5, times(1)).clone(); // Verify that the internal MD5 was cloned
        }
    }

    @Test
    void testCloneNotSupportedException() throws NoSuchAlgorithmException, CloneNotSupportedException {
        // Test clone() when internal MessageDigest throws CloneNotSupportedException
        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(mockMd5);
            HMACT64 originalHmac = new HMACT64(TEST_KEY);

            when(mockMd5.clone()).thenThrow(new CloneNotSupportedException("Test Clone Not Supported"));

            assertThrows(IllegalStateException.class, originalHmac::clone);
        }
    }

    // Integration test with actual MD5 to verify HMAC calculation logic
    @Test
    void testHMACT64WithActualMD5() throws NoSuchAlgorithmException {
        // This test uses a real MD5 instance to verify the HMAC calculation logic
        // HMACT64 is a modified HMAC-MD5 where the key is truncated at 64 bytes
        // instead of being hashed when it exceeds the block size.

        byte[] key = { (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b,
                (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b };
        byte[] data = "Hi There".getBytes();

        // Calculate expected HMACT64 result manually
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] ipad = new byte[64];
        byte[] opad = new byte[64];

        // HMACT64 specific: truncate key to 64 bytes if needed
        int keyLen = Math.min(key.length, 64);
        for (int i = 0; i < keyLen; i++) {
            ipad[i] = (byte) (key[i] ^ 0x36);
            opad[i] = (byte) (key[i] ^ 0x5c);
        }
        for (int i = keyLen; i < 64; i++) {
            ipad[i] = 0x36;
            opad[i] = 0x5c;
        }

        // Calculate inner hash
        md5.reset();
        md5.update(ipad);
        md5.update(data);
        byte[] innerHash = md5.digest();

        // Calculate outer hash
        md5.reset();
        md5.update(opad);
        byte[] expectedResult = md5.digest(innerHash);

        // Test HMACT64 implementation
        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(MessageDigest.getInstance("MD5"));

            HMACT64 hmac = new HMACT64(key);
            hmac.engineUpdate(data, 0, data.length);
            byte[] result = hmac.engineDigest();

            assertArrayEquals(expectedResult, result);
        }
    }

    @Test
    void testHMACT64WithActualMD5AndDifferentData() throws NoSuchAlgorithmException {
        byte[] key = "key".getBytes();
        byte[] data = "The quick brown fox jumps over the lazy dog".getBytes();

        // Calculate expected HMAC-MD5 using standard Java MessageDigest for comparison
        // This is a simplified HMAC-MD5 calculation for comparison, not a full RFC 2104 implementation.
        // The HMACT64 implementation is what we are testing.
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] ipad = new byte[64];
        byte[] opad = new byte[64];

        for (int i = 0; i < key.length; i++) {
            ipad[i] = (byte) (key[i] ^ 0x36);
            opad[i] = (byte) (key[i] ^ 0x5c);
        }
        for (int i = key.length; i < 64; i++) {
            ipad[i] = 0x36;
            opad[i] = 0x5c;
        }

        md5.update(ipad);
        md5.update(data);
        byte[] innerHash = md5.digest();

        md5.reset();
        md5.update(opad);
        md5.update(innerHash);
        byte[] expected = md5.digest();

        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(MessageDigest.getInstance("MD5"));

            HMACT64 hmac = new HMACT64(key);
            hmac.engineUpdate(data, 0, data.length);
            byte[] result = hmac.engineDigest();

            assertArrayEquals(expected, result);
        }
    }

    @Test
    void testHMACT64WithEmptyData() throws NoSuchAlgorithmException {
        // Test with empty data
        byte[] key = "key".getBytes();
        byte[] data = EMPTY_DATA;

        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] ipad = new byte[64];
        byte[] opad = new byte[64];

        for (int i = 0; i < key.length; i++) {
            ipad[i] = (byte) (key[i] ^ 0x36);
            opad[i] = (byte) (key[i] ^ 0x5c);
        }
        for (int i = key.length; i < 64; i++) {
            ipad[i] = 0x36;
            opad[i] = 0x5c;
        }

        md5.update(ipad);
        md5.update(data);
        byte[] innerHash = md5.digest();

        md5.reset();
        md5.update(opad);
        md5.update(innerHash);
        byte[] expected = md5.digest();

        try (MockedStatic<Crypto> mockedCrypto = mockStatic(Crypto.class)) {
            mockedCrypto.when(Crypto::getMD5).thenReturn(MessageDigest.getInstance("MD5"));

            HMACT64 hmac = new HMACT64(key);
            hmac.engineUpdate(data, 0, data.length);
            byte[] result = hmac.engineDigest();

            assertArrayEquals(expected, result);
        }
    }
}
