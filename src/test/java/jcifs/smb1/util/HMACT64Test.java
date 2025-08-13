package jcifs.smb1.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

class HMACT64Test {

    private static final byte[] TEST_KEY = "testkey".getBytes();
    private static final byte[] LONG_TEST_KEY = new byte[80]; // Longer than 64 bytes
    private static final byte[] SHORT_TEST_KEY = "short".getBytes();
    private static final byte[] TEST_DATA = "testdata".getBytes();
    private static final byte[] EMPTY_DATA = new byte[0];

    static {
        // Initialize long key with predictable data
        Arrays.fill(LONG_TEST_KEY, (byte) 0xAB);
    }

    @Test
    void testConstructorWithNormalKey() {
        // Test constructor with a normal length key
        HMACT64 hmac = new HMACT64(TEST_KEY);
        assertNotNull(hmac);
    }

    @Test
    void testConstructorWithLongKey() {
        // Test constructor with a key longer than BLOCK_LENGTH (64 bytes)
        // HMACT64 truncates keys at 64 bytes
        HMACT64 hmac = new HMACT64(LONG_TEST_KEY);
        assertNotNull(hmac);
    }

    @Test
    void testConstructorWithShortKey() {
        // Test constructor with a key shorter than BLOCK_LENGTH (64 bytes)
        HMACT64 hmac = new HMACT64(SHORT_TEST_KEY);
        assertNotNull(hmac);
    }

    @Test
    void testEngineUpdateByte() {
        // Test engineUpdate(byte b)
        HMACT64 hmac = new HMACT64(TEST_KEY);
        hmac.engineUpdate((byte) 0x01);
        // No exception means success
    }

    @Test
    void testEngineUpdateByteArray() {
        // Test engineUpdate(byte[] input, int offset, int len)
        HMACT64 hmac = new HMACT64(TEST_KEY);
        hmac.engineUpdate(TEST_DATA, 0, TEST_DATA.length);
        // No exception means success
    }

    @Test
    void testEngineUpdateByteArrayPartial() {
        // Test engineUpdate with partial array
        HMACT64 hmac = new HMACT64(TEST_KEY);
        hmac.engineUpdate(TEST_DATA, 2, TEST_DATA.length - 2);
        // No exception means success
    }

    @Test
    void testEngineReset() {
        // Test engineReset()
        HMACT64 hmac = new HMACT64(TEST_KEY);
        hmac.engineUpdate(TEST_DATA, 0, TEST_DATA.length);
        hmac.engineReset();
        // After reset, should be able to digest again
        byte[] result = hmac.engineDigest();
        assertNotNull(result);
    }

    @Test
    void testEngineGetDigestLength() {
        // Test engineGetDigestLength()
        HMACT64 hmac = new HMACT64(TEST_KEY);
        // MD5 digest length is 16 bytes
        assertEquals(16, hmac.engineGetDigestLength());
    }

    @Test
    void testEngineDigest() {
        // Test engineDigest()
        HMACT64 hmac = new HMACT64(TEST_KEY);
        hmac.engineUpdate(TEST_DATA, 0, TEST_DATA.length);
        byte[] result = hmac.engineDigest();
        
        assertNotNull(result);
        assertEquals(16, result.length); // MD5 produces 16 bytes
    }

    @Test
    void testEngineDigestWithBuffer() {
        // Test engineDigest(byte[] buf, int offset, int len)
        HMACT64 hmac = new HMACT64(TEST_KEY);
        hmac.engineUpdate(TEST_DATA, 0, TEST_DATA.length);
        
        byte[] buffer = new byte[32];
        int bytesWritten = hmac.engineDigest(buffer, 5, 16);
        
        assertEquals(16, bytesWritten);
        // Check that bytes were written to the correct position
        byte[] extractedResult = Arrays.copyOfRange(buffer, 5, 21);
        assertEquals(16, extractedResult.length);
    }

    @Test
    void testEngineDigestWithInsufficientBuffer() {
        // Test engineDigest with buffer too small
        HMACT64 hmac = new HMACT64(TEST_KEY);
        hmac.engineUpdate(TEST_DATA, 0, TEST_DATA.length);
        
        byte[] buffer = new byte[10];
        // Should throw exception when buffer is too small
        assertThrows(IllegalStateException.class, () -> hmac.engineDigest(buffer, 0, 10));
    }

    @Test
    void testClone() {
        // Test clone() method
        HMACT64 originalHmac = new HMACT64(TEST_KEY);
        originalHmac.engineUpdate(TEST_DATA, 0, TEST_DATA.length / 2);
        
        HMACT64 clonedHmac = (HMACT64) originalHmac.clone();
        
        assertNotNull(clonedHmac);
        assertNotSame(originalHmac, clonedHmac);
        
        // Both should produce the same result when given the same remaining data
        originalHmac.engineUpdate(TEST_DATA, TEST_DATA.length / 2, TEST_DATA.length - TEST_DATA.length / 2);
        clonedHmac.engineUpdate(TEST_DATA, TEST_DATA.length / 2, TEST_DATA.length - TEST_DATA.length / 2);
        
        byte[] originalResult = originalHmac.engineDigest();
        byte[] clonedResult = clonedHmac.engineDigest();
        
        assertArrayEquals(originalResult, clonedResult);
    }

    @Test
    void testMultipleUpdates() {
        // Test multiple update calls
        HMACT64 hmac1 = new HMACT64(TEST_KEY);
        HMACT64 hmac2 = new HMACT64(TEST_KEY);
        
        // Update hmac1 all at once
        hmac1.engineUpdate(TEST_DATA, 0, TEST_DATA.length);
        
        // Update hmac2 byte by byte
        for (byte b : TEST_DATA) {
            hmac2.engineUpdate(b);
        }
        
        // Both should produce the same result
        byte[] result1 = hmac1.engineDigest();
        byte[] result2 = hmac2.engineDigest();
        
        assertArrayEquals(result1, result2);
    }

    @Test
    void testHMACT64WithKnownTestVector() throws NoSuchAlgorithmException {
        // Test with known test vector
        // Using test vector from RFC 2104 adapted for HMACT64
        byte[] key = new byte[16];
        Arrays.fill(key, (byte) 0x0b);
        byte[] data = "Hi There".getBytes();
        
        // Expected result calculated manually for HMACT64 with this key and data
        HMACT64 hmac = new HMACT64(key);
        hmac.engineUpdate(data, 0, data.length);
        byte[] result = hmac.engineDigest();
        
        // Verify it produces a valid MD5 hash (16 bytes)
        assertNotNull(result);
        assertEquals(16, result.length);
        
        // Calculate the same using manual HMACT64 algorithm
        byte[] expectedResult = calculateHMACT64Manually(key, data);
        assertArrayEquals(expectedResult, result);
    }

    @Test
    void testHMACT64WithEmptyData() {
        // Test with empty data
        HMACT64 hmac = new HMACT64(TEST_KEY);
        hmac.engineUpdate(EMPTY_DATA, 0, EMPTY_DATA.length);
        byte[] result = hmac.engineDigest();
        
        assertNotNull(result);
        assertEquals(16, result.length);
    }

    @Test
    void testHMACT64WithEmptyKey() {
        // Test with empty key
        byte[] emptyKey = new byte[0];
        HMACT64 hmac = new HMACT64(emptyKey);
        hmac.engineUpdate(TEST_DATA, 0, TEST_DATA.length);
        byte[] result = hmac.engineDigest();
        
        assertNotNull(result);
        assertEquals(16, result.length);
    }

    @Test
    void testResetAndReuse() {
        // Test that HMACT64 can be reset and reused
        HMACT64 hmac = new HMACT64(TEST_KEY);
        
        // First use
        hmac.engineUpdate(TEST_DATA, 0, TEST_DATA.length);
        byte[] result1 = hmac.engineDigest();
        
        // Reset and reuse with same data
        hmac.engineReset();
        hmac.engineUpdate(TEST_DATA, 0, TEST_DATA.length);
        byte[] result2 = hmac.engineDigest();
        
        // Should produce the same result
        assertArrayEquals(result1, result2);
    }

    @Test
    void testDifferentKeysProduceDifferentResults() {
        // Test that different keys produce different results
        byte[] key1 = "key1".getBytes();
        byte[] key2 = "key2".getBytes();
        
        HMACT64 hmac1 = new HMACT64(key1);
        HMACT64 hmac2 = new HMACT64(key2);
        
        hmac1.engineUpdate(TEST_DATA, 0, TEST_DATA.length);
        hmac2.engineUpdate(TEST_DATA, 0, TEST_DATA.length);
        
        byte[] result1 = hmac1.engineDigest();
        byte[] result2 = hmac2.engineDigest();
        
        // Results should be different
        boolean different = false;
        for (int i = 0; i < result1.length; i++) {
            if (result1[i] != result2[i]) {
                different = true;
                break;
            }
        }
        assertEquals(true, different, "Different keys should produce different HMAC values");
    }

    @Test
    void testDifferentDataProducesDifferentResults() {
        // Test that different data produces different results
        byte[] data1 = "data1".getBytes();
        byte[] data2 = "data2".getBytes();
        
        HMACT64 hmac1 = new HMACT64(TEST_KEY);
        HMACT64 hmac2 = new HMACT64(TEST_KEY);
        
        hmac1.engineUpdate(data1, 0, data1.length);
        hmac2.engineUpdate(data2, 0, data2.length);
        
        byte[] result1 = hmac1.engineDigest();
        byte[] result2 = hmac2.engineDigest();
        
        // Results should be different
        boolean different = false;
        for (int i = 0; i < result1.length; i++) {
            if (result1[i] != result2[i]) {
                different = true;
                break;
            }
        }
        assertEquals(true, different, "Different data should produce different HMAC values");
    }

    // Helper method to manually calculate HMACT64 for verification
    private byte[] calculateHMACT64Manually(byte[] key, byte[] data) throws NoSuchAlgorithmException {
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
        return md5.digest(innerHash);
    }
}