package jcifs.smb1.util;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link HMACT64}.  The tests exercise the public API and a
 * few protected engine methods using {@link MessageDigest#MD5}.  They also
 * verify the clone contract and that the instance behaves as a proper
 * {@link java.security.MessageDigest} implementation.
 *
 * <p>
 * Mockito is used to inject a mock {@link java.security.MessageDigest} into
 * a {@link HMACT64} instance so we can assert that the underlying digest is
 * invoked correctly.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
public class HMACT64Test {

    /**
     * Compute an expected HMACT64 digest using the specification.  This is
     * independent from the {@code HMACT64} implementation except that it
     * uses the same underlying {@link MessageDigest} algorithm.
     */
    private static byte[] expectedDigest(byte[] key, byte[] msg) {
        final int BLOCK = 64;
        byte[] ipad = new byte[BLOCK];
        byte[] opad = new byte[BLOCK];
        int len = Math.min(key.length, BLOCK);
        for (int i = 0; i < len; i++) {
            ipad[i] = (byte) (key[i] ^ (byte) 0x36);
            opad[i] = (byte) (key[i] ^ (byte) 0x5c);
        }
        for (int i = len; i < BLOCK; i++) {
            ipad[i] = (byte) 0x36;
            opad[i] = (byte) 0x5c;
        }
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(ipad);
            md5.update(msg);
            byte[] inner = md5.digest();
            md5.update(opad);
            md5.update(inner);
            return md5.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Provide a stream of test cases covering a range of key and message
     * lengths – including normal lengths, empty inputs, and keys larger than
     * the 64‑byte block.
     */
    private static Stream<org.junit.jupiter.params.provider.Arguments> provideKeyAndMsg() {
        return Stream.of(
            // normal key and message
            org.junit.jupiter.params.provider.Arguments.of(new byte[] {1, 2, 3, 4}, new byte[] {5, 6}),
            // empty message
            org.junit.jupiter.params.provider.Arguments.of(new byte[] {1, 2, 3}, new byte[0]),
            // zero‑length key
            org.junit.jupiter.params.provider.Arguments.of(new byte[0], new byte[] {10, 20, 30}),
            // key longer than 64 bytes – should be truncated
            org.junit.jupiter.params.provider.Arguments.of(generateLongKey(100), new byte[] {1, 2, 3})
        );
    }

    /** Utility to generate a key > 64 bytes for edge cases. */
    private static byte[] generateLongKey(int len) {
        byte[] key = new byte[len];
        for (int i = 0; i < len; i++) {
            key[i] = (byte) (i & 0xff);
        }
        return key;
    }

    @ParameterizedTest(name = "HMACT64 digest with key {0} and msg {1}")
    @MethodSource("provideKeyAndMsg")
    void testDigestWithVariousInputs(byte[] key, byte[] msg) {
        byte[] expected = expectedDigest(key, msg);
        HMACT64 hmac = new HMACT64(key);
        byte[] actual = hmac.digest(msg);
        assertArrayEquals(expected, actual, "Digest mismatch for key " + Arrays.toString(key));
    }

    @Test
    @DisplayName("Constructor throws NPE when key is null")
    void testNullKeyThrows() {
        assertThrows(NullPointerException.class, () -> new HMACT64(null));
    }

    @Test
    @DisplayName("Digest after reset yields same as recompute from scratch")
    void testResetBehavior() {
        byte[] key = new byte[] {1, 2, 3};
        byte[] part1 = new byte[] {4, 5};
        byte[] part2 = new byte[] {6};
        
        // Compute first digest
        HMACT64 hmac = new HMACT64(key);
        hmac.update(part1);
        hmac.update(part2);
        byte[] digest1 = hmac.digest();
        
        // MessageDigest.digest() should automatically reset the state
        // So we should be able to compute a fresh digest
        hmac.reset();  // Explicitly reset to ensure clean state
        hmac.update(part1);
        hmac.update(part2);
        byte[] digest2 = hmac.digest();
        
        assertArrayEquals(digest1, digest2, "Digest after reset should match original");
    }

    @Test
    @DisplayName("Clone produces independent copy – state is isolated")
    void testCloneIndependent() {
        byte[] key = new byte[] {1, 2, 3};
        byte[] msg1 = new byte[] {4, 5};
        byte[] msg2 = new byte[] {6};
        
        // Create original HMACT64 and update with msg1
        HMACT64 hmac1 = new HMACT64(key);
        hmac1.update(msg1);
        
        // Clone captures current state
        HMACT64 hmac2 = (HMACT64) hmac1.clone();
        
        // Complete digest on both - they should produce same result
        byte[] d1 = hmac1.digest();
        byte[] d2 = hmac2.digest();
        assertArrayEquals(d1, d2, "Clone should preserve state and produce same digest");
        
        // Now test independence - reset and digest different messages
        hmac1.reset();
        hmac1.update(msg1);
        byte[] d1New = hmac1.digest();
        
        hmac2.reset();
        hmac2.update(msg2);
        byte[] d2New = hmac2.digest();
        
        // Verify they compute correctly
        assertArrayEquals(expectedDigest(key, msg1), d1New, "Original should compute msg1 correctly");
        assertArrayEquals(expectedDigest(key, msg2), d2New, "Clone should compute msg2 correctly");
        
        // Ensure digests are different for different messages
        assertFalse(Arrays.equals(d1New, d2New), "Different messages should produce different digests");
    }

    @Test
    @DisplayName("Digest into preallocated buffer (offset and length)")
    void testDigestIntoBuffer() throws java.security.DigestException {
        byte[] key = new byte[] {1, 2, 3};
        byte[] msg = new byte[] {4, 5, 6};
        byte[] expected = expectedDigest(key, msg);
        HMACT64 hmac = new HMACT64(key);
        hmac.update(msg);  // Must update with message before calling digest
        byte[] buf = new byte[32];
        int len = hmac.digest(buf, 0, expected.length);
        assertEquals(expected.length, len, "Returned length should match digest length");
        assertArrayEquals(expected, Arrays.copyOfRange(buf, 0, len), "Buffer copy should equal full digest");
    }

    @Test
    @DisplayName("Digest length reported correctly (16 for MD5)")
    void testEngineGetDigestLength() {
        HMACT64 hmac = new HMACT64(new byte[] {1, 2, 3});
        assertEquals(16, hmac.getDigestLength(), "Digest length should be 16 bytes due to MD5");
    }

    @Test
    @DisplayName("Mockito ensures internal MD5 is invoked during update")
    void testInternalMD5Interactions() throws Exception {
        byte[] key = new byte[] {1, 2};
        HMACT64 hmac = new HMACT64(key);
        // Inject a mock MessageDigest via reflection
        MessageDigest mockMD5 = mock(MessageDigest.class);
        Field md5Field = HMACT64.class.getDeclaredField("md5");
        md5Field.setAccessible(true);
        md5Field.set(hmac, mockMD5);
        // Arrange–Act
        hmac.update((byte) 10);
        hmac.update(new byte[] {20, 30});
        hmac.digest();
        // Assert: update called twice, then digest called
        verify(mockMD5, times(1)).update((byte) 10);
        verify(mockMD5, times(1)).update(eq(new byte[] {20, 30}), eq(0), eq(2));
        // digest will invoke update again; not checking order here
        verify(mockMD5, atLeastOnce()).digest();
    }
}

