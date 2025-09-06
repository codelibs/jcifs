package org.codelibs.jcifs.smb.internal.smb2.lock;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Arrays;

import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("Smb2Lock Test")
class Smb2LockTest {

    private Smb2Lock lock;
    private byte[] buffer;

    @BeforeEach
    void setUp() {
        buffer = new byte[128];
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create lock with valid parameters")
        void testConstructorWithValidParameters() {
            long offset = 1024L;
            long length = 2048L;
            int flags = Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK;

            lock = new Smb2Lock(offset, length, flags);

            assertNotNull(lock);
        }

        @Test
        @DisplayName("Should create lock with zero offset and length")
        void testConstructorWithZeroValues() {
            lock = new Smb2Lock(0L, 0L, 0);

            assertNotNull(lock);
        }

        @Test
        @DisplayName("Should create lock with maximum values")
        void testConstructorWithMaxValues() {
            long maxOffset = Long.MAX_VALUE;
            long maxLength = Long.MAX_VALUE;
            int flags = 0xFFFFFFFF;

            lock = new Smb2Lock(maxOffset, maxLength, flags);

            assertNotNull(lock);
        }

        @Test
        @DisplayName("Should create lock with negative values")
        void testConstructorWithNegativeValues() {
            lock = new Smb2Lock(-1L, -1L, -1);

            assertNotNull(lock);
        }
    }

    @Nested
    @DisplayName("Size Tests")
    class SizeTests {

        @Test
        @DisplayName("Should return constant size of 24 bytes")
        void testSize() {
            lock = new Smb2Lock(100L, 200L, Smb2Lock.SMB2_LOCKFLAG_SHARED_LOCK);

            assertEquals(24, lock.size());
        }

        @ParameterizedTest
        @DisplayName("Should return 24 bytes regardless of parameters")
        @CsvSource({ "0, 0, 0", "100, 200, 1", "9223372036854775807, 9223372036854775807, 2147483647", "-1, -1, -1" })
        void testSizeWithDifferentValues(long offset, long length, int flags) {
            lock = new Smb2Lock(offset, length, flags);

            assertEquals(24, lock.size());
        }
    }

    @Nested
    @DisplayName("Encoding Tests")
    class EncodingTests {

        @Test
        @DisplayName("Should encode basic lock structure correctly")
        void testBasicEncoding() {
            long offset = 0x1234567890ABCDEFL;
            long length = 0xFEDCBA0987654321L;
            int flags = 0x12345678;

            lock = new Smb2Lock(offset, length, flags);
            int encoded = lock.encode(buffer, 0);

            assertEquals(24, encoded);

            // Verify offset (8 bytes)
            assertEquals(offset, SMBUtil.readInt8(buffer, 0));

            // Verify length (8 bytes)
            assertEquals(length, SMBUtil.readInt8(buffer, 8));

            // Verify flags (4 bytes)
            assertEquals(flags, SMBUtil.readInt4(buffer, 16));

            // Verify reserved field is zeros (4 bytes)
            assertEquals(0, SMBUtil.readInt4(buffer, 20));
        }

        @Test
        @DisplayName("Should encode at different buffer positions")
        void testEncodingAtDifferentPositions() {
            long offset = 1000L;
            long length = 2000L;
            int flags = Smb2Lock.SMB2_LOCKFLAG_UNLOCK;

            lock = new Smb2Lock(offset, length, flags);

            // Test encoding at position 10
            int encoded = lock.encode(buffer, 10);

            assertEquals(24, encoded);
            assertEquals(offset, SMBUtil.readInt8(buffer, 10));
            assertEquals(length, SMBUtil.readInt8(buffer, 18));
            assertEquals(flags, SMBUtil.readInt4(buffer, 26));
            assertEquals(0, SMBUtil.readInt4(buffer, 30));
        }

        @Test
        @DisplayName("Should encode with all lock flags")
        void testEncodingWithAllFlags() {
            long offset = 512L;
            long length = 1024L;
            int allFlags = Smb2Lock.SMB2_LOCKFLAG_SHARED_LOCK | Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK | Smb2Lock.SMB2_LOCKFLAG_UNLOCK
                    | Smb2Lock.SMB2_LOCKFLAG_FAIL_IMMEDIATELY;

            lock = new Smb2Lock(offset, length, allFlags);
            lock.encode(buffer, 0);

            assertEquals(allFlags, SMBUtil.readInt4(buffer, 16));
        }

        @Test
        @DisplayName("Should encode zero values correctly")
        void testEncodingWithZeroValues() {
            lock = new Smb2Lock(0L, 0L, 0);
            lock.encode(buffer, 0);

            assertEquals(0L, SMBUtil.readInt8(buffer, 0));
            assertEquals(0L, SMBUtil.readInt8(buffer, 8));
            assertEquals(0, SMBUtil.readInt4(buffer, 16));
            assertEquals(0, SMBUtil.readInt4(buffer, 20));
        }

        @Test
        @DisplayName("Should encode maximum values correctly")
        void testEncodingWithMaxValues() {
            long maxValue = Long.MAX_VALUE;
            int maxFlags = Integer.MAX_VALUE;

            lock = new Smb2Lock(maxValue, maxValue, maxFlags);
            lock.encode(buffer, 0);

            assertEquals(maxValue, SMBUtil.readInt8(buffer, 0));
            assertEquals(maxValue, SMBUtil.readInt8(buffer, 8));
            assertEquals(maxFlags, SMBUtil.readInt4(buffer, 16));
        }

        @Test
        @DisplayName("Should encode negative values as unsigned")
        void testEncodingWithNegativeValues() {
            long negativeOffset = -1L;
            long negativeLength = -100L;
            int negativeFlags = -1;

            lock = new Smb2Lock(negativeOffset, negativeLength, negativeFlags);
            lock.encode(buffer, 0);

            // Negative values should be encoded as unsigned
            assertEquals(negativeOffset, SMBUtil.readInt8(buffer, 0));
            assertEquals(negativeLength, SMBUtil.readInt8(buffer, 8));
            assertEquals(negativeFlags, SMBUtil.readInt4(buffer, 16));
        }

        @Test
        @DisplayName("Should not modify reserved field bytes")
        void testReservedFieldNotModified() {
            lock = new Smb2Lock(999L, 888L, 0xFF);

            // Fill buffer with non-zero values
            Arrays.fill(buffer, (byte) 0xFF);

            lock.encode(buffer, 0);

            // Reserved field bytes are not modified by the encode method
            // The implementation just skips these bytes without writing zeros
            assertEquals(-1, SMBUtil.readInt4(buffer, 20));
        }
    }

    @Nested
    @DisplayName("Flag Constants Tests")
    class FlagConstantsTests {

        @Test
        @DisplayName("Should have correct shared lock flag value")
        void testSharedLockFlag() {
            assertEquals(0x1, Smb2Lock.SMB2_LOCKFLAG_SHARED_LOCK);
        }

        @Test
        @DisplayName("Should have correct exclusive lock flag value")
        void testExclusiveLockFlag() {
            assertEquals(0x2, Smb2Lock.SMB2_LOCKFLAG_EXCLUSIVE_LOCK);
        }

        @Test
        @DisplayName("Should have correct unlock flag value")
        void testUnlockFlag() {
            assertEquals(0x4, Smb2Lock.SMB2_LOCKFLAG_UNLOCK);
        }

        @Test
        @DisplayName("Should have correct fail immediately flag value")
        void testFailImmediatelyFlag() {
            assertEquals(0x10, Smb2Lock.SMB2_LOCKFLAG_FAIL_IMMEDIATELY);
        }

        @Test
        @DisplayName("Should allow flag combinations")
        void testFlagCombinations() {
            int sharedWithFailImmediately = Smb2Lock.SMB2_LOCKFLAG_SHARED_LOCK | Smb2Lock.SMB2_LOCKFLAG_FAIL_IMMEDIATELY;

            lock = new Smb2Lock(100L, 200L, sharedWithFailImmediately);
            lock.encode(buffer, 0);

            assertEquals(0x11, SMBUtil.readInt4(buffer, 16));
        }
    }

    @Nested
    @DisplayName("Edge Cases and Boundary Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle encoding at buffer boundary")
        void testEncodingAtBufferBoundary() {
            byte[] smallBuffer = new byte[24];
            lock = new Smb2Lock(100L, 200L, 1);

            int encoded = lock.encode(smallBuffer, 0);

            assertEquals(24, encoded);
            assertEquals(100L, SMBUtil.readInt8(smallBuffer, 0));
            assertEquals(200L, SMBUtil.readInt8(smallBuffer, 8));
            assertEquals(1, SMBUtil.readInt4(smallBuffer, 16));
        }

        @ParameterizedTest
        @DisplayName("Should encode consistently with various flag values")
        @ValueSource(ints = { 0, 1, 2, 4, 16, 0xFF, 0xFFFF, 0xFFFFFF, 0x7FFFFFFF, -1 })
        void testEncodingWithVariousFlags(int flags) {
            lock = new Smb2Lock(1024L, 2048L, flags);
            int encoded = lock.encode(buffer, 0);

            assertEquals(24, encoded);
            assertEquals(flags, SMBUtil.readInt4(buffer, 16));
        }

        @Test
        @DisplayName("Should encode multiple locks sequentially")
        void testSequentialEncoding() {
            Smb2Lock lock1 = new Smb2Lock(100L, 200L, 1);
            Smb2Lock lock2 = new Smb2Lock(300L, 400L, 2);
            Smb2Lock lock3 = new Smb2Lock(500L, 600L, 4);

            int offset = 0;
            offset += lock1.encode(buffer, offset);
            offset += lock2.encode(buffer, offset);
            offset += lock3.encode(buffer, offset);

            assertEquals(72, offset); // 3 * 24

            // Verify first lock
            assertEquals(100L, SMBUtil.readInt8(buffer, 0));
            assertEquals(200L, SMBUtil.readInt8(buffer, 8));
            assertEquals(1, SMBUtil.readInt4(buffer, 16));

            // Verify second lock
            assertEquals(300L, SMBUtil.readInt8(buffer, 24));
            assertEquals(400L, SMBUtil.readInt8(buffer, 32));
            assertEquals(2, SMBUtil.readInt4(buffer, 40));

            // Verify third lock
            assertEquals(500L, SMBUtil.readInt8(buffer, 48));
            assertEquals(600L, SMBUtil.readInt8(buffer, 56));
            assertEquals(4, SMBUtil.readInt4(buffer, 64));
        }

        @Test
        @DisplayName("Should handle power of two values")
        void testPowerOfTwoValues() {
            long powerOfTwoOffset = 1L << 32; // 2^32
            long powerOfTwoLength = 1L << 16; // 2^16
            int powerOfTwoFlags = 1 << 8; // 2^8

            lock = new Smb2Lock(powerOfTwoOffset, powerOfTwoLength, powerOfTwoFlags);
            lock.encode(buffer, 0);

            assertEquals(powerOfTwoOffset, SMBUtil.readInt8(buffer, 0));
            assertEquals(powerOfTwoLength, SMBUtil.readInt8(buffer, 8));
            assertEquals(powerOfTwoFlags, SMBUtil.readInt4(buffer, 16));
        }
    }
}
