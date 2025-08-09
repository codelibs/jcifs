/*
 * © 2025 Test Suite
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
package jcifs.internal.dfs;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;

import jcifs.internal.util.SMBUtil;

/**
 * Test suite for DfsReferralRequestBuffer
 */
class DfsReferralRequestBufferTest {

    private DfsReferralRequestBuffer buffer;

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create buffer with simple path and referral level")
        void testConstructorWithSimplePath() {
            String path = "\\\\server\\share";
            int maxReferralLevel = 3;
            
            buffer = new DfsReferralRequestBuffer(path, maxReferralLevel);
            
            assertNotNull(buffer);
            // Verify through encode since there are no getters
            int expectedSize = 4 + 2 * path.length();
            assertEquals(expectedSize, buffer.size());
        }

        @Test
        @DisplayName("Should create buffer with empty path")
        void testConstructorWithEmptyPath() {
            String path = "";
            int maxReferralLevel = 1;
            
            buffer = new DfsReferralRequestBuffer(path, maxReferralLevel);
            
            assertNotNull(buffer);
            assertEquals(4, buffer.size()); // 2 bytes for level + 2 bytes for null terminator
        }

        @Test
        @DisplayName("Should create buffer with null path")
        void testConstructorWithNullPath() {
            String path = null;
            int maxReferralLevel = 2;
            
            // The implementation doesn't check for null in constructor
            buffer = new DfsReferralRequestBuffer(path, maxReferralLevel);
            assertNotNull(buffer);
            
            // Will throw NPE when trying to call size() or encode()
            assertThrows(NullPointerException.class, () -> {
                buffer.size();
            });
        }

        @ParameterizedTest
        @DisplayName("Should handle various referral levels")
        @ValueSource(ints = {0, 1, 2, 3, 4, 5, 255, 256, 32767, 65535})
        void testConstructorWithVariousReferralLevels(int maxReferralLevel) {
            String path = "\\\\test";
            
            buffer = new DfsReferralRequestBuffer(path, maxReferralLevel);
            
            assertNotNull(buffer);
            assertEquals(4 + 2 * path.length(), buffer.size());
        }

        @Test
        @DisplayName("Should handle negative referral level")
        void testConstructorWithNegativeReferralLevel() {
            String path = "\\\\server\\share";
            int maxReferralLevel = -1;
            
            buffer = new DfsReferralRequestBuffer(path, maxReferralLevel);
            
            assertNotNull(buffer);
            // Negative values will be cast to unsigned when encoded
            assertEquals(4 + 2 * path.length(), buffer.size());
        }
    }

    @Nested
    @DisplayName("Size Calculation Tests")
    class SizeTests {

        @ParameterizedTest
        @DisplayName("Should calculate correct size for various path lengths")
        @CsvSource({
            "'', 4",
            "'a', 6",
            "'\\\\', 8",
            "'\\\\server', 20",
            "'\\\\server\\share', 32",
            "'\\\\server\\share\\path', 42",
            "'\\\\server\\share\\very\\long\\path\\with\\many\\segments', 100"
        })
        void testSizeCalculation(String path, int expectedSize) {
            buffer = new DfsReferralRequestBuffer(path, 3);
            
            assertEquals(expectedSize, buffer.size());
        }

        @Test
        @DisplayName("Should calculate size for Unicode characters")
        void testSizeWithUnicodeCharacters() {
            // Unicode characters still count as single chars in Java
            String path = "\\\\server\\共享\\路径";
            buffer = new DfsReferralRequestBuffer(path, 3);
            
            int expectedSize = 4 + 2 * path.length();
            assertEquals(expectedSize, buffer.size());
        }

        @Test
        @DisplayName("Should calculate size for very long path")
        void testSizeWithVeryLongPath() {
            StringBuilder pathBuilder = new StringBuilder("\\\\server\\share");
            for (int i = 0; i < 100; i++) {
                pathBuilder.append("\\segment").append(i);
            }
            String path = pathBuilder.toString();
            
            buffer = new DfsReferralRequestBuffer(path, 3);
            
            int expectedSize = 4 + 2 * path.length();
            assertEquals(expectedSize, buffer.size());
        }
    }

    @Nested
    @DisplayName("Encode Tests")
    class EncodeTests {

        @Test
        @DisplayName("Should encode simple path correctly")
        void testEncodeSimplePath() {
            String path = "\\\\server\\share";
            int maxReferralLevel = 3;
            buffer = new DfsReferralRequestBuffer(path, maxReferralLevel);
            
            byte[] dst = new byte[buffer.size()];
            int bytesEncoded = buffer.encode(dst, 0);
            
            assertEquals(buffer.size(), bytesEncoded);
            
            // Verify encoded data
            ByteBuffer bb = ByteBuffer.wrap(dst).order(ByteOrder.LITTLE_ENDIAN);
            assertEquals(maxReferralLevel, bb.getShort());
            
            // Verify path encoding (UTF-16LE)
            byte[] pathBytes = path.getBytes(StandardCharsets.UTF_16LE);
            byte[] encodedPath = new byte[pathBytes.length];
            bb.get(encodedPath);
            assertArrayEquals(pathBytes, encodedPath);
            
            // Verify null terminator
            assertEquals(0, bb.getShort());
        }

        @Test
        @DisplayName("Should encode with offset correctly")
        void testEncodeWithOffset() {
            String path = "\\\\test";
            int maxReferralLevel = 5;
            buffer = new DfsReferralRequestBuffer(path, maxReferralLevel);
            
            int offset = 10;
            byte[] dst = new byte[offset + buffer.size()];
            int bytesEncoded = buffer.encode(dst, offset);
            
            assertEquals(buffer.size(), bytesEncoded);
            
            // Verify that data before offset is untouched
            for (int i = 0; i < offset; i++) {
                assertEquals(0, dst[i]);
            }
            
            // Verify encoded data at offset
            ByteBuffer bb = ByteBuffer.wrap(dst).order(ByteOrder.LITTLE_ENDIAN);
            bb.position(offset);
            assertEquals(maxReferralLevel, bb.getShort());
        }

        @Test
        @DisplayName("Should encode empty path correctly")
        void testEncodeEmptyPath() {
            String path = "";
            int maxReferralLevel = 1;
            buffer = new DfsReferralRequestBuffer(path, maxReferralLevel);
            
            byte[] dst = new byte[buffer.size()];
            int bytesEncoded = buffer.encode(dst, 0);
            
            assertEquals(4, bytesEncoded);
            
            ByteBuffer bb = ByteBuffer.wrap(dst).order(ByteOrder.LITTLE_ENDIAN);
            assertEquals(maxReferralLevel, bb.getShort());
            assertEquals(0, bb.getShort()); // null terminator
        }

        @ParameterizedTest
        @DisplayName("Should encode various referral levels correctly")
        @ValueSource(ints = {0, 1, 255, 256, 32767, 65535})
        void testEncodeVariousReferralLevels(int maxReferralLevel) {
            String path = "\\\\server";
            buffer = new DfsReferralRequestBuffer(path, maxReferralLevel);
            
            byte[] dst = new byte[buffer.size()];
            buffer.encode(dst, 0);
            
            ByteBuffer bb = ByteBuffer.wrap(dst).order(ByteOrder.LITTLE_ENDIAN);
            assertEquals((short) maxReferralLevel, bb.getShort());
        }

        @Test
        @DisplayName("Should encode Unicode path correctly")
        void testEncodeUnicodePath() {
            String path = "\\\\サーバー\\共有\\パス";
            int maxReferralLevel = 3;
            buffer = new DfsReferralRequestBuffer(path, maxReferralLevel);
            
            byte[] dst = new byte[buffer.size()];
            int bytesEncoded = buffer.encode(dst, 0);
            
            assertEquals(buffer.size(), bytesEncoded);
            
            // Verify the path is correctly encoded in UTF-16LE
            ByteBuffer bb = ByteBuffer.wrap(dst).order(ByteOrder.LITTLE_ENDIAN);
            bb.getShort(); // Skip referral level
            
            byte[] pathBytes = path.getBytes(StandardCharsets.UTF_16LE);
            byte[] encodedPath = new byte[pathBytes.length];
            bb.get(encodedPath);
            assertArrayEquals(pathBytes, encodedPath);
        }

        @Test
        @DisplayName("Should encode special characters in path")
        void testEncodeSpecialCharactersPath() {
            String path = "\\\\server\\share$\\@special!\\#test";
            int maxReferralLevel = 2;
            buffer = new DfsReferralRequestBuffer(path, maxReferralLevel);
            
            byte[] dst = new byte[buffer.size()];
            int bytesEncoded = buffer.encode(dst, 0);
            
            assertEquals(buffer.size(), bytesEncoded);
            
            // Decode and verify
            ByteBuffer bb = ByteBuffer.wrap(dst).order(ByteOrder.LITTLE_ENDIAN);
            assertEquals(maxReferralLevel, bb.getShort());
            
            byte[] pathBytes = path.getBytes(StandardCharsets.UTF_16LE);
            byte[] encodedPath = new byte[pathBytes.length];
            bb.get(encodedPath);
            assertArrayEquals(pathBytes, encodedPath);
        }

        @Test
        @DisplayName("Should handle negative referral level as unsigned")
        void testEncodeNegativeReferralLevel() {
            String path = "\\\\server";
            int maxReferralLevel = -1;
            buffer = new DfsReferralRequestBuffer(path, maxReferralLevel);
            
            byte[] dst = new byte[buffer.size()];
            buffer.encode(dst, 0);
            
            ByteBuffer bb = ByteBuffer.wrap(dst).order(ByteOrder.LITTLE_ENDIAN);
            // -1 as unsigned short should be 65535
            assertEquals((short) -1, bb.getShort());
            assertEquals(65535, Short.toUnsignedInt((short) -1));
        }
    }

    @Nested
    @DisplayName("Integration Tests with SMBUtil")
    class SMBUtilIntegrationTests {

        @Test
        @DisplayName("Should use SMBUtil.writeInt2 for referral level")
        void testSMBUtilWriteInt2ForReferralLevel() {
            try (MockedStatic<SMBUtil> mockedSMBUtil = mockStatic(SMBUtil.class)) {
                String path = "\\\\server";
                int maxReferralLevel = 3;
                buffer = new DfsReferralRequestBuffer(path, maxReferralLevel);
                
                // Configure mock to do nothing when called
                mockedSMBUtil.when(() -> SMBUtil.writeInt2(anyLong(), any(byte[].class), anyInt())).thenAnswer(invocation -> null);
                
                byte[] dst = new byte[buffer.size()];
                buffer.encode(dst, 0);
                
                // Verify SMBUtil.writeInt2 was called for referral level (with long parameter)
                mockedSMBUtil.verify(() -> SMBUtil.writeInt2(eq((long)maxReferralLevel), any(byte[].class), eq(0)));
                // Verify SMBUtil.writeInt2 was called for null terminator
                mockedSMBUtil.verify(() -> SMBUtil.writeInt2(eq(0L), any(byte[].class), anyInt()));
            }
        }

        @Test
        @DisplayName("Should encode correctly with real SMBUtil")
        void testRealSMBUtilEncoding() {
            String path = "\\\\server\\share\\file.txt";
            int maxReferralLevel = 4;
            buffer = new DfsReferralRequestBuffer(path, maxReferralLevel);
            
            byte[] dst = new byte[buffer.size()];
            int bytesEncoded = buffer.encode(dst, 0);
            
            // Manually verify the encoded bytes
            assertEquals(buffer.size(), bytesEncoded);
            
            // Check referral level (little-endian)
            assertEquals(4, dst[0] & 0xFF);
            assertEquals(0, dst[1] & 0xFF);
            
            // Check path starts at byte 2
            byte[] expectedPathBytes = path.getBytes(StandardCharsets.UTF_16LE);
            byte[] actualPathBytes = new byte[expectedPathBytes.length];
            System.arraycopy(dst, 2, actualPathBytes, 0, expectedPathBytes.length);
            assertArrayEquals(expectedPathBytes, actualPathBytes);
            
            // Check null terminator at the end
            int nullTerminatorIndex = 2 + expectedPathBytes.length;
            assertEquals(0, dst[nullTerminatorIndex]);
            assertEquals(0, dst[nullTerminatorIndex + 1]);
        }
    }

    @Nested
    @DisplayName("Edge Cases and Boundary Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle maximum path length")
        void testMaximumPathLength() {
            // Create a very long path (but not too long to cause memory issues)
            StringBuilder sb = new StringBuilder("\\\\server");
            for (int i = 0; i < 1000; i++) {
                sb.append("\\segment");
            }
            String path = sb.toString();
            
            buffer = new DfsReferralRequestBuffer(path, 3);
            
            byte[] dst = new byte[buffer.size()];
            int bytesEncoded = buffer.encode(dst, 0);
            
            assertEquals(buffer.size(), bytesEncoded);
            assertEquals(4 + 2 * path.length(), bytesEncoded);
        }

        @Test
        @DisplayName("Should handle path with only backslashes")
        void testPathWithOnlyBackslashes() {
            String path = "\\\\\\\\\\\\";
            buffer = new DfsReferralRequestBuffer(path, 2);
            
            byte[] dst = new byte[buffer.size()];
            int bytesEncoded = buffer.encode(dst, 0);
            
            assertEquals(buffer.size(), bytesEncoded);
            
            // Verify the backslashes are encoded correctly
            ByteBuffer bb = ByteBuffer.wrap(dst).order(ByteOrder.LITTLE_ENDIAN);
            bb.getShort(); // Skip referral level
            
            byte[] pathBytes = path.getBytes(StandardCharsets.UTF_16LE);
            byte[] encodedPath = new byte[pathBytes.length];
            bb.get(encodedPath);
            assertArrayEquals(pathBytes, encodedPath);
        }

        @Test
        @DisplayName("Should encode consistently on multiple calls")
        void testEncodeIdempotency() {
            String path = "\\\\server\\share";
            buffer = new DfsReferralRequestBuffer(path, 3);
            
            byte[] dst1 = new byte[buffer.size()];
            byte[] dst2 = new byte[buffer.size()];
            
            int bytesEncoded1 = buffer.encode(dst1, 0);
            int bytesEncoded2 = buffer.encode(dst2, 0);
            
            assertEquals(bytesEncoded1, bytesEncoded2);
            assertArrayEquals(dst1, dst2);
        }

        @Test
        @DisplayName("Should handle buffer with exact required size")
        void testExactBufferSize() {
            String path = "\\\\test";
            buffer = new DfsReferralRequestBuffer(path, 5);
            
            int requiredSize = buffer.size();
            byte[] dst = new byte[requiredSize]; // Exact size
            
            int bytesEncoded = buffer.encode(dst, 0);
            
            assertEquals(requiredSize, bytesEncoded);
        }

        @Test
        @DisplayName("Should handle large buffer with offset")
        void testLargeBufferWithOffset() {
            String path = "\\\\server\\share";
            buffer = new DfsReferralRequestBuffer(path, 3);
            
            int offset = 1000;
            byte[] dst = new byte[offset + buffer.size() + 100]; // Extra space
            
            int bytesEncoded = buffer.encode(dst, offset);
            
            assertEquals(buffer.size(), bytesEncoded);
            
            // Verify data is at correct offset
            ByteBuffer bb = ByteBuffer.wrap(dst).order(ByteOrder.LITTLE_ENDIAN);
            bb.position(offset);
            assertEquals(3, bb.getShort());
        }
    }

    @Nested
    @DisplayName("Performance and Stress Tests")
    class PerformanceTests {

        @Test
        @DisplayName("Should handle rapid successive encodes")
        void testRapidSuccessiveEncodes() {
            String path = "\\\\server\\share\\folder\\file.dat";
            buffer = new DfsReferralRequestBuffer(path, 3);
            
            byte[] dst = new byte[buffer.size()];
            
            // Perform many rapid encodes
            for (int i = 0; i < 10000; i++) {
                int bytesEncoded = buffer.encode(dst, 0);
                assertEquals(buffer.size(), bytesEncoded);
            }
        }

        @Test
        @DisplayName("Should handle concurrent size calculations")
        void testConcurrentSizeCalculations() throws InterruptedException {
            String path = "\\\\server\\share\\test";
            buffer = new DfsReferralRequestBuffer(path, 3);
            
            int expectedSize = buffer.size();
            
            // Create multiple threads to call size()
            Thread[] threads = new Thread[10];
            for (int i = 0; i < threads.length; i++) {
                threads[i] = new Thread(() -> {
                    for (int j = 0; j < 1000; j++) {
                        assertEquals(expectedSize, buffer.size());
                    }
                });
                threads[i].start();
            }
            
            // Wait for all threads
            for (Thread thread : threads) {
                thread.join();
            }
        }
    }
}