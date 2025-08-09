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
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;

import jcifs.internal.util.SMBUtil;

/**
 * Test suite for DfsReferralResponseBuffer
 */
class DfsReferralResponseBufferTest {

    private DfsReferralResponseBuffer buffer;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        buffer = new DfsReferralResponseBuffer();
    }

    @Nested
    @DisplayName("Constructor and Initial State Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should initialize with null referrals")
        void testInitialState() {
            assertNull(buffer.getReferrals());
            assertEquals(0, buffer.getPathConsumed());
            assertEquals(0, buffer.getNumReferrals());
            assertEquals(0, buffer.getTflags());
        }
    }

    @Nested
    @DisplayName("Decode Tests")
    class DecodeTests {

        @Test
        @DisplayName("Should decode buffer with no referrals")
        void testDecodeNoReferrals() {
            // Prepare test data: pathConsumed=0, numReferrals=0, tflags=0
            byte[] testBuffer = new byte[8];
            ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
            bb.putShort((short) 0);  // pathConsumed (will be divided by 2)
            bb.putShort((short) 0);  // numReferrals
            bb.putShort((short) 0);  // tflags
            bb.putShort((short) 0);  // tflags high bytes (skipped in decode)

            int bytesDecoded = buffer.decode(testBuffer, 0, testBuffer.length);

            assertEquals(8, bytesDecoded);
            assertEquals(0, buffer.getPathConsumed());
            assertEquals(0, buffer.getNumReferrals());
            assertEquals(0, buffer.getTflags());
            assertNotNull(buffer.getReferrals());
            assertEquals(0, buffer.getReferrals().length);
        }

        @Test
        @DisplayName("Should decode buffer with single referral")
        void testDecodeSingleReferral() {
            // Create buffer with one v3 referral
            byte[] testBuffer = new byte[100];
            ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
            
            // DfsReferralResponseBuffer header
            bb.putShort((short) 16);  // pathConsumed (will be divided by 2 = 8)
            bb.putShort((short) 1);   // numReferrals
            bb.putShort((short) 5);   // tflags
            bb.putShort((short) 0);   // tflags high bytes (skipped)
            
            // Referral v3 structure
            bb.putShort((short) 3);   // version
            bb.putShort((short) 34);  // size
            bb.putShort((short) 1);   // serverType
            bb.putShort((short) 2);   // rflags
            bb.putShort((short) 10);  // proximity
            bb.putShort((short) 300); // ttl
            bb.putShort((short) 20);  // pathOffset
            bb.putShort((short) 24);  // altPathOffset
            bb.putShort((short) 28);  // nodeOffset
            
            // Add path string at offset 20 (8 + 20 = 28)
            bb.position(28);
            bb.put("\\test\0".getBytes(StandardCharsets.UTF_16LE));

            int bytesDecoded = buffer.decode(testBuffer, 0, testBuffer.length);

            assertEquals(42, bytesDecoded); // 8 header + 34 referral
            assertEquals(8, buffer.getPathConsumed());
            assertEquals(1, buffer.getNumReferrals());
            assertEquals(5, buffer.getTflags());
            assertNotNull(buffer.getReferrals());
            assertEquals(1, buffer.getReferrals().length);
            assertEquals(3, buffer.getReferrals()[0].getVersion());
        }

        @Test
        @DisplayName("Should decode buffer with multiple referrals")
        void testDecodeMultipleReferrals() {
            // Create buffer with two v1 referrals
            byte[] testBuffer = new byte[200];
            ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
            
            // DfsReferralResponseBuffer header
            bb.putShort((short) 32);  // pathConsumed (will be divided by 2 = 16)
            bb.putShort((short) 2);   // numReferrals
            bb.putShort((short) 7);   // tflags
            bb.putShort((short) 0);   // tflags high bytes
            
            // First Referral v1
            bb.putShort((short) 1);   // version
            bb.putShort((short) 20);  // size
            bb.putShort((short) 2);   // serverType
            bb.putShort((short) 3);   // rflags
            // v1 node string follows
            bb.put("\\server1\0".getBytes(StandardCharsets.UTF_16LE));
            
            // Position for second referral
            bb.position(28); // 8 header + 20 first referral
            
            // Second Referral v1
            bb.putShort((short) 1);   // version
            bb.putShort((short) 22);  // size
            bb.putShort((short) 2);   // serverType
            bb.putShort((short) 4);   // rflags
            // v1 node string follows
            bb.put("\\server2\0".getBytes(StandardCharsets.UTF_16LE));

            int bytesDecoded = buffer.decode(testBuffer, 0, testBuffer.length);

            assertEquals(50, bytesDecoded); // 8 header + 20 + 22 referrals
            assertEquals(16, buffer.getPathConsumed());
            assertEquals(2, buffer.getNumReferrals());
            assertEquals(7, buffer.getTflags());
            assertNotNull(buffer.getReferrals());
            assertEquals(2, buffer.getReferrals().length);
            assertEquals(1, buffer.getReferrals()[0].getVersion());
            assertEquals(1, buffer.getReferrals()[1].getVersion());
        }

        @ParameterizedTest
        @DisplayName("Should handle various pathConsumed values")
        @CsvSource({
            "0, 0",
            "10, 5",
            "100, 50",
            "1000, 500",
            "65534, 32767"
        })
        void testPathConsumedValues(int rawValue, int expectedResult) {
            byte[] testBuffer = new byte[8];
            ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
            bb.putShort((short) rawValue);  // pathConsumed
            bb.putShort((short) 0);         // numReferrals
            bb.putShort((short) 0);         // tflags
            bb.putShort((short) 0);         // tflags high bytes

            buffer.decode(testBuffer, 0, testBuffer.length);

            assertEquals(expectedResult, buffer.getPathConsumed());
        }

        @ParameterizedTest
        @DisplayName("Should handle various tflags values")
        @ValueSource(ints = {0, 1, 255, 256, 32767, 65535})
        void testTflagsValues(int tflagsValue) {
            byte[] testBuffer = new byte[8];
            ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
            bb.putShort((short) 0);         // pathConsumed
            bb.putShort((short) 0);         // numReferrals
            bb.putShort((short) tflagsValue); // tflags
            bb.putShort((short) 0);         // tflags high bytes (skipped)

            buffer.decode(testBuffer, 0, testBuffer.length);

            assertEquals(tflagsValue, buffer.getTflags());
        }

        @Test
        @DisplayName("Should decode with non-zero buffer offset")
        void testDecodeWithOffset() {
            byte[] testBuffer = new byte[20];
            int offset = 5;
            ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
            
            // Add padding before actual data
            bb.position(offset);
            bb.putShort((short) 24);  // pathConsumed
            bb.putShort((short) 0);   // numReferrals
            bb.putShort((short) 10);  // tflags
            bb.putShort((short) 0);   // tflags high bytes

            int bytesDecoded = buffer.decode(testBuffer, offset, testBuffer.length - offset);

            assertEquals(8, bytesDecoded);
            assertEquals(12, buffer.getPathConsumed()); // 24 / 2
            assertEquals(0, buffer.getNumReferrals());
            assertEquals(10, buffer.getTflags());
        }

        @Test
        @DisplayName("Should handle referral decode failure gracefully")
        void testReferralDecodeFailure() {
            // Create buffer with invalid referral data
            byte[] testBuffer = new byte[20];
            ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
            
            bb.putShort((short) 0);   // pathConsumed
            bb.putShort((short) 1);   // numReferrals = 1
            bb.putShort((short) 0);   // tflags
            bb.putShort((short) 0);   // tflags high bytes
            
            // Invalid referral version
            bb.putShort((short) 99);  // unsupported version

            // Should throw exception for unsupported version
            assertThrows(Exception.class, () -> {
                buffer.decode(testBuffer, 0, testBuffer.length);
            });
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should return string representation with no referrals")
        void testToStringNoReferrals() {
            byte[] testBuffer = new byte[8];
            ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
            bb.putShort((short) 10);
            bb.putShort((short) 0);
            bb.putShort((short) 5);
            bb.putShort((short) 0);

            buffer.decode(testBuffer, 0, testBuffer.length);
            String result = buffer.toString();

            assertNotNull(result);
            assertTrue(result.contains("pathConsumed=5"));
            assertTrue(result.contains("numReferrals=0"));
            assertTrue(result.contains("flags=5"));
            assertTrue(result.contains("referrals=[]"));
        }

        @Test
        @DisplayName("Should return string representation with referrals")
        void testToStringWithReferrals() {
            byte[] testBuffer = new byte[50];
            ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
            
            bb.putShort((short) 20);  // pathConsumed
            bb.putShort((short) 1);   // numReferrals
            bb.putShort((short) 15);  // tflags
            bb.putShort((short) 0);   // tflags high bytes
            
            // Simple v1 referral
            bb.putShort((short) 1);   // version
            bb.putShort((short) 16);  // size
            bb.putShort((short) 1);   // serverType
            bb.putShort((short) 2);   // rflags
            bb.put("\\test\0".getBytes(StandardCharsets.UTF_16LE));

            buffer.decode(testBuffer, 0, testBuffer.length);
            String result = buffer.toString();

            assertNotNull(result);
            assertTrue(result.contains("pathConsumed=10"));
            assertTrue(result.contains("numReferrals=1"));
            assertTrue(result.contains("flags=15"));
            assertTrue(result.contains("referrals=["));
            assertFalse(result.contains("referrals=[]"));
        }
    }

    @Nested
    @DisplayName("Getter Methods Tests")
    class GetterTests {

        @BeforeEach
        void setupBuffer() {
            // Create buffer with 3 v1 referrals
            byte[] testBuffer = new byte[100];
            ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
            
            // Header
            bb.putShort((short) 100);  // pathConsumed
            bb.putShort((short) 3);    // numReferrals
            bb.putShort((short) 25);   // tflags
            bb.putShort((short) 0);    // tflags high bytes

            // First Referral v1
            bb.putShort((short) 1);   // version
            bb.putShort((short) 16);  // size
            bb.putShort((short) 1);   // serverType
            bb.putShort((short) 2);   // rflags
            bb.put("\\srv1\0".getBytes(StandardCharsets.UTF_16LE));
            
            // Position for second referral
            bb.position(24); // 8 header + 16 first referral
            
            // Second Referral v1
            bb.putShort((short) 1);   // version
            bb.putShort((short) 16);  // size
            bb.putShort((short) 1);   // serverType
            bb.putShort((short) 3);   // rflags
            bb.put("\\srv2\0".getBytes(StandardCharsets.UTF_16LE));
            
            // Position for third referral
            bb.position(40); // 8 header + 16 + 16
            
            // Third Referral v1
            bb.putShort((short) 1);   // version
            bb.putShort((short) 16);  // size
            bb.putShort((short) 2);   // serverType
            bb.putShort((short) 4);   // rflags
            bb.put("\\srv3\0".getBytes(StandardCharsets.UTF_16LE));

            buffer.decode(testBuffer, 0, testBuffer.length);
        }

        @Test
        @DisplayName("Should return correct pathConsumed value")
        void testGetPathConsumed() {
            assertEquals(50, buffer.getPathConsumed()); // 100 / 2
        }

        @Test
        @DisplayName("Should return correct numReferrals value")
        void testGetNumReferrals() {
            assertEquals(3, buffer.getNumReferrals());
        }

        @Test
        @DisplayName("Should return correct tflags value")
        void testGetTflags() {
            assertEquals(25, buffer.getTflags());
        }

        @Test
        @DisplayName("Should return referrals array")
        void testGetReferrals() {
            assertNotNull(buffer.getReferrals());
            assertEquals(3, buffer.getReferrals().length);
        }
    }

    @Nested
    @DisplayName("Edge Cases and Boundary Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle maximum values")
        void testMaximumValues() {
            byte[] testBuffer = new byte[8];
            ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
            bb.putShort((short) 0xFFFE);  // Max even pathConsumed
            bb.putShort((short) 0);       // numReferrals
            bb.putShort((short) 0xFFFF);  // Max tflags
            bb.putShort((short) 0);       // tflags high bytes

            buffer.decode(testBuffer, 0, testBuffer.length);

            assertEquals(32767, buffer.getPathConsumed()); // 65534 / 2
            assertEquals(65535, buffer.getTflags());
        }

        @Test
        @DisplayName("Should handle minimum buffer size")
        void testMinimumBufferSize() {
            byte[] testBuffer = new byte[8]; // Minimum size for header
            
            int bytesDecoded = buffer.decode(testBuffer, 0, testBuffer.length);

            assertEquals(8, bytesDecoded);
            assertEquals(0, buffer.getPathConsumed());
            assertEquals(0, buffer.getNumReferrals());
        }

        @Test
        @DisplayName("Should handle odd pathConsumed values")
        void testOddPathConsumedValue() {
            byte[] testBuffer = new byte[8];
            ByteBuffer bb = ByteBuffer.wrap(testBuffer).order(ByteOrder.LITTLE_ENDIAN);
            bb.putShort((short) 15);  // Odd number
            bb.putShort((short) 0);
            bb.putShort((short) 0);
            bb.putShort((short) 0);

            buffer.decode(testBuffer, 0, testBuffer.length);

            assertEquals(7, buffer.getPathConsumed()); // 15 / 2 = 7 (integer division)
        }
    }
}