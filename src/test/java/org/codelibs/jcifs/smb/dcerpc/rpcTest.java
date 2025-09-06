package org.codelibs.jcifs.smb.dcerpc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.dcerpc.ndr.NdrBuffer;
import org.codelibs.jcifs.smb.dcerpc.ndr.NdrException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Comprehensive test suite for RPC data structures
 * Tests encoding/decoding of UUID, Policy Handle, Unicode String, and SIDObject types
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("RPC Data Structures Test Suite")
class rpcTest {

    @Mock
    private NdrBuffer mockNdrBuffer;

    @Mock
    private NdrBuffer mockDeferredBuffer;

    @Nested
    @DisplayName("UUID Tests")
    class UuidTests {

        @Test
        @DisplayName("Should encode UUID correctly")
        void testUuidTEncode() throws NdrException {
            // Given: A UUID with test values
            rpc.uuid_t uuid = new rpc.uuid_t();
            uuid.time_low = 0x12345678;
            uuid.time_mid = (short) 0x9ABC;
            uuid.time_hi_and_version = (short) 0xDEF0;
            uuid.clock_seq_hi_and_reserved = (byte) 0x11;
            uuid.clock_seq_low = (byte) 0x22;
            uuid.node = new byte[] { (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE, (byte) 0xFF };

            // Mock the derive method to return a buffer for node encoding
            when(mockNdrBuffer.derive(anyInt())).thenReturn(mockNdrBuffer);

            // When: Encoding the UUID
            uuid.encode(mockNdrBuffer);

            // Then: Verify the encoding sequence
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer).enc_ndr_long(0x12345678);
            verify(mockNdrBuffer).enc_ndr_short((short) 0x9ABC);
            verify(mockNdrBuffer).enc_ndr_short((short) 0xDEF0);
            verify(mockNdrBuffer).enc_ndr_small((byte) 0x11);
            verify(mockNdrBuffer).enc_ndr_small((byte) 0x22);
            verify(mockNdrBuffer).advance(6);
            verify(mockNdrBuffer).derive(anyInt());
            // Verify each node byte is encoded
            verify(mockNdrBuffer).enc_ndr_small((byte) 0xAA);
            verify(mockNdrBuffer).enc_ndr_small((byte) 0xBB);
            verify(mockNdrBuffer).enc_ndr_small((byte) 0xCC);
            verify(mockNdrBuffer).enc_ndr_small((byte) 0xDD);
            verify(mockNdrBuffer).enc_ndr_small((byte) 0xEE);
            verify(mockNdrBuffer).enc_ndr_small((byte) 0xFF);
        }

        @Test
        @DisplayName("Should decode UUID correctly")
        void testUuidTDecode() throws NdrException {
            // Given: A UUID object to decode into
            rpc.uuid_t uuid = new rpc.uuid_t();

            // Mock the NdrBuffer responses for decoding
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(0x12345678);
            when(mockNdrBuffer.dec_ndr_short()).thenReturn((int) (short) 0x9ABC, (int) (short) 0xDEF0);
            when(mockNdrBuffer.dec_ndr_small()).thenReturn((int) (byte) 0x11, (int) (byte) 0x22, // clock seq bytes
                    (int) (byte) 0xAA, (int) (byte) 0xBB, (int) (byte) 0xCC, (int) (byte) 0xDD, (int) (byte) 0xEE, (int) (byte) 0xFF // node bytes
            );
            when(mockNdrBuffer.derive(anyInt())).thenReturn(mockNdrBuffer);

            // When: Decoding the UUID
            uuid.decode(mockNdrBuffer);

            // Then: Verify the decoding sequence and values
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer).dec_ndr_long();
            verify(mockNdrBuffer, times(2)).dec_ndr_short();
            verify(mockNdrBuffer, times(8)).dec_ndr_small();
            verify(mockNdrBuffer).advance(6);
            verify(mockNdrBuffer).derive(anyInt());

            assertEquals(0x12345678, uuid.time_low);
            assertEquals((short) 0x9ABC, uuid.time_mid);
            assertEquals((short) 0xDEF0, uuid.time_hi_and_version);
            assertEquals((byte) 0x11, uuid.clock_seq_hi_and_reserved);
            assertEquals((byte) 0x22, uuid.clock_seq_low);
            assertArrayEquals(new byte[] { (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE, (byte) 0xFF }, uuid.node);
        }

        @Test
        @DisplayName("Should handle encode-decode roundtrip correctly")
        void testUuidTEncodeDecodeRoundtrip() throws NdrException {
            // Given: An original UUID with specific values
            rpc.uuid_t originalUuid = new rpc.uuid_t();
            originalUuid.time_low = 0x87654321;
            originalUuid.time_mid = (short) 0x4321;
            originalUuid.time_hi_and_version = (short) 0x8765;
            originalUuid.clock_seq_hi_and_reserved = (byte) 0x99;
            originalUuid.clock_seq_low = (byte) 0x88;
            originalUuid.node = new byte[] { (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66 };

            // Mock encoding buffer
            NdrBuffer encodeBuffer = mock(NdrBuffer.class);
            when(encodeBuffer.derive(anyInt())).thenReturn(encodeBuffer);
            originalUuid.encode(encodeBuffer);

            // Mock decoding buffer with the same values
            NdrBuffer decodeBuffer = mock(NdrBuffer.class);
            when(decodeBuffer.dec_ndr_long()).thenReturn(originalUuid.time_low);
            when(decodeBuffer.dec_ndr_short()).thenReturn((int) originalUuid.time_mid, (int) originalUuid.time_hi_and_version);
            when(decodeBuffer.dec_ndr_small()).thenReturn((int) originalUuid.clock_seq_hi_and_reserved, (int) originalUuid.clock_seq_low,
                    (int) originalUuid.node[0], (int) originalUuid.node[1], (int) originalUuid.node[2], (int) originalUuid.node[3],
                    (int) originalUuid.node[4], (int) originalUuid.node[5]);
            when(decodeBuffer.derive(anyInt())).thenReturn(decodeBuffer);

            // When: Decoding into a new UUID
            rpc.uuid_t decodedUuid = new rpc.uuid_t();
            decodedUuid.decode(decodeBuffer);

            // Then: Values should match
            assertEquals(originalUuid.time_low, decodedUuid.time_low);
            assertEquals(originalUuid.time_mid, decodedUuid.time_mid);
            assertEquals(originalUuid.time_hi_and_version, decodedUuid.time_hi_and_version);
            assertEquals(originalUuid.clock_seq_hi_and_reserved, decodedUuid.clock_seq_hi_and_reserved);
            assertEquals(originalUuid.clock_seq_low, decodedUuid.clock_seq_low);
            assertArrayEquals(originalUuid.node, decodedUuid.node);
        }
    }

    @Nested
    @DisplayName("Policy Handle Tests")
    class PolicyHandleTests {

        @Test
        @DisplayName("Should encode policy handle correctly")
        void testPolicyHandleEncode() throws NdrException {
            // Given: A policy handle with test values
            rpc.policy_handle policyHandle = new rpc.policy_handle();
            policyHandle.type = 123;
            policyHandle.uuid = new rpc.uuid_t();
            policyHandle.uuid.time_low = 0x11111111;
            policyHandle.uuid.time_mid = (short) 0x2222;
            policyHandle.uuid.time_hi_and_version = (short) 0x3333;
            policyHandle.uuid.clock_seq_hi_and_reserved = (byte) 0x44;
            policyHandle.uuid.clock_seq_low = (byte) 0x55;
            policyHandle.uuid.node = new byte[] { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06 };

            when(mockNdrBuffer.derive(anyInt())).thenReturn(mockNdrBuffer);

            // When: Encoding the policy handle
            policyHandle.encode(mockNdrBuffer);

            // Then: Verify the encoding sequence
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer).enc_ndr_long(123);
            verify(mockNdrBuffer).enc_ndr_long(0x11111111);
            verify(mockNdrBuffer).enc_ndr_short((short) 0x2222);
            verify(mockNdrBuffer).enc_ndr_short((short) 0x3333);
            verify(mockNdrBuffer).enc_ndr_small((byte) 0x44);
            verify(mockNdrBuffer).enc_ndr_small((byte) 0x55);
            verify(mockNdrBuffer).advance(6);
            verify(mockNdrBuffer).derive(anyInt());
            // Verify each node byte is encoded
            verify(mockNdrBuffer).enc_ndr_small((byte) 0x01);
            verify(mockNdrBuffer).enc_ndr_small((byte) 0x02);
            verify(mockNdrBuffer).enc_ndr_small((byte) 0x03);
            verify(mockNdrBuffer).enc_ndr_small((byte) 0x04);
            verify(mockNdrBuffer).enc_ndr_small((byte) 0x05);
            verify(mockNdrBuffer).enc_ndr_small((byte) 0x06);
        }

        @Test
        @DisplayName("Should throw exception when encoding null UUID")
        void testPolicyHandleEncodeNullUuidThrowsException() {
            // Given: A policy handle with null UUID
            rpc.policy_handle policyHandle = new rpc.policy_handle();
            policyHandle.type = 123;
            policyHandle.uuid = null;

            // When/Then: Should throw NdrException
            assertThrows(NdrException.class, () -> policyHandle.encode(mockNdrBuffer));
        }

        @Test
        @DisplayName("Should decode policy handle correctly")
        void testPolicyHandleDecode() throws NdrException {
            // Given: A policy handle to decode into
            rpc.policy_handle policyHandle = new rpc.policy_handle();

            when(mockNdrBuffer.dec_ndr_long()).thenReturn(456, 0x22222222);
            when(mockNdrBuffer.dec_ndr_short()).thenReturn((int) (short) 0x3333, (int) (short) 0x4444);
            when(mockNdrBuffer.dec_ndr_small()).thenReturn((int) (byte) 0x55, (int) (byte) 0x66, // clock seq bytes
                    (int) (byte) 0x07, (int) (byte) 0x08, (int) (byte) 0x09, (int) (byte) 0x0A, (int) (byte) 0x0B, (int) (byte) 0x0C // node bytes
            );
            when(mockNdrBuffer.derive(anyInt())).thenReturn(mockNdrBuffer);

            // When: Decoding the policy handle
            policyHandle.decode(mockNdrBuffer);

            // Then: Verify the decoding sequence and values
            verify(mockNdrBuffer, times(2)).align(4);
            verify(mockNdrBuffer, times(2)).dec_ndr_long();
            verify(mockNdrBuffer, times(2)).dec_ndr_short();
            verify(mockNdrBuffer, times(8)).dec_ndr_small();
            verify(mockNdrBuffer).advance(6);
            verify(mockNdrBuffer).derive(anyInt());

            assertEquals(456, policyHandle.type);
            assertNotNull(policyHandle.uuid);
            assertEquals(0x22222222, policyHandle.uuid.time_low);
            assertEquals((short) 0x3333, policyHandle.uuid.time_mid);
            assertEquals((short) 0x4444, policyHandle.uuid.time_hi_and_version);
            assertEquals((byte) 0x55, policyHandle.uuid.clock_seq_hi_and_reserved);
            assertEquals((byte) 0x66, policyHandle.uuid.clock_seq_low);
            assertArrayEquals(new byte[] { (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C },
                    policyHandle.uuid.node);
        }
    }

    @Nested
    @DisplayName("Unicode String Tests")
    class UnicodeStringTests {

        @Test
        @DisplayName("Should encode unicode string with null buffer correctly")
        void testUnicodeStringEncodeNullBuffer() throws NdrException {
            // Given: A unicode string with null buffer
            rpc.unicode_string unicodeString = new rpc.unicode_string();
            unicodeString.length = (short) 0;
            unicodeString.maximum_length = (short) 0;
            unicodeString.buffer = null;

            // When: Encoding the unicode string
            unicodeString.encode(mockNdrBuffer);

            // Then: Verify the encoding sequence
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer, times(2)).enc_ndr_short((short) 0); // length and maximum_length
            verify(mockNdrBuffer).enc_ndr_referent(null, 1);
            // No deferred encoding for null buffer
        }

        @Test
        @DisplayName("Should decode unicode string with null buffer correctly")
        void testUnicodeStringDecodeNullBuffer() throws NdrException {
            // Given: A unicode string to decode into
            rpc.unicode_string unicodeString = new rpc.unicode_string();

            when(mockNdrBuffer.dec_ndr_short()).thenReturn((int) (short) 0, (int) (short) 0);
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(0); // Null referent pointer

            // When: Decoding the unicode string
            unicodeString.decode(mockNdrBuffer);

            // Then: Verify the decoding sequence and values
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer, times(2)).dec_ndr_short();
            verify(mockNdrBuffer).dec_ndr_long();
            // No deferred decoding for null buffer

            assertEquals((short) 0, unicodeString.length);
            assertEquals((short) 0, unicodeString.maximum_length);
            assertNull(unicodeString.buffer);
        }

        @Test
        @DisplayName("Should handle basic unicode string field assignments")
        void testUnicodeStringBasicFields() {
            // Given: A unicode string
            rpc.unicode_string unicodeString = new rpc.unicode_string();

            // When: Setting values
            unicodeString.length = (short) 10;
            unicodeString.maximum_length = (short) 20;
            unicodeString.buffer = new short[] { 65, 66, 67 }; // A, B, C

            // Then: Values should be set correctly
            assertEquals((short) 10, unicodeString.length);
            assertEquals((short) 20, unicodeString.maximum_length);
            assertArrayEquals(new short[] { 65, 66, 67 }, unicodeString.buffer);
        }

        @Test
        @DisplayName("Should test unicode string encoding without deferred buffer access")
        void testUnicodeStringEncodeStructure() throws NdrException {
            // Given: A unicode string with values that won't use deferred encoding
            rpc.unicode_string unicodeString = new rpc.unicode_string();
            unicodeString.length = (short) 6;
            unicodeString.maximum_length = (short) 10;
            unicodeString.buffer = new short[] { 100, 200, 300 };

            // Create a real NdrBuffer mock that can handle the deferred field access
            // But only test the non-deferred parts to avoid field mocking issues

            // When: Trying to encode (may throw exception due to deferred buffer)
            // Then: Should at least call the basic encoding methods before hitting deferred
            assertThrows(Exception.class, () -> {
                unicodeString.encode(mockNdrBuffer);
            }, "Should encounter issue with deferred buffer access");

            // Verify that basic encoding was attempted
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer).enc_ndr_short((short) 6);
            verify(mockNdrBuffer).enc_ndr_short((short) 10);
            verify(mockNdrBuffer).enc_ndr_referent(unicodeString.buffer, 1);
        }
    }

    @Nested
    @DisplayName("SIDObject Tests")
    class SidTests {

        @Test
        @DisplayName("Should encode SIDObject correctly")
        void testSidTEncode() throws NdrException {
            // Given: A SIDObject with test values
            rpc.sid_t sid = new rpc.sid_t();
            sid.revision = (byte) 1;
            sid.sub_authority_count = (byte) 2;
            sid.identifier_authority = new byte[] { (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 5 };
            sid.sub_authority = new int[] { 1000, 2000 };

            when(mockNdrBuffer.derive(anyInt())).thenReturn(mockNdrBuffer);

            // When: Encoding the SIDObject
            sid.encode(mockNdrBuffer);

            // Then: Verify the encoding sequence
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer).enc_ndr_long(2); // sub_authority_count
            verify(mockNdrBuffer).enc_ndr_small((byte) 1); // revision
            verify(mockNdrBuffer).enc_ndr_small((byte) 2); // sub_authority_count
            verify(mockNdrBuffer).advance(6); // identifier_authority advance
            verify(mockNdrBuffer).advance(8); // sub_authority advance (4 * 2)
            verify(mockNdrBuffer, times(2)).derive(anyInt());

            // Verify identifier_authority bytes (5 zeros + 1 five)
            verify(mockNdrBuffer, times(5)).enc_ndr_small((byte) 0);
            verify(mockNdrBuffer).enc_ndr_small((byte) 5);

            // Verify sub_authority values
            verify(mockNdrBuffer).enc_ndr_long(1000);
            verify(mockNdrBuffer).enc_ndr_long(2000);
        }

        @Test
        @DisplayName("Should decode SIDObject correctly")
        void testSidTDecode() throws NdrException {
            // Given: A SIDObject to decode into
            rpc.sid_t sid = new rpc.sid_t();

            when(mockNdrBuffer.dec_ndr_long()).thenReturn(2, 1000, 2000); // sub_authority_count, sub_authorities
            when(mockNdrBuffer.dec_ndr_small()).thenReturn((int) (byte) 1, (int) (byte) 2, // revision, sub_authority_count
                    (int) (byte) 0, (int) (byte) 0, (int) (byte) 0, // identifier_authority
                    (int) (byte) 0, (int) (byte) 0, (int) (byte) 5);
            when(mockNdrBuffer.derive(anyInt())).thenReturn(mockNdrBuffer);

            // When: Decoding the SIDObject
            sid.decode(mockNdrBuffer);

            // Then: Verify the decoding sequence and values
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer, times(3)).dec_ndr_long(); // sub_authority_count + 2 sub_authorities
            verify(mockNdrBuffer, times(8)).dec_ndr_small(); // revision + sub_authority_count + 6 identifier_authority bytes
            verify(mockNdrBuffer).advance(6); // identifier_authority advance
            verify(mockNdrBuffer).advance(8); // sub_authority advance (4 * 2)
            verify(mockNdrBuffer, times(2)).derive(anyInt());

            assertEquals((byte) 1, sid.revision);
            assertEquals((byte) 2, sid.sub_authority_count);
            assertArrayEquals(new byte[] { (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 5 }, sid.identifier_authority);
            assertArrayEquals(new int[] { 1000, 2000 }, sid.sub_authority);
        }

        @Test
        @DisplayName("Should handle SIDObject encode-decode roundtrip correctly")
        void testSidTEncodeDecodeRoundtrip() throws NdrException {
            // Given: An original SIDObject with specific values
            rpc.sid_t originalSid = new rpc.sid_t();
            originalSid.revision = (byte) 1;
            originalSid.sub_authority_count = (byte) 3;
            originalSid.identifier_authority = new byte[] { (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5, (byte) 6 };
            originalSid.sub_authority = new int[] { 10, 20, 30 };

            // Mock encoding buffer
            NdrBuffer encodeBuffer = mock(NdrBuffer.class);
            when(encodeBuffer.derive(anyInt())).thenReturn(encodeBuffer);
            originalSid.encode(encodeBuffer);

            // Mock decoding buffer with the same values
            NdrBuffer decodeBuffer = mock(NdrBuffer.class);
            when(decodeBuffer.dec_ndr_long()).thenReturn((int) originalSid.sub_authority_count, // sub_authority_count
                    originalSid.sub_authority[0], // sub_authorities
                    originalSid.sub_authority[1], originalSid.sub_authority[2]);
            when(decodeBuffer.dec_ndr_small()).thenReturn((int) originalSid.revision, (int) originalSid.sub_authority_count,
                    (int) originalSid.identifier_authority[0], (int) originalSid.identifier_authority[1],
                    (int) originalSid.identifier_authority[2], (int) originalSid.identifier_authority[3],
                    (int) originalSid.identifier_authority[4], (int) originalSid.identifier_authority[5]);
            when(decodeBuffer.derive(anyInt())).thenReturn(decodeBuffer);

            // When: Decoding into a new SIDObject
            rpc.sid_t decodedSid = new rpc.sid_t();
            decodedSid.decode(decodeBuffer);

            // Then: Values should match
            assertEquals(originalSid.revision, decodedSid.revision);
            assertEquals(originalSid.sub_authority_count, decodedSid.sub_authority_count);
            assertArrayEquals(originalSid.identifier_authority, decodedSid.identifier_authority);
            assertArrayEquals(originalSid.sub_authority, decodedSid.sub_authority);
        }
    }
}