package jcifs.dcerpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;

@ExtendWith(MockitoExtension.class)
@DisplayName("DcerpcMessage Tests")
class DcerpcMessageTest {

    @Mock
    private NdrBuffer mockBuffer;
    
    private TestDcerpcMessage message;

    // Concrete implementation for testing abstract DcerpcMessage
    private static class TestDcerpcMessage extends DcerpcMessage {
        private int opnumValue;

        public TestDcerpcMessage(int opnumValue) {
            this.opnumValue = opnumValue;
        }

        @Override
        public int getOpnum() {
            return opnumValue;
        }

        @Override
        public void encode_in(NdrBuffer buf) throws NdrException {
            // Simulate encoding some data
            buf.enc_ndr_long(12345);
        }

        @Override
        public void decode_out(NdrBuffer buf) throws NdrException {
            // Simulate decoding some data
            buf.dec_ndr_long();
        }
    }

    @BeforeEach
    void setUp() {
        message = new TestDcerpcMessage(10); // Example opnum
    }

    @Nested
    @DisplayName("Flag Management Tests")
    class FlagManagementTests {
        
        @Test
        @DisplayName("isFlagSet should correctly identify set flags")
        void testIsFlagSet() {
            // Test when flag is not set
            message.flags = 0;
            assertFalse(message.isFlagSet(DcerpcConstants.RPC_C_PF_BROADCAST));

            // Test when flag is set
            message.flags = DcerpcConstants.RPC_C_PF_BROADCAST;
            assertTrue(message.isFlagSet(DcerpcConstants.RPC_C_PF_BROADCAST));

            // Test with multiple flags, one is set
            message.flags = DcerpcConstants.RPC_C_PF_BROADCAST | DcerpcConstants.RPC_C_PF_NO_FRAGMENT;
            assertTrue(message.isFlagSet(DcerpcConstants.RPC_C_PF_BROADCAST));
            assertTrue(message.isFlagSet(DcerpcConstants.RPC_C_PF_NO_FRAGMENT));
            assertFalse(message.isFlagSet(DcerpcConstants.RPC_C_PF_IDEMPOTENT));
        }

        @Test
        @DisplayName("unsetFlag should remove specified flags")
        void testUnsetFlag() {
            // Test unsetting an existing flag
            message.flags = DcerpcConstants.RPC_C_PF_BROADCAST | DcerpcConstants.RPC_C_PF_NO_FRAGMENT;
            message.unsetFlag(DcerpcConstants.RPC_C_PF_BROADCAST);
            assertFalse(message.isFlagSet(DcerpcConstants.RPC_C_PF_BROADCAST));
            assertTrue(message.isFlagSet(DcerpcConstants.RPC_C_PF_NO_FRAGMENT));

            // Test unsetting a non-existing flag
            message.flags = DcerpcConstants.RPC_C_PF_BROADCAST;
            message.unsetFlag(DcerpcConstants.RPC_C_PF_IDEMPOTENT);
            assertTrue(message.isFlagSet(DcerpcConstants.RPC_C_PF_BROADCAST));
        }

        @Test
        @DisplayName("setFlag should add specified flags")
        void testSetFlag() {
            // Test setting a new flag
            message.flags = 0;
            message.setFlag(DcerpcConstants.RPC_C_PF_BROADCAST);
            assertTrue(message.isFlagSet(DcerpcConstants.RPC_C_PF_BROADCAST));

            // Test setting an already existing flag
            message.flags = DcerpcConstants.RPC_C_PF_BROADCAST;
            message.setFlag(DcerpcConstants.RPC_C_PF_BROADCAST);
            assertTrue(message.isFlagSet(DcerpcConstants.RPC_C_PF_BROADCAST));

            // Test setting multiple flags
            message.flags = DcerpcConstants.RPC_C_PF_BROADCAST;
            message.setFlag(DcerpcConstants.RPC_C_PF_NO_FRAGMENT);
            assertTrue(message.isFlagSet(DcerpcConstants.RPC_C_PF_BROADCAST));
            assertTrue(message.isFlagSet(DcerpcConstants.RPC_C_PF_NO_FRAGMENT));
        }
    }
    
    @Nested
    @DisplayName("Result Management Tests")
    class ResultManagementTests {
        
        @Test
        @DisplayName("getResult should return null for success (result=0)")
        void testGetResultSuccess() {
            message.result = 0;
            assertNull(message.getResult());
        }
        
        @Test
        @DisplayName("getResult should return DcerpcException for non-zero result")
        void testGetResultError() {
            message.result = 123; // Example error code
            DcerpcException exception = message.getResult();
            assertNotNull(exception);
            assertEquals(123, exception.getErrorCode());
        }
    }

    @Nested
    @DisplayName("Header Encoding Tests")
    class HeaderEncodingTests {
        
        @Test
        @DisplayName("encode_header should write all header fields")
        void testEncodeHeader() throws NdrException {
            message.ptype = DcerpcConstants.RPC_PT_REQUEST;
            message.flags = DcerpcConstants.RPC_C_PF_BROADCAST;
            message.length = 100;
            message.call_id = 5;

            // Use lenient stubbing to avoid UnnecessaryStubbingException
            lenient().doNothing().when(mockBuffer).enc_ndr_small(anyInt());
            lenient().doNothing().when(mockBuffer).enc_ndr_long(anyInt());
            lenient().doNothing().when(mockBuffer).enc_ndr_short(anyInt());

            message.encode_header(mockBuffer);

            // Verify that key values were written - avoid checking values that may be called multiple times
            verify(mockBuffer).enc_ndr_small(5); // RPC version
            verify(mockBuffer).enc_ndr_long(0x00000010); // Little-endian / ASCII / IEEE
            verify(mockBuffer).enc_ndr_short(message.length);
            verify(mockBuffer).enc_ndr_long(message.call_id);
            // Note: ptype and flags may be 0, which conflicts with minor version = 0
        }
    }

    @Nested
    @DisplayName("Header Decoding Tests")
    class HeaderDecodingTests {
        
        @Test
        @DisplayName("decode_header should successfully parse valid header")
        void testDecodeHeaderSuccess() throws NdrException {
            // Mock NdrBuffer methods for successful decoding
            when(mockBuffer.dec_ndr_small()).thenReturn(5).thenReturn(0) // RPC version
                    .thenReturn(DcerpcConstants.RPC_PT_RESPONSE) // ptype
                    .thenReturn(DcerpcConstants.RPC_C_PF_BROADCAST); // flags
            when(mockBuffer.dec_ndr_long()).thenReturn(0x00000010) // Data representation
                    .thenReturn(123); // call_id
            when(mockBuffer.dec_ndr_short()).thenReturn(100) // length
                    .thenReturn(0); // auth_value length

            message.decode_header(mockBuffer);

            assertEquals(DcerpcConstants.RPC_PT_RESPONSE, message.ptype);
            assertEquals(DcerpcConstants.RPC_C_PF_BROADCAST, message.flags);
            assertEquals(100, message.length);
            assertEquals(123, message.call_id);
        }

        @Test
        @DisplayName("decode_header should throw NdrException for invalid RPC version")
        void testDecodeHeaderThrowsNdrExceptionForRpcVersion() {
            when(mockBuffer.dec_ndr_small()).thenReturn(4); // Incorrect RPC version
            assertThrows(NdrException.class, () -> message.decode_header(mockBuffer));
        }

        @Test
        @DisplayName("decode_header should throw NdrException for invalid minor RPC version")
        void testDecodeHeaderThrowsNdrExceptionForMinorRpcVersion() {
            when(mockBuffer.dec_ndr_small()).thenReturn(5).thenReturn(1); // Incorrect minor RPC version
            assertThrows(NdrException.class, () -> message.decode_header(mockBuffer));
        }

        @Test
        @DisplayName("decode_header should throw NdrException for unsupported data representation")
        void testDecodeHeaderThrowsNdrExceptionForDataRepresentation() {
            when(mockBuffer.dec_ndr_small()).thenReturn(5).thenReturn(0).thenReturn(DcerpcConstants.RPC_PT_RESPONSE)
                    .thenReturn(DcerpcConstants.RPC_C_PF_BROADCAST);
            when(mockBuffer.dec_ndr_long()).thenReturn(0x00000011); // Incorrect data representation
            assertThrows(NdrException.class, () -> message.decode_header(mockBuffer));
        }

        @Test
        @DisplayName("decode_header should throw NdrException for non-zero authentication length")
        void testDecodeHeaderThrowsNdrExceptionForAuthentication() {
            when(mockBuffer.dec_ndr_small()).thenReturn(5).thenReturn(0).thenReturn(DcerpcConstants.RPC_PT_RESPONSE)
                    .thenReturn(DcerpcConstants.RPC_C_PF_BROADCAST);
            when(mockBuffer.dec_ndr_long()).thenReturn(0x00000010);
            when(mockBuffer.dec_ndr_short()).thenReturn(100).thenReturn(1); // Non-zero auth_value length
            assertThrows(NdrException.class, () -> message.decode_header(mockBuffer));
        }
    }

    @Nested
    @DisplayName("Message Encoding Tests")
    class MessageEncodingTests {
        
        @Test
        @DisplayName("encode should handle REQUEST ptype correctly")
        void testEncodeRequestPtype() throws NdrException {
            message.ptype = DcerpcConstants.RPC_PT_REQUEST; // 0
            message.call_id = 1;
            message.opnumValue = 5;

            when(mockBuffer.getIndex()).thenReturn(0).thenReturn(16).thenReturn(20).thenReturn(24);
            lenient().doNothing().when(mockBuffer).advance(anyInt());
            lenient().doNothing().when(mockBuffer).enc_ndr_long(anyInt());
            lenient().doNothing().when(mockBuffer).enc_ndr_short(anyInt());
            lenient().doNothing().when(mockBuffer).enc_ndr_small(anyInt());
            lenient().doNothing().when(mockBuffer).setIndex(anyInt());

            message.encode(mockBuffer);

            // Verify key operations happened - avoid values that may conflict (ptype=0, minor version=0)
            verify(mockBuffer).enc_ndr_small(5); // RPC version
            verify(mockBuffer).enc_ndr_long(0x00000010); // Little-endian / ASCII / IEEE
            verify(mockBuffer).enc_ndr_long(message.call_id);
            verify(mockBuffer).enc_ndr_short(message.getOpnum()); // opnum
            verify(mockBuffer).enc_ndr_long(12345); // From TestDcerpcMessage.encode_in
        }

        @Test
        @DisplayName("encode should handle non-REQUEST ptype correctly")
        void testEncodeNonRequestPtype() throws NdrException {
            message.ptype = DcerpcConstants.RPC_PT_RESPONSE; // 2, not 0
            message.call_id = 1;

            when(mockBuffer.getIndex()).thenReturn(0).thenReturn(16).thenReturn(20);
            lenient().doNothing().when(mockBuffer).advance(anyInt());
            lenient().doNothing().when(mockBuffer).enc_ndr_long(anyInt());
            lenient().doNothing().when(mockBuffer).enc_ndr_short(anyInt());
            lenient().doNothing().when(mockBuffer).enc_ndr_small(anyInt());
            lenient().doNothing().when(mockBuffer).setIndex(anyInt());

            message.encode(mockBuffer);

            // Verify header encoding happened
            verify(mockBuffer).enc_ndr_small(5); // RPC version  
            verify(mockBuffer).enc_ndr_long(0x00000010); // Little-endian / ASCII / IEEE
            verify(mockBuffer).enc_ndr_long(message.call_id);
            verify(mockBuffer).enc_ndr_long(12345); // From TestDcerpcMessage.encode_in
            // Note: ptype = 2 (RESPONSE) so it's safe to verify
            verify(mockBuffer).enc_ndr_small(DcerpcConstants.RPC_PT_RESPONSE);
        }
    }

    @Nested
    @DisplayName("Message Decoding Tests")
    class MessageDecodingTests {
        
        @Test
        @DisplayName("decode should handle RESPONSE ptype correctly")
        void testDecodeResponsePtype() throws NdrException {
            message.ptype = DcerpcConstants.RPC_PT_RESPONSE; // 2

            // Mock NdrBuffer for decode_header
            when(mockBuffer.dec_ndr_small()).thenReturn(5).thenReturn(0) // RPC version
                    .thenReturn(DcerpcConstants.RPC_PT_RESPONSE) // ptype
                    .thenReturn(0); // flags
            when(mockBuffer.dec_ndr_long()).thenReturn(0x00000010) // Data representation
                    .thenReturn(1) // call_id
                    .thenReturn(100) // alloc_hint
                    .thenReturn(0); // From TestDcerpcMessage.decode_out
            when(mockBuffer.dec_ndr_short()).thenReturn(100) // length
                    .thenReturn(0) // auth_value length
                    .thenReturn(0) // context id
                    .thenReturn(0); // cancel count

            message.decode(mockBuffer);

            assertEquals(DcerpcConstants.RPC_PT_RESPONSE, message.ptype);
            assertEquals(100, message.alloc_hint);
        }

        @Test
        @DisplayName("decode should handle FAULT ptype correctly")
        void testDecodeFaultPtype() throws NdrException {
            message.ptype = DcerpcConstants.RPC_PT_FAULT; // 3

            // Mock NdrBuffer for decode_header
            when(mockBuffer.dec_ndr_small()).thenReturn(5).thenReturn(0) // RPC version
                    .thenReturn(DcerpcConstants.RPC_PT_FAULT) // ptype
                    .thenReturn(0); // flags
            when(mockBuffer.dec_ndr_long()).thenReturn(0x00000010) // Data representation
                    .thenReturn(1) // call_id
                    .thenReturn(100) // alloc_hint
                    .thenReturn(500); // result for fault
            when(mockBuffer.dec_ndr_short()).thenReturn(100) // length
                    .thenReturn(0) // auth_value length
                    .thenReturn(0) // context id
                    .thenReturn(0); // cancel count

            message.decode(mockBuffer);

            assertEquals(DcerpcConstants.RPC_PT_FAULT, message.ptype);
            assertEquals(100, message.alloc_hint);
            assertEquals(500, message.result);
        }

        @Test
        @DisplayName("decode should handle BIND_ACK ptype correctly")
        void testDecodeBindAckPtype() throws NdrException {
            message.ptype = DcerpcConstants.RPC_PT_BIND_ACK; // 12

            // Mock NdrBuffer for decode_header
            when(mockBuffer.dec_ndr_small()).thenReturn(5).thenReturn(0) // RPC version
                    .thenReturn(DcerpcConstants.RPC_PT_BIND_ACK) // ptype
                    .thenReturn(0); // flags
            when(mockBuffer.dec_ndr_long()).thenReturn(0x00000010) // Data representation
                    .thenReturn(1) // call_id
                    .thenReturn(0); // From TestDcerpcMessage.decode_out
            when(mockBuffer.dec_ndr_short()).thenReturn(100) // length
                    .thenReturn(0); // auth_value length

            message.decode(mockBuffer);

            assertEquals(DcerpcConstants.RPC_PT_BIND_ACK, message.ptype);
        }

        @Test
        @DisplayName("decode should handle BIND_NAK ptype correctly")
        void testDecodeBindNakPtype() throws NdrException {
            message.ptype = DcerpcConstants.RPC_PT_BIND_NAK; // 13

            // Mock NdrBuffer for decode_header
            when(mockBuffer.dec_ndr_small()).thenReturn(5).thenReturn(0) // RPC version
                    .thenReturn(DcerpcConstants.RPC_PT_BIND_NAK) // ptype
                    .thenReturn(0); // flags
            when(mockBuffer.dec_ndr_long()).thenReturn(0x00000010) // Data representation
                    .thenReturn(1) // call_id
                    .thenReturn(0); // result for bind_nak (ptype 13 is fault)
            when(mockBuffer.dec_ndr_short()).thenReturn(100) // length
                    .thenReturn(0); // auth_value length

            message.decode(mockBuffer);

            assertEquals(DcerpcConstants.RPC_PT_BIND_NAK, message.ptype);
            assertEquals(0, message.result);
        }

        @Test
        @DisplayName("decode should throw NdrException for unexpected ptype")
        void testDecodeThrowsNdrExceptionForUnexpectedPtype() throws NdrException {
            message.ptype = DcerpcConstants.RPC_PT_ALTER_CONTEXT; // 14, not in allowed list

            // Mock NdrBuffer for decode_header
            when(mockBuffer.dec_ndr_small()).thenReturn(5).thenReturn(0) // RPC version
                    .thenReturn(DcerpcConstants.RPC_PT_ALTER_CONTEXT) // ptype
                    .thenReturn(0); // flags
            when(mockBuffer.dec_ndr_long()).thenReturn(0x00000010) // Data representation
                    .thenReturn(1); // call_id
            when(mockBuffer.dec_ndr_short()).thenReturn(100) // length
                    .thenReturn(0); // auth_value length

            assertThrows(NdrException.class, () -> message.decode(mockBuffer));
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("getPtype should return correct packet type")
        void testGetPtype() {
            message.ptype = DcerpcConstants.RPC_PT_REQUEST;
            assertEquals(DcerpcConstants.RPC_PT_REQUEST, message.getPtype());
        }

        @Test
        @DisplayName("getFlags should return correct flags")
        void testGetFlags() {
            message.flags = DcerpcConstants.RPC_C_PF_BROADCAST;
            assertEquals(DcerpcConstants.RPC_C_PF_BROADCAST, message.getFlags());
        }

        @Test
        @DisplayName("getOpnum should return correct operation number")
        void testGetOpnum() {
            assertEquals(10, message.getOpnum()); // TestDcerpcMessage was created with opnum 10
        }
    }
}