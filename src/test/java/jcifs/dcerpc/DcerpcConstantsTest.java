package jcifs.dcerpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("DcerpcConstants Tests")
class DcerpcConstantsTest {

    @Nested
    @DisplayName("UUID Constants Tests")
    class UuidConstantsTests {

        @Test
        @DisplayName("DCERPC_UUID_SYNTAX_NDR should have correct UUID value")
        void testDcerpcUuidSyntaxNdr() {
            // Arrange
            String expectedUuid = "8a885d04-1ceb-11c9-9fe8-08002b104860";

            // Act
            String actualUuid = DcerpcConstants.DCERPC_UUID_SYNTAX_NDR.toString().toLowerCase();

            // Assert
            assertNotNull(DcerpcConstants.DCERPC_UUID_SYNTAX_NDR, "DCERPC_UUID_SYNTAX_NDR should not be null");
            assertEquals(expectedUuid, actualUuid, "DCERPC_UUID_SYNTAX_NDR should have the correct UUID value");
        }
    }

    @Nested
    @DisplayName("Fragment Flag Constants Tests")
    class FragmentFlagTests {

        @Test
        @DisplayName("DCERPC_FIRST_FRAG should have correct value")
        void testDcerpcFirstFrag() {
            assertEquals(0x01, DcerpcConstants.DCERPC_FIRST_FRAG, "DCERPC_FIRST_FRAG should be 0x01");
        }

        @Test
        @DisplayName("DCERPC_LAST_FRAG should have correct value")
        void testDcerpcLastFrag() {
            assertEquals(0x02, DcerpcConstants.DCERPC_LAST_FRAG, "DCERPC_LAST_FRAG should be 0x02");
        }

        @Test
        @DisplayName("DCERPC_PENDING_CANCEL should have correct value")
        void testDcerpcPendingCancel() {
            assertEquals(0x04, DcerpcConstants.DCERPC_PENDING_CANCEL, "DCERPC_PENDING_CANCEL should be 0x04");
        }

        @Test
        @DisplayName("DCERPC_RESERVED_1 should have correct value")
        void testDcerpcReserved1() {
            assertEquals(0x08, DcerpcConstants.DCERPC_RESERVED_1, "DCERPC_RESERVED_1 should be 0x08");
        }

        @Test
        @DisplayName("DCERPC_CONC_MPX should have correct value")
        void testDcerpcConcMpx() {
            assertEquals(0x10, DcerpcConstants.DCERPC_CONC_MPX, "DCERPC_CONC_MPX should be 0x10");
        }

        @Test
        @DisplayName("DCERPC_DID_NOT_EXECUTE should have correct value")
        void testDcerpcDidNotExecute() {
            assertEquals(0x20, DcerpcConstants.DCERPC_DID_NOT_EXECUTE, "DCERPC_DID_NOT_EXECUTE should be 0x20");
        }

        @Test
        @DisplayName("DCERPC_MAYBE should have correct value")
        void testDcerpcMaybe() {
            assertEquals(0x40, DcerpcConstants.DCERPC_MAYBE, "DCERPC_MAYBE should be 0x40");
        }

        @Test
        @DisplayName("DCERPC_OBJECT_UUID should have correct value")
        void testDcerpcObjectUuid() {
            assertEquals(0x80, DcerpcConstants.DCERPC_OBJECT_UUID, "DCERPC_OBJECT_UUID should be 0x80");
        }
    }

    @Nested
    @DisplayName("RPC Packet Type Constants Tests")
    class RpcPacketTypeTests {

        @Test
        @DisplayName("RPC_PT_REQUEST should have correct value")
        void testRpcPtRequest() {
            assertEquals(0x00, DcerpcConstants.RPC_PT_REQUEST, "RPC_PT_REQUEST should be 0x00");
        }

        @Test
        @DisplayName("RPC_PT_PING should have correct value")
        void testRpcPtPing() {
            assertEquals(0x01, DcerpcConstants.RPC_PT_PING, "RPC_PT_PING should be 0x01");
        }

        @Test
        @DisplayName("RPC_PT_RESPONSE should have correct value")
        void testRpcPtResponse() {
            assertEquals(0x02, DcerpcConstants.RPC_PT_RESPONSE, "RPC_PT_RESPONSE should be 0x02");
        }

        @Test
        @DisplayName("RPC_PT_FAULT should have correct value")
        void testRpcPtFault() {
            assertEquals(0x03, DcerpcConstants.RPC_PT_FAULT, "RPC_PT_FAULT should be 0x03");
        }

        @Test
        @DisplayName("RPC_PT_BIND should have correct value")
        void testRpcPtBind() {
            assertEquals(0x0B, DcerpcConstants.RPC_PT_BIND, "RPC_PT_BIND should be 0x0B");
        }

        @Test
        @DisplayName("RPC_PT_BIND_ACK should have correct value")
        void testRpcPtBindAck() {
            assertEquals(0x0C, DcerpcConstants.RPC_PT_BIND_ACK, "RPC_PT_BIND_ACK should be 0x0C");
        }

        @Test
        @DisplayName("RPC_PT_BIND_NAK should have correct value")
        void testRpcPtBindNak() {
            assertEquals(0x0D, DcerpcConstants.RPC_PT_BIND_NAK, "RPC_PT_BIND_NAK should be 0x0D");
        }

        @Test
        @DisplayName("RPC_PT_ALTER_CONTEXT should have correct value")
        void testRpcPtAlterContext() {
            assertEquals(0x0E, DcerpcConstants.RPC_PT_ALTER_CONTEXT, "RPC_PT_ALTER_CONTEXT should be 0x0E");
        }

        @Test
        @DisplayName("RPC_PT_ALTER_CONTEXT_RESPONSE should have correct value")
        void testRpcPtAlterContextResponse() {
            assertEquals(0x0F, DcerpcConstants.RPC_PT_ALTER_CONTEXT_RESPONSE, "RPC_PT_ALTER_CONTEXT_RESPONSE should be 0x0F");
        }

        @Test
        @DisplayName("RPC_PT_SHUTDOWN should have correct value")
        void testRpcPtShutdown() {
            assertEquals(0x11, DcerpcConstants.RPC_PT_SHUTDOWN, "RPC_PT_SHUTDOWN should be 0x11");
        }

        @Test
        @DisplayName("RPC_PT_CANCEL should have correct value")
        void testRpcPtCancel() {
            assertEquals(0x12, DcerpcConstants.RPC_PT_CANCEL, "RPC_PT_CANCEL should be 0x12");
        }

        @Test
        @DisplayName("RPC_PT_ACK should have correct value")
        void testRpcPtAck() {
            assertEquals(0x13, DcerpcConstants.RPC_PT_ACK, "RPC_PT_ACK should be 0x13");
        }

        @Test
        @DisplayName("RPC_PT_REJECT should have correct value")
        void testRpcPtReject() {
            assertEquals(0x14, DcerpcConstants.RPC_PT_REJECT, "RPC_PT_REJECT should be 0x14");
        }

        @Test
        @DisplayName("RPC_PT_CO_CANCEL should have correct value")
        void testRpcPtCoCancel() {
            assertEquals(0x15, DcerpcConstants.RPC_PT_CO_CANCEL, "RPC_PT_CO_CANCEL should be 0x15");
        }

        @Test
        @DisplayName("RPC_PT_ORPHANED should have correct value")
        void testRpcPtOrphaned() {
            assertEquals(0x16, DcerpcConstants.RPC_PT_ORPHANED, "RPC_PT_ORPHANED should be 0x16");
        }
    }

    @Nested
    @DisplayName("RPC Packet Flag Constants Tests")
    class RpcPacketFlagTests {

        @Test
        @DisplayName("RPC_C_PF_BROADCAST should have correct value")
        void testRpcCPfBroadcast() {
            assertEquals(0x01, DcerpcConstants.RPC_C_PF_BROADCAST, "RPC_C_PF_BROADCAST should be 0x01");
        }

        @Test
        @DisplayName("RPC_C_PF_NO_FRAGMENT should have correct value")
        void testRpcCPfNoFragment() {
            assertEquals(0x02, DcerpcConstants.RPC_C_PF_NO_FRAGMENT, "RPC_C_PF_NO_FRAGMENT should be 0x02");
        }

        @Test
        @DisplayName("RPC_C_PF_MAYBE should have correct value")
        void testRpcCPfMaybe() {
            assertEquals(0x04, DcerpcConstants.RPC_C_PF_MAYBE, "RPC_C_PF_MAYBE should be 0x04");
        }

        @Test
        @DisplayName("RPC_C_PF_IDEMPOTENT should have correct value")
        void testRpcCPfIdempotent() {
            assertEquals(0x08, DcerpcConstants.RPC_C_PF_IDEMPOTENT, "RPC_C_PF_IDEMPOTENT should be 0x08");
        }

        @Test
        @DisplayName("RPC_C_PF_BROADCAST_MAYBE should have correct value")
        void testRpcCPfBroadcastMaybe() {
            assertEquals(0x10, DcerpcConstants.RPC_C_PF_BROADCAST_MAYBE, "RPC_C_PF_BROADCAST_MAYBE should be 0x10");
        }

        @Test
        @DisplayName("RPC_C_PF_NOT_IDEMPOTENT should have correct value")
        void testRpcCPfNotIdempotent() {
            assertEquals(0x20, DcerpcConstants.RPC_C_PF_NOT_IDEMPOTENT, "RPC_C_PF_NOT_IDEMPOTENT should be 0x20");
        }

        @Test
        @DisplayName("RPC_C_PF_NO_AUTO_LISTEN should have correct value")
        void testRpcCPfNoAutoListen() {
            assertEquals(0x40, DcerpcConstants.RPC_C_PF_NO_AUTO_LISTEN, "RPC_C_PF_NO_AUTO_LISTEN should be 0x40");
        }

        @Test
        @DisplayName("RPC_C_PF_NO_AUTO_RETRY should have correct value")
        void testRpcCPfNoAutoRetry() {
            assertEquals(0x80, DcerpcConstants.RPC_C_PF_NO_AUTO_RETRY, "RPC_C_PF_NO_AUTO_RETRY should be 0x80");
        }
    }

    @Nested
    @DisplayName("Constants Validation Tests")
    class ConstantsValidationTests {

        @Test
        @DisplayName("All fragment flags should have unique values")
        void testFragmentFlagsUniqueness() {
            // Verify that fragment flags are unique and follow bit pattern
            assertEquals(1, Integer.bitCount(DcerpcConstants.DCERPC_FIRST_FRAG), "DCERPC_FIRST_FRAG should be a single bit");
            assertEquals(1, Integer.bitCount(DcerpcConstants.DCERPC_LAST_FRAG), "DCERPC_LAST_FRAG should be a single bit");
            assertEquals(1, Integer.bitCount(DcerpcConstants.DCERPC_PENDING_CANCEL), "DCERPC_PENDING_CANCEL should be a single bit");
            assertEquals(1, Integer.bitCount(DcerpcConstants.DCERPC_RESERVED_1), "DCERPC_RESERVED_1 should be a single bit");
            assertEquals(1, Integer.bitCount(DcerpcConstants.DCERPC_CONC_MPX), "DCERPC_CONC_MPX should be a single bit");
            assertEquals(1, Integer.bitCount(DcerpcConstants.DCERPC_DID_NOT_EXECUTE), "DCERPC_DID_NOT_EXECUTE should be a single bit");
            assertEquals(1, Integer.bitCount(DcerpcConstants.DCERPC_MAYBE), "DCERPC_MAYBE should be a single bit");
            assertEquals(1, Integer.bitCount(DcerpcConstants.DCERPC_OBJECT_UUID), "DCERPC_OBJECT_UUID should be a single bit");
        }

        @Test
        @DisplayName("All RPC packet flags should have unique values")
        void testRpcPacketFlagsUniqueness() {
            // Verify that RPC packet flags are unique and follow bit pattern
            assertEquals(1, Integer.bitCount(DcerpcConstants.RPC_C_PF_BROADCAST), "RPC_C_PF_BROADCAST should be a single bit");
            assertEquals(1, Integer.bitCount(DcerpcConstants.RPC_C_PF_NO_FRAGMENT), "RPC_C_PF_NO_FRAGMENT should be a single bit");
            assertEquals(1, Integer.bitCount(DcerpcConstants.RPC_C_PF_MAYBE), "RPC_C_PF_MAYBE should be a single bit");
            assertEquals(1, Integer.bitCount(DcerpcConstants.RPC_C_PF_IDEMPOTENT), "RPC_C_PF_IDEMPOTENT should be a single bit");
            assertEquals(1, Integer.bitCount(DcerpcConstants.RPC_C_PF_BROADCAST_MAYBE), "RPC_C_PF_BROADCAST_MAYBE should be a single bit");
            assertEquals(1, Integer.bitCount(DcerpcConstants.RPC_C_PF_NOT_IDEMPOTENT), "RPC_C_PF_NOT_IDEMPOTENT should be a single bit");
            assertEquals(1, Integer.bitCount(DcerpcConstants.RPC_C_PF_NO_AUTO_LISTEN), "RPC_C_PF_NO_AUTO_LISTEN should be a single bit");
            assertEquals(1, Integer.bitCount(DcerpcConstants.RPC_C_PF_NO_AUTO_RETRY), "RPC_C_PF_NO_AUTO_RETRY should be a single bit");
        }

        @Test
        @DisplayName("RPC packet types should have valid range")
        void testRpcPacketTypeRange() {
            // Verify that packet types are within valid range (0x00-0x16)
            int[] packetTypes = { DcerpcConstants.RPC_PT_REQUEST, DcerpcConstants.RPC_PT_PING, DcerpcConstants.RPC_PT_RESPONSE,
                    DcerpcConstants.RPC_PT_FAULT, DcerpcConstants.RPC_PT_BIND, DcerpcConstants.RPC_PT_BIND_ACK,
                    DcerpcConstants.RPC_PT_BIND_NAK, DcerpcConstants.RPC_PT_ALTER_CONTEXT, DcerpcConstants.RPC_PT_ALTER_CONTEXT_RESPONSE,
                    DcerpcConstants.RPC_PT_SHUTDOWN, DcerpcConstants.RPC_PT_CANCEL, DcerpcConstants.RPC_PT_ACK,
                    DcerpcConstants.RPC_PT_REJECT, DcerpcConstants.RPC_PT_CO_CANCEL, DcerpcConstants.RPC_PT_ORPHANED };

            for (int packetType : packetTypes) {
                assertTrue(packetType >= 0x00 && packetType <= 0x16,
                        String.format("Packet type 0x%02X should be in valid range 0x00-0x16", packetType));
            }
        }

        @Test
        @DisplayName("Fragment flags should be within byte range")
        void testFragmentFlagsRange() {
            // Verify that fragment flags are within byte range (0x00-0xFF)
            int[] fragmentFlags = { DcerpcConstants.DCERPC_FIRST_FRAG, DcerpcConstants.DCERPC_LAST_FRAG,
                    DcerpcConstants.DCERPC_PENDING_CANCEL, DcerpcConstants.DCERPC_RESERVED_1, DcerpcConstants.DCERPC_CONC_MPX,
                    DcerpcConstants.DCERPC_DID_NOT_EXECUTE, DcerpcConstants.DCERPC_MAYBE, DcerpcConstants.DCERPC_OBJECT_UUID };

            for (int flag : fragmentFlags) {
                assertTrue(flag >= 0x00 && flag <= 0xFF,
                        String.format("Fragment flag 0x%02X should be in valid byte range 0x00-0xFF", flag));
            }
        }

        @Test
        @DisplayName("RPC packet flags should be within byte range")
        void testRpcPacketFlagsRange() {
            // Verify that RPC packet flags are within byte range (0x00-0xFF)
            int[] rpcFlags = { DcerpcConstants.RPC_C_PF_BROADCAST, DcerpcConstants.RPC_C_PF_NO_FRAGMENT, DcerpcConstants.RPC_C_PF_MAYBE,
                    DcerpcConstants.RPC_C_PF_IDEMPOTENT, DcerpcConstants.RPC_C_PF_BROADCAST_MAYBE, DcerpcConstants.RPC_C_PF_NOT_IDEMPOTENT,
                    DcerpcConstants.RPC_C_PF_NO_AUTO_LISTEN, DcerpcConstants.RPC_C_PF_NO_AUTO_RETRY };

            for (int flag : rpcFlags) {
                assertTrue(flag >= 0x00 && flag <= 0xFF,
                        String.format("RPC packet flag 0x%02X should be in valid byte range 0x00-0xFF", flag));
            }
        }
    }
}