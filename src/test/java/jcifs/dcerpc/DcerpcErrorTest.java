package jcifs.dcerpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("DcerpcError Test")
class DcerpcErrorTest {

    @Test
    @DisplayName("Should verify DCERPC_FAULT_OTHER constant value")
    void testDcerpcFaultOther() {
        assertEquals(0x00000001, DcerpcError.DCERPC_FAULT_OTHER, "DCERPC_FAULT_OTHER value should be 0x00000001");
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_ACCESS_DENIED constant value")
    void testDcerpcFaultAccessDenied() {
        assertEquals(0x00000005, DcerpcError.DCERPC_FAULT_ACCESS_DENIED, "DCERPC_FAULT_ACCESS_DENIED value should be 0x00000005");
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_CANT_PERFORM constant value")
    void testDcerpcFaultCantPerform() {
        assertEquals(0x000006D8, DcerpcError.DCERPC_FAULT_CANT_PERFORM, "DCERPC_FAULT_CANT_PERFORM value should be 0x000006D8");
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_NDR constant value")
    void testDcerpcFaultNdr() {
        assertEquals(0x000006F7, DcerpcError.DCERPC_FAULT_NDR, "DCERPC_FAULT_NDR value should be 0x000006F7");
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_INVALID_TAG constant value")
    void testDcerpcFaultInvalidTag() {
        assertEquals(0x1C000006, DcerpcError.DCERPC_FAULT_INVALID_TAG, "DCERPC_FAULT_INVALID_TAG value should be 0x1C000006");
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_CONTEXT_MISMATCH constant value")
    void testDcerpcFaultContextMismatch() {
        assertEquals(0x1C00001A, DcerpcError.DCERPC_FAULT_CONTEXT_MISMATCH, "DCERPC_FAULT_CONTEXT_MISMATCH value should be 0x1C00001A");
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_OP_RNG_ERROR constant value")
    void testDcerpcFaultOpRngError() {
        assertEquals(0x1C010002, DcerpcError.DCERPC_FAULT_OP_RNG_ERROR, "DCERPC_FAULT_OP_RNG_ERROR value should be 0x1C010002");
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_UNK_IF constant value")
    void testDcerpcFaultUnkIf() {
        assertEquals(0x1C010003, DcerpcError.DCERPC_FAULT_UNK_IF, "DCERPC_FAULT_UNK_IF value should be 0x1C010003");
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_PROTO_ERROR constant value")
    void testDcerpcFaultProtoError() {
        assertEquals(0x1c01000b, DcerpcError.DCERPC_FAULT_PROTO_ERROR, "DCERPC_FAULT_PROTO_ERROR value should be 0x1c01000b");
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_CODES array content and size")
    void testDcerpcFaultCodesArray() {
        assertNotNull(DcerpcError.DCERPC_FAULT_CODES, "DCERPC_FAULT_CODES array should not be null");
        assertEquals(9, DcerpcError.DCERPC_FAULT_CODES.length, "DCERPC_FAULT_CODES array should contain 9 elements");

        assertEquals(DcerpcError.DCERPC_FAULT_OTHER, DcerpcError.DCERPC_FAULT_CODES[0]);
        assertEquals(DcerpcError.DCERPC_FAULT_ACCESS_DENIED, DcerpcError.DCERPC_FAULT_CODES[1]);
        assertEquals(DcerpcError.DCERPC_FAULT_CANT_PERFORM, DcerpcError.DCERPC_FAULT_CODES[2]);
        assertEquals(DcerpcError.DCERPC_FAULT_NDR, DcerpcError.DCERPC_FAULT_CODES[3]);
        assertEquals(DcerpcError.DCERPC_FAULT_INVALID_TAG, DcerpcError.DCERPC_FAULT_CODES[4]);
        assertEquals(DcerpcError.DCERPC_FAULT_CONTEXT_MISMATCH, DcerpcError.DCERPC_FAULT_CODES[5]);
        assertEquals(DcerpcError.DCERPC_FAULT_OP_RNG_ERROR, DcerpcError.DCERPC_FAULT_CODES[6]);
        assertEquals(DcerpcError.DCERPC_FAULT_UNK_IF, DcerpcError.DCERPC_FAULT_CODES[7]);
        assertEquals(DcerpcError.DCERPC_FAULT_PROTO_ERROR, DcerpcError.DCERPC_FAULT_CODES[8]);
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_MESSAGES array content and size")
    void testDcerpcFaultMessagesArray() {
        assertNotNull(DcerpcError.DCERPC_FAULT_MESSAGES, "DCERPC_FAULT_MESSAGES array should not be null");
        assertEquals(9, DcerpcError.DCERPC_FAULT_MESSAGES.length, "DCERPC_FAULT_MESSAGES array should contain 9 elements");

        assertEquals("DCERPC_FAULT_OTHER", DcerpcError.DCERPC_FAULT_MESSAGES[0]);
        assertEquals("DCERPC_FAULT_ACCESS_DENIED", DcerpcError.DCERPC_FAULT_MESSAGES[1]);
        assertEquals("DCERPC_FAULT_CANT_PERFORM", DcerpcError.DCERPC_FAULT_MESSAGES[2]);
        assertEquals("DCERPC_FAULT_NDR", DcerpcError.DCERPC_FAULT_MESSAGES[3]);
        assertEquals("DCERPC_FAULT_INVALID_TAG", DcerpcError.DCERPC_FAULT_MESSAGES[4]);
        assertEquals("DCERPC_FAULT_CONTEXT_MISMATCH", DcerpcError.DCERPC_FAULT_MESSAGES[5]);
        assertEquals("DCERPC_FAULT_OP_RNG_ERROR", DcerpcError.DCERPC_FAULT_MESSAGES[6]);
        assertEquals("DCERPC_FAULT_UNK_IF", DcerpcError.DCERPC_FAULT_MESSAGES[7]);
        assertEquals("DCERPC_FAULT_PROTO_ERROR", DcerpcError.DCERPC_FAULT_MESSAGES[8]);
    }

    @Test
    @DisplayName("Should verify consistency between DCERPC_FAULT_CODES and DCERPC_FAULT_MESSAGES arrays")
    void testFaultCodesAndMessagesConsistency() {
        assertEquals(DcerpcError.DCERPC_FAULT_CODES.length, DcerpcError.DCERPC_FAULT_MESSAGES.length,
                "Arrays DCERPC_FAULT_CODES and DCERPC_FAULT_MESSAGES should have the same length");

        // This test implicitly checks the order and mapping
        assertEquals("DCERPC_FAULT_OTHER", DcerpcError.DCERPC_FAULT_MESSAGES[0]);
        assertEquals("DCERPC_FAULT_ACCESS_DENIED", DcerpcError.DCERPC_FAULT_MESSAGES[1]);
        assertEquals("DCERPC_FAULT_CANT_PERFORM", DcerpcError.DCERPC_FAULT_MESSAGES[2]);
        assertEquals("DCERPC_FAULT_NDR", DcerpcError.DCERPC_FAULT_MESSAGES[3]);
        assertEquals("DCERPC_FAULT_INVALID_TAG", DcerpcError.DCERPC_FAULT_MESSAGES[4]);
        assertEquals("DCERPC_FAULT_CONTEXT_MISMATCH", DcerpcError.DCERPC_FAULT_MESSAGES[5]);
        assertEquals("DCERPC_FAULT_OP_RNG_ERROR", DcerpcError.DCERPC_FAULT_MESSAGES[6]);
        assertEquals("DCERPC_FAULT_UNK_IF", DcerpcError.DCERPC_FAULT_MESSAGES[7]);
        assertEquals("DCERPC_FAULT_PROTO_ERROR", DcerpcError.DCERPC_FAULT_MESSAGES[8]);
    }
}
