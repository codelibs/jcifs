package org.codelibs.jcifs.smb.dcerpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("DcerpcError Test")
class DcerpcErrorTest {

    @Test
    @DisplayName("Should verify DCERPC_FAULT_OTHER constant value")
    void testDcerpcFaultOther() {
        assertEquals(0x00000001, DcerpcError.DCERPC_FAULT_OTHER);
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_ACCESS_DENIED constant value")
    void testDcerpcFaultAccessDenied() {
        assertEquals(0x00000005, DcerpcError.DCERPC_FAULT_ACCESS_DENIED);
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_CANT_PERFORM constant value")
    void testDcerpcFaultCantPerform() {
        assertEquals(0x000006D8, DcerpcError.DCERPC_FAULT_CANT_PERFORM);
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_NDR constant value")
    void testDcerpcFaultNdr() {
        assertEquals(0x000006F7, DcerpcError.DCERPC_FAULT_NDR);
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_INVALID_TAG constant value")
    void testDcerpcFaultInvalidTag() {
        assertEquals(0x1C000006, DcerpcError.DCERPC_FAULT_INVALID_TAG);
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_CONTEXT_MISMATCH constant value")
    void testDcerpcFaultContextMismatch() {
        assertEquals(0x1C00001A, DcerpcError.DCERPC_FAULT_CONTEXT_MISMATCH);
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_OP_RNG_ERROR constant value")
    void testDcerpcFaultOpRngError() {
        assertEquals(0x1C010002, DcerpcError.DCERPC_FAULT_OP_RNG_ERROR);
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_UNK_IF constant value")
    void testDcerpcFaultUnkIf() {
        assertEquals(0x1C010003, DcerpcError.DCERPC_FAULT_UNK_IF);
    }

    @Test
    @DisplayName("Should verify DCERPC_FAULT_PROTO_ERROR constant value")
    void testDcerpcFaultProtoError() {
        assertEquals(0x1c01000b, DcerpcError.DCERPC_FAULT_PROTO_ERROR);
    }

    @Test
    @DisplayName("Should verify all fault code constants are unique")
    void testFaultCodesUniqueness() {
        Set<Integer> faultCodes = new HashSet<>();

        // Add all fault codes to a set to check uniqueness
        faultCodes.add(DcerpcError.DCERPC_FAULT_OTHER);
        faultCodes.add(DcerpcError.DCERPC_FAULT_ACCESS_DENIED);
        faultCodes.add(DcerpcError.DCERPC_FAULT_CANT_PERFORM);
        faultCodes.add(DcerpcError.DCERPC_FAULT_NDR);
        faultCodes.add(DcerpcError.DCERPC_FAULT_INVALID_TAG);
        faultCodes.add(DcerpcError.DCERPC_FAULT_CONTEXT_MISMATCH);
        faultCodes.add(DcerpcError.DCERPC_FAULT_OP_RNG_ERROR);
        faultCodes.add(DcerpcError.DCERPC_FAULT_UNK_IF);
        faultCodes.add(DcerpcError.DCERPC_FAULT_PROTO_ERROR);

        // Verify all 9 codes are unique
        assertEquals(9, faultCodes.size(), "All fault codes should be unique");
    }

    @Test
    @DisplayName("Should verify fault code value ranges and patterns")
    void testFaultCodeValueRanges() {
        // Standard fault codes (0x00000000 - 0x0000FFFF range)
        assertTrue(DcerpcError.DCERPC_FAULT_OTHER >= 0 && DcerpcError.DCERPC_FAULT_OTHER <= 0x0000FFFF,
                "DCERPC_FAULT_OTHER should be in standard range");
        assertTrue(DcerpcError.DCERPC_FAULT_ACCESS_DENIED >= 0 && DcerpcError.DCERPC_FAULT_ACCESS_DENIED <= 0x0000FFFF,
                "DCERPC_FAULT_ACCESS_DENIED should be in standard range");
        assertTrue(DcerpcError.DCERPC_FAULT_CANT_PERFORM >= 0 && DcerpcError.DCERPC_FAULT_CANT_PERFORM <= 0x0000FFFF,
                "DCERPC_FAULT_CANT_PERFORM should be in standard range");
        assertTrue(DcerpcError.DCERPC_FAULT_NDR >= 0 && DcerpcError.DCERPC_FAULT_NDR <= 0x0000FFFF,
                "DCERPC_FAULT_NDR should be in standard range");

        // Extended fault codes (0x1C000000 range)
        assertTrue((DcerpcError.DCERPC_FAULT_INVALID_TAG & 0xFF000000) == 0x1C000000, "DCERPC_FAULT_INVALID_TAG should be in 0x1C range");
        assertTrue((DcerpcError.DCERPC_FAULT_CONTEXT_MISMATCH & 0xFF000000) == 0x1C000000,
                "DCERPC_FAULT_CONTEXT_MISMATCH should be in 0x1C range");
        assertTrue((DcerpcError.DCERPC_FAULT_OP_RNG_ERROR & 0xFF000000) == 0x1C000000, "DCERPC_FAULT_OP_RNG_ERROR should be in 0x1C range");
        assertTrue((DcerpcError.DCERPC_FAULT_UNK_IF & 0xFF000000) == 0x1C000000, "DCERPC_FAULT_UNK_IF should be in 0x1C range");
        assertTrue((DcerpcError.DCERPC_FAULT_PROTO_ERROR & 0xFF000000) == 0x1C000000, "DCERPC_FAULT_PROTO_ERROR should be in 0x1C range");
    }

    @Test
    @DisplayName("Should verify DcerpcException uses fault codes correctly")
    void testDcerpcExceptionIntegration() {
        // Test that DcerpcException can be created and implements DcerpcError
        DcerpcException ex1 = new DcerpcException("Test error", null);
        assertTrue(ex1 instanceof DcerpcError, "DcerpcException should implement DcerpcError");

        // Test that DcerpcException can be created with string messages
        DcerpcException ex2 = new DcerpcException("Access denied error");
        assertTrue(ex2 instanceof DcerpcError, "DcerpcException should implement DcerpcError");

        // Test with root cause
        Exception rootCause = new Exception("Root cause");
        DcerpcException ex3 = new DcerpcException("Error with cause", rootCause);
        assertEquals(rootCause, ex3.getCause());
    }

    @Test
    @DisplayName("Should verify error message lookup for known fault codes")
    void testErrorMessageLookup() {
        // Test message lookup using DcerpcException's static method
        String msg1 = DcerpcException.getMessageByDcerpcError(DcerpcError.DCERPC_FAULT_OTHER);
        assertEquals("DCERPC_FAULT_OTHER", msg1);

        String msg2 = DcerpcException.getMessageByDcerpcError(DcerpcError.DCERPC_FAULT_ACCESS_DENIED);
        assertEquals("DCERPC_FAULT_ACCESS_DENIED", msg2);

        String msg3 = DcerpcException.getMessageByDcerpcError(DcerpcError.DCERPC_FAULT_CANT_PERFORM);
        assertEquals("DCERPC_FAULT_CANT_PERFORM", msg3);

        String msg4 = DcerpcException.getMessageByDcerpcError(DcerpcError.DCERPC_FAULT_NDR);
        assertEquals("DCERPC_FAULT_NDR", msg4);

        String msg5 = DcerpcException.getMessageByDcerpcError(DcerpcError.DCERPC_FAULT_INVALID_TAG);
        assertEquals("DCERPC_FAULT_INVALID_TAG", msg5);

        String msg6 = DcerpcException.getMessageByDcerpcError(DcerpcError.DCERPC_FAULT_CONTEXT_MISMATCH);
        assertEquals("DCERPC_FAULT_CONTEXT_MISMATCH", msg6);

        String msg7 = DcerpcException.getMessageByDcerpcError(DcerpcError.DCERPC_FAULT_OP_RNG_ERROR);
        assertEquals("DCERPC_FAULT_OP_RNG_ERROR", msg7);

        String msg8 = DcerpcException.getMessageByDcerpcError(DcerpcError.DCERPC_FAULT_UNK_IF);
        assertEquals("DCERPC_FAULT_UNK_IF", msg8);

        String msg9 = DcerpcException.getMessageByDcerpcError(DcerpcError.DCERPC_FAULT_PROTO_ERROR);
        assertEquals("DCERPC_FAULT_PROTO_ERROR", msg9);
    }
}