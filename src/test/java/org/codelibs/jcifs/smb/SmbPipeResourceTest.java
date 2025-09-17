package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * Tests for the SmbPipeResource interface.
 * This test class primarily verifies the constant values defined in the interface.
 */
class SmbPipeResourceTest {

    /**
     * Test if the PIPE_TYPE_RDONLY constant has the correct value.
     */
    @Test
    void testPipeTypeRdonly() {
        assertEquals(SmbConstants.O_RDONLY, SmbPipeResource.PIPE_TYPE_RDONLY, "PIPE_TYPE_RDONLY should match SmbConstants.O_RDONLY");
    }

    /**
     * Test if the PIPE_TYPE_WRONLY constant has the correct value.
     */
    @Test
    void testPipeTypeWronly() {
        assertEquals(SmbConstants.O_WRONLY, SmbPipeResource.PIPE_TYPE_WRONLY, "PIPE_TYPE_WRONLY should match SmbConstants.O_WRONLY");
    }

    /**
     * Test if the PIPE_TYPE_RDWR constant has the correct value.
     */
    @Test
    void testPipeTypeRdwr() {
        assertEquals(SmbConstants.O_RDWR, SmbPipeResource.PIPE_TYPE_RDWR, "PIPE_TYPE_RDWR should match SmbConstants.O_RDWR");
    }

    /**
     * Test if the PIPE_TYPE_CALL constant has the correct value.
     */
    @Test
    void testPipeTypeCall() {
        assertEquals(0x0100, SmbPipeResource.PIPE_TYPE_CALL, "PIPE_TYPE_CALL should be 0x0100");
    }

    /**
     * Test if the PIPE_TYPE_TRANSACT constant has the correct value.
     */
    @Test
    void testPipeTypeTransact() {
        assertEquals(0x0200, SmbPipeResource.PIPE_TYPE_TRANSACT, "PIPE_TYPE_TRANSACT should be 0x0200");
    }

    /**
     * Test if the PIPE_TYPE_DCE_TRANSACT constant has the correct value.
     */
    @Test
    void testPipeTypeDceTransact() {
        assertEquals(0x0200 | 0x0400, SmbPipeResource.PIPE_TYPE_DCE_TRANSACT, "PIPE_TYPE_DCE_TRANSACT should be 0x0600");
    }

    /**
     * Test if the PIPE_TYPE_UNSHARED constant has the correct value.
     */
    @Test
    void testPipeTypeUnshared() {
        assertEquals(0x800, SmbPipeResource.PIPE_TYPE_UNSHARED, "PIPE_TYPE_UNSHARED should be 0x800");
    }
}
