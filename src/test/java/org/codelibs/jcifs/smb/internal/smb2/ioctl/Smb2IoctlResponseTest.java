/*
 * Tests for Smb2IoctlResponse.
 *
 * Notes:
 * - Comments are in English as requested.
 * - JUnit 5 is used; Mockito is not required here.
 */
package org.codelibs.jcifs.smb.internal.smb2.ioctl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.codelibs.jcifs.smb.config.BaseConfiguration;
import org.codelibs.jcifs.smb.impl.NtStatus;
import org.codelibs.jcifs.smb.impl.SmbException;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.Test;

class Smb2IoctlResponseTest {

    // Helper: build a minimal SMB2 header with a given status
    private static byte[] buildHeader(int status) {
        byte[] hdr = new byte[64]; // SMB2 header is 64 bytes
        System.arraycopy(SMBUtil.SMB2_HEADER, 0, hdr, 0, 64);
        // Write Status (little-endian) at offset 8 in the SMB2 header
        SMBUtil.writeInt4(status, hdr, 8);
        // Write Command = SMB2_IOCTL (0x000B) at offset 12
        SMBUtil.writeInt2(0x000B, hdr, 12);
        // Mark as server response to be realistic (optional)
        SMBUtil.writeInt4(0x00000001, hdr, 16); // Flags = SMB2_FLAGS_SERVER_TO_REDIR
        return hdr;
    }

    // Helper: build SMB2 IOCTL response body (without header) with structureSize=49
    private static byte[] buildIoctlResponseBody(int ctlCode, byte[] fileId, int inputCount, byte[] inputBytes, int outputCount,
            byte[] outputBytes, int ioctlFlags) {
        final int headerLen = 64; // SMB2 header is 64 bytes
        final int bodyFixed = 48; // body size minus 1 for structure size field overlap
        final int payloadStart = headerLen + bodyFixed;
        final int bodyLen = bodyFixed + inputCount + outputCount;

        byte[] buf = new byte[bodyLen];
        int pos = 0;

        // structureSize (LE) - includes 1 byte of the variable part
        SMBUtil.writeInt2(49, buf, pos);
        pos += 2;
        // 2 reserved bytes
        pos += 2;
        // ctlCode
        SMBUtil.writeInt4(ctlCode, buf, pos);
        pos += 4;
        // fileId (16 bytes)
        byte[] fid = fileId != null ? fileId : new byte[16];
        System.arraycopy(fid, 0, buf, pos, 16);
        pos += 16;

        // Calculate offsets relative to start of SMB2 header
        int inputOffsetField = inputCount > 0 ? payloadStart : 0;
        int outputOffsetField = outputCount > 0 ? payloadStart + inputCount : 0;

        // inputOffset (relative to header start)
        SMBUtil.writeInt4(inputOffsetField, buf, pos);
        pos += 4;
        // inputCount
        SMBUtil.writeInt4(inputCount, buf, pos);
        pos += 4;
        // outputOffset (relative to header start)
        SMBUtil.writeInt4(outputOffsetField, buf, pos);
        pos += 4;
        // outputCount
        SMBUtil.writeInt4(outputCount, buf, pos);
        pos += 4;
        // ioctlFlags
        SMBUtil.writeInt4(ioctlFlags, buf, pos);
        pos += 4;
        // reserved2 (4 bytes)
        pos += 4;

        // Write payload data: input then output
        if (inputCount > 0 && inputBytes != null) {
            System.arraycopy(inputBytes, 0, buf, pos, inputCount);
            pos += inputCount;
        }
        if (outputCount > 0 && outputBytes != null) {
            System.arraycopy(outputBytes, 0, buf, pos, outputCount);
        }
        return buf;
    }

    // Helper: build an error body (without header) with structureSize=9
    private static byte[] buildErrorBody(int errorContextCount, int bc, byte[] errorData) {
        int bodyLen = 8 + bc; // 8 bytes fixed + variable data
        byte[] buf = new byte[bodyLen];
        SMBUtil.writeInt2(9, buf, 0); // structureSize
        buf[2] = (byte) errorContextCount; // ErrorContextCount
        // one reserved byte at position 3
        SMBUtil.writeInt4(bc, buf, 4); // ByteCount
        if (bc > 0 && errorData != null) {
            System.arraycopy(errorData, 0, buf, 8, bc);
        }
        return buf;
    }

    @Test
    void decodesErrorStructureThroughReadBytesWireFormat() throws Exception {
        // For STATUS_INVALID_PARAMETER the override makes isErrorResponseStatus() return false,
        // so readBytesWireFormat() is invoked and must delegate back to readErrorResponse() when it sees size=9.
        byte[] header = buildHeader(NtStatus.NT_STATUS_INVALID_PARAMETER);
        byte[] body = buildErrorBody(2, 3, new byte[] { (byte) 0xAA, (byte) 0xBB, (byte) 0xCC });
        byte[] packet = new byte[header.length + body.length];
        System.arraycopy(header, 0, packet, 0, header.length);
        System.arraycopy(body, 0, packet, header.length, body.length);

        BaseConfiguration config = new BaseConfiguration(true);
        Smb2IoctlResponse resp = new Smb2IoctlResponse(config);

        int read = resp.decode(packet, 0);
        assertTrue(read >= packet.length, "Decoded length should cover entire packet");
        assertNotNull(resp.getErrorData(), "Error data should be decoded");
        assertEquals(3, resp.getErrorData().length);
        assertEquals(2, resp.getErrorContextCount());
        assertArrayEquals(new byte[] { (byte) 0xAA, (byte) 0xBB, (byte) 0xCC }, resp.getErrorData());
    }

    @Test
    void throwsOnUnexpectedStructureSize() throws Exception {
        // structureSize != 49 and != 9 should raise an exception
        byte[] header = buildHeader(NtStatus.NT_STATUS_SUCCESS);
        byte[] buf = new byte[header.length + 10];
        System.arraycopy(header, 0, buf, 0, header.length);
        // Write invalid structure size 50 at body start
        SMBUtil.writeInt2(50, buf, Smb2Constants.SMB2_HEADER_LENGTH);

        BaseConfiguration config = new BaseConfiguration(true);
        Smb2IoctlResponse resp = new Smb2IoctlResponse(config);
        assertThrows(SMBProtocolDecodingException.class, () -> resp.decode(buf, 0));
    }

    @Test
    void copiesOutputIntoProvidedBufferAndBlocksGetOutputData() throws Exception {
        // When an output buffer is provided, bytes are copied and getOutputData(Class) should fail.
        byte[] header = buildHeader(NtStatus.NT_STATUS_SUCCESS);
        byte[] output = new byte[] { 1, 2, 3, 4, 5 };
        byte[] body = buildIoctlResponseBody(Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK, new byte[16], 0, null, output.length, output, 0x0);
        byte[] packet = new byte[header.length + body.length];
        System.arraycopy(header, 0, packet, 0, header.length);
        System.arraycopy(body, 0, packet, header.length, body.length);

        BaseConfiguration config = new BaseConfiguration(true);
        byte[] outBuf = new byte[output.length];
        Smb2IoctlResponse resp = new Smb2IoctlResponse(config, outBuf);

        resp.decode(packet, 0);
        assertEquals(output.length, resp.getOutputLength());
        assertArrayEquals(output, outBuf, "Output should be copied into provided buffer");
        // No Decodable output when buffer is provided
        assertNull(resp.getOutputData());
        assertThrows(SmbException.class, () -> resp.getOutputData(SrvCopyChunkCopyResponse.class));
    }

    @Test
    void throwsWhenOutputExceedsProvidedBuffer() throws Exception {
        byte[] header = buildHeader(NtStatus.NT_STATUS_SUCCESS);
        byte[] output = new byte[] { 1, 2, 3, 4, 5, 6 };
        byte[] body = buildIoctlResponseBody(Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK_WRITE, new byte[16], 0, null, output.length, output, 0);
        byte[] packet = new byte[header.length + body.length];
        System.arraycopy(header, 0, packet, 0, header.length);
        System.arraycopy(body, 0, packet, header.length, body.length);

        BaseConfiguration config = new BaseConfiguration(true);
        byte[] outBuf = new byte[4]; // too small
        Smb2IoctlResponse resp = new Smb2IoctlResponse(config, outBuf);
        assertThrows(SMBProtocolDecodingException.class, () -> resp.decode(packet, 0));
    }

    @Test
    void decodesSrvCopyChunkCopyResponse() throws Exception {
        // Validate createOutputDecodable() mapping and Decodable decode
        byte[] header = buildHeader(NtStatus.NT_STATUS_SUCCESS);

        // Prepare 3 ints: chunksWritten=1, chunkBytesWritten=2, totalBytesWritten=3
        byte[] out = new byte[12];
        SMBUtil.writeInt4(1, out, 0);
        SMBUtil.writeInt4(2, out, 4);
        SMBUtil.writeInt4(3, out, 8);

        byte[] body = buildIoctlResponseBody(Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK, new byte[16], 0, null, out.length, out, 0x1234);
        byte[] packet = new byte[header.length + body.length];
        System.arraycopy(header, 0, packet, 0, header.length);
        System.arraycopy(body, 0, packet, header.length, body.length);

        BaseConfiguration config = new BaseConfiguration(true);
        Smb2IoctlResponse resp = new Smb2IoctlResponse(config);

        resp.decode(packet, 0);
        assertEquals(Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK, resp.getCtlCode());
        assertEquals(0x1234, resp.getIoctlFlags());
        assertNotNull(resp.getFileId());
        assertEquals(16, resp.getFileId().length);
        assertEquals(12, resp.getOutputLength());

        SrvCopyChunkCopyResponse od = resp.getOutputData(SrvCopyChunkCopyResponse.class);
        assertEquals(1, od.getChunksWritten());
        assertEquals(2, od.getChunkBytesWritten());
        assertEquals(3, od.getTotalBytesWritten());

        // Type mismatch should raise SmbException
        assertThrows(SmbException.class, () -> resp.getOutputData(SrvRequestResumeKeyResponse.class));
    }

    @Test
    void decodesPipePeekOnBufferOverflowStatus() throws Exception {
        // For BUFFER_OVERFLOW with FSCTL_PIPE_PEEK, isErrorResponseStatus() should be false and decoding proceeds.
        byte[] header = buildHeader(NtStatus.NT_STATUS_BUFFER_OVERFLOW);

        // SrvPipePeekResponse expects at least 16 bytes (4 ints) output
        byte[] out = new byte[16];
        // leave all fields zero for simplicity

        byte[] body = buildIoctlResponseBody(Smb2IoctlRequest.FSCTL_PIPE_PEEK, new byte[16], 0, null, out.length, out, 0);
        byte[] packet = new byte[header.length + body.length];
        System.arraycopy(header, 0, packet, 0, header.length);
        System.arraycopy(body, 0, packet, header.length, body.length);

        BaseConfiguration config = new BaseConfiguration(true);
        // Use constructor that sets ctlCode
        Smb2IoctlResponse resp = new Smb2IoctlResponse(config, null, Smb2IoctlRequest.FSCTL_PIPE_PEEK);
        resp.decode(packet, 0);

        SrvPipePeekResponse peek = resp.getOutputData(SrvPipePeekResponse.class);
        assertNotNull(peek);
        assertEquals(16, resp.getOutputLength());
        // Default zeros
        assertEquals(0, peek.getNamedPipeState());
        assertEquals(0, peek.getReadDataAvailable());
        assertEquals(0, peek.getNumberOfMessages());
        assertEquals(0, peek.getMessageLength());
    }
}
