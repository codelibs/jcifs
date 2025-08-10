/*
 * Tests for Smb2IoctlResponse.
 *
 * Notes:
 * - Comments are in English as requested.
 * - JUnit 5 is used; Mockito is not required here.
 */
package jcifs.internal.smb2.ioctl;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import jcifs.config.BaseConfiguration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.NtStatus;
import jcifs.smb.SmbException;

class Smb2IoctlResponseTest {

    // Helper: build a minimal SMB2 header with a given status
    private static byte[] buildHeader(int status) {
        byte[] hdr = new byte[SMBUtil.SMB2_HEADER.length];
        System.arraycopy(SMBUtil.SMB2_HEADER, 0, hdr, 0, SMBUtil.SMB2_HEADER.length);
        // Write Status (little-endian) at offset 8 in the SMB2 header
        SMBUtil.writeInt4(status, hdr, 8);
        // Write Command = SMB2_IOCTL (0x000B) at offset 12
        SMBUtil.writeInt2(0x000B, hdr, 12);
        // Mark as server response to be realistic (optional)
        SMBUtil.writeInt4(0x00000001, hdr, 16); // Flags = SMB2_FLAGS_SERVER_TO_REDIR
        return hdr;
    }

    // Helper: assemble a full SMB2 IOCTL response with structureSize=49
    private static byte[] buildIoctlResponseBody(int ctlCode, byte[] fileId, int inputCount, byte[] inputBytes,
            int outputCount, byte[] outputBytes, int ioctlFlags) {
        final int bodyStart = Smb2Constants.SMB2_HEADER_LENGTH;
        final int fixed = 49; // structure size expected by decoder
        int payloadStart = bodyStart + fixed;
        int totalLen = payloadStart + inputCount + outputCount;

        byte[] buf = new byte[totalLen];
        // structureSize (LE)
        SMBUtil.writeInt2(49, buf, bodyStart);
        // skip 2 reserved bytes (bodyStart + 2..3)
        // ctlCode
        SMBUtil.writeInt4(ctlCode, buf, bodyStart + 4);
        // fileId (16 bytes)
        byte[] fid = fileId != null ? fileId : new byte[16];
        System.arraycopy(fid, 0, buf, bodyStart + 8, 16);

        int inputOffsetField = inputCount > 0 ? payloadStart : 0;
        int outputOffsetField = outputCount > 0 ? payloadStart + inputCount : 0;

        // inputOffset (relative to header start)
        SMBUtil.writeInt4(inputOffsetField - 0 /* headerStart is 0 in tests */, buf, bodyStart + 24);
        // inputCount
        SMBUtil.writeInt4(inputCount, buf, bodyStart + 28);
        // outputOffset (relative to header start)
        SMBUtil.writeInt4(outputOffsetField - 0, buf, bodyStart + 32);
        // outputCount
        SMBUtil.writeInt4(outputCount, buf, bodyStart + 36);
        // ioctlFlags
        SMBUtil.writeInt4(ioctlFlags, buf, bodyStart + 40);
        // reserved2 at +44 (leave zero)

        // payload: input then output
        int p = payloadStart;
        if (inputCount > 0 && inputBytes != null) {
            System.arraycopy(inputBytes, 0, buf, p, inputCount);
            p += inputCount;
        }
        if (outputCount > 0 && outputBytes != null) {
            System.arraycopy(outputBytes, 0, buf, p, outputCount);
        }
        return buf;
    }

    // Helper: build an error body with structureSize=9
    private static byte[] buildErrorBody(int errorContextCount, int bc, byte[] errorData) {
        final int bodyStart = Smb2Constants.SMB2_HEADER_LENGTH;
        int totalLen = bodyStart + 4 /* 2 + 2 */ + 4 /* bc */ + bc;
        byte[] buf = new byte[totalLen];
        SMBUtil.writeInt2(9, buf, bodyStart); // structureSize
        buf[bodyStart + 2] = (byte) errorContextCount; // ErrorContextCount
        // one reserved byte at bodyStart + 3
        SMBUtil.writeInt4(bc, buf, bodyStart + 4); // ByteCount
        if (bc > 0 && errorData != null) {
            System.arraycopy(errorData, 0, buf, bodyStart + 8, bc);
        }
        return buf;
    }

    @Test
    void decodesErrorStructureThroughReadBytesWireFormat() throws Exception {
        // For STATUS_INVALID_PARAMETER the override makes isErrorResponseStatus() return false,
        // so readBytesWireFormat() is invoked and must delegate back to readErrorResponse() when it sees size=9.
        byte[] header = buildHeader(NtStatus.NT_STATUS_INVALID_PARAMETER);
        byte[] body = buildErrorBody(2, 3, new byte[] { (byte) 0xAA, (byte) 0xBB, (byte) 0xCC });
        byte[] packet = new byte[header.length + (body.length - header.length)];
        System.arraycopy(header, 0, packet, 0, header.length);
        System.arraycopy(body, header.length, packet, header.length, body.length - header.length);

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
        byte[] body = buildIoctlResponseBody(
                Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK,
                new byte[16],
                0, null,
                output.length, output,
                0x0);
        byte[] packet = new byte[body.length];
        System.arraycopy(header, 0, packet, 0, header.length);
        System.arraycopy(body, header.length, packet, header.length, body.length - header.length);

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
        byte[] body = buildIoctlResponseBody(
                Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK_WRITE,
                new byte[16],
                0, null,
                output.length, output,
                0);
        byte[] packet = new byte[body.length];
        System.arraycopy(header, 0, packet, 0, header.length);
        System.arraycopy(body, header.length, packet, header.length, body.length - header.length);

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

        byte[] body = buildIoctlResponseBody(
                Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK,
                new byte[16],
                0, null,
                out.length, out,
                0x1234);
        byte[] packet = new byte[body.length];
        System.arraycopy(header, 0, packet, 0, header.length);
        System.arraycopy(body, header.length, packet, header.length, body.length - header.length);

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

        byte[] body = buildIoctlResponseBody(
                Smb2IoctlRequest.FSCTL_PIPE_PEEK,
                new byte[16],
                0, null,
                out.length, out,
                0);
        byte[] packet = new byte[body.length];
        System.arraycopy(header, 0, packet, 0, header.length);
        System.arraycopy(body, header.length, packet, header.length, body.length - header.length);

        BaseConfiguration config = new BaseConfiguration(true);
        Smb2IoctlResponse resp = new Smb2IoctlResponse(config);
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

