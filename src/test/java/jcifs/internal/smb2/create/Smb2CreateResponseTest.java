/*
 * Tests for Smb2CreateResponse decoding and behavior.
 */
package jcifs.internal.smb2.create;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb2.RequestWithFileId;
import jcifs.internal.util.SMBUtil;

@ExtendWith(MockitoExtension.class)
class Smb2CreateResponseTest {

    // SMB2 header size in bytes
    private static final int SMB2_HEADER_LENGTH = 64;

    /**
     * Build a minimal SMB2 header for a response.
     */
    private static byte[] buildSmb2Header() {
        byte[] header = Arrays.copyOf(SMBUtil.SMB2_HEADER, SMBUtil.SMB2_HEADER.length);
        // Mark as server->client response for realism
        SMBUtil.writeInt4(0x00000001, header, 16); // Flags
        // Command SMB2_CREATE (0x0005)
        SMBUtil.writeInt2(0x0005, header, 12);
        // Some message id
        SMBUtil.writeInt8(1L, header, 24);
        return header;
    }

    /**
     * Build a basic CREATE response body without create contexts.
     */
    private static byte[] buildCreateBodyNoContexts(byte oplock, byte openFlags, int createAction, long ctime,
            long atime, long mtime, long chtime, long allocSize, long eof, int attrs, byte[] fileId) {
        byte[] body = new byte[2 + 2 + 4 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4 + 16 + 4 + 4];
        int i = 0;
        SMBUtil.writeInt2(89, body, i); // StructureSize
        body[i + 2] = oplock;
        body[i + 3] = openFlags;
        i += 4;

        SMBUtil.writeInt4(createAction, body, i); // CreateAction
        i += 4;

        SMBUtil.writeTime(ctime, body, i); // CreationTime
        i += 8;
        SMBUtil.writeTime(atime, body, i); // LastAccessTime
        i += 8;
        SMBUtil.writeTime(mtime, body, i); // LastWriteTime
        i += 8;
        SMBUtil.writeTime(chtime, body, i); // ChangeTime
        i += 8;

        SMBUtil.writeInt8(allocSize, body, i); // AllocationSize
        i += 8;
        SMBUtil.writeInt8(eof, body, i); // EndOfFile
        i += 8;

        SMBUtil.writeInt4(attrs, body, i); // FileAttributes
        i += 4;
        i += 4; // Reserved2

        System.arraycopy(fileId, 0, body, i, 16); // FileId
        i += 16;

        SMBUtil.writeInt4(0, body, i); // CreateContextsOffset
        i += 4;
        SMBUtil.writeInt4(0, body, i); // CreateContextsLength
        i += 4;

        assert i == body.length;
        return body;
    }

    /**
     * Build a CREATE response body with a single, unrecognized create context.
     * The parser should iterate it but produce an empty contexts array.
     */
    private static byte[] buildCreateBodyWithContext(byte[] fileId, int contextStartOffsetFromHeader) {
        // Base body part size (up to and including CreateContextsLength)
        byte[] base = buildCreateBodyNoContexts((byte) 1, (byte) 2, 3, 1000L, 2000L, 3000L, 4000L,
                512L, 1024L, 0x20, fileId);

        // Create a simple context entry
        byte[] ctx = new byte[0x40];
        int ci = 0;
        SMBUtil.writeInt4(0, ctx, ci); // Next = 0 (only one)
        ci += 4;
        SMBUtil.writeInt2(0x10, ctx, ci); // NameOffset
        SMBUtil.writeInt2(4, ctx, ci + 2); // NameLength
        ci += 4;
        // Reserved (2) + DataOffset (2)
        // Put data at offset 0x20
        SMBUtil.writeInt2(0, ctx, ci); // Reserved
        SMBUtil.writeInt2(0x20, ctx, ci + 2); // DataOffset
        ci += 4;
        SMBUtil.writeInt4(8, ctx, ci); // DataLength
        ci += 4;
        // Name bytes at 0x10
        byte[] name = new byte[] { 'T', 'E', 'S', 'T' };
        System.arraycopy(name, 0, ctx, 0x10, name.length);
        // Data bytes at 0x20
        byte[] data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        System.arraycopy(data, 0, ctx, 0x20, data.length);

        // Update base to point to the context area
        int offsetFieldPos = base.length - 8; // position of CreateContextsOffset
        SMBUtil.writeInt4(contextStartOffsetFromHeader, base, offsetFieldPos);
        SMBUtil.writeInt4(ctx.length, base, offsetFieldPos + 4);

        // Assemble full body: base (fixed-size fields only), but actual context bytes sit elsewhere in the full packet
        // Return just the base; caller is responsible for placing ctx at the correct absolute offset.
        // We will return a composite buffer from the test when building the full packet.
        // To keep this helper simple, return base and let the caller append/pad and inject ctx.
        return base;
    }

    /**
     * Build a full SMB2 packet combining header and provided body, optionally injecting context bytes.
     */
    private static byte[] buildPacket(byte[] header, byte[] body, Integer ctxOffsetFromHeader, byte[] ctxBytes) {
        int totalLen;
        if (ctxOffsetFromHeader != null && ctxBytes != null) {
            totalLen = Math.max(SMB2_HEADER_LENGTH + body.length, ctxOffsetFromHeader + ctxBytes.length);
        } else {
            totalLen = SMB2_HEADER_LENGTH + body.length;
        }
        byte[] packet = new byte[totalLen];
        System.arraycopy(header, 0, packet, 0, header.length);
        System.arraycopy(body, 0, packet, SMB2_HEADER_LENGTH, body.length);
        if (ctxOffsetFromHeader != null && ctxBytes != null) {
            System.arraycopy(ctxBytes, 0, packet, ctxOffsetFromHeader, ctxBytes.length);
        }
        return packet;
    }

    @Test
    void decode_basic_noContexts() throws Exception {
        Configuration config = Mockito.mock(Configuration.class);
        Smb2CreateResponse resp = new Smb2CreateResponse(config, "file.txt");

        byte[] fileId = new byte[16];
        for (int i = 0; i < fileId.length; i++) fileId[i] = (byte) (i + 1);

        byte[] header = buildSmb2Header();
        byte[] body = buildCreateBodyNoContexts((byte) 0x7, (byte) 0x2, 0x11223344,
                1111L, 2222L, 3333L, 4444L,
                123456789L, 987654321L, 0xA5A5A5A5, fileId);
        byte[] packet = buildPacket(header, body, null, null);

        int read = resp.decode(packet, 0, false);
        assertTrue(read >= SMB2_HEADER_LENGTH + body.length, "Should decode at least header+body");

        // Validate simple getters
        assertEquals((byte) 0x7, resp.getOplockLevel());
        assertEquals((byte) 0x2, resp.getOpenFlags());
        assertEquals(0x11223344, resp.getCreateAction());
        assertEquals(1111L, resp.getCreationTime());
        assertEquals(1111L, resp.getCreateTime()); // SmbBasicFileInfo mapping
        assertEquals(2222L, resp.getLastAccessTime());
        assertEquals(3333L, resp.getLastWriteTime());
        assertEquals(4444L, resp.getChangeTime());
        assertEquals(123456789L, resp.getAllocationSize());
        assertEquals(987654321L, resp.getEndOfFile());
        assertEquals(987654321L, resp.getSize()); // SmbBasicFileInfo mapping
        assertEquals(0xA5A5A5A5, resp.getFileAttributes());
        assertEquals(0xA5A5A5A5, resp.getAttributes()); // SmbBasicFileInfo mapping
        assertArrayEquals(fileId, resp.getFileId());
        assertEquals("file.txt", resp.getFileName());

        // No create contexts section present -> null
        assertNull(resp.getCreateContexts());
    }

    @Test
    void decode_withCreateContext_unrecognized_yieldsEmptyArray() throws Exception {
        Configuration config = Mockito.mock(Configuration.class);
        Smb2CreateResponse resp = new Smb2CreateResponse(config, "file.txt");

        byte[] fileId = new byte[16];
        Arrays.fill(fileId, (byte) 0xCC);

        byte[] header = buildSmb2Header();
        int ctxOffsetFromHeader = 256; // arbitrary aligned location beyond header
        byte[] baseBody = buildCreateBodyWithContext(fileId, ctxOffsetFromHeader);

        // Build actual context bytes matching the pointers inside baseBody
        byte[] ctx = new byte[0x40];
        int ci = 0;
        SMBUtil.writeInt4(0, ctx, ci); // Next = 0
        ci += 4;
        SMBUtil.writeInt2(0x10, ctx, ci); // NameOffset
        SMBUtil.writeInt2(4, ctx, ci + 2); // NameLength
        ci += 4;
        SMBUtil.writeInt2(0, ctx, ci); // Reserved
        SMBUtil.writeInt2(0x20, ctx, ci + 2); // DataOffset
        ci += 4;
        SMBUtil.writeInt4(8, ctx, ci); // DataLength
        ci += 4;
        System.arraycopy(new byte[] { 'T', 'E', 'S', 'T' }, 0, ctx, 0x10, 4);
        System.arraycopy(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, 0, ctx, 0x20, 8);

        byte[] packet = buildPacket(header, baseBody, ctxOffsetFromHeader, ctx);

        resp.decode(packet, 0, false);

        // Unrecognized context types lead to an empty array, not null
        assertNotNull(resp.getCreateContexts());
        assertEquals(0, resp.getCreateContexts().length);
    }

    @Test
    void prepare_setsFileId_whenReceived_andNextSupportsIt() throws Exception {
        Configuration config = Mockito.mock(Configuration.class);
        Smb2CreateResponse resp = new Smb2CreateResponse(config, "x");

        // Give it a known fileId by decoding a minimal packet
        byte[] fileId = new byte[16];
        for (int i = 0; i < 16; i++) fileId[i] = (byte) (0xF0 + i);
        byte[] header = buildSmb2Header();
        byte[] body = buildCreateBodyNoContexts((byte) 0, (byte) 0, 0, 0L, 0L, 0L, 0L, 0L, 0L, 0, fileId);
        byte[] packet = buildPacket(header, body, null, null);
        resp.decode(packet, 0, false); // marks as received

        // Create a request that implements both CommonServerMessageBlockRequest and RequestWithFileId
        CommonServerMessageBlockRequest next = mock(CommonServerMessageBlockRequest.class,
                withSettings().extraInterfaces(RequestWithFileId.class));

        resp.prepare(next);

        verify((RequestWithFileId) next, times(1)).setFileId(eq(fileId));
    }

    @Test
    void prepare_doesNothing_whenNotReceived() {
        Configuration config = Mockito.mock(Configuration.class);
        Smb2CreateResponse resp = new Smb2CreateResponse(config, "x");

        CommonServerMessageBlockRequest next = mock(CommonServerMessageBlockRequest.class,
                withSettings().extraInterfaces(RequestWithFileId.class));

        resp.prepare(next);

        verify((RequestWithFileId) next, never()).setFileId(any());
    }

    @Test
    void decode_invalidStructureSize_throws() {
        Configuration config = Mockito.mock(Configuration.class);
        Smb2CreateResponse resp = new Smb2CreateResponse(config, "bad");

        byte[] header = buildSmb2Header();
        byte[] body = new byte[2 + 2 + 4];
        // Wrong structure size (e.g., 0)
        SMBUtil.writeInt2(0, body, 0);
        // The rest of the fields are irrelevant since it should fail early
        byte[] packet = buildPacket(header, body, null, null);

        assertThrows(SMBProtocolDecodingException.class, () -> resp.decode(packet, 0, false));
    }
}

