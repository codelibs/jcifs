package org.codelibs.jcifs.smb.internal.smb2.create;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Test class for Smb2CreateRequest
 */
@ExtendWith(MockitoExtension.class)
class Smb2CreateRequestTest {

    @Mock
    private Configuration mockConfig;

    @Mock
    private CIFSContext mockContext;

    @Mock
    private CreateContextRequest mockCreateContext;

    private Smb2CreateRequest request;

    @BeforeEach
    void setUp() {
        // Setup will be done in individual tests when needed
    }

    @Test
    @DisplayName("Test constructor with path initialization")
    void testConstructor() {
        // Test with normal path
        request = new Smb2CreateRequest(mockConfig, "test\\file.txt");
        assertNotNull(request);
        assertEquals("\\test\\file.txt", request.getPath());

        // Test with leading backslash
        request = new Smb2CreateRequest(mockConfig, "\\test\\file2.txt");
        assertEquals("\\test\\file2.txt", request.getPath());

        // Test with empty path
        request = new Smb2CreateRequest(mockConfig, "");
        assertEquals("\\", request.getPath());
    }

    @Test
    @DisplayName("Test setPath with various input formats")
    void testSetPath() {
        request = new Smb2CreateRequest(mockConfig, "");

        // Test normal path
        request.setPath("test\\file.txt");
        assertEquals("\\test\\file.txt", request.getPath());

        // Test path with leading backslash (should be stripped)
        request.setPath("\\test\\file.txt");
        assertEquals("\\test\\file.txt", request.getPath());

        // Test path with trailing backslash (should be stripped)
        request.setPath("test\\directory\\");
        assertEquals("\\test\\directory", request.getPath());

        // Test path with both leading and trailing backslash
        request.setPath("\\test\\directory\\");
        assertEquals("\\test\\directory", request.getPath());

        // Test single backslash
        request.setPath("\\");
        assertEquals("\\", request.getPath());

        // Test empty path
        request.setPath("");
        assertEquals("\\", request.getPath());
    }

    @Test
    @DisplayName("Test getPath returns correct formatted path")
    void testGetPath() {
        request = new Smb2CreateRequest(mockConfig, "share\\file.txt");
        assertEquals("\\share\\file.txt", request.getPath());

        request.setPath("newpath\\newfile.txt");
        assertEquals("\\newpath\\newfile.txt", request.getPath());
    }

    @Test
    @DisplayName("Test setFullUNCPath and related getters")
    void testFullUNCPath() {
        request = new Smb2CreateRequest(mockConfig, "test\\file.txt");

        assertNull(request.getFullUNCPath());
        assertNull(request.getServer());
        assertNull(request.getDomain());

        request.setFullUNCPath("DOMAIN", "SERVER", "\\\\SERVER\\share\\file.txt");

        assertEquals("DOMAIN", request.getDomain());
        assertEquals("SERVER", request.getServer());
        assertEquals("\\\\SERVER\\share\\file.txt", request.getFullUNCPath());
    }

    @Test
    @DisplayName("Test DFS resolution settings")
    void testDfsResolution() {
        request = new Smb2CreateRequest(mockConfig, "test.txt");

        // Initially should be false
        assertFalse(request.isResolveInDfs());

        // Set to true
        request.setResolveInDfs(true);
        assertTrue(request.isResolveInDfs());

        // Set to false
        request.setResolveInDfs(false);
        assertFalse(request.isResolveInDfs());
    }

    @Test
    @DisplayName("Test security flags setter")
    void testSetSecurityFlags() {
        request = new Smb2CreateRequest(mockConfig, "test.txt");

        request.setSecurityFlags((byte) 0x01);
        // Verify through writeBytesWireFormat
        byte[] buffer = new byte[1024];
        request.writeBytesWireFormat(buffer, 0);
        assertEquals((byte) 0x01, buffer[2]);
    }

    @Test
    @DisplayName("Test oplock level setter")
    void testSetRequestedOplockLevel() {
        request = new Smb2CreateRequest(mockConfig, "test.txt");

        request.setRequestedOplockLevel(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH);
        byte[] buffer = new byte[1024];
        request.writeBytesWireFormat(buffer, 0);
        assertEquals(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH, buffer[3]);

        request.setRequestedOplockLevel(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_EXCLUSIVE);
        request.writeBytesWireFormat(buffer, 0);
        assertEquals(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_EXCLUSIVE, buffer[3]);
    }

    @Test
    @DisplayName("Test impersonation level setter")
    void testSetImpersonationLevel() {
        request = new Smb2CreateRequest(mockConfig, "test.txt");

        request.setImpersonationLevel(Smb2CreateRequest.SMB2_IMPERSONATION_LEVEL_DELEGATE);
        byte[] buffer = new byte[1024];
        request.writeBytesWireFormat(buffer, 0);

        // Read impersonation level from buffer (offset 4-7)
        int impLevel = (buffer[4] & 0xFF) | ((buffer[5] & 0xFF) << 8) | ((buffer[6] & 0xFF) << 16) | ((buffer[7] & 0xFF) << 24);
        assertEquals(Smb2CreateRequest.SMB2_IMPERSONATION_LEVEL_DELEGATE, impLevel);
    }

    @Test
    @DisplayName("Test SMB create flags setter")
    void testSetSmbCreateFlags() {
        request = new Smb2CreateRequest(mockConfig, "test.txt");

        long flags = 0x1234567890ABCDEFL;
        request.setSmbCreateFlags(flags);

        byte[] buffer = new byte[1024];
        request.writeBytesWireFormat(buffer, 0);

        // Verify flags are written at correct offset (8-15)
        long readFlags = 0;
        for (int i = 0; i < 8; i++) {
            readFlags |= ((long) (buffer[8 + i] & 0xFF)) << (i * 8);
        }
        assertEquals(flags, readFlags);
    }

    @Test
    @DisplayName("Test desired access setter")
    void testSetDesiredAccess() {
        request = new Smb2CreateRequest(mockConfig, "test.txt");

        int access = 0x12345678;
        request.setDesiredAccess(access);

        byte[] buffer = new byte[1024];
        request.writeBytesWireFormat(buffer, 0);

        // Read desired access from buffer (offset 24-27 after 8 bytes reserved)
        int readAccess = (buffer[24] & 0xFF) | ((buffer[25] & 0xFF) << 8) | ((buffer[26] & 0xFF) << 16) | ((buffer[27] & 0xFF) << 24);
        assertEquals(access, readAccess);
    }

    @Test
    @DisplayName("Test file attributes setter")
    void testSetFileAttributes() {
        request = new Smb2CreateRequest(mockConfig, "test.txt");

        int attributes = 0x00000020; // FILE_ATTRIBUTE_ARCHIVE
        request.setFileAttributes(attributes);

        byte[] buffer = new byte[1024];
        request.writeBytesWireFormat(buffer, 0);

        // Read file attributes from buffer (offset 28-31)
        int readAttributes = (buffer[28] & 0xFF) | ((buffer[29] & 0xFF) << 8) | ((buffer[30] & 0xFF) << 16) | ((buffer[31] & 0xFF) << 24);
        assertEquals(attributes, readAttributes);
    }

    @Test
    @DisplayName("Test share access setter")
    void testSetShareAccess() {
        request = new Smb2CreateRequest(mockConfig, "test.txt");

        int shareAccess = Smb2CreateRequest.FILE_SHARE_READ | Smb2CreateRequest.FILE_SHARE_WRITE | Smb2CreateRequest.FILE_SHARE_DELETE;
        request.setShareAccess(shareAccess);

        byte[] buffer = new byte[1024];
        request.writeBytesWireFormat(buffer, 0);

        // Read share access from buffer (offset 32-35)
        int readShareAccess = (buffer[32] & 0xFF) | ((buffer[33] & 0xFF) << 8) | ((buffer[34] & 0xFF) << 16) | ((buffer[35] & 0xFF) << 24);
        assertEquals(shareAccess, readShareAccess);
    }

    @Test
    @DisplayName("Test create disposition setter")
    void testSetCreateDisposition() {
        request = new Smb2CreateRequest(mockConfig, "test.txt");

        request.setCreateDisposition(Smb2CreateRequest.FILE_OVERWRITE_IF);

        byte[] buffer = new byte[1024];
        request.writeBytesWireFormat(buffer, 0);

        // Read create disposition from buffer (offset 36-39)
        int readDisposition = (buffer[36] & 0xFF) | ((buffer[37] & 0xFF) << 8) | ((buffer[38] & 0xFF) << 16) | ((buffer[39] & 0xFF) << 24);
        assertEquals(Smb2CreateRequest.FILE_OVERWRITE_IF, readDisposition);
    }

    @Test
    @DisplayName("Test create options setter")
    void testSetCreateOptions() {
        request = new Smb2CreateRequest(mockConfig, "test.txt");

        int options = Smb2CreateRequest.FILE_DIRECTORY_FILE | Smb2CreateRequest.FILE_DELETE_ON_CLOSE;
        request.setCreateOptions(options);

        byte[] buffer = new byte[1024];
        request.writeBytesWireFormat(buffer, 0);

        // Read create options from buffer (offset 40-43)
        int readOptions = (buffer[40] & 0xFF) | ((buffer[41] & 0xFF) << 8) | ((buffer[42] & 0xFF) << 16) | ((buffer[43] & 0xFF) << 24);
        assertEquals(options, readOptions);
    }

    @Test
    @DisplayName("Test size calculation without create contexts")
    void testSizeWithoutCreateContexts() {
        request = new Smb2CreateRequest(mockConfig, "test.txt");

        int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 56;
        int nameLen = 2 * "test.txt".length();
        expectedSize += ((nameLen + 7) / 8) * 8; // size8(nameLen)
        expectedSize = ((expectedSize + 7) / 8) * 8; // size8(size)

        assertEquals(expectedSize, request.size());
    }

    @Test
    @DisplayName("Test size calculation with empty path")
    void testSizeWithEmptyPath() {
        request = new Smb2CreateRequest(mockConfig, "");

        int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 56;
        expectedSize += 8; // size8(1) - empty name gets 1 byte
        expectedSize = ((expectedSize + 7) / 8) * 8; // size8(size)

        assertEquals(expectedSize, request.size());
    }

    @Test
    @DisplayName("Test createResponse")
    void testCreateResponse() {
        // Setup mock for this specific test
        when(mockContext.getConfig()).thenReturn(mockConfig);

        request = new Smb2CreateRequest(mockConfig, "test\\file.txt");

        Smb2CreateResponse response = request.createResponse(mockContext, request);

        assertNotNull(response);
        assertTrue(response instanceof Smb2CreateResponse);
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() {
        request = new Smb2CreateRequest(mockConfig, "test\\file.txt");
        request.setResolveInDfs(true);

        String str = request.toString();
        assertNotNull(str);
        assertTrue(str.contains("name=test\\file.txt"));
        assertTrue(str.contains("resolveDfs=true"));
    }

    @Test
    @DisplayName("Test writeBytesWireFormat with empty name")
    void testWriteBytesWireFormatEmptyName() {
        request = new Smb2CreateRequest(mockConfig, "");

        byte[] buffer = new byte[1024];
        int bytesWritten = request.writeBytesWireFormat(buffer, 0);

        assertTrue(bytesWritten > 0);

        // Verify structure size field
        assertEquals(57, buffer[0]);
        assertEquals(0, buffer[1]);
    }

    @Test
    @DisplayName("Test writeBytesWireFormat with long path")
    void testWriteBytesWireFormatLongPath() {
        String longPath = "very\\long\\path\\to\\some\\deeply\\nested\\file\\in\\directory\\structure.txt";
        request = new Smb2CreateRequest(mockConfig, longPath);

        byte[] buffer = new byte[2048];
        int bytesWritten = request.writeBytesWireFormat(buffer, 0);

        assertTrue(bytesWritten > 0);

        // Verify name length field at offset 46 (after 44 bytes of fixed fields + 2 for name offset)
        byte[] nameBytes = longPath.getBytes(StandardCharsets.UTF_16LE);
        int nameLenInBuffer = (buffer[46] & 0xFF) | ((buffer[47] & 0xFF) << 8);
        assertEquals(nameBytes.length, nameLenInBuffer);
    }

    @Test
    @DisplayName("Test readBytesWireFormat returns 0")
    void testReadBytesWireFormat() {
        request = new Smb2CreateRequest(mockConfig, "test.txt");

        byte[] buffer = new byte[1024];
        int bytesRead = request.readBytesWireFormat(buffer, 0);

        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("Test all oplock level constants")
    void testOplockLevelConstants() {
        assertEquals((byte) 0x0, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_NONE);
        assertEquals((byte) 0x1, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_II);
        assertEquals((byte) 0x8, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_EXCLUSIVE);
        assertEquals((byte) 0x9, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH);
        assertEquals((byte) 0xFF, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_LEASE);
    }

    @Test
    @DisplayName("Test all impersonation level constants")
    void testImpersonationLevelConstants() {
        assertEquals(0x0, Smb2CreateRequest.SMB2_IMPERSONATION_LEVEL_ANONYMOUS);
        assertEquals(0x1, Smb2CreateRequest.SMB2_IMPERSONATION_LEVEL_IDENTIFICATION);
        assertEquals(0x2, Smb2CreateRequest.SMB2_IMPERSONATION_LEVEL_IMPERSONATION);
        assertEquals(0x3, Smb2CreateRequest.SMB2_IMPERSONATION_LEVEL_DELEGATE);
    }

    @Test
    @DisplayName("Test file share constants")
    void testFileShareConstants() {
        assertEquals(0x1, Smb2CreateRequest.FILE_SHARE_READ);
        assertEquals(0x2, Smb2CreateRequest.FILE_SHARE_WRITE);
        assertEquals(0x4, Smb2CreateRequest.FILE_SHARE_DELETE);
    }

    @Test
    @DisplayName("Test file disposition constants")
    void testFileDispositionConstants() {
        assertEquals(0x0, Smb2CreateRequest.FILE_SUPERSEDE);
        assertEquals(0x1, Smb2CreateRequest.FILE_OPEN);
        assertEquals(0x2, Smb2CreateRequest.FILE_CREATE);
        assertEquals(0x3, Smb2CreateRequest.FILE_OPEN_IF);
        assertEquals(0x4, Smb2CreateRequest.FILE_OVERWRITE);
        assertEquals(0x5, Smb2CreateRequest.FILE_OVERWRITE_IF);
    }

    @Test
    @DisplayName("Test file create options constants")
    void testFileCreateOptionsConstants() {
        assertEquals(0x1, Smb2CreateRequest.FILE_DIRECTORY_FILE);
        assertEquals(0x2, Smb2CreateRequest.FILE_WRITE_THROUGH);
        assertEquals(0x4, Smb2CreateRequest.FILE_SEQUENTIAL_ONLY);
        assertEquals(0x8, Smb2CreateRequest.FILE_NO_IMTERMEDIATE_BUFFERING);
        assertEquals(0x10, Smb2CreateRequest.FILE_SYNCHRONOUS_IO_ALERT);
        assertEquals(0x20, Smb2CreateRequest.FILE_SYNCHRONOUS_IO_NONALERT);
        assertEquals(0x40, Smb2CreateRequest.FILE_NON_DIRECTORY_FILE);
        assertEquals(0x100, Smb2CreateRequest.FILE_COMPLETE_IF_OPLOCKED);
        assertEquals(0x200, Smb2CreateRequest.FILE_NO_EA_KNOWLEDGE);
        assertEquals(0x400, Smb2CreateRequest.FILE_OPEN_REMOTE_INSTANCE);
        assertEquals(0x800, Smb2CreateRequest.FILE_RANDOM_ACCESS);
        assertEquals(0x1000, Smb2CreateRequest.FILE_DELETE_ON_CLOSE);
        assertEquals(0x2000, Smb2CreateRequest.FILE_OPEN_BY_FILE_ID);
        assertEquals(0x4000, Smb2CreateRequest.FILE_OPEN_FOR_BACKUP_INTENT);
        assertEquals(0x8000, Smb2CreateRequest.FILE_NO_COMPRESSION);
        assertEquals(0x10000, Smb2CreateRequest.FILE_OPEN_REQUIRING_OPLOCK);
        assertEquals(0x20000, Smb2CreateRequest.FILE_DISALLOW_EXCLUSIVE);
        assertEquals(0x100000, Smb2CreateRequest.FILE_RESERVE_OPFILTER);
        assertEquals(0x200000, Smb2CreateRequest.FILE_OPEN_REPARSE_POINT);
        assertEquals(0x400000, Smb2CreateRequest.FILE_NOP_RECALL);
        assertEquals(0x800000, Smb2CreateRequest.FILE_OPEN_FOR_FREE_SPACE_QUERY);
    }

    @Test
    @DisplayName("Test default values after construction")
    void testDefaultValues() {
        request = new Smb2CreateRequest(mockConfig, "test.txt");

        byte[] buffer = new byte[1024];
        request.writeBytesWireFormat(buffer, 0);

        // Check default oplock level (NONE)
        assertEquals(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_NONE, buffer[3]);

        // Check default impersonation level (IMPERSONATION)
        int impLevel = (buffer[4] & 0xFF) | ((buffer[5] & 0xFF) << 8) | ((buffer[6] & 0xFF) << 16) | ((buffer[7] & 0xFF) << 24);
        assertEquals(Smb2CreateRequest.SMB2_IMPERSONATION_LEVEL_IMPERSONATION, impLevel);

        // Check default desired access (0x00120089) at offset 24
        int desiredAccess = (buffer[24] & 0xFF) | ((buffer[25] & 0xFF) << 8) | ((buffer[26] & 0xFF) << 16) | ((buffer[27] & 0xFF) << 24);
        assertEquals(0x00120089, desiredAccess);

        // Check default share access (READ | WRITE) at offset 32
        int shareAccess = (buffer[32] & 0xFF) | ((buffer[33] & 0xFF) << 8) | ((buffer[34] & 0xFF) << 16) | ((buffer[35] & 0xFF) << 24);
        assertEquals(Smb2CreateRequest.FILE_SHARE_READ | Smb2CreateRequest.FILE_SHARE_WRITE, shareAccess);

        // Check default create disposition (OPEN) at offset 36
        int createDisposition =
                (buffer[36] & 0xFF) | ((buffer[37] & 0xFF) << 8) | ((buffer[38] & 0xFF) << 16) | ((buffer[39] & 0xFF) << 24);
        assertEquals(Smb2CreateRequest.FILE_OPEN, createDisposition);
    }

    @Test
    @DisplayName("Test path with special characters")
    void testPathWithSpecialCharacters() {
        String specialPath = "folder\\file with spaces.txt";
        request = new Smb2CreateRequest(mockConfig, specialPath);
        assertEquals("\\folder\\file with spaces.txt", request.getPath());

        String unicodePath = "文件夹\\文件.txt";
        request = new Smb2CreateRequest(mockConfig, unicodePath);
        assertEquals("\\文件夹\\文件.txt", request.getPath());
    }

    @Test
    @DisplayName("Test multiple path operations")
    void testMultiplePathOperations() {
        request = new Smb2CreateRequest(mockConfig, "initial\\path.txt");
        assertEquals("\\initial\\path.txt", request.getPath());

        request.setPath("\\second\\path.txt");
        assertEquals("\\second\\path.txt", request.getPath());

        request.setPath("third\\path\\");
        assertEquals("\\third\\path", request.getPath());

        // Multiple leading backslashes - only first one gets stripped, then trailing ones get stripped
        // But getPath() adds a backslash at the beginning, so \\fourth\path\\ becomes \fourth\path\
        request.setPath("\\\\fourth\\path\\\\");
        assertEquals("\\\\fourth\\path\\", request.getPath());
    }

    @Test
    @DisplayName("a create context carries its name at offset 16 and 8-byte aligned data, with no padding after the last one")
    void testEncodeSingleCreateContext() {
        request = new Smb2CreateRequest(mockConfig, "a");
        request.setCreateContexts(new RawCreateContext(ascii("TEST"), new byte[] { 1, 2, 3, 4, 5 }));

        // The 64 byte header, the 56 byte fixed body and the 2 byte name padded to 8 put the context at 128.
        // It ends at 128 + 16 (header) + 4 (name) + 4 (padding) + 5 (data) = 157.
        assertEquals(160, request.size());
        final byte[] buffer = prefilledBuffer();
        assertEquals(160, request.encode(buffer, 0));

        assertCreateContexts(buffer, 128, 29);
        assertCreateContext(buffer, 128, 0, ascii("TEST"), 24, new byte[] { 1, 2, 3, 4, 5 });
    }

    @Test
    @DisplayName("each create context points at its 8-byte aligned successor")
    void testEncodeChainedCreateContexts() {
        request = new Smb2CreateRequest(mockConfig, "a");
        request.setCreateContexts(new RawCreateContext(ascii("TEST"), new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }),
                new RawCreateContext(ascii("ABCD"), new byte[] { 9, 10, 11 }));

        // The first context ends on a boundary at 160; the second ends at 160 + 24 + 3 = 187.
        assertEquals(192, request.size());
        final byte[] buffer = prefilledBuffer();
        assertEquals(192, request.encode(buffer, 0));

        assertCreateContexts(buffer, 128, 59);
        assertCreateContext(buffer, 128, 32, ascii("TEST"), 24, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        assertCreateContext(buffer, 160, 0, ascii("ABCD"), 24, new byte[] { 9, 10, 11 });
    }

    @Test
    @DisplayName("a create context without data sends DataOffset 0 and is padded before its successor")
    void testEncodeCreateContextWithoutData() {
        request = new Smb2CreateRequest(mockConfig, "a");
        request.setCreateContexts(new RawCreateContext(ascii("QFid"), new byte[0]),
                new RawCreateContext(ascii("TEST"), new byte[] { 1, 2, 3, 4, 5 }));

        // The first context is header and name only, ending at 148 and padded to 152.
        // The second ends at 152 + 24 + 5 = 181.
        assertEquals(184, request.size());
        final byte[] buffer = prefilledBuffer();
        assertEquals(184, request.encode(buffer, 0));

        assertCreateContexts(buffer, 128, 53);
        assertCreateContext(buffer, 128, 24, ascii("QFid"), 0, new byte[0]);
        assertCreateContext(buffer, 152, 0, ascii("TEST"), 24, new byte[] { 1, 2, 3, 4, 5 });
    }

    @Test
    @DisplayName("a create context named by a 16 byte GUID has its data directly after the name")
    void testEncodeCreateContextWithGuidName() {
        // SMB2_CREATE_APP_INSTANCE_ID is named by a GUID rather than a four character tag
        final byte[] name = { 0x45, (byte) 0xBC, (byte) 0xA6, 0x6A, (byte) 0xEF, (byte) 0xA7, (byte) 0xF7, 0x4A, (byte) 0x90, 0x08,
                (byte) 0xFA, 0x46, 0x2E, 0x14, 0x4D, 0x74 };
        final byte[] data = new byte[20];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i + 1);
        }
        request = new Smb2CreateRequest(mockConfig, "a");
        request.setCreateContexts(new RawCreateContext(name, data));

        // Header and name end on a boundary at 160; the data ends at 180.
        assertEquals(184, request.size());
        final byte[] buffer = prefilledBuffer();
        assertEquals(184, request.encode(buffer, 0));

        assertCreateContexts(buffer, 128, 52);
        assertCreateContext(buffer, 128, 0, name, 32, data);
    }

    @Test
    @DisplayName("a request with an empty create context list leaves the create contexts section empty")
    void testEncodeWithEmptyCreateContexts() {
        request = new Smb2CreateRequest(mockConfig, "a");
        request.setCreateContexts();

        final byte[] buffer = prefilledBuffer();
        assertEquals(128, request.encode(buffer, 0));

        assertCreateContexts(buffer, 0, 0);
    }

    @Test
    @DisplayName("create context alignment is measured from the SMB2 header when the message follows a transport header")
    void testEncodeCreateContextsAfterTransportHeader() {
        request = new Smb2CreateRequest(mockConfig, "a");
        request.setCreateContexts(new RawCreateContext(ascii("QFid"), new byte[0]),
                new RawCreateContext(ascii("TEST"), new byte[] { 1, 2, 3, 4, 5 }));

        // The transport writes a 4 byte header before the message. This is testEncodeCreateContextWithoutData moved by 4;
        // aligning from the start of the buffer instead of the SMB2 header would shift the padded offsets.
        final byte[] buffer = prefilledBuffer();
        assertEquals(184, request.encode(buffer, 4));

        assertCreateContexts(buffer, 4, 128, 53);
        assertCreateContext(buffer, 4 + 128, 24, ascii("QFid"), 0, new byte[0]);
        assertCreateContext(buffer, 4 + 152, 0, ascii("TEST"), 24, new byte[] { 1, 2, 3, 4, 5 });
    }

    @Test
    @DisplayName("a create context whose size() reports no data but which writes some is refused rather than sent without it")
    void testEncodeRefusesContextThatUnderstatesItsSize() {
        request = new Smb2CreateRequest(mockConfig, "a");
        request.setCreateContexts(new RawCreateContext(ascii("TEST"), new byte[] { 1, 2, 3, 4, 5 }, 0));

        assertThrows(IllegalStateException.class, () -> request.encode(prefilledBuffer(), 0));
    }

    private static byte[] ascii(final String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * @return a buffer whose stale contents show up in any field the encoder does not write
     */
    private static byte[] prefilledBuffer() {
        final byte[] buffer = new byte[512];
        Arrays.fill(buffer, (byte) 0xAA);
        return buffer;
    }

    private static void assertCreateContexts(final byte[] buffer, final int offset, final int length) {
        assertCreateContexts(buffer, 0, offset, length);
    }

    private static void assertCreateContexts(final byte[] buffer, final int headerStart, final int offset, final int length) {
        // CreateContextsOffset and CreateContextsLength are 48 and 52 bytes into the body following the 64 byte header
        assertEquals(offset, SMBUtil.readInt4(buffer, headerStart + 64 + 48), "CreateContextsOffset");
        assertEquals(length, SMBUtil.readInt4(buffer, headerStart + 64 + 52), "CreateContextsLength");
    }

    private static void assertCreateContext(final byte[] buffer, final int start, final int next, final byte[] name, final int dataOffset,
            final byte[] data) {
        assertEquals(next, SMBUtil.readInt4(buffer, start), "Next");
        assertEquals(16, SMBUtil.readInt2(buffer, start + 4), "NameOffset");
        assertEquals(name.length, SMBUtil.readInt2(buffer, start + 6), "NameLength");
        assertEquals(0, SMBUtil.readInt2(buffer, start + 8), "Reserved");
        assertEquals(dataOffset, SMBUtil.readInt2(buffer, start + 10), "DataOffset");
        assertEquals(data.length, SMBUtil.readInt4(buffer, start + 12), "DataLength");
        assertArrayEquals(name, Arrays.copyOfRange(buffer, start + 16, start + 16 + name.length), "Name");
        assertArrayEquals(data, Arrays.copyOfRange(buffer, start + dataOffset, start + dataOffset + data.length), "Data");
    }

    /**
     * A create context that sends fixed name and data bytes.
     */
    private static final class RawCreateContext implements CreateContextRequest {

        private final byte[] name;
        private final byte[] data;
        private final int reportedSize;

        RawCreateContext(final byte[] name, final byte[] data) {
            this(name, data, data.length);
        }

        /**
         * @param reportedSize what {@link #size()} returns; a well-behaved context reports its data length
         */
        RawCreateContext(final byte[] name, final byte[] data, final int reportedSize) {
            this.name = name;
            this.data = data;
            this.reportedSize = reportedSize;
        }

        @Override
        public byte[] getName() {
            return this.name;
        }

        @Override
        public int encode(final byte[] dst, final int dstIndex) {
            System.arraycopy(this.data, 0, dst, dstIndex, this.data.length);
            return this.data.length;
        }

        @Override
        public int size() {
            return this.reportedSize;
        }
    }
}
