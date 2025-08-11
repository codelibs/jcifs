package jcifs.smb;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.net.MalformedURLException;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.internal.fscc.FileEndOfFileInformation;
import jcifs.internal.smb1.com.SmbComWrite;
import jcifs.internal.smb1.com.SmbComWriteResponse;
import jcifs.internal.smb1.trans2.Trans2SetFileInformation;
import jcifs.internal.smb1.trans2.Trans2SetFileInformationResponse;
import jcifs.internal.smb2.info.Smb2SetInfoRequest;

/**
 * Tests for SmbRandomAccessFile covering happy paths, edge cases, and interactions.
 */
@ExtendWith(MockitoExtension.class)
public class SmbRandomAccessFileTest {

    // Helper: build a minimally wired instance with mocks; avoids real I/O
    private SmbRandomAccessFile newInstance(String mode, boolean smb2, boolean ntSmbsCap, boolean unshared)
            throws CIFSException {
        SmbFile file = mock(SmbFile.class);
        SmbTreeHandleImpl tree = mock(SmbTreeHandleImpl.class);
        Configuration cfg = mock(Configuration.class);
        SmbFileHandleImpl fh = mock(SmbFileHandleImpl.class);

        when(file.ensureTreeConnected()).thenReturn(tree);
        when(tree.getConfig()).thenReturn(cfg);
        when(tree.getReceiveBufferSize()).thenReturn(1024);
        when(tree.getSendBufferSize()).thenReturn(1024);
        when(tree.hasCapability(anyInt())).thenAnswer(inv -> ntSmbsCap && inv.getArgument(0).equals(SmbConstants.CAP_NT_SMBS));
        when(tree.areSignaturesActive()).thenReturn(false);
        when(tree.isSMB2()).thenReturn(smb2);

        when(file.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenReturn(fh);
        when(fh.acquire()).thenReturn(fh);
        when(fh.isValid()).thenReturn(true);
        when(fh.getTree()).thenReturn(tree);
        when(fh.getFileId()).thenReturn(new byte[16]);
        when(fh.getFid()).thenReturn(1);

        // build via package-private constructor to control unshared flag
        return new SmbRandomAccessFile(file, mode, SmbConstants.DEFAULT_SHARING, unshared);
    }

    @Test
    @DisplayName("Constructor: invalid mode throws IllegalArgumentException")
    void constructor_invalidMode_throws() {
        SmbFile file = mock(SmbFile.class);
        assertThrows(IllegalArgumentException.class, () -> new SmbRandomAccessFile(file, "badmode"));
    }

    @Test
    @DisplayName("open(): acquires and releases handle (no I/O)")
    void open_acquiresAndReleasesHandle() throws Exception {
        SmbRandomAccessFile raf = spy(newInstance("rw", false, true, false));
        SmbFileHandleImpl fh = mock(SmbFileHandleImpl.class);
        doReturn(fh).when(raf).ensureOpen();

        // Act
        raf.open();

        // Assert: open() ensures handle and closes it via try-with-resources
        verify(raf, times(1)).ensureOpen();
        verify(fh, times(1)).close();
    }

    @Test
    @DisplayName("close(): clears cache and closes handle; does not close shared SmbFile")
    void close_sharedFile_closesHandle_only() throws Exception {
        SmbRandomAccessFile raf = newInstance("rw", false, true, false);
        SmbFile file = (SmbFile) Mockito.spy(getField(raf, "file"));
        setField(raf, "file", file);
        SmbFileHandleImpl handle = (SmbFileHandleImpl) getField(raf, "handle");

        // Act
        raf.close();

        // Assert interactions
        verify(handle, atLeastOnce()).close();
        verify(file, times(1)).clearAttributeCache();
        verify(file, never()).close();
    }

    @Test
    @DisplayName("close(): closes SmbFile when unsharedFile=true")
    void close_unsharedFile_closesFile() throws Exception {
        SmbRandomAccessFile raf = newInstance("rw", false, true, true);
        SmbFile file = (SmbFile) Mockito.spy(getField(raf, "file"));
        setField(raf, "file", file);

        raf.close();

        verify(file, times(1)).clearAttributeCache();
        verify(file, times(1)).close();
    }

    @Test
    @DisplayName("read(byte[],off,0): returns 0 without I/O")
    void read_lenZero_returnsZero() throws Exception {
        SmbRandomAccessFile raf = newInstance("r", false, false, false);
        byte[] buf = new byte[4];
        assertEquals(0, raf.read(buf, 0, 0));
    }

    @Test
    @DisplayName("read(): returns -1 when underlying read reports EOF")
    void read_returnsMinusOne_onEOF() throws Exception {
        SmbRandomAccessFile raf = spy(newInstance("r", false, false, false));
        // Stub the 3-arg read to signal EOF
        doReturn(-1).when(raf).read(any(byte[].class), anyInt(), eq(1));
        assertEquals(-1, raf.read());
    }

    @Test
    @DisplayName("readFully(): throws SmbEndOfFileException on premature EOF")
    void readFully_throws_onEOF() throws Exception {
        SmbRandomAccessFile raf = spy(newInstance("r", false, false, false));
        doReturn(-1).when(raf).read(any(byte[].class), anyInt(), anyInt());
        assertThrows(SmbEndOfFileException.class, () -> raf.readFully(new byte[4]));
    }

    @Test
    @DisplayName("readFully(): reads across multiple partial reads")
    void readFully_readsAll() throws Exception {
        SmbRandomAccessFile raf = spy(newInstance("r", false, false, false));
        AtomicInteger calls = new AtomicInteger();
        doAnswer(inv -> {
            int len = inv.getArgument(2);
            // First call returns len-1, second returns 1
            return calls.getAndIncrement() == 0 ? Math.max(1, len - 1) : 1;
        }).when(raf).read(any(byte[].class), anyInt(), anyInt());
        byte[] dst = new byte[4];
        assertDoesNotThrow(() -> raf.readFully(dst));
        assertEquals(2, calls.get());
    }

    @Test
    @DisplayName("skipBytes(): advances file pointer for positive values")
    void skipBytes_advancesFP() throws Exception {
        SmbRandomAccessFile raf = newInstance("r", false, false, false);
        assertEquals(0L, raf.getFilePointer());
        int skipped = raf.skipBytes(5);
        assertEquals(5, skipped);
        assertEquals(5L, raf.getFilePointer());
        assertEquals(0, raf.skipBytes(-3));
    }

    @Test
    @DisplayName("seek() and getFilePointer(): set and get position")
    void seek_and_getFilePointer() throws Exception {
        SmbRandomAccessFile raf = newInstance("r", false, false, false);
        raf.seek(123L);
        assertEquals(123L, raf.getFilePointer());
    }

    @Test
    @DisplayName("length(): delegates to SmbFile.length()")
    void length_delegates() throws Exception {
        SmbRandomAccessFile raf = newInstance("r", false, false, false);
        SmbFile file = (SmbFile) getField(raf, "file");
        when(file.length()).thenReturn(42L);
        assertEquals(42L, raf.length());
    }

    @Test
    @DisplayName("setLength(): SMB2 path sends Smb2SetInfoRequest")
    void setLength_smb2_sendsSetInfo() throws Exception {
        SmbRandomAccessFile raf = newInstance("rw", true, false, false);
        SmbFileHandleImpl fh = (SmbFileHandleImpl) getField(raf, "handle");
        SmbTreeHandleImpl tree = fh.getTree();
        // do not actually perform network call
        when(tree.send(any(jcifs.internal.Request.class), any(RequestParam.class))).thenReturn(null);

        raf.setLength(100L);

        verify(tree, times(1)).send(any(Smb2SetInfoRequest.class), eq(RequestParam.NO_RETRY));
    }

    @Test
    @DisplayName("setLength(): NT SMBs capability uses Trans2SetFileInformation")
    void setLength_ntsmbs_usesTrans2() throws Exception {
        SmbRandomAccessFile raf = newInstance("rw", false, true, false);
        SmbFileHandleImpl fh = (SmbFileHandleImpl) getField(raf, "handle");
        SmbTreeHandleImpl tree = fh.getTree();
        when(tree.send(any(Trans2SetFileInformation.class), any(Trans2SetFileInformationResponse.class), any(RequestParam.class)))
                .thenReturn(null);

        raf.setLength(200L);

        verify(tree, times(1))
                .send(any(Trans2SetFileInformation.class), any(Trans2SetFileInformationResponse.class), eq(RequestParam.NO_RETRY));
    }

    @Test
    @DisplayName("setLength(): legacy path uses SmbComWrite for truncation")
    void setLength_legacy_usesComWrite() throws Exception {
        SmbRandomAccessFile raf = newInstance("rw", false, false, false);
        SmbFileHandleImpl fh = (SmbFileHandleImpl) getField(raf, "handle");
        SmbTreeHandleImpl tree = fh.getTree();
        when(tree.send(any(SmbComWrite.class), any(SmbComWriteResponse.class), any(RequestParam.class))).thenReturn(null);

        raf.setLength(0L);

        verify(tree, times(1)).send(any(SmbComWrite.class), any(SmbComWriteResponse.class), eq(RequestParam.NO_RETRY));
    }

    @Test
    @DisplayName("readBoolean/readByte/readUnsignedByte: decode 1-byte values")
    void read_oneByteVariants() throws Exception {
        SmbRandomAccessFile raf = spy(newInstance("r", false, false, false));
        // For each 1-byte read, fill provided buffer with 0xFF/0x01
        doAnswer(inv -> {
            byte[] b = inv.getArgument(0);
            int off = inv.getArgument(1);
            b[off] = (byte) 0xFF;
            return 1;
        }).when(raf).read(any(byte[].class), anyInt(), eq(1));
        assertTrue(raf.readBoolean());
        assertEquals((byte) 0xFF, raf.readByte());
        assertEquals(0xFF, raf.readUnsignedByte());
    }

    @Test
    @DisplayName("readShort/UnsignedShort/Char: big-endian decoding")
    void read_twoByteVariants() throws Exception {
        SmbRandomAccessFile raf = spy(newInstance("r", false, false, false));
        doAnswer(inv -> {
            byte[] b = inv.getArgument(0);
            int off = inv.getArgument(1);
            b[off] = 0x12;
            b[off + 1] = 0x34;
            return 2;
        }).when(raf).read(any(byte[].class), anyInt(), eq(2));
        assertEquals(0x1234, raf.readUnsignedShort());
        assertEquals((short) 0x1234, raf.readShort());
        assertEquals((char) 0x1234, raf.readChar());
    }

    @Test
    @DisplayName("readInt/Long/Float/Double: big-endian decoding")
    void read_multiByteVariants() throws Exception {
        SmbRandomAccessFile raf = spy(newInstance("r", false, false, false));
        // int 0x01020304
        doAnswer(inv -> {
            byte[] b = inv.getArgument(0);
            int off = inv.getArgument(1);
            b[off] = 0x01; b[off+1] = 0x02; b[off+2] = 0x03; b[off+3] = 0x04;
            return 4;
        }).when(raf).read(any(byte[].class), anyInt(), eq(4));
        assertEquals(0x01020304, raf.readInt());

        // long 0x0102030405060708L
        doAnswer(inv -> {
            byte[] b = inv.getArgument(0);
            int off = inv.getArgument(1);
            b[off]=0x01; b[off+1]=0x02; b[off+2]=0x03; b[off+3]=0x04;
            b[off+4]=0x05; b[off+5]=0x06; b[off+6]=0x07; b[off+7]=0x08;
            return 8;
        }).when(raf).read(any(byte[].class), anyInt(), eq(8));
        assertEquals(0x0102030405060708L, raf.readLong());

        // float 1.0f -> 0x3F800000
        doAnswer(inv -> {
            byte[] b = inv.getArgument(0);
            int off = inv.getArgument(1);
            b[off]=0x3F; b[off+1]=0x80; b[off+2]=0x00; b[off+3]=0x00;
            return 4;
        }).when(raf).read(any(byte[].class), anyInt(), eq(4));
        assertEquals(1.0f, raf.readFloat(), 0.00001);

        // double 1.0 -> 0x3FF0000000000000
        doAnswer(inv -> {
            byte[] b = inv.getArgument(0);
            int off = inv.getArgument(1);
            b[off]=0x3F; b[off+1]=(byte)0xF0; b[off+2]=0x00; b[off+3]=0x00;
            b[off+4]=0x00; b[off+5]=0x00; b[off+6]=0x00; b[off+7]=0x00;
            return 8;
        }).when(raf).read(any(byte[].class), anyInt(), eq(8));
        assertEquals(1.0d, raf.readDouble(), 0.0000001);
    }

    @Test
    @DisplayName("readLine(): reads until newline and handles CRLF")
    void readLine_reads() throws Exception {
        SmbRandomAccessFile raf = spy(newInstance("r", false, false, false));
        // Sequence: 'a','b','\r','\n','c','\n'
        when(raf.read()).thenReturn((int)'a', (int)'b', (int)'\r', (int)'\n');
        assertEquals("ab", raf.readLine());

        when(raf.read()).thenReturn((int)'c', (int)'\n');
        assertEquals("c", raf.readLine());

        when(raf.read()).thenReturn(-1);
        assertNull(raf.readLine());
    }

    @Test
    @DisplayName("readUTF(): decodes bytes after size prefix")
    void readUTF_decodes() throws Exception {
        SmbRandomAccessFile raf = spy(newInstance("r", false, false, false));
        // Size prefix 3, then bytes for "abc"
        doReturn(3).when(raf).readUnsignedShort();
        doAnswer(inv -> {
            byte[] b = inv.getArgument(0);
            int off = inv.getArgument(1);
            b[off]= 'a'; b[off+1] = 'b'; b[off+2] = 'c';
            return 3;
        }).when(raf).read(any(byte[].class), anyInt(), eq(3));
        assertEquals("abc", raf.readUTF());
    }

    @Test
    @DisplayName("write(boolean/byte): writes single byte")
    void write_oneByteVariants() throws Exception {
        SmbRandomAccessFile raf = spy(newInstance("rw", false, true, false));
        // Intercept the 3-arg write to validate len
        doNothing().when(raf).write(any(byte[].class), anyInt(), anyInt());
        raf.writeBoolean(true);
        raf.writeByte(0x7F);
        ArgumentCaptor<Integer> lenCap = ArgumentCaptor.forClass(Integer.class);
        verify(raf, atLeast(2)).write(any(byte[].class), anyInt(), lenCap.capture());
        assertTrue(lenCap.getAllValues().stream().allMatch(len -> len == 1));
    }

    @Test
    @DisplayName("write(short/char/int/long/float/double): correct byte lengths")
    void write_multiByteVariants_lengths() throws Exception {
        SmbRandomAccessFile raf = spy(newInstance("rw", false, true, false));
        doNothing().when(raf).write(any(byte[].class), anyInt(), anyInt());

        raf.writeShort(1);
        raf.writeChar('A');
        raf.writeInt(1);
        raf.writeLong(1L);
        raf.writeFloat(1.0f);
        raf.writeDouble(1.0);

        // Verify length counts
        verify(raf).write(any(byte[].class), anyInt(), eq(2)); // short
        verify(raf).write(any(byte[].class), anyInt(), eq(2)); // char
        verify(raf).write(any(byte[].class), anyInt(), eq(4)); // int
        verify(raf).write(any(byte[].class), anyInt(), eq(8)); // long
        verify(raf).write(any(byte[].class), anyInt(), eq(4)); // float
        verify(raf).write(any(byte[].class), anyInt(), eq(8)); // double
    }

    @Test
    @DisplayName("writeBytes(): writes string bytes; writeChars(): 2x length")
    void write_stringVariants() throws Exception {
        SmbRandomAccessFile raf = spy(newInstance("rw", false, true, false));
        doNothing().when(raf).write(any(byte[].class), anyInt(), anyInt());

        raf.writeBytes("hi");
        raf.writeChars("yo");

        verify(raf).write(any(byte[].class), eq(0), eq(2)); // bytes
        verify(raf).write(any(byte[].class), eq(0), eq(4)); // chars
    }

    @Test
    @DisplayName("writeUTF(): prefixes size and writes encoded bytes")
    void writeUTF_encodesAndPrefixes() throws Exception {
        SmbRandomAccessFile raf = spy(newInstance("rw", false, true, false));
        doNothing().when(raf).write(any(byte[].class), anyInt(), anyInt());
        doNothing().when(raf).writeShort(anyInt());

        raf.writeUTF("é"); // 2-byte UTF-8 char

        // size prefix should be 2, and then write called with len=2
        verify(raf).writeShort(eq(2));
        verify(raf).write(any(byte[].class), eq(0), eq(2));
    }

    @Test
    @DisplayName("write(byte[],off,0): returns without I/O")
    void write_lenZero_noIO() throws Exception {
        SmbRandomAccessFile raf = spy(newInstance("rw", false, true, false));
        // If ensureOpen is called, fail the test
        doThrow(new AssertionError("ensureOpen should not be called"))
                .when(raf).ensureOpen();
        raf.write(new byte[1], 0, 0);
    }

    @Test
    @DisplayName("Null inputs: read(byte[]) and write* with nulls throw NPE")
    void nullInputs_throwNPE() throws Exception {
        SmbRandomAccessFile raf = newInstance("rw", false, true, false);
        assertThrows(NullPointerException.class, () -> raf.read((byte[]) null));
        assertThrows(NullPointerException.class, () -> raf.writeBytes(null));
        assertThrows(NullPointerException.class, () -> raf.writeChars(null));
        assertThrows(NullPointerException.class, () -> raf.writeUTF(null));
    }

    // Small reflection helpers to access private fields for interaction verification
    private static Object getField(Object target, String name) {
        try {
            var f = target.getClass().getDeclaredField(name);
            f.setAccessible(true);
            return f.get(target);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void setField(Object target, String name, Object value) {
        try {
            var f = target.getClass().getDeclaredField(name);
            f.setAccessible(true);
            f.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

