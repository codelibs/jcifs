package jcifs.smb1.smb1;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.TimeZone;

import jcifs.smb1.smb1.SmbConstants;
import jcifs.smb1.smb1.ServerMessageBlock;
import jcifs.smb1.util.Hexdump;

class ServerMessageBlockTest {

    private TestServerMessageBlock smb;

    // A concrete implementation of the abstract ServerMessageBlock for testing
    private static class TestServerMessageBlock extends ServerMessageBlock {
        private byte[] paramWords;
        private byte[] bytes;

        TestServerMessageBlock() {
            super();
            this.paramWords = new byte[0];
            this.bytes = new byte[0];
        }

        void setParamWords(byte[] paramWords) {
            this.paramWords = paramWords;
            this.wordCount = paramWords.length / 2;
        }

        void setBytes(byte[] bytes) {
            this.bytes = bytes;
            this.byteCount = bytes.length;
        }

        @Override
        int writeParameterWordsWireFormat(byte[] dst, int dstIndex) {
            System.arraycopy(paramWords, 0, dst, dstIndex, paramWords.length);
            return paramWords.length;
        }

        @Override
        int writeBytesWireFormat(byte[] dst, int dstIndex) {
            System.arraycopy(bytes, 0, dst, dstIndex, bytes.length);
            return bytes.length;
        }

        @Override
        int readParameterWordsWireFormat(byte[] buffer, int bufferIndex) {
            System.arraycopy(buffer, bufferIndex, paramWords, 0, wordCount * 2);
            return wordCount * 2;
        }

        @Override
        int readBytesWireFormat(byte[] buffer, int bufferIndex) {
            System.arraycopy(buffer, bufferIndex, bytes, 0, byteCount);
            return byteCount;
        }
    }

    @BeforeEach
    void setUp() {
        smb = new TestServerMessageBlock();
    }

    @Test
    void testInt2ReadWrite() {
        byte[] buffer = new byte[2];
        ServerMessageBlock.writeInt2(0x1234, buffer, 0);
        assertEquals(0x1234, ServerMessageBlock.readInt2(buffer, 0));
    }

    @Test
    void testInt4ReadWrite() {
        byte[] buffer = new byte[4];
        ServerMessageBlock.writeInt4(0x12345678, buffer, 0);
        assertEquals(0x12345678, ServerMessageBlock.readInt4(buffer, 0));
    }

    @Test
    void testInt8ReadWrite() {
        byte[] buffer = new byte[8];
        long value = 0x123456789ABCDEF0L;
        ServerMessageBlock.writeInt8(value, buffer, 0);
        assertEquals(value, ServerMessageBlock.readInt8(buffer, 0));
    }

    @Test
    void testTimeReadWrite() {
        byte[] buffer = new byte[8];
        long time = System.currentTimeMillis();
        ServerMessageBlock.writeTime(time, buffer, 0);
        long readTime = ServerMessageBlock.readTime(buffer, 0);
        // Precision may be lost, so check within a second
        assertTrue(Math.abs(time - readTime) < 1000);
    }
    
    @Test
    void testTimeReadWriteZero() {
        byte[] buffer = new byte[8];
        ServerMessageBlock.writeTime(0, buffer, 0);
        // When zero is written, it stays as zero in buffer
        // When read back, it converts to negative Unix time due to Windows FileTime conversion
        long expectedTime = -SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601;
        assertEquals(expectedTime, ServerMessageBlock.readTime(buffer, 0));
    }

    @Test
    void testUTimeReadWrite() {
        byte[] buffer = new byte[4];
        long time = System.currentTimeMillis();
        // UTime is seconds since epoch, so divide by 1000
        long unixTime = time / 1000L;
        
        // Mocking date for timezone consistency
        TimeZone original = TimeZone.getDefault();
        try {
            TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
            ServerMessageBlock.writeUTime(unixTime * 1000L, buffer, 0);
            long readTime = ServerMessageBlock.readUTime(buffer, 0);
            assertEquals(unixTime * 1000L, readTime);
        } finally {
            TimeZone.setDefault(original);
        }
    }

    @Test
    void testStringReadWriteASCII() throws UnsupportedEncodingException {
        smb.useUnicode = false;
        String testString = "Hello World";
        byte[] buffer = new byte[testString.length() + 1];
        int len = smb.writeString(testString, buffer, 0);
        assertEquals(testString.length() + 1, len);
        String readString = smb.readString(buffer, 0);
        assertEquals(testString, readString);
    }

    @Test
    void testStringReadWriteUnicode() throws UnsupportedEncodingException {
        smb.useUnicode = true;
        String testString = "Hello Unicode World";
        byte[] buffer = new byte[testString.length() * 2 + 2];
        int len = smb.writeString(testString, buffer, 0);
        assertEquals(testString.length() * 2 + 2, len);
        String readString = smb.readString(buffer, 0);
        assertEquals(testString, readString);
    }
    
    @Test
    void testStringReadWriteUnicodeWithOddAlignment() throws UnsupportedEncodingException {
        smb.useUnicode = true;
        smb.headerStart = 1; // Make the start odd
        String testString = "Aligned Unicode";
        byte[] buffer = new byte[testString.length() * 2 + 2 + 1]; // +1 for alignment
        int len = smb.writeString(testString, buffer, 1);
        // When dstIndex=1 and headerStart=1, (1-1)%2=0, no alignment padding needed
        // Length is string bytes (15*2) + 2 null terminators = 32
        assertEquals(testString.length() * 2 + 2, len);
        String readString = smb.readString(buffer, 1);
        assertEquals(testString, readString);
    }

    @Test
    void testReadStringWithMaxLength() {
        smb.useUnicode = false;
        byte[] buffer = new byte[6];
        System.arraycopy("short".getBytes(), 0, buffer, 0, 5);
        buffer[5] = 0; // Null terminator
        String result = smb.readString(buffer, 0, 5, false);
        assertEquals("short", result);
    }

    @Test
    void testReadStringWithMaxLengthExceeded() {
        smb.useUnicode = false;
        byte[] buffer = "a very long string that exceeds max length".getBytes();
        assertThrows(RuntimeException.class, () -> {
            smb.readString(buffer, 0, 10, false);
        });
    }

    @Test
    void testEncodeDecode() {
        // Setup SMB with some data
        smb.command = ServerMessageBlock.SMB_COM_ECHO;
        smb.mid = 123;
        smb.pid = 456;
        smb.tid = 789;
        smb.uid = 101;
        smb.flags2 = ServerMessageBlock.FLAGS2_UNICODE;
        smb.useUnicode = true;

        byte[] params = { 0x01, 0x02, 0x03, 0x04 };
        byte[] bytes = { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
        smb.setParamWords(params);
        smb.setBytes(bytes);

        byte[] buffer = new byte[1024];
        int length = smb.encode(buffer, 0);

        // Create a new SMB to decode into
        TestServerMessageBlock decodedSmb = new TestServerMessageBlock();
        decodedSmb.setParamWords(new byte[params.length]);
        decodedSmb.setBytes(new byte[bytes.length]);
        decodedSmb.decode(buffer, 0);

        assertEquals(smb.command, decodedSmb.command);
        assertEquals(smb.mid, decodedSmb.mid);
        assertEquals(smb.pid, decodedSmb.pid);
        assertEquals(smb.tid, decodedSmb.tid);
        assertEquals(smb.uid, decodedSmb.uid);
        assertEquals(smb.flags2, decodedSmb.flags2);
        assertEquals(smb.wordCount, decodedSmb.wordCount);
        assertEquals(smb.byteCount, decodedSmb.byteCount);
        assertArrayEquals(smb.paramWords, decodedSmb.paramWords);
        assertArrayEquals(smb.bytes, decodedSmb.bytes);
    }

    @Test
    void testWriteHeaderReadHeader() {
        byte[] buffer = new byte[32];
        smb.command = ServerMessageBlock.SMB_COM_NEGOTIATE;
        smb.flags = (byte)0x18;
        smb.flags2 = 0x0001;
        smb.tid = 1;
        smb.pid = 2;
        smb.uid = 3;
        smb.mid = 4;

        smb.writeHeaderWireFormat(buffer, 0);

        TestServerMessageBlock readSmb = new TestServerMessageBlock();
        readSmb.readHeaderWireFormat(buffer, 0);

        assertEquals(smb.command, readSmb.command);
        assertEquals(smb.flags, readSmb.flags);
        assertEquals(smb.flags2, readSmb.flags2);
        assertEquals(smb.tid, readSmb.tid);
        assertEquals(smb.pid, readSmb.pid);
        assertEquals(smb.uid, readSmb.uid);
        assertEquals(smb.mid, readSmb.mid);
    }

    @Test
    void testIsResponse() {
        smb.flags = (byte) ServerMessageBlock.FLAGS_RESPONSE;
        assertTrue(smb.isResponse());
        smb.flags = 0;
        assertFalse(smb.isResponse());
    }

    @Test
    void testEqualsAndHashCode() {
        ServerMessageBlock smb1 = new TestServerMessageBlock();
        smb1.mid = 100;

        ServerMessageBlock smb2 = new TestServerMessageBlock();
        smb2.mid = 100;

        ServerMessageBlock smb3 = new TestServerMessageBlock();
        smb3.mid = 200;

        assertEquals(smb1, smb2);
        assertNotEquals(smb1, smb3);
        assertEquals(smb1.hashCode(), smb2.hashCode());
        assertNotEquals(smb1.hashCode(), smb3.hashCode());
        assertNotEquals(smb1, new Object());
    }

    @Test
    void testToString() {
        smb.command = ServerMessageBlock.SMB_COM_ECHO;
        smb.errorCode = 0;
        smb.mid = 1;
        String str = smb.toString();
        assertTrue(str.contains("command=SMB_COM_ECHO"));
        assertTrue(str.contains("errorCode=0"));
        assertTrue(str.contains("mid=1"));
    }
    
    @Test
    void testToStringUnknownCommand() {
        smb.command = (byte)0xFF; // Unknown command
        smb.errorCode = 0;
        smb.mid = 1;
        String str = smb.toString();
        assertTrue(str.contains("command=UNKNOWN"));
    }
}
