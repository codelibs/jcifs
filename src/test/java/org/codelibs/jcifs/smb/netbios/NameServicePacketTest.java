package org.codelibs.jcifs.smb.netbios;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.UnknownHostException;

import org.codelibs.jcifs.smb.Configuration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class NameServicePacketTest {

    private TestNameServicePacket packet;
    @Mock
    private Configuration mockConfig;
    @Mock
    private Name mockQuestionName;
    @Mock
    private Name mockRecordName;

    // Concrete implementation of NameServicePacket for testing
    private static class TestNameServicePacket extends NameServicePacket {
        public TestNameServicePacket(Configuration config) {
            super(config);
        }

        @Override
        int writeBodyWireFormat(byte[] dst, int dstIndex) {
            // For testing purposes, we can return a fixed length or mock behavior
            return 0;
        }

        @Override
        int readBodyWireFormat(byte[] src, int srcIndex) {
            // For testing purposes, we can return a fixed length or mock behavior
            return 0;
        }

        @Override
        int writeRDataWireFormat(byte[] dst, int dstIndex) {
            // For testing purposes, we can return a fixed length or mock behavior
            return 0;
        }

        @Override
        int readRDataWireFormat(byte[] src, int srcIndex) {
            // For testing purposes, we can return a fixed length or mock behavior
            // Create a dummy Name object for NbtAddress constructor
            Name dummyName = new Name(config, "DUMMY_NAME", 0, null);
            addrEntry[addrIndex] = new NbtAddress(dummyName, 0, false, NbtAddress.B_NODE);
            return 6; // NbtAddress is 6 bytes
        }
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        packet = new TestNameServicePacket(mockConfig);
        packet.questionName = mockQuestionName;
        packet.recordName = mockRecordName;
    }

    @Test
    void testWriteInt2() {
        byte[] dst = new byte[2];
        NameServicePacket.writeInt2(0x1234, dst, 0);
        assertEquals((byte) 0x12, dst[0]);
        assertEquals((byte) 0x34, dst[1]);
    }

    @Test
    void testWriteInt4() {
        byte[] dst = new byte[4];
        NameServicePacket.writeInt4(0x12345678, dst, 0);
        assertEquals((byte) 0x12, dst[0]);
        assertEquals((byte) 0x34, dst[1]);
        assertEquals((byte) 0x56, dst[2]);
        assertEquals((byte) 0x78, dst[3]);
    }

    @Test
    void testReadInt2() {
        byte[] src = { (byte) 0x12, (byte) 0x34 };
        assertEquals(0x1234, NameServicePacket.readInt2(src, 0));
    }

    @Test
    void testReadInt4() {
        byte[] src = { (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78 };
        assertEquals(0x12345678, NameServicePacket.readInt4(src, 0));
    }

    @Test
    void testReadNameTrnId() {
        byte[] src = { (byte) 0xAB, (byte) 0xCD };
        assertEquals(0xABCD, NameServicePacket.readNameTrnId(src, 0));
    }

    @Test
    void testConstructor() {
        assertTrue(packet.isRecurDesired);
        assertTrue(packet.isBroadcast);
        assertEquals(1, packet.questionCount);
        assertEquals(NameServicePacket.IN, packet.questionClass);
        assertEquals(mockConfig, packet.config);
    }

    @Test
    void testWriteHeaderWireFormat() {
        byte[] dst = new byte[NameServicePacket.HEADER_LENGTH];
        packet.nameTrnId = 0x1234;
        packet.isResponse = true;
        packet.opCode = NameServicePacket.QUERY;
        packet.isAuthAnswer = true;
        packet.isTruncated = true;
        packet.isRecurDesired = true;
        packet.isRecurAvailable = true;
        packet.isBroadcast = true;
        packet.resultCode = NameServicePacket.FMT_ERR;
        packet.questionCount = 1;
        packet.answerCount = 2;
        packet.authorityCount = 3;
        packet.additionalCount = 4;

        int written = packet.writeHeaderWireFormat(dst, 0);
        assertEquals(NameServicePacket.HEADER_LENGTH, written);

        assertEquals((byte) 0x12, dst[0]); // nameTrnId
        assertEquals((byte) 0x34, dst[1]);
        assertEquals((byte) (0x80 | (NameServicePacket.QUERY << 3) | 0x04 | 0x02 | 0x01), dst[2]); // flags1
        assertEquals((byte) (0x80 | 0x10 | NameServicePacket.FMT_ERR), dst[3]); // flags2
        assertEquals((byte) 0x00, dst[4]); // questionCount
        assertEquals((byte) 0x01, dst[5]);
        assertEquals((byte) 0x00, dst[6]); // answerCount
        assertEquals((byte) 0x02, dst[7]);
        assertEquals((byte) 0x00, dst[8]); // authorityCount
        assertEquals((byte) 0x03, dst[9]);
        assertEquals((byte) 0x00, dst[10]); // additionalCount
        assertEquals((byte) 0x04, dst[11]);
    }

    @Test
    void testReadHeaderWireFormat() {
        byte[] src = new byte[NameServicePacket.HEADER_LENGTH];
        NameServicePacket.writeInt2(0x1234, src, 0);
        src[2] = (byte) (0x80 | (NameServicePacket.QUERY << 3) | 0x04 | 0x02 | 0x01);
        src[3] = (byte) (0x80 | 0x10 | NameServicePacket.FMT_ERR);
        NameServicePacket.writeInt2(1, src, 4);
        NameServicePacket.writeInt2(2, src, 6);
        NameServicePacket.writeInt2(3, src, 8);
        NameServicePacket.writeInt2(4, src, 10);

        int read = packet.readHeaderWireFormat(src, 0);
        assertEquals(NameServicePacket.HEADER_LENGTH, read);

        assertEquals(0x1234, packet.nameTrnId);
        assertTrue(packet.isResponse);
        assertEquals(NameServicePacket.QUERY, packet.opCode);
        assertTrue(packet.isAuthAnswer);
        assertTrue(packet.isTruncated);
        assertTrue(packet.isRecurDesired);
        assertTrue(packet.isRecurAvailable);
        assertTrue(packet.isBroadcast);
        assertEquals(NameServicePacket.FMT_ERR, packet.resultCode);
        assertEquals(1, packet.questionCount);
        assertEquals(2, packet.answerCount);
        assertEquals(3, packet.authorityCount);
        assertEquals(4, packet.additionalCount);
    }

    @Test
    void testWriteQuestionSectionWireFormat() {
        byte[] dst = new byte[20]; // Sufficient size
        packet.questionType = NameServicePacket.NB;
        packet.questionClass = NameServicePacket.IN;

        when(mockQuestionName.writeWireFormat(any(byte[].class), anyInt())).thenReturn(10); // Mock name length

        int written = packet.writeQuestionSectionWireFormat(dst, 0);
        assertEquals(14, written); // 10 (name) + 2 (type) + 2 (class)
        verify(mockQuestionName).writeWireFormat(dst, 0);
        assertEquals((byte) 0x00, dst[10]); // questionType high byte
        assertEquals((byte) NameServicePacket.NB, dst[11]); // questionType low byte
        assertEquals((byte) 0x00, dst[12]); // questionClass high byte
        assertEquals((byte) NameServicePacket.IN, dst[13]); // questionClass low byte
    }

    @Test
    void testReadQuestionSectionWireFormat() {
        byte[] src = new byte[20];
        NameServicePacket.writeInt2(NameServicePacket.NB, src, 10); // Mock type
        NameServicePacket.writeInt2(NameServicePacket.IN, src, 12); // Mock class

        when(mockQuestionName.readWireFormat(any(byte[].class), anyInt())).thenReturn(10); // Mock name length

        int read = packet.readQuestionSectionWireFormat(src, 0);
        assertEquals(14, read); // 10 (name) + 2 (type) + 2 (class)
        verify(mockQuestionName).readWireFormat(src, 0);
        assertEquals(NameServicePacket.NB, packet.questionType);
        assertEquals(NameServicePacket.IN, packet.questionClass);
    }

    @Test
    void testWriteResourceRecordWireFormat_questionNamePointer() {
        byte[] dst = new byte[20];
        packet.recordName = packet.questionName; // Set recordName to be the same as questionName
        packet.recordType = NameServicePacket.A;
        packet.recordClass = NameServicePacket.IN;
        packet.ttl = 100;
        packet.rDataLength = 0; // Will be set by writeRDataWireFormat

        // TestNameServicePacket.writeRDataWireFormat returns 0
        int written = packet.writeResourceRecordWireFormat(dst, 0);
        assertEquals(12, written); // 2 (pointer) + 2 (type) + 2 (class) + 4 (ttl) + 2 (rDataLength) + 0 (rData)

        assertEquals((byte) 0xC0, dst[0]); // Pointer
        assertEquals((byte) 0x0C, dst[1]);
        assertEquals((byte) 0x00, dst[2]); // recordType high byte
        assertEquals((byte) NameServicePacket.A, dst[3]); // recordType low byte
        assertEquals((byte) 0x00, dst[4]); // recordClass high byte
        assertEquals((byte) NameServicePacket.IN, dst[5]); // recordClass low byte
        assertEquals(0x00, dst[6]); // ttl
        assertEquals(0x00, dst[7]);
        assertEquals(0x00, dst[8]);
        assertEquals(0x64, dst[9]);
        assertEquals((byte) 0x00, dst[10]); // rDataLength high byte
        assertEquals((byte) 0x00, dst[11]); // rDataLength low byte (0 because writeRDataWireFormat returns 0)
    }

    @Test
    void testWriteResourceRecordWireFormat_differentRecordName() {
        byte[] dst = new byte[30];
        packet.recordType = NameServicePacket.A;
        packet.recordClass = NameServicePacket.IN;
        packet.ttl = 100;
        packet.rDataLength = 0;

        when(mockRecordName.writeWireFormat(any(byte[].class), anyInt())).thenReturn(10); // Mock name length
        // TestNameServicePacket.writeRDataWireFormat returns 0

        int written = packet.writeResourceRecordWireFormat(dst, 0);
        assertEquals(20, written); // 10 (name) + 2 (type) + 2 (class) + 4 (ttl) + 2 (rDataLength) + 0 (rData)
        verify(mockRecordName).writeWireFormat(dst, 0);
    }

    @Test
    void testReadResourceRecordWireFormat_questionNamePointer() {
        byte[] src = new byte[20];
        src[0] = (byte) 0xC0;
        src[1] = (byte) 0x0C;
        NameServicePacket.writeInt2(NameServicePacket.A, src, 2); // recordType
        NameServicePacket.writeInt2(NameServicePacket.IN, src, 4); // recordClass
        NameServicePacket.writeInt4(100, src, 6); // ttl
        NameServicePacket.writeInt2(6, src, 10); // rDataLength (for one NbtAddress)

        packet.questionName = mockQuestionName; // Ensure questionName is set

        int read = packet.readResourceRecordWireFormat(src, 0);
        assertEquals(18, read); // 2 (pointer) + 2 (type) + 2 (class) + 4 (ttl) + 2 (rDataLength) + 6 (rData)
        assertEquals(packet.questionName, packet.recordName);
        assertEquals(NameServicePacket.A, packet.recordType);
        assertEquals(NameServicePacket.IN, packet.recordClass);
        assertEquals(100, packet.ttl);
        assertEquals(6, packet.rDataLength);
        assertNotNull(packet.addrEntry);
        assertEquals(1, packet.addrEntry.length);
    }

    @Test
    void testReadResourceRecordWireFormat_differentRecordName() {
        byte[] src = new byte[20];
        // No pointer, so mockRecordName will be read
        NameServicePacket.writeInt2(NameServicePacket.A, src, 10); // recordType (assuming name takes 10 bytes)
        NameServicePacket.writeInt2(NameServicePacket.IN, src, 12); // recordClass
        NameServicePacket.writeInt4(100, src, 14); // ttl
        NameServicePacket.writeInt2(6, src, 18); // rDataLength

        when(mockRecordName.readWireFormat(any(byte[].class), anyInt())).thenReturn(10); // Mock name length

        int read = packet.readResourceRecordWireFormat(src, 0);
        assertEquals(26, read); // 10 (name) + 2 (type) + 2 (class) + 4 (ttl) + 2 (rDataLength) + 6 (rData)
        verify(mockRecordName).readWireFormat(src, 0);
        assertEquals(NameServicePacket.A, packet.recordType);
        assertEquals(NameServicePacket.IN, packet.recordClass);
        assertEquals(100, packet.ttl);
        assertEquals(6, packet.rDataLength);
        assertNotNull(packet.addrEntry);
        assertEquals(1, packet.addrEntry.length);
    }

    @Test
    void testReadResourceRecordWireFormat_multipleRDataEntries() {
        byte[] src = new byte[30];
        src[0] = (byte) 0xC0;
        src[1] = (byte) 0x0C;
        NameServicePacket.writeInt2(NameServicePacket.A, src, 2); // recordType
        NameServicePacket.writeInt2(NameServicePacket.IN, src, 4); // recordClass
        NameServicePacket.writeInt4(100, src, 6); // ttl
        NameServicePacket.writeInt2(12, src, 10); // rDataLength (for two NbtAddress)

        packet.questionName = mockQuestionName;

        int read = packet.readResourceRecordWireFormat(src, 0);
        assertEquals(24, read); // 2 (pointer) + 2 (type) + 2 (class) + 4 (ttl) + 2 (rDataLength) + 12 (rData)
        assertEquals(12, packet.rDataLength);
        assertNotNull(packet.addrEntry);
        assertEquals(2, packet.addrEntry.length);
    }

    @Test
    void testWriteWireFormat() {
        byte[] dst = new byte[50];
        packet.nameTrnId = 0x1234;
        packet.questionCount = 1;
        packet.questionType = NameServicePacket.NB;
        packet.questionClass = NameServicePacket.IN;

        when(mockQuestionName.writeWireFormat(any(byte[].class), anyInt())).thenReturn(10);

        int written = packet.writeWireFormat(dst, 0);
        // HEADER_LENGTH (12) + writeBodyWireFormat (0) = 12
        assertEquals(12, written);
    }

    @Test
    void testReadWireFormat() {
        byte[] src = new byte[50];
        NameServicePacket.writeInt2(0x1234, src, 0); // nameTrnId
        src[2] = (byte) (0x00 | (NameServicePacket.QUERY << 3)); // opCode
        src[3] = (byte) (0x00); // flags2
        NameServicePacket.writeInt2(1, src, 4); // questionCount
        NameServicePacket.writeInt2(0, src, 6); // answerCount
        NameServicePacket.writeInt2(0, src, 8); // authorityCount
        NameServicePacket.writeInt2(0, src, 10); // additionalCount

        // Mock question name and its readWireFormat
        when(mockQuestionName.readWireFormat(any(byte[].class), anyInt())).thenReturn(10);
        NameServicePacket.writeInt2(NameServicePacket.NB, src, 12 + 10); // questionType
        NameServicePacket.writeInt2(NameServicePacket.IN, src, 12 + 10 + 2); // questionClass

        int read = packet.readWireFormat(src, 0);
        // HEADER_LENGTH (12) + readBodyWireFormat (0) = 12
        assertEquals(12, read);
        assertEquals(0x1234, packet.nameTrnId);
        assertEquals(1, packet.questionCount);
    }

    @Test
    void testToString() throws UnknownHostException {
        packet.nameTrnId = 1;
        packet.isResponse = true;
        packet.opCode = NameServicePacket.QUERY;
        packet.isAuthAnswer = true;
        packet.isTruncated = true;
        packet.isRecurAvailable = true;
        packet.isRecurDesired = true;
        packet.isBroadcast = true;
        packet.resultCode = NameServicePacket.FMT_ERR;
        packet.questionCount = 1;
        packet.answerCount = 0;
        packet.authorityCount = 0;
        packet.additionalCount = 0;
        packet.questionName = new Name(mockConfig, "TEST_NAME", 0, null);
        packet.questionType = NameServicePacket.NB;
        packet.questionClass = NameServicePacket.IN;
        packet.recordName = new Name(mockConfig, "TEST_RECORD", 0, null);
        packet.recordType = NameServicePacket.A;
        packet.recordClass = NameServicePacket.IN;
        packet.ttl = 3600;
        packet.rDataLength = 6;
        // Create a dummy Name object for NbtAddress constructor
        Name dummyName = new Name(mockConfig, "DUMMY_NAME", 0, null);
        packet.addrEntry = new NbtAddress[] { new NbtAddress(dummyName, 0, false, NbtAddress.B_NODE) };

        String expectedString =
                "nameTrnId=1,isResponse=true,opCode=QUERY,isAuthAnswer=true,isTruncated=true,isRecurAvailable=true,isRecurDesired=true,isBroadcast=true,resultCode=FMT_ERR,questionCount=1,answerCount=0,authorityCount=0,additionalCount=0,questionName=TEST_NAME<00>,questionType=NB,questionClass=IN,recordName=TEST_RECORD<00>,recordType=A,recordClass=IN,ttl=3600,rDataLength=6";
        assertEquals(expectedString, packet.toString());

        // Test other opCode, resultCode, questionType, recordType branches
        packet.opCode = NameServicePacket.WACK;
        packet.resultCode = NameServicePacket.SRV_ERR;
        packet.questionType = NameServicePacket.NBSTAT;
        packet.recordType = NameServicePacket.NBSTAT;
        expectedString =
                "nameTrnId=1,isResponse=true,opCode=WACK,isAuthAnswer=true,isTruncated=true,isRecurAvailable=true,isRecurDesired=true,isBroadcast=true,resultCode=SRV_ERR,questionCount=1,answerCount=0,authorityCount=0,additionalCount=0,questionName=TEST_NAME<00>,questionType=NBSTAT,questionClass=IN,recordName=TEST_RECORD<00>,recordType=NBSTAT,recordClass=IN,ttl=3600,rDataLength=6";
        assertEquals(expectedString, packet.toString());

        packet.opCode = 99; // Default case
        packet.resultCode = 99; // Default case
        packet.questionType = 99; // Default case
        packet.recordType = 99; // Default case
        expectedString =
                "nameTrnId=1,isResponse=true,opCode=99,isAuthAnswer=true,isTruncated=true,isRecurAvailable=true,isRecurDesired=true,isBroadcast=true,resultCode=0x3,questionCount=1,answerCount=0,authorityCount=0,additionalCount=0,questionName=TEST_NAME<00>,questionType=0x0063,questionClass=IN,recordName=TEST_RECORD<00>,recordType=0x0063,recordClass=IN,ttl=3600,rDataLength=6";
        assertEquals(expectedString, packet.toString());

        // Test recordName == questionName branch in toString
        packet.recordName = packet.questionName;
        expectedString =
                "nameTrnId=1,isResponse=true,opCode=99,isAuthAnswer=true,isTruncated=true,isRecurAvailable=true,isRecurDesired=true,isBroadcast=true,resultCode=0x3,questionCount=1,answerCount=0,authorityCount=0,additionalCount=0,questionName=TEST_NAME<00>,questionType=0x0063,questionClass=IN,recordName=TEST_NAME<00>,recordType=0x0063,recordClass=IN,ttl=3600,rDataLength=6";
        assertEquals(expectedString, packet.toString());
    }
}
