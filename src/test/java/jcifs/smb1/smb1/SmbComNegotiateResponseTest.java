package jcifs.smb1.smb1;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Date;

import jcifs.smb1.UniAddress;
import jcifs.smb1.smb1.SmbConstants;
import jcifs.smb1.smb1.SmbTransport;
import jcifs.smb1.smb1.SmbComNegotiateResponse;
import jcifs.smb1.smb1.ServerMessageBlock;

/**
 * Unit tests for the SmbComNegotiateResponse class.
 */
class SmbComNegotiateResponseTest {

    private SmbTransport.ServerData serverData;
    private SmbComNegotiateResponse response;

    @BeforeEach
    void setUp() throws UnknownHostException {
        // To instantiate the non-static inner class ServerData, we need an instance of the outer class SmbTransport.
        UniAddress uniAddress = new UniAddress(InetAddress.getByName("127.0.0.1"));
        SmbTransport transport = new SmbTransport(uniAddress, 445, null, 0);
        serverData = transport.new ServerData();
        response = new SmbComNegotiateResponse(serverData);
    }

    @Test
    void testReadParameterWordsWireFormat() {
        // Prepare a byte array with sample parameter words
        ByteBuffer buffer = ByteBuffer.allocate(34);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putShort((short) 0); // dialectIndex
        buffer.put((byte) 0x0F); // securityMode (user, encrypted, sigs enabled, sigs required)
        buffer.putShort((short) 50); // maxMpxCount
        buffer.putShort((short) 10); // maxNumberVcs
        buffer.putInt(8192); // maxBufferSize
        buffer.putInt(65536); // maxRawSize
        buffer.putInt(123456789); // sessionKey
        buffer.putInt(SmbConstants.CAP_UNICODE | SmbConstants.CAP_NT_SMBS); // capabilities
        buffer.putLong(new Date().getTime()); // serverTime
        buffer.putShort((short) -480); // serverTimeZone
        buffer.put((byte) 8); // encryptionKeyLength

        byte[] paramWords = buffer.array();

        // Call the method to test
        int bytesRead = response.readParameterWordsWireFormat(paramWords, 0);

        // Assert that the correct number of bytes were read
        assertEquals(34, bytesRead);

        // Assert that the serverData fields are populated correctly
        assertEquals(0, response.dialectIndex);
        assertEquals(0x0F, serverData.securityMode);
        assertEquals(0x01, serverData.security);
        assertTrue(serverData.encryptedPasswords);
        assertTrue(serverData.signaturesEnabled);
        assertTrue(serverData.signaturesRequired);
        assertEquals(50, serverData.maxMpxCount);
        assertEquals(10, serverData.maxNumberVcs);
        assertEquals(8192, serverData.maxBufferSize);
        assertEquals(65536, serverData.maxRawSize);
        assertEquals(123456789, serverData.sessionKey);
        assertEquals(SmbConstants.CAP_UNICODE | SmbConstants.CAP_NT_SMBS, serverData.capabilities);
        // readInt2 returns unsigned value, so -480 becomes 65056
        assertEquals(65056, serverData.serverTimeZone);
        assertEquals(8, serverData.encryptionKeyLength);
    }

    @Test
    void testReadParameterWordsWireFormat_InvalidDialect() {
        byte[] paramWords = new byte[2];
        paramWords[0] = 11; // dialectIndex > 10

        int bytesRead = response.readParameterWordsWireFormat(paramWords, 0);

        assertEquals(2, bytesRead);
        assertEquals(11, response.dialectIndex);
    }

    @Test
    void testReadBytesWireFormat_NoExtendedSecurity() throws UnsupportedEncodingException {
        // Setup server data for this scenario
        serverData.capabilities = 0; // No extended security
        serverData.encryptionKeyLength = 8;
        response.byteCount = 15; // 8 bytes key + 6 bytes "DOMAIN" + 1 null terminator

        // Prepare byte array
        byte[] encryptionKey = "12345678".getBytes();
        byte[] domainNameBytes = "DOMAIN".getBytes(ServerMessageBlock.OEM_ENCODING);
        ByteBuffer buffer = ByteBuffer.allocate(response.byteCount);
        buffer.put(encryptionKey);
        buffer.put(domainNameBytes);
        buffer.put((byte) 0x00); // Null terminator

        byte[] byteData = buffer.array();

        // Call the method
        int bytesRead = response.readBytesWireFormat(byteData, 0);

        // Assertions
        // readBytesWireFormat returns bytes processed up to null terminator
        assertEquals(14, bytesRead); // 8 bytes key + 6 bytes domain name
        assertArrayEquals(encryptionKey, serverData.encryptionKey);
        assertEquals("DOMAIN", serverData.oemDomainName);
    }

    @Test
    void testReadBytesWireFormat_NoExtendedSecurity_Unicode() throws UnsupportedEncodingException {
        // Setup server data for this scenario
        serverData.capabilities = 0; // No extended security
        serverData.encryptionKeyLength = 8;
        response.flags2 = ServerMessageBlock.FLAGS2_UNICODE;
        byte[] domainNameBytes = "DOMAIN_U".getBytes("UTF-16LE");
        response.byteCount = 8 + domainNameBytes.length + 2; // key + domain + null terminator

        // Prepare byte array
        byte[] encryptionKey = "12345678".getBytes();
        ByteBuffer buffer = ByteBuffer.allocate(response.byteCount);
        buffer.put(encryptionKey);
        buffer.put(domainNameBytes);
        buffer.putShort((short) 0x0000); // Null terminator

        byte[] byteData = buffer.array();

        // Call the method
        int bytesRead = response.readBytesWireFormat(byteData, 0);

        // Assertions
        // readBytesWireFormat returns bytes actually read (up to null terminator)
        assertEquals(8 + domainNameBytes.length, bytesRead);
        assertArrayEquals(encryptionKey, serverData.encryptionKey);
        assertEquals("DOMAIN_U", serverData.oemDomainName);
    }

    @Test
    void testReadBytesWireFormat_ExtendedSecurity() {
        // Setup server data for this scenario
        serverData.capabilities = SmbConstants.CAP_EXTENDED_SECURITY;
        response.byteCount = 16; // GUID length

        // Prepare byte array with a GUID
        byte[] guid = new byte[16];
        for (int i = 0; i < 16; i++) {
            guid[i] = (byte) i;
        }
        
        // Call the method
        int bytesRead = response.readBytesWireFormat(guid, 0);

        // Assertions
        // When CAP_EXTENDED_SECURITY is set, it only copies GUID but doesn't update bufferIndex
        assertEquals(0, bytesRead);
        assertArrayEquals(guid, serverData.guid);
        assertEquals("", serverData.oemDomainName);
    }
    
    @Test
    void testReadBytesWireFormat_NoDomainName() {
        // Scenario where byteCount is only the encryption key length
        serverData.capabilities = 0;
        serverData.encryptionKeyLength = 8;
        response.byteCount = 8;

        byte[] encryptionKey = "12345678".getBytes();
        
        int bytesRead = response.readBytesWireFormat(encryptionKey, 0);

        assertEquals(8, bytesRead);
        assertArrayEquals(encryptionKey, serverData.encryptionKey);
        assertEquals("", serverData.oemDomainName);
    }

    @Test
    void testToString() {
        // Populate serverData with some values
        response.dialectIndex = 5;
        serverData.securityMode = 0x03; // User, Encrypted
        serverData.security = 1;
        serverData.encryptedPasswords = true;
        serverData.maxMpxCount = 10;
        serverData.maxNumberVcs = 2;
        serverData.maxBufferSize = 4096;
        serverData.maxRawSize = 8192;
        serverData.sessionKey = 0xABCDEF;
        serverData.capabilities = SmbConstants.CAP_UNICODE;
        serverData.serverTime = new Date(1672531200000L).getTime(); // 2023-01-01 00:00:00 GMT
        serverData.serverTimeZone = 300;
        serverData.encryptionKeyLength = 8;
        response.byteCount = 10;
        serverData.oemDomainName = "TEST_DOMAIN";

        String result = response.toString();

        assertTrue(result.contains("dialectIndex=5"));
        assertTrue(result.contains("securityMode=0x3"));
        assertTrue(result.contains("security=user"));
        assertTrue(result.contains("encryptedPasswords=true"));
        assertTrue(result.contains("maxMpxCount=10"));
        assertTrue(result.contains("maxNumberVcs=2"));
        assertTrue(result.contains("maxBufferSize=4096"));
        assertTrue(result.contains("maxRawSize=8192"));
        assertTrue(result.contains("sessionKey=0x00ABCDEF"));
        // CAP_UNICODE is 0x0004, when formatted as 8 hex digits = 0x00000004
        assertTrue(result.contains("capabilities=0x00000004"));
        assertTrue(result.contains("serverTime=" + new Date(serverData.serverTime)));
        assertTrue(result.contains("serverTimeZone=300"));
        assertTrue(result.contains("encryptionKeyLength=8"));
        assertTrue(result.contains("byteCount=10"));
        assertTrue(result.contains("oemDomainName=TEST_DOMAIN"));
    }

    @Test
    void testWriteParameterWordsWireFormat() {
        // This method is empty, just call it for coverage
        assertEquals(0, response.writeParameterWordsWireFormat(new byte[0], 0));
    }

    @Test
    void testWriteBytesWireFormat() {
        // This method is empty, just call it for coverage
        assertEquals(0, response.writeBytesWireFormat(new byte[0], 0));
    }
}
