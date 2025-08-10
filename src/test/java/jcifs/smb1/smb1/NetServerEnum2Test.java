/*
 * Copyright 2024 Shinsuke
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jcifs.smb1.smb1;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

import jcifs.smb1.smb1.NetServerEnum2;
import jcifs.smb1.smb1.SmbComTransaction;
import jcifs.smb1.smb1.ServerMessageBlock;

/**
 * Unit tests for the NetServerEnum2 class.
 */
class NetServerEnum2Test {

    private NetServerEnum2 netServerEnum2;
    private final String testDomain = "TEST_DOMAIN";
    private final int testServerTypes = NetServerEnum2.SV_TYPE_ALL;

    @BeforeEach
    void setUp() {
        netServerEnum2 = new NetServerEnum2(testDomain, testServerTypes);
    }

    /**
     * Test the constructor of NetServerEnum2.
     */
    @Test
    void testConstructor() {
        assertEquals(testDomain, netServerEnum2.domain);
        assertEquals(testServerTypes, netServerEnum2.serverTypes);
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION, netServerEnum2.command);
        assertEquals(SmbComTransaction.NET_SERVER_ENUM2, netServerEnum2.subCommand);
        assertEquals("\\PIPE\\LANMAN", netServerEnum2.name);
        assertEquals(8, netServerEnum2.maxParameterCount);
        assertEquals(16384, netServerEnum2.maxDataCount);
        assertEquals(0, netServerEnum2.maxSetupCount);
        assertEquals(0, netServerEnum2.setupCount);
        assertEquals(5000, netServerEnum2.timeout);
    }

    /**
     * Test the reset method.
     */
    @Test
    void testReset() {
        String lastName = "LAST_NAME";
        netServerEnum2.reset(0, lastName);
        assertEquals(lastName, netServerEnum2.lastName);
    }

    /**
     * Test the writeSetupWireFormat method.
     */
    @Test
    void testWriteSetupWireFormat() {
        byte[] dst = new byte[10];
        int result = netServerEnum2.writeSetupWireFormat(dst, 0);
        assertEquals(0, result);
    }

    /**
     * Test the writeParametersWireFormat method for NET_SERVER_ENUM2.
     */
    @Test
    void testWriteParametersWireFormat_Enum2() throws UnsupportedEncodingException {
        byte[] dst = new byte[100];
        int bytesWritten = netServerEnum2.writeParametersWireFormat(dst, 0);

        // Verify subcommand
        assertEquals(SmbComTransaction.NET_SERVER_ENUM2 & 0xFF, (dst[0] & 0xFF) | ((dst[1] & 0xFF) << 8));

        // Verify description
        byte[] descr = NetServerEnum2.DESCR[0].getBytes("ASCII");
        byte[] writtenDescr = new byte[descr.length];
        System.arraycopy(dst, 2, writtenDescr, 0, descr.length);
        assertArrayEquals(descr, writtenDescr);

        int currentIndex = 2 + descr.length;
        // Verify level (0x0001)
        assertEquals(1, (dst[currentIndex] & 0xFF) | ((dst[currentIndex + 1] & 0xFF) << 8));
        currentIndex += 2;

        // Verify maxDataCount
        assertEquals(netServerEnum2.maxDataCount, (dst[currentIndex] & 0xFF) | ((dst[currentIndex + 1] & 0xFF) << 8));
        currentIndex += 2;

        // Verify serverTypes
        assertEquals(testServerTypes, (dst[currentIndex] & 0xFF) | ((dst[currentIndex + 1] & 0xFF) << 8) |
                ((dst[currentIndex + 2] & 0xFF) << 16) | ((dst[currentIndex + 3] & 0xFF) << 24));
        currentIndex += 4;

        // Verify domain
        String writtenDomain = new String(dst, currentIndex, testDomain.length(), StandardCharsets.US_ASCII);
        assertEquals(testDomain.toUpperCase(), writtenDomain);
        
        // Verify total bytes written
        assertEquals(currentIndex + testDomain.length() + 1, bytesWritten);
    }
    
    /**
     * Test the writeParametersWireFormat method for NET_SERVER_ENUM3.
     */
    @Test
    void testWriteParametersWireFormat_Enum3() throws UnsupportedEncodingException {
        netServerEnum2.subCommand = (byte)SmbComTransaction.NET_SERVER_ENUM3;
        String lastName = "LAST_SERVER";
        netServerEnum2.reset(0, lastName);
        
        byte[] dst = new byte[150];
        int bytesWritten = netServerEnum2.writeParametersWireFormat(dst, 0);

        // Verify subcommand
        assertEquals(SmbComTransaction.NET_SERVER_ENUM3 & 0xFF, (dst[0] & 0xFF) | ((dst[1] & 0xFF) << 8));

        // Verify description
        byte[] descr = NetServerEnum2.DESCR[1].getBytes("ASCII");
        byte[] writtenDescr = new byte[descr.length];
        System.arraycopy(dst, 2, writtenDescr, 0, descr.length);
        assertArrayEquals(descr, writtenDescr);

        int currentIndex = 2 + descr.length;
        // Verify level (0x0001)
        assertEquals(1, (dst[currentIndex] & 0xFF) | ((dst[currentIndex + 1] & 0xFF) << 8));
        currentIndex += 2;

        // Verify maxDataCount
        assertEquals(netServerEnum2.maxDataCount, (dst[currentIndex] & 0xFF) | ((dst[currentIndex + 1] & 0xFF) << 8));
        currentIndex += 2;

        // Verify serverTypes
        assertEquals(testServerTypes, (dst[currentIndex] & 0xFF) | ((dst[currentIndex + 1] & 0xFF) << 8) |
                ((dst[currentIndex + 2] & 0xFF) << 16) | ((dst[currentIndex + 3] & 0xFF) << 24));
        currentIndex += 4;

        // Verify domain
        String writtenDomain = new String(dst, currentIndex, testDomain.length(), StandardCharsets.US_ASCII);
        assertEquals(testDomain.toUpperCase(), writtenDomain);
        currentIndex += testDomain.length() + 1;

        // Verify lastName
        String writtenLastName = new String(dst, currentIndex, lastName.length(), StandardCharsets.US_ASCII);
        assertEquals(lastName.toUpperCase(), writtenLastName);
        
        // Verify total bytes written
        assertEquals(currentIndex + lastName.length() + 1, bytesWritten);
    }

    /**
     * Test the writeDataWireFormat method.
     */
    @Test
    void testWriteDataWireFormat() {
        byte[] dst = new byte[10];
        int result = netServerEnum2.writeDataWireFormat(dst, 0);
        assertEquals(0, result);
    }

    /**
     * Test the readSetupWireFormat method.
     */
    @Test
    void testReadSetupWireFormat() {
        byte[] buffer = new byte[10];
        int result = netServerEnum2.readSetupWireFormat(buffer, 0, 10);
        assertEquals(0, result);
    }

    /**
     * Test the readParametersWireFormat method.
     */
    @Test
    void testReadParametersWireFormat() {
        byte[] buffer = new byte[10];
        int result = netServerEnum2.readParametersWireFormat(buffer, 0, 10);
        assertEquals(0, result);
    }

    /**
     * Test the readDataWireFormat method.
     */
    @Test
    void testReadDataWireFormat() {
        byte[] buffer = new byte[10];
        int result = netServerEnum2.readDataWireFormat(buffer, 0, 10);
        assertEquals(0, result);
    }

    /**
     * Test the toString method with SV_TYPE_ALL.
     */
    @Test
    void testToString_SV_TYPE_ALL() {
        String result = netServerEnum2.toString();
        // Verify the key parts of the string representation
        assertTrue(result.startsWith("NetServerEnum2["));
        assertTrue(result.contains("command=SMB_COM_TRANSACTION"));
        assertTrue(result.contains(",name=\\PIPE\\LANMAN"));
        assertTrue(result.contains(",serverTypes=SV_TYPE_ALL]"));
    }

    /**
     * Test the toString method with SV_TYPE_DOMAIN_ENUM.
     */
    @Test
    void testToString_SV_TYPE_DOMAIN_ENUM() {
        netServerEnum2 = new NetServerEnum2(testDomain, NetServerEnum2.SV_TYPE_DOMAIN_ENUM);
        String result = netServerEnum2.toString();
        // Verify the key parts of the string representation
        assertTrue(result.startsWith("NetServerEnum2["));
        assertTrue(result.contains("command=SMB_COM_TRANSACTION"));
        assertTrue(result.contains(",name=\\PIPE\\LANMAN"));
        assertTrue(result.contains(",serverTypes=SV_TYPE_DOMAIN_ENUM]"));
    }
}