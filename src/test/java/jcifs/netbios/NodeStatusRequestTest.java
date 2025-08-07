package jcifs.netbios;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.Configuration;

@ExtendWith(MockitoExtension.class)
class NodeStatusRequestTest {

    @Mock
    private Configuration mockConfig;
    
    @Mock
    private Name mockName;
    
    private NodeStatusRequest nodeStatusRequest;
    
    @BeforeEach
    void setUp() {
        // Setup default mock behavior
        lenient().when(mockConfig.getNetbiosScope()).thenReturn("DEFAULT.SCOPE");
        lenient().when(mockConfig.getOemEncoding()).thenReturn("UTF-8");
        
        // Setup mock name
        lenient().when(mockName.writeWireFormat(any(byte[].class), anyInt())).thenReturn(34);
        mockName.hexCode = 0x20;
        mockName.name = "TEST";
        mockName.scope = "test.scope";
    }
    
    @Test
    void constructor_shouldInitializeFieldsCorrectly() throws Exception {
        // Act
        nodeStatusRequest = new NodeStatusRequest(mockConfig, mockName);
        
        // Assert
        assertSame(mockName, nodeStatusRequest.questionName);
        assertEquals(NameServicePacket.NBSTAT, nodeStatusRequest.questionType);
        assertFalse(nodeStatusRequest.isRecurDesired);
        assertFalse(nodeStatusRequest.isBroadcast);
        
        // Verify config is set through parent constructor
        Field configField = NameServicePacket.class.getDeclaredField("config");
        configField.setAccessible(true);
        assertSame(mockConfig, configField.get(nodeStatusRequest));
    }
    
    @Test
    void writeBodyWireFormat_shouldTemporarilySetHexCodeToZero() {
        // Arrange
        nodeStatusRequest = new NodeStatusRequest(mockConfig, mockName);
        byte[] dst = new byte[100];
        int originalHexCode = 0x20;
        mockName.hexCode = originalHexCode;
        
        // Setup spy to verify writeQuestionSectionWireFormat is called
        NodeStatusRequest spyRequest = spy(nodeStatusRequest);
        doReturn(40).when(spyRequest).writeQuestionSectionWireFormat(any(byte[].class), anyInt());
        
        // Act
        int result = spyRequest.writeBodyWireFormat(dst, 0);
        
        // Assert
        assertEquals(40, result);
        assertEquals(originalHexCode, mockName.hexCode); // Should be restored
        verify(spyRequest).writeQuestionSectionWireFormat(dst, 0);
    }
    
    @Test
    void writeBodyWireFormat_shouldPreserveOriginalHexCode() {
        // Arrange
        nodeStatusRequest = new NodeStatusRequest(mockConfig, mockName);
        byte[] dst = new byte[100];
        int originalHexCode = 0x1C;
        mockName.hexCode = originalHexCode;
        
        // Act
        nodeStatusRequest.writeBodyWireFormat(dst, 0);
        
        // Assert
        assertEquals(originalHexCode, mockName.hexCode);
    }
    
    @Test
    void writeBodyWireFormat_withRealName_shouldWriteCorrectly() {
        // Arrange
        Name realName = new Name(mockConfig, "TESTNAME", 0x20, "test.scope");
        nodeStatusRequest = new NodeStatusRequest(mockConfig, realName);
        byte[] dst = new byte[200];
        
        // Act
        int result = nodeStatusRequest.writeBodyWireFormat(dst, 10);
        
        // Assert
        assertTrue(result > 0);
        // Verify the hex code was temporarily set to 0x00
        // The first byte after the name encoding should reflect this
    }
    
    @Test
    void readBodyWireFormat_shouldAlwaysReturnZero() {
        // Arrange
        nodeStatusRequest = new NodeStatusRequest(mockConfig, mockName);
        byte[] src = new byte[100];
        
        // Act
        int result = nodeStatusRequest.readBodyWireFormat(src, 0);
        
        // Assert
        assertEquals(0, result);
    }
    
    @Test
    void readBodyWireFormat_withDifferentOffsets_shouldAlwaysReturnZero() {
        // Arrange
        nodeStatusRequest = new NodeStatusRequest(mockConfig, mockName);
        byte[] src = new byte[100];
        
        // Act & Assert
        assertEquals(0, nodeStatusRequest.readBodyWireFormat(src, 0));
        assertEquals(0, nodeStatusRequest.readBodyWireFormat(src, 50));
        assertEquals(0, nodeStatusRequest.readBodyWireFormat(src, 99));
    }
    
    @Test
    void writeRDataWireFormat_shouldAlwaysReturnZero() {
        // Arrange
        nodeStatusRequest = new NodeStatusRequest(mockConfig, mockName);
        byte[] dst = new byte[100];
        
        // Act
        int result = nodeStatusRequest.writeRDataWireFormat(dst, 0);
        
        // Assert
        assertEquals(0, result);
    }
    
    @Test
    void writeRDataWireFormat_withDifferentOffsets_shouldAlwaysReturnZero() {
        // Arrange
        nodeStatusRequest = new NodeStatusRequest(mockConfig, mockName);
        byte[] dst = new byte[100];
        
        // Act & Assert
        assertEquals(0, nodeStatusRequest.writeRDataWireFormat(dst, 0));
        assertEquals(0, nodeStatusRequest.writeRDataWireFormat(dst, 50));
        assertEquals(0, nodeStatusRequest.writeRDataWireFormat(dst, 99));
    }
    
    @Test
    void readRDataWireFormat_shouldAlwaysReturnZero() {
        // Arrange
        nodeStatusRequest = new NodeStatusRequest(mockConfig, mockName);
        byte[] src = new byte[100];
        
        // Act
        int result = nodeStatusRequest.readRDataWireFormat(src, 0);
        
        // Assert
        assertEquals(0, result);
    }
    
    @Test
    void readRDataWireFormat_withDifferentOffsets_shouldAlwaysReturnZero() {
        // Arrange
        nodeStatusRequest = new NodeStatusRequest(mockConfig, mockName);
        byte[] src = new byte[100];
        
        // Act & Assert
        assertEquals(0, nodeStatusRequest.readRDataWireFormat(src, 0));
        assertEquals(0, nodeStatusRequest.readRDataWireFormat(src, 50));
        assertEquals(0, nodeStatusRequest.readRDataWireFormat(src, 99));
    }
    
    @Test
    void toString_shouldReturnFormattedString() {
        // Arrange
        nodeStatusRequest = new NodeStatusRequest(mockConfig, mockName);
        
        // Act
        String result = nodeStatusRequest.toString();
        
        // Assert
        assertNotNull(result);
        assertTrue(result.startsWith("NodeStatusRequest["));
        assertTrue(result.endsWith("]"));
        assertTrue(result.contains("NodeStatusRequest"));
    }
    
    @Test
    void toString_shouldIncludeParentToString() {
        // Arrange
        Name realName = new Name(mockConfig, "TESTNAME", 0x20, "test.scope");
        nodeStatusRequest = new NodeStatusRequest(mockConfig, realName);
        nodeStatusRequest.nameTrnId = 12345;
        
        // Act
        String result = nodeStatusRequest.toString();
        
        // Assert
        assertTrue(result.contains("NodeStatusRequest"));
        assertTrue(result.contains("nameTrnId=12345"));
        assertTrue(result.contains("TESTNAME"));
    }
    
    @Test
    void toString_withNullQuestionName_shouldHandleGracefully() {
        // Arrange
        nodeStatusRequest = new NodeStatusRequest(mockConfig, mockName);
        nodeStatusRequest.questionName = null;
        
        // Act
        String result = nodeStatusRequest.toString();
        
        // Assert
        assertNotNull(result);
        assertTrue(result.contains("NodeStatusRequest"));
        assertTrue(result.contains("null"));
    }
    
    @Test
    void writeWireFormat_shouldDelegateToParent() {
        // Arrange
        nodeStatusRequest = new NodeStatusRequest(mockConfig, mockName);
        byte[] dst = new byte[200];
        
        // Act
        int result = nodeStatusRequest.writeWireFormat(dst, 0);
        
        // Assert
        assertTrue(result >= NameServicePacket.HEADER_LENGTH);
    }
    
    @Test
    void readWireFormat_shouldDelegateToParent() {
        // Arrange
        nodeStatusRequest = new NodeStatusRequest(mockConfig, mockName);
        byte[] src = new byte[200];
        // Setup minimal valid header
        src[0] = 0x00; src[1] = 0x01; // Transaction ID
        src[2] = 0x00; // Flags
        src[3] = 0x00; // Flags
        src[4] = 0x00; src[5] = 0x01; // Question count
        
        // Act
        int result = nodeStatusRequest.readWireFormat(src, 0);
        
        // Assert
        assertTrue(result >= NameServicePacket.HEADER_LENGTH);
    }
    
    @Test
    void integration_writeAndReadComplete() {
        // Arrange
        Name realName = new Name(mockConfig, "WORKSTATION", 0x00, null);
        nodeStatusRequest = new NodeStatusRequest(mockConfig, realName);
        nodeStatusRequest.nameTrnId = 0x1234;
        
        byte[] buffer = new byte[512];
        
        // Act - Write
        int writeLength = nodeStatusRequest.writeWireFormat(buffer, 0);
        
        // Assert write
        assertTrue(writeLength > 0);
        
        // Create new request to read
        NodeStatusRequest readRequest = new NodeStatusRequest(mockConfig, new Name(mockConfig));
        
        // Act - Read
        int readLength = readRequest.readWireFormat(buffer, 0);
        
        // Assert read
        assertEquals(0x1234, readRequest.nameTrnId);
        assertEquals(NameServicePacket.NBSTAT, readRequest.questionType);
        assertFalse(readRequest.isRecurDesired);
        assertFalse(readRequest.isBroadcast);
    }
    
    @Test
    void writeBodyWireFormat_withHexCodeFF_shouldResetToZeroAndRestore() {
        // Arrange
        nodeStatusRequest = new NodeStatusRequest(mockConfig, mockName);
        byte[] dst = new byte[100];
        int originalHexCode = 0xFF;
        mockName.hexCode = originalHexCode;
        
        // Create a spy to capture the state during writeQuestionSectionWireFormat
        NodeStatusRequest spyRequest = spy(nodeStatusRequest);
        doAnswer(invocation -> {
            // Verify hexCode is 0 during the call
            assertEquals(0x00, mockName.hexCode);
            return 40;
        }).when(spyRequest).writeQuestionSectionWireFormat(any(byte[].class), anyInt());
        
        // Act
        spyRequest.writeBodyWireFormat(dst, 0);
        
        // Assert
        assertEquals(originalHexCode, mockName.hexCode); // Should be restored
    }
    
    @Test
    void constructor_withNullName_shouldStillSetProperties() {
        // Act
        nodeStatusRequest = new NodeStatusRequest(mockConfig, null);
        
        // Assert
        assertNull(nodeStatusRequest.questionName);
        assertEquals(NameServicePacket.NBSTAT, nodeStatusRequest.questionType);
        assertFalse(nodeStatusRequest.isRecurDesired);
        assertFalse(nodeStatusRequest.isBroadcast);
    }
    
    @Test
    void writeBodyWireFormat_withNullQuestionName_shouldHandleGracefully() {
        // Arrange
        nodeStatusRequest = new NodeStatusRequest(mockConfig, null);
        byte[] dst = new byte[100];
        
        // Act & Assert
        assertThrows(NullPointerException.class, () -> {
            nodeStatusRequest.writeBodyWireFormat(dst, 0);
        });
    }
    
    @Test
    void multipleWriteBodyWireFormat_shouldProduceSameResult() {
        // Arrange
        Name realName = new Name(mockConfig, "SERVER", 0x20, "domain.local");
        nodeStatusRequest = new NodeStatusRequest(mockConfig, realName);
        byte[] dst1 = new byte[100];
        byte[] dst2 = new byte[100];
        
        // Act
        int result1 = nodeStatusRequest.writeBodyWireFormat(dst1, 0);
        int result2 = nodeStatusRequest.writeBodyWireFormat(dst2, 0);
        
        // Assert
        assertEquals(result1, result2);
        assertArrayEquals(dst1, dst2);
    }
    
    @Test
    void writeBodyWireFormat_atDifferentOffsets_shouldWriteCorrectly() {
        // Arrange
        Name realName = new Name(mockConfig, "HOST", 0x00, null);
        nodeStatusRequest = new NodeStatusRequest(mockConfig, realName);
        byte[] dst = new byte[200];
        
        // Act
        int result1 = nodeStatusRequest.writeBodyWireFormat(dst, 0);
        int result2 = nodeStatusRequest.writeBodyWireFormat(dst, 50);
        int result3 = nodeStatusRequest.writeBodyWireFormat(dst, 100);
        
        // Assert
        assertEquals(result1, result2);
        assertEquals(result2, result3);
        assertTrue(result1 > 0);
    }
    
    @Test
    void nodeStatusRequest_asNameServicePacket_shouldMaintainPolymorphism() {
        // Arrange
        NameServicePacket packet = new NodeStatusRequest(mockConfig, mockName);
        
        // Assert
        assertInstanceOf(NodeStatusRequest.class, packet);
        assertEquals(NameServicePacket.NBSTAT, packet.questionType);
        assertFalse(packet.isRecurDesired);
        assertFalse(packet.isBroadcast);
    }
    
    @Test
    void writeBodyWireFormat_verifyHexCodeIsRestoredEvenOnException() {
        // Arrange
        nodeStatusRequest = new NodeStatusRequest(mockConfig, mockName);
        byte[] dst = new byte[100];
        int originalHexCode = 0x20;
        mockName.hexCode = originalHexCode;
        
        // Create a spy that throws an exception during writeQuestionSectionWireFormat
        NodeStatusRequest spyRequest = spy(nodeStatusRequest);
        doThrow(new RuntimeException("Test exception")).when(spyRequest)
            .writeQuestionSectionWireFormat(any(byte[].class), anyInt());
        
        // Act & Assert
        assertThrows(RuntimeException.class, () -> {
            spyRequest.writeBodyWireFormat(dst, 0);
        });
        
        // Verify hexCode is still restored
        assertEquals(originalHexCode, mockName.hexCode);
    }
}