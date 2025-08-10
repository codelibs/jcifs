package jcifs.smb;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.IOException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.internal.smb2.io.Smb2WriteRequest;
import jcifs.internal.smb2.io.Smb2WriteResponse;

@ExtendWith(MockitoExtension.class)
class SmbFileOutputStreamTest {

    @Mock
    private SmbFile mockFile;
    
    @Mock
    private SmbTreeHandleImpl mockTreeHandle;
    
    @Mock
    private SmbFileHandleImpl mockFileHandle;
    
    @Mock
    private Configuration mockConfig;
    
    @Mock
    private Smb2WriteResponse mockWriteResponse;
    
    private SmbFileOutputStream outputStream;
    
    @BeforeEach
    void setUp() {
        // Common setup for most tests
        lenient().when(mockFileHandle.getTree()).thenReturn(mockTreeHandle);
        lenient().when(mockTreeHandle.getConfig()).thenReturn(mockConfig);
    }
    
    @Test
    void testWriteSingleByte() throws IOException, CIFSException {
        // Given
        when(mockTreeHandle.isSMB2()).thenReturn(true);
        when(mockTreeHandle.getSendBufferSize()).thenReturn(65536);
        when(mockFileHandle.isValid()).thenReturn(false, true); // First false to trigger ensureOpen, then true
        when(mockFileHandle.getFileId()).thenReturn(new byte[16]);
        when(mockFileHandle.acquire()).thenReturn(mockFileHandle);
        
        // Mock for ensureOpen to reopen file
        when(mockFile.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt()))
            .thenReturn(mockFileHandle);
        
        when(mockTreeHandle.send(any(Smb2WriteRequest.class), any())).thenReturn(mockWriteResponse);
        when(mockWriteResponse.getCount()).thenReturn(1);
        
        outputStream = new SmbFileOutputStream(mockFile, mockTreeHandle, mockFileHandle, 
            SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC,
            SmbConstants.FILE_WRITE_DATA, 
            SmbConstants.DEFAULT_SHARING);
        
        // When
        outputStream.write(65); // Write 'A'
        
        // Then
        verify(mockTreeHandle, atLeastOnce()).send(any(Smb2WriteRequest.class), any());
    }
    
    @Test
    void testWriteByteArray() throws IOException, CIFSException {
        // Given
        when(mockTreeHandle.isSMB2()).thenReturn(true);
        when(mockTreeHandle.getSendBufferSize()).thenReturn(65536);
        when(mockFileHandle.isValid()).thenReturn(false, true);
        when(mockFileHandle.getFileId()).thenReturn(new byte[16]);
        when(mockFileHandle.acquire()).thenReturn(mockFileHandle);
        
        when(mockFile.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt()))
            .thenReturn(mockFileHandle);
        
        byte[] data = "Hello World".getBytes();
        when(mockTreeHandle.send(any(Smb2WriteRequest.class), any())).thenReturn(mockWriteResponse);
        when(mockWriteResponse.getCount()).thenReturn(data.length);
        
        outputStream = new SmbFileOutputStream(mockFile, mockTreeHandle, mockFileHandle,
            SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC,
            SmbConstants.FILE_WRITE_DATA,
            SmbConstants.DEFAULT_SHARING);
        
        // When
        outputStream.write(data);
        
        // Then
        verify(mockTreeHandle, atLeastOnce()).send(any(Smb2WriteRequest.class), any());
    }
    
    @Test
    void testWriteByteArrayWithOffset() throws IOException, CIFSException {
        // Given
        when(mockTreeHandle.isSMB2()).thenReturn(true);
        when(mockTreeHandle.getSendBufferSize()).thenReturn(65536);
        when(mockFileHandle.isValid()).thenReturn(false, true);
        when(mockFileHandle.getFileId()).thenReturn(new byte[16]);
        when(mockFileHandle.acquire()).thenReturn(mockFileHandle);
        
        when(mockFile.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt()))
            .thenReturn(mockFileHandle);
        
        when(mockTreeHandle.send(any(Smb2WriteRequest.class), any())).thenReturn(mockWriteResponse);
        when(mockWriteResponse.getCount()).thenReturn(5);
        
        outputStream = new SmbFileOutputStream(mockFile, mockTreeHandle, mockFileHandle,
            SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC,
            SmbConstants.FILE_WRITE_DATA,
            SmbConstants.DEFAULT_SHARING);
        
        byte[] data = "Hello World".getBytes();
        
        // When
        outputStream.write(data, 6, 5); // Write "World"
        
        // Then
        verify(mockTreeHandle, atLeastOnce()).send(any(Smb2WriteRequest.class), any());
    }
    
    @Test
    void testFlush() throws IOException, CIFSException {
        // Given
        when(mockTreeHandle.isSMB2()).thenReturn(true);
        when(mockTreeHandle.getSendBufferSize()).thenReturn(65536);
        when(mockFileHandle.isValid()).thenReturn(true);
        
        outputStream = new SmbFileOutputStream(mockFile, mockTreeHandle, mockFileHandle,
            SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC,
            SmbConstants.FILE_WRITE_DATA,
            SmbConstants.DEFAULT_SHARING);
        
        // When
        outputStream.flush();
        
        // Then - flush should complete without error
        assertTrue(outputStream.isOpen());
    }
    
    @Test
    void testClose() throws IOException, CIFSException {
        // Given
        when(mockTreeHandle.isSMB2()).thenReturn(true);
        when(mockTreeHandle.getSendBufferSize()).thenReturn(65536);
        when(mockFileHandle.isValid()).thenReturn(true).thenReturn(false);
        
        outputStream = new SmbFileOutputStream(mockFile, mockTreeHandle, mockFileHandle,
            SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC,
            SmbConstants.FILE_WRITE_DATA,
            SmbConstants.DEFAULT_SHARING);
        
        // When
        outputStream.close();
        
        // Then
        verify(mockFileHandle).close();
        verify(mockFile).clearAttributeCache();
        assertFalse(outputStream.isOpen());
    }
    
    @Test
    void testIsOpen() throws CIFSException {
        // Given
        when(mockTreeHandle.isSMB2()).thenReturn(true);
        when(mockTreeHandle.getSendBufferSize()).thenReturn(65536);
        when(mockFileHandle.isValid()).thenReturn(true);
        
        outputStream = new SmbFileOutputStream(mockFile, mockTreeHandle, mockFileHandle,
            SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC,
            SmbConstants.FILE_WRITE_DATA,
            SmbConstants.DEFAULT_SHARING);
        
        // When & Then
        assertTrue(outputStream.isOpen());
        
        when(mockFileHandle.isValid()).thenReturn(false);
        assertFalse(outputStream.isOpen());
    }
    
    @Test
    void testWriteAfterClose() throws IOException, CIFSException {
        // Given
        when(mockTreeHandle.isSMB2()).thenReturn(true);
        when(mockTreeHandle.getSendBufferSize()).thenReturn(65536);
        when(mockFileHandle.isValid()).thenReturn(true);
        
        outputStream = new SmbFileOutputStream(mockFile, mockTreeHandle, mockFileHandle,
            SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC,
            SmbConstants.FILE_WRITE_DATA,
            SmbConstants.DEFAULT_SHARING);
        
        // Close the stream
        outputStream.close();
        
        // When & Then - after close, tmp is null so write(int) will throw NullPointerException
        // This is the actual behavior of the implementation
        assertThrows(NullPointerException.class, () -> outputStream.write(65));
    }
    
    @Test
    void testWriteNullArray() throws CIFSException {
        // Given
        when(mockTreeHandle.isSMB2()).thenReturn(true);
        when(mockTreeHandle.getSendBufferSize()).thenReturn(65536);
        when(mockFileHandle.isValid()).thenReturn(true);
        
        outputStream = new SmbFileOutputStream(mockFile, mockTreeHandle, mockFileHandle,
            SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC,
            SmbConstants.FILE_WRITE_DATA,
            SmbConstants.DEFAULT_SHARING);
        
        // When & Then
        assertThrows(NullPointerException.class, () -> outputStream.write(null));
        assertThrows(NullPointerException.class, () -> outputStream.write(null, 0, 10));
    }
    
    @Test
    void testWriteInvalidOffsetAndLength() throws IOException, CIFSException {
        // Given
        when(mockTreeHandle.isSMB2()).thenReturn(true);
        when(mockTreeHandle.getSendBufferSize()).thenReturn(65536);
        when(mockFileHandle.isValid()).thenReturn(false, true);
        when(mockFileHandle.acquire()).thenReturn(mockFileHandle);
        when(mockFileHandle.getFileId()).thenReturn(new byte[16]);
        
        when(mockFile.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt()))
            .thenReturn(mockFileHandle);
        
        // Mock responses for successful writes to test boundary conditions
        when(mockTreeHandle.send(any(Smb2WriteRequest.class), any())).thenReturn(mockWriteResponse);
        when(mockWriteResponse.getCount()).thenReturn(10, 5); // Return proper byte counts
        
        outputStream = new SmbFileOutputStream(mockFile, mockTreeHandle, mockFileHandle,
            SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC,
            SmbConstants.FILE_WRITE_DATA,
            SmbConstants.DEFAULT_SHARING);
        
        byte[] data = new byte[10];
        
        // When & Then - test boundary conditions
        // Negative length or offset should not cause issues (len <= 0 returns early)
        assertDoesNotThrow(() -> outputStream.write(data, 0, -1)); // negative length, returns early
        assertDoesNotThrow(() -> outputStream.write(data, 0, 0));  // zero length, returns early
        
        // These should pass through to the underlying implementation
        assertDoesNotThrow(() -> outputStream.write(data, 0, 10)); // valid - will consume first mock (10)
        assertDoesNotThrow(() -> outputStream.write(data, 5, 5));  // valid - will consume second mock (5)
    }
    
    @Test
    void testAppendMode() throws IOException, CIFSException {
        // Given
        when(mockTreeHandle.isSMB2()).thenReturn(true);
        when(mockTreeHandle.getSendBufferSize()).thenReturn(65536);
        when(mockFileHandle.isValid()).thenReturn(false, true);
        when(mockFileHandle.getFileId()).thenReturn(new byte[16]);
        when(mockFileHandle.acquire()).thenReturn(mockFileHandle);
        
        when(mockFile.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt()))
            .thenReturn(mockFileHandle);
        lenient().when(mockFileHandle.getInitialSize()).thenReturn(100L); // File already has 100 bytes
        
        when(mockTreeHandle.send(any(Smb2WriteRequest.class), any())).thenReturn(mockWriteResponse);
        when(mockWriteResponse.getCount()).thenReturn(8);
        
        // Create output stream in append mode - note the append flag sets initial fp to 100
        outputStream = new SmbFileOutputStream(mockFile, mockTreeHandle, mockFileHandle,
            SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_APPEND,
            SmbConstants.FILE_WRITE_DATA,
            SmbConstants.DEFAULT_SHARING);
        
        byte[] data = "Appended".getBytes();
        
        // When
        outputStream.write(data);
        
        // Then - verify write request was sent
        verify(mockTreeHandle, atLeastOnce()).send(any(Smb2WriteRequest.class), any());
    }
    
    @Test
    void testMultipleWrites() throws IOException, CIFSException {
        // Given
        when(mockTreeHandle.isSMB2()).thenReturn(true);
        when(mockTreeHandle.getSendBufferSize()).thenReturn(65536);
        when(mockFileHandle.isValid()).thenReturn(false, true, true);
        when(mockFileHandle.getFileId()).thenReturn(new byte[16]);
        when(mockFileHandle.acquire()).thenReturn(mockFileHandle);
        
        when(mockFile.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt()))
            .thenReturn(mockFileHandle);
        
        when(mockTreeHandle.send(any(Smb2WriteRequest.class), any())).thenReturn(mockWriteResponse);
        when(mockWriteResponse.getCount()).thenReturn(6, 5); // First write returns 6, second returns 5
        
        outputStream = new SmbFileOutputStream(mockFile, mockTreeHandle, mockFileHandle,
            SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC,
            SmbConstants.FILE_WRITE_DATA,
            SmbConstants.DEFAULT_SHARING);
        
        byte[] data1 = "Hello ".getBytes();
        byte[] data2 = "World".getBytes();
        
        // When
        outputStream.write(data1);
        outputStream.write(data2);
        
        // Then - verify two write requests were sent
        verify(mockTreeHandle, times(2)).send(any(Smb2WriteRequest.class), any());
    }
    
    @Test
    void testConstructorWithSmbFileOnly() throws IOException, CIFSException {
        // Given
        // Mock the AutoCloseable tree handle behavior
        SmbTreeHandleImpl autoCloseableMockTreeHandle = mock(SmbTreeHandleImpl.class);
        when(mockFile.ensureTreeConnected()).thenReturn(autoCloseableMockTreeHandle);
        when(autoCloseableMockTreeHandle.isSMB2()).thenReturn(true);
        lenient().when(autoCloseableMockTreeHandle.getConfig()).thenReturn(mockConfig);
        
        // Mock the AutoCloseable file handle behavior
        SmbFileHandleImpl autoCloseableMockFileHandle = mock(SmbFileHandleImpl.class);
        when(mockFile.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt()))
            .thenReturn(autoCloseableMockFileHandle);
        when(autoCloseableMockFileHandle.acquire()).thenReturn(autoCloseableMockFileHandle);
        lenient().when(autoCloseableMockFileHandle.isValid()).thenReturn(true);
        lenient().when(autoCloseableMockFileHandle.getInitialSize()).thenReturn(0L);
        
        when(autoCloseableMockTreeHandle.getSendBufferSize()).thenReturn(65536);
        
        // When
        outputStream = new SmbFileOutputStream(mockFile);
        
        // Then
        assertNotNull(outputStream);
        
        // Verify the AutoCloseable resources were closed
        verify(autoCloseableMockTreeHandle).close();
        verify(autoCloseableMockFileHandle).close();
    }
    
    @Test
    void testConstructorWithAppendFlag() throws IOException, CIFSException {
        // Given
        // Mock the AutoCloseable tree handle behavior
        SmbTreeHandleImpl autoCloseableMockTreeHandle = mock(SmbTreeHandleImpl.class);
        when(mockFile.ensureTreeConnected()).thenReturn(autoCloseableMockTreeHandle);
        when(autoCloseableMockTreeHandle.isSMB2()).thenReturn(true);
        lenient().when(autoCloseableMockTreeHandle.getConfig()).thenReturn(mockConfig);
        
        // Mock the AutoCloseable file handle behavior
        SmbFileHandleImpl autoCloseableMockFileHandle = mock(SmbFileHandleImpl.class);
        when(mockFile.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt()))
            .thenReturn(autoCloseableMockFileHandle);
        when(autoCloseableMockFileHandle.acquire()).thenReturn(autoCloseableMockFileHandle);
        lenient().when(autoCloseableMockFileHandle.isValid()).thenReturn(true);
        when(autoCloseableMockFileHandle.getInitialSize()).thenReturn(50L); // Existing file with 50 bytes
        
        when(autoCloseableMockTreeHandle.getSendBufferSize()).thenReturn(65536);
        
        // When
        outputStream = new SmbFileOutputStream(mockFile, true);
        
        // Then
        assertNotNull(outputStream);
        
        // Verify the AutoCloseable resources were closed
        verify(autoCloseableMockTreeHandle).close();
        verify(autoCloseableMockFileHandle).close();
    }
}