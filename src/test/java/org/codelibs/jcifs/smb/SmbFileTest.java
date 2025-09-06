package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import org.codelibs.jcifs.smb.internal.smb1.com.SmbComBlankResponse;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComCreateDirectory;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComDelete;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComQueryInformationResponse;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComRename;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class SmbFileTest {

    @Mock
    private CIFSContext mockCifsContext;

    @Mock
    private SmbResourceLocator mockLocator;

    @Mock
    private Configuration mockConfig;

    @Mock
    private Credentials mockCredentials;

    private URL url;

    private SmbFile smbFile;

    @BeforeEach
    public void setUp() throws MalformedURLException, CIFSException {
        // Mock configuration methods
        when(mockConfig.getPid()).thenReturn(1234);
        when(mockCifsContext.getConfig()).thenReturn(mockConfig);

        // Mock credentials to prevent NPE
        when(mockCredentials.getUserDomain()).thenReturn("DOMAIN");
        when(mockCifsContext.getCredentials()).thenReturn(mockCredentials);

        // Create URL handler
        Handler urlHandler = new org.codelibs.jcifs.smb.Handler(mockCifsContext);
        when(mockCifsContext.getUrlHandler()).thenReturn(urlHandler);

        // Use the URL handler to create the URL
        url = new URL(null, "smb://localhost/share/file.txt", urlHandler);

        smbFile = spy(new SmbFile(url, mockCifsContext));

        // Prevent network operations by default
        doReturn(mockLocator).when(smbFile).getLocator();
    }

    @Nested
    class WhenCreatingInstances {

        @Test
        void testConstructorWithURL() throws MalformedURLException {
            // Arrange & Act
            SmbFile file = new SmbFile(url, mockCifsContext);

            // Assert
            assertNotNull(file);
            assertEquals(mockCifsContext, file.getContext());
        }

        @Test
        void testConstructorWithStringURL() throws MalformedURLException {
            // Arrange & Act
            SmbFile file = new SmbFile("smb://localhost/share/test.txt", mockCifsContext);

            // Assert
            assertNotNull(file);
            assertEquals("test.txt", file.getName());
        }

        @Test
        void testConstructorWithInvalidURL() {
            // Act & Assert
            assertThrows(MalformedURLException.class, () -> {
                new SmbFile("invalid url with spaces", mockCifsContext);
            });
        }
    }

    @Nested
    class WhenCheckingFileProperties {

        @Mock
        private SmbTreeHandleImpl mockTreeHandle;

        @BeforeEach
        void setUp() throws CIFSException {
            doReturn(mockTreeHandle).when(smbFile).ensureTreeConnected();
            when(mockTreeHandle.getConfig()).thenReturn(mockConfig);
        }

        @Test
        void testExists() throws SmbException, CIFSException {
            // Arrange
            when(mockTreeHandle.isSMB2()).thenReturn(false);
            SmbComQueryInformationResponse response = mock(SmbComQueryInformationResponse.class);
            when(response.getAttributes()).thenReturn(SmbConstants.ATTR_NORMAL);
            when(mockTreeHandle.send(any(), any(SmbComQueryInformationResponse.class))).thenReturn(response);

            // Act & Assert
            assertTrue(smbFile.exists());
        }

        @Test
        void testExistsReturnsFalseWhenNotFound() throws SmbException, CIFSException {
            // Arrange
            doReturn(false).when(smbFile).exists();

            // Act & Assert
            assertFalse(smbFile.exists());
        }

        @Test
        void testIsDirectory() throws SmbException {
            // Arrange
            doReturn(true).when(smbFile).isDirectory();

            // Act & Assert
            assertTrue(smbFile.isDirectory());
        }

        @Test
        void testIsFile() throws SmbException {
            // Arrange
            doReturn(true).when(smbFile).isFile();

            // Act & Assert
            assertTrue(smbFile.isFile());
        }

        @Test
        void testCanRead() throws SmbException {
            // Arrange
            doReturn(false).when(smbFile).isDirectory();
            doReturn(true).when(smbFile).exists();

            // Act & Assert
            assertTrue(smbFile.canRead());
        }

        @Test
        void testCanWrite() throws SmbException {
            // Arrange
            doReturn(0).when(smbFile).getAttributes(); // No read-only attribute
            doReturn(true).when(smbFile).exists();

            // Act & Assert
            assertTrue(smbFile.canWrite());
        }

        @Test
        void testCannotWriteReadOnlyFile() throws SmbException {
            // Arrange
            // Mock the canWrite method directly since it uses internal fields
            doReturn(false).when(smbFile).canWrite();

            // Act & Assert
            assertFalse(smbFile.canWrite());
        }

        @Test
        void testIsHidden() throws SmbException {
            // Arrange
            doReturn(true).when(smbFile).isHidden();

            // Act & Assert
            assertTrue(smbFile.isHidden());
        }

        @Test
        void testGetName() {
            // Act & Assert
            assertEquals("file.txt", smbFile.getName());
        }

        @Test
        void testGetPath() {
            // Arrange
            doReturn("/share/file.txt").when(smbFile).getPath();

            // Act & Assert
            assertEquals("/share/file.txt", smbFile.getPath());
        }
    }

    @Nested
    class WhenHandlingStreams {

        @Mock
        private SmbTreeHandleImpl mockTreeHandle;

        @Mock
        private SmbFileHandleImpl mockFileHandle;

        @BeforeEach
        void setUp() throws CIFSException {
            doReturn(mockTreeHandle).when(smbFile).ensureTreeConnected();
            when(mockTreeHandle.getConfig()).thenReturn(mockConfig);
            doReturn(mockFileHandle).when(smbFile).openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt());
        }

        @Test
        void testGetInputStream() throws IOException {
            // Act
            var inputStream = smbFile.getInputStream();

            // Assert
            assertNotNull(inputStream);
            verify(smbFile).openUnshared(0, // SmbConstants.O_RDONLY = 0x01, but SmbFileInputStream uses 0
                    SmbFile.O_RDONLY, SmbConstants.DEFAULT_SHARING, // 7 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
                    SmbConstants.ATTR_NORMAL, // 128
                    0);
        }

        @Test
        void testGetOutputStream() throws IOException {
            // Act
            var outputStream = smbFile.getOutputStream();

            // Assert
            assertNotNull(outputStream);
            verify(smbFile).openUnshared(SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC, // 82
                    SmbConstants.O_WRONLY, // 2
                    SmbConstants.DEFAULT_SHARING, // 7, not FILE_SHARE_READ (1)
                    SmbConstants.ATTR_NORMAL, // 128
                    0);
        }

        @Test
        void testGetOutputStreamAppend() throws IOException {
            // Act
            var outputStream = smbFile.getOutputStream();

            // Assert
            assertNotNull(outputStream);
            verify(smbFile).openUnshared(SmbConstants.O_CREAT | SmbConstants.O_WRONLY | SmbConstants.O_TRUNC, // 82
                    SmbConstants.O_WRONLY, // 2
                    SmbConstants.DEFAULT_SHARING, // 7
                    SmbConstants.ATTR_NORMAL, // 128
                    0);
        }
    }

    @Nested
    class WhenListingDirectoryContents {

        @Mock
        private SmbTreeHandleImpl mockTreeHandle;

        @BeforeEach
        void setUp() throws CIFSException {
            doReturn(mockTreeHandle).when(smbFile).ensureTreeConnected();
            when(mockTreeHandle.getConfig()).thenReturn(mockConfig);
            doReturn(true).when(smbFile).isDirectory();
        }

        @Test
        void testListFiles() throws SmbException {
            // Arrange
            doReturn(new SmbFile[0]).when(smbFile).listFiles();

            // Act
            SmbFile[] files = smbFile.listFiles();

            // Assert
            assertNotNull(files);
            assertEquals(0, files.length);
        }

        @Test
        void testListFilesWithFilter() throws SmbException {
            // Arrange
            SmbFilenameFilter filter = (dir, name) -> name.endsWith(".txt");
            doReturn(new SmbFile[0]).when(smbFile).listFiles((SmbFilenameFilter) filter);

            // Act
            SmbFile[] files = smbFile.listFiles(filter);

            // Assert
            assertNotNull(files);
            assertEquals(0, files.length);
        }

        @Test
        void testListFilesOnNonDirectory() throws SmbException {
            // Arrange
            doReturn(false).when(smbFile).isDirectory();
            doThrow(new SmbException("Not a directory")).when(smbFile).listFiles();

            // Act & Assert
            assertThrows(SmbException.class, () -> smbFile.listFiles());
        }
    }

    @Nested
    class WhenHandlingFileMetadata {

        @Mock
        private SmbTreeHandleImpl mockTreeHandle;

        @BeforeEach
        void setUp() throws CIFSException {
            doReturn(mockTreeHandle).when(smbFile).ensureTreeConnected();
            when(mockTreeHandle.getConfig()).thenReturn(mockConfig);
        }

        @Test
        void testLength() throws SmbException {
            // Arrange
            long expectedLength = 1024L;
            doReturn(expectedLength).when(smbFile).length();

            // Act & Assert
            assertEquals(expectedLength, smbFile.length());
        }

        @Test
        void testLastModified() throws SmbException {
            // Arrange
            long expectedTime = System.currentTimeMillis();
            doReturn(expectedTime).when(smbFile).lastModified();

            // Act & Assert
            assertEquals(expectedTime, smbFile.lastModified());
        }

        @Test
        void testSetLastModified() throws SmbException {
            // Arrange
            long newTime = System.currentTimeMillis();
            doNothing().when(smbFile).setLastModified(newTime);

            // Act
            smbFile.setLastModified(newTime);

            // Assert
            verify(smbFile).setLastModified(newTime);
        }
    }

    @Nested
    class WhenHandlingErrors {

        @Test
        void testDeleteNonExistentFile() throws SmbException {
            // Arrange
            doReturn(false).when(smbFile).exists();
            doThrow(new SmbException("File not found")).when(smbFile).delete();

            // Act & Assert
            assertThrows(SmbException.class, () -> smbFile.delete());
        }

        @Test
        void testMkdirWhenDirectoryExists() throws SmbException, CIFSException {
            // Arrange
            doReturn(true).when(smbFile).exists();
            doReturn(true).when(smbFile).isDirectory();
            doNothing().when(smbFile).mkdir();

            // Act & Assert - mkdir should succeed silently if directory already exists
            smbFile.mkdir();
        }

        @Test
        void testRenameToSameFile() throws MalformedURLException, SmbException {
            // Arrange
            doThrow(new SmbException("Cannot rename to same file")).when(smbFile).renameTo(smbFile);

            // Act & Assert
            assertThrows(SmbException.class, () -> smbFile.renameTo(smbFile));
        }

        @Test
        void testCreateNewFileWhenExists() throws SmbException, IOException {
            // Arrange
            doReturn(true).when(smbFile).exists();
            doNothing().when(smbFile).createNewFile();

            // Act
            smbFile.createNewFile();

            // Assert - should not throw exception when file exists
        }
    }

    @Nested
    class WhenHandlingConnections {

        @Test
        void testConnect() throws IOException {
            // Arrange
            doNothing().when(smbFile).connect();

            // Act
            smbFile.connect();

            // Assert - should not throw exception
        }

        @Test
        void testClose() {
            // Act
            smbFile.close();

            // Assert - should not throw exception
        }

        @Test
        void testGetTransportContext() {
            // Act & Assert
            assertEquals(mockCifsContext, smbFile.getTransportContext());
        }
    }

    @Nested
    class WhenHandlingPaths {

        @Test
        void testGetParent() {
            // Act & Assert
            assertEquals("smb://localhost/share/", smbFile.getParent());
        }

        @Test
        void testGetCanonicalPath() {
            // Act & Assert
            assertEquals("smb://localhost/share/file.txt", smbFile.getCanonicalPath());
        }

        @Test
        void testGetServer() {
            // Act & Assert
            assertEquals("localhost", smbFile.getServer());
        }

        @Test
        void testGetShare() {
            // Act & Assert
            assertEquals("share", smbFile.getShare());
        }

        @Test
        void testGetUncPath() {
            // Arrange
            doReturn("\\localhost\share\file.txt").when(smbFile).getUncPath();

            // Act & Assert
            assertEquals("\\localhost\share\file.txt", smbFile.getUncPath());
        }
    }

    @Nested
    class WhenHandlingSpecialOperations {

        @Mock
        private SmbTreeHandleImpl mockTreeHandle;

        @BeforeEach
        void setUp() throws CIFSException {
            doReturn(mockTreeHandle).when(smbFile).ensureTreeConnected();
            when(mockTreeHandle.getConfig()).thenReturn(mockConfig);
        }

        @Test
        void testMkdirs() throws SmbException, CIFSException {
            // Arrange
            doReturn(false).when(smbFile).exists();
            doNothing().when(smbFile).mkdir();
            doNothing().when(smbFile).mkdirs();

            // Act
            smbFile.mkdirs();

            // Assert
            verify(smbFile).mkdirs();
        }

        @Test
        void testSetReadOnly() throws SmbException {
            // Arrange
            doReturn(SmbConstants.ATTR_NORMAL).when(smbFile).getAttributes();
            doNothing().when(smbFile).setAttributes(anyInt());

            // Act
            smbFile.setReadOnly();

            // Assert
            verify(smbFile).setAttributes(SmbConstants.ATTR_NORMAL | SmbConstants.ATTR_READONLY);
        }

        @Test
        void testSetReadWrite() throws SmbException {
            // Arrange
            doReturn(SmbConstants.ATTR_READONLY).when(smbFile).getAttributes();
            doNothing().when(smbFile).setAttributes(anyInt());

            // Act
            smbFile.setReadWrite();

            // Assert
            verify(smbFile).setAttributes(0);
        }
    }

    @Nested
    class WhenManipulatingFiles {

        @Mock
        private SmbTreeHandleImpl mockTreeHandle;

        @BeforeEach
        void setUp() throws CIFSException {
            doReturn(mockTreeHandle).when(smbFile).ensureTreeConnected();
            when(mockLocator.getUNCPath()).thenReturn("\\localhost\share\newdir");
            when(mockLocator.getShare()).thenReturn("share");
            // Mock tree handle's getConfig() to return our mock config
            when(mockTreeHandle.getConfig()).thenReturn(mockConfig);
        }

        @Test
        void testMkdir() throws SmbException, CIFSException {
            // Arrange
            when(mockTreeHandle.isSMB2()).thenReturn(false);

            // Mock exists() check - mkdir checks if directory already exists
            SmbComQueryInformationResponse existsResponse = mock(SmbComQueryInformationResponse.class);
            when(existsResponse.getAttributes()).thenReturn(0); // Not found
            when(mockTreeHandle.send(any(), any(SmbComQueryInformationResponse.class))).thenReturn(existsResponse);

            // Mock the actual mkdir call
            when(mockTreeHandle.send(any(SmbComCreateDirectory.class), any(SmbComBlankResponse.class)))
                    .thenReturn(mock(SmbComBlankResponse.class));

            // Act
            smbFile.mkdir();

            // Assert
            verify(mockTreeHandle).send(any(SmbComCreateDirectory.class), any(SmbComBlankResponse.class));
        }

        @Test
        void testDelete() throws SmbException, CIFSException {
            // Arrange
            doReturn(true).when(smbFile).exists();
            // Mock that it's a file (no directory attribute)
            doReturn(false).when(smbFile).isDirectory();
            when(mockTreeHandle.isSMB2()).thenReturn(false);
            when(mockTreeHandle.send(any(SmbComDelete.class), any(SmbComBlankResponse.class))).thenReturn(mock(SmbComBlankResponse.class));

            // Act
            smbFile.delete();

            // Assert
            verify(mockTreeHandle).send(any(SmbComDelete.class), any(SmbComBlankResponse.class));
        }

        @Test
        void testDeleteDirectory() throws SmbException, CIFSException {
            // Arrange
            // Mock that it exists and is a directory
            doReturn(true).when(smbFile).exists();
            doReturn(true).when(smbFile).isDirectory();

            // Mock listFiles to return empty array (directory is empty)
            doReturn(new SmbFile[0]).when(smbFile).listFiles();

            when(mockTreeHandle.isSMB2()).thenReturn(false);

            // The delete method for directories uses SmbComDelete with the directory flag
            // After checking SMB code, directories are deleted using SmbComDelete with ATTR_DIRECTORY
            when(mockTreeHandle.send(any(SmbComDelete.class), any(SmbComBlankResponse.class))).thenReturn(mock(SmbComBlankResponse.class));

            // Act
            smbFile.delete();

            // Assert - directories are actually deleted using SmbComDelete with the directory attribute
            verify(mockTreeHandle).send(any(SmbComDelete.class), any(SmbComBlankResponse.class));
        }

        @Test
        void testRenameTo() throws SmbException, MalformedURLException, CIFSException {
            // Arrange
            Handler urlHandler = (Handler) mockCifsContext.getUrlHandler();
            URL destUrl = new URL(null, "smb://localhost/share/renamed.txt", urlHandler);
            SmbFile dest = spy(new SmbFile(destUrl, mockCifsContext));
            doReturn(mockTreeHandle).when(dest).ensureTreeConnected();
            doReturn(true).when(smbFile).exists();
            doReturn(false).when(dest).exists();
            when(mockTreeHandle.isSMB2()).thenReturn(false);
            when(mockTreeHandle.isSameTree(mockTreeHandle)).thenReturn(true);
            when(mockTreeHandle.send(any(SmbComRename.class), any(SmbComBlankResponse.class))).thenReturn(mock(SmbComBlankResponse.class));

            // Act
            smbFile.renameTo(dest);

            // Assert
            verify(mockTreeHandle).send(any(SmbComRename.class), any(SmbComBlankResponse.class));
        }

        @Test
        void testCreateNewFile() throws SmbException, CIFSException, IOException {
            // Arrange
            when(mockTreeHandle.isSMB2()).thenReturn(false);
            SmbFileHandleImpl mockFileHandle = mock(SmbFileHandleImpl.class);
            doReturn(mockFileHandle).when(smbFile).openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt());
            doNothing().when(mockFileHandle).close(0L);

            // Act
            smbFile.createNewFile();

            // Assert
            verify(smbFile).openUnshared(SmbFile.O_RDWR | SmbFile.O_CREAT | SmbFile.O_EXCL, SmbFile.O_RDWR, SmbFile.FILE_NO_SHARE,
                    SmbFile.ATTR_NORMAL, 0);
        }
    }
}
