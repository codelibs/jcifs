package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.SmbResourceLocator;
import jcifs.SmbConstants;
import jcifs.internal.smb1.com.SmbComBlankResponse;
import jcifs.internal.smb1.com.SmbComCreateDirectory;
import jcifs.internal.smb1.com.SmbComDelete;
import jcifs.internal.smb1.com.SmbComDeleteDirectory;
import jcifs.internal.smb1.com.SmbComQueryInformationResponse;
import jcifs.internal.smb1.com.SmbComRename;

@ExtendWith(MockitoExtension.class)
public class SmbFileTest {

    @Mock
    private CIFSContext mockCifsContext;

    @Mock
    private SmbResourceLocator mockLocator;

    @Mock
    private Configuration mockConfig;

    private URL url;

    private SmbFile smbFile;

    @BeforeEach
    public void setUp() throws MalformedURLException, CIFSException {
        url = new URL("smb://localhost/share/file.txt");
        when(mockCifsContext.getUrlHandler()).thenReturn(new jcifs.smb.Handler(mockCifsContext));
        when(mockCifsContext.getConfig()).thenReturn(mockConfig);

        smbFile = spy(new SmbFile(url, mockCifsContext));

        // Prevent network operations by default
        doReturn(mockLocator).when(smbFile).getLocator();
    }

    // ... constructor and getter tests ...

    @Nested
    class WhenManipulatingFiles {

        @Mock
        private SmbTreeHandleImpl mockTreeHandle;

        @BeforeEach
        void setUp() throws CIFSException {
            doReturn(mockTreeHandle).when(smbFile).ensureTreeConnected();
            when(mockLocator.getUNCPath()).thenReturn("\\localhost\share\newdir");
            when(mockLocator.getShare()).thenReturn("share");
        }

        @Test
        void testMkdir() throws SmbException, CIFSException {
            // Arrange
            when(mockTreeHandle.isSMB2()).thenReturn(false);
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
            when(mockTreeHandle.send(any(SmbComDelete.class), any(SmbComBlankResponse.class)))
                    .thenReturn(mock(SmbComBlankResponse.class));

            // Act
            smbFile.delete();

            // Assert
            verify(mockTreeHandle).send(any(SmbComDelete.class), any(SmbComBlankResponse.class));
        }

        @Test
        void testDeleteDirectory() throws SmbException, CIFSException {
            // Arrange
            doReturn(true).when(smbFile).exists();
            // Mock that it's a directory
            doReturn(true).when(smbFile).isDirectory();
            when(mockTreeHandle.isSMB2()).thenReturn(false);
            when(mockTreeHandle.send(any(SmbComDeleteDirectory.class), any(SmbComBlankResponse.class)))
                    .thenReturn(mock(SmbComBlankResponse.class));
            // Mock listFiles to return an empty array to avoid recursion
            doReturn(new SmbFile[0]).when(smbFile).listFiles();

            // Act
            smbFile.delete();

            // Assert
            verify(mockTreeHandle).send(any(SmbComDeleteDirectory.class), any(SmbComBlankResponse.class));
        }

        @Test
        void testRenameTo() throws SmbException, MalformedURLException, CIFSException {
            // Arrange
            SmbFile dest = spy(new SmbFile("smb://localhost/share/renamed.txt", mockCifsContext));
            doReturn(mockTreeHandle).when(dest).ensureTreeConnected();
            doReturn(true).when(smbFile).exists();
            doReturn(false).when(dest).exists();
            when(mockTreeHandle.isSMB2()).thenReturn(false);
            when(mockTreeHandle.isSameTree(mockTreeHandle)).thenReturn(true);
            when(mockTreeHandle.send(any(SmbComRename.class), any(SmbComBlankResponse.class)))
                    .thenReturn(mock(SmbComBlankResponse.class));

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
            verify(smbFile).openUnshared(
                SmbFile.O_RDWR | SmbFile.O_CREAT | SmbFile.O_EXCL,
                SmbFile.O_RDWR,
                SmbFile.FILE_NO_SHARE,
                SmbFile.ATTR_NORMAL,
                0);
        }
    }
}
