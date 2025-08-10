/*
 * © 2024 Shinsuke Ogawa
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CloseableIterator;
import jcifs.ResourceFilter;
import jcifs.SmbConstants;
import jcifs.SmbResource;

/**
 * Tests for {@link DirFileEntryAdapterIterator}.
 */
@ExtendWith(MockitoExtension.class)
class DirFileEntryAdapterIteratorTest {

    @Mock
    private SmbResource mockParent;

    @Mock
    private CloseableIterator<FileEntry> mockDelegate;

    @Mock
    private ResourceFilter mockFilter;

    @Mock
    private FileEntry mockFileEntry;

    private DirFileEntryAdapterIterator iterator;

    @BeforeEach
    void setUp() {
        iterator = new DirFileEntryAdapterIterator(mockParent, mockDelegate, mockFilter);
    }

    /**
     * Test the constructor of {@link DirFileEntryAdapterIterator}.
     */
    @Test
    void testConstructor() {
        assertNotNull(iterator, "Iterator should be instantiated");
    }

    /**
     * Test the {@link DirFileEntryAdapterIterator#adapt(FileEntry)} method.
     *
     * @throws MalformedURLException if the URL is invalid
     */
    @Test
    void testAdapt() throws MalformedURLException {
        // Given
        String fileName = "testFile.txt";
        int attributes = SmbConstants.ATTR_ARCHIVE;
        long createTime = System.currentTimeMillis() - 2000;
        long lastModified = System.currentTimeMillis() - 1000;
        long lastAccess = System.currentTimeMillis();
        long length = 1024;

        when(mockFileEntry.getName()).thenReturn(fileName);
        when(mockFileEntry.getAttributes()).thenReturn(attributes);
        when(mockFileEntry.createTime()).thenReturn(createTime);
        when(mockFileEntry.lastModified()).thenReturn(lastModified);
        when(mockFileEntry.lastAccess()).thenReturn(lastAccess);
        when(mockFileEntry.length()).thenReturn(length);

        // When
        SmbResource adaptedResource = iterator.adapt(mockFileEntry);

        // Then
        assertNotNull(adaptedResource, "Adapted resource should not be null");
        assertEquals(SmbFile.class, adaptedResource.getClass(), "Adapted resource should be an SmbFile");

        SmbFile adaptedFile = (SmbFile) adaptedResource;
        assertEquals(fileName, adaptedFile.getName(), "File name should match");
        assertEquals(attributes, adaptedFile.getAttributes(), "Attributes should match");
        assertEquals(createTime, adaptedFile.createTime(), "Create time should match");
        assertEquals(lastModified, adaptedFile.lastModified(), "Last modified time should match");
        assertEquals(length, adaptedFile.length(), "Length should match");
    }
}
