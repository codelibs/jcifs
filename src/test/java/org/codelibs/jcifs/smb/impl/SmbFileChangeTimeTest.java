/*
 * © 2026 CodeLibs, Inc.
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
package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CloseableIterator;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.context.BaseContext;
import org.codelibs.jcifs.smb.internal.SmbBasicFileInfo;
import org.codelibs.jcifs.smb.internal.fscc.FileBasicInfo;
import org.codelibs.jcifs.smb.internal.fscc.FileBothDirectoryInfo;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComNTCreateAndX;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComNTCreateAndXResponse;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComQueryInformation;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComQueryInformationResponse;
import org.codelibs.jcifs.smb.internal.smb1.trans2.Trans2QueryPathInformation;
import org.codelibs.jcifs.smb.internal.smb1.trans2.Trans2QueryPathInformationResponse;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CloseResponse;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateRequest;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateResponse;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Strings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@link SmbFile#changeTime()} carries the ChangeTime of every response that reads the attributes.
 *
 * <p>
 * Every time below is distinct from every other, so a path that hands out the last write time (or any other time)
 * as the change time fails here. A real Samba server cannot tell the two apart: it reports the last write time as the
 * change time.
 * </p>
 */
class SmbFileChangeTimeTest {

    private static final long CREATE_TIME = 1_600_000_000_000L;
    private static final long LAST_ACCESS_TIME = 1_600_000_001_000L;
    private static final long LAST_WRITE_TIME = 1_600_000_002_000L;
    private static final long CHANGE_TIME = 1_600_000_003_000L;

    private CIFSContext context;
    private SmbTreeHandleImpl tree;
    private SmbFile file;

    @BeforeEach
    void setUp() throws Exception {
        this.context = new BaseContext(new PropertyConfiguration(new Properties()));
        this.tree = mock(SmbTreeHandleImpl.class);
        when(this.tree.getConfig()).thenReturn(this.context.getConfig());
        this.file = spy(new SmbFile("smb://server/share/dir/file.txt", this.context));
        doReturn(this.tree).when(this.file).ensureTreeConnected();
    }

    @Test
    @DisplayName("a directory listing entry hands its ChangeTime to the SmbFile it becomes")
    void listingEntry() throws Exception {
        final FileBothDirectoryInfo entry = new FileBothDirectoryInfo(this.context.getConfig(), true);
        final byte[] name = Strings.getUNIBytes("file.txt");
        final byte[] buffer = new byte[94 + name.length];
        SMBUtil.writeTime(CREATE_TIME, buffer, 8);
        SMBUtil.writeTime(LAST_ACCESS_TIME, buffer, 16);
        SMBUtil.writeTime(LAST_WRITE_TIME, buffer, 24);
        SMBUtil.writeTime(CHANGE_TIME, buffer, 32);
        SMBUtil.writeInt4(SmbConstants.ATTR_ARCHIVE, buffer, 56);
        SMBUtil.writeInt4(name.length, buffer, 60);
        System.arraycopy(name, 0, buffer, 94, name.length);
        entry.decode(buffer, 0, buffer.length);

        final Iterator<FileEntry> entries = List.<FileEntry> of(entry).iterator();
        final CloseableIterator<FileEntry> delegate = new CloseableIterator<>() {
            @Override
            public boolean hasNext() {
                return entries.hasNext();
            }

            @Override
            public FileEntry next() {
                return entries.next();
            }

            @Override
            public void close() {
            }
        };
        try (SmbFile dir = new SmbFile("smb://server/share/dir/", this.context);
                DirFileEntryAdapterIterator listing = new DirFileEntryAdapterIterator(dir, delegate, null);
                SmbFile listed = (SmbFile) listing.next()) {
            assertEquals("file.txt", listed.getName());
            assertTimes(listed);
        }
    }

    @Test
    @DisplayName("SMB2: the attributes a close reports after the query are the ones kept")
    void smb2CloseResponse() throws Exception {
        when(this.tree.isSMB2()).thenReturn(true);
        final Smb2CloseResponse close = mock(Smb2CloseResponse.class);
        when(close.getCloseFlags()).thenReturn(Smb2CloseResponse.SMB2_CLOSE_FLAG_POSTQUERY_ATTIB);
        stubTimes(close);
        final Smb2CreateResponse create = mock(Smb2CreateResponse.class);
        doAnswer(invocation -> {
            final Smb2CreateRequest request = invocation.getArgument(0);
            request.getNext().setResponse(close);
            return create;
        }).when(this.tree).send(any(Smb2CreateRequest.class));

        assertTimes(this.file);
    }

    @Test
    @DisplayName("SMB2: without post-query attributes on the close the create response is used")
    void smb2CreateResponseOnQuery() throws Exception {
        when(this.tree.isSMB2()).thenReturn(true);
        final Smb2CloseResponse close = mock(Smb2CloseResponse.class);
        final Smb2CreateResponse create = mock(Smb2CreateResponse.class);
        stubTimes(create);
        doAnswer(invocation -> {
            final Smb2CreateRequest request = invocation.getArgument(0);
            request.getNext().setResponse(close);
            return create;
        }).when(this.tree).send(any(Smb2CreateRequest.class));

        assertTimes(this.file);
    }

    @Test
    @DisplayName("SMB2: the create response of an open keeps its ChangeTime")
    void smb2Open() throws Exception {
        when(this.tree.isSMB2()).thenReturn(true);
        final Smb2CreateResponse create = mock(Smb2CreateResponse.class);
        stubTimes(create);
        doReturn(create).when(this.tree).send(any(Smb2CreateRequest.class));

        // The handle is left alone: closing it would talk to the mocked tree.
        this.file.openUnshared(SmbConstants.O_RDONLY, SmbConstants.FILE_READ_DATA, SmbConstants.DEFAULT_SHARING, SmbConstants.ATTR_NORMAL,
                0);
        assertTimes(this.file);
    }

    @Test
    @DisplayName("SMB1: the NT create AndX response of an open keeps its ChangeTime")
    void smb1Open() throws Exception {
        when(this.tree.isSMB2()).thenReturn(false);
        when(this.tree.hasCapability(SmbConstants.CAP_NT_SMBS)).thenReturn(true);
        doAnswer(invocation -> {
            decodeNtCreateAndX(invocation.getArgument(1));
            return null;
        }).when(this.tree).send(any(SmbComNTCreateAndX.class), any(SmbComNTCreateAndXResponse.class));

        // The handle is left alone: closing it would talk to the mocked tree.
        this.file.openUnshared(SmbConstants.O_RDONLY, SmbConstants.FILE_READ_DATA, SmbConstants.DEFAULT_SHARING, SmbConstants.ATTR_NORMAL,
                0);
        assertTimes(this.file);
    }

    @Test
    @DisplayName("SMB1: the FILE_BASIC_INFO of a path query keeps its ChangeTime")
    void smb1QueryPath() throws Exception {
        when(this.tree.isSMB2()).thenReturn(false);
        when(this.tree.hasCapability(SmbConstants.CAP_NT_SMBS)).thenReturn(true);
        final Trans2QueryPathInformationResponse response = mock(Trans2QueryPathInformationResponse.class);
        when(response.getInfo(any())).thenReturn(new FileBasicInfo(CREATE_TIME, LAST_ACCESS_TIME, LAST_WRITE_TIME, CHANGE_TIME, 0));
        doReturn(response).when(this.tree).send(any(Trans2QueryPathInformation.class), any(Trans2QueryPathInformationResponse.class));

        assertTimes(this.file);
    }

    @Test
    @DisplayName("SMB1 core: a query that carries only the last write time reports no change time")
    void smb1CoreQueryPath() throws Exception {
        when(this.tree.isSMB2()).thenReturn(false);
        final SmbComQueryInformationResponse response = mock(SmbComQueryInformationResponse.class);
        when(response.getLastWriteTime()).thenReturn(LAST_WRITE_TIME);
        doReturn(response).when(this.tree).send(any(SmbComQueryInformation.class), any(SmbComQueryInformationResponse.class));

        assertEquals(LAST_WRITE_TIME, this.file.lastModified());
        assertEquals(0L, this.file.changeTime());
    }

    @Test
    @DisplayName("a refresh that finds the file gone clears the change time it had")
    void resetWhenGone() throws Exception {
        try (SmbFile dir = new SmbFile("smb://server/share/dir/", this.context)) {
            final SmbFile stale = spy(new SmbFile(dir, "file.txt", false, SmbConstants.TYPE_FILESYSTEM, 0, CREATE_TIME, LAST_WRITE_TIME,
                    LAST_ACCESS_TIME, CHANGE_TIME, 0L));
            doReturn(this.tree).when(stale).ensureTreeConnected();
            when(this.tree.isSMB2()).thenReturn(true);
            when(this.tree.send(any(Smb2CreateRequest.class))).thenThrow(new SmbException(NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND, false));

            assertFalse(stale.exists());
            assertEquals(0L, stale.changeTime());
        }
    }

    @Test
    @DisplayName("a share has no change time")
    void share() throws Exception {
        try (SmbFile share = new SmbFile("smb://server/share/", this.context)) {
            assertEquals(0L, share.changeTime());
        }
    }

    private static void stubTimes(final SmbBasicFileInfo info) {
        when(info.getCreateTime()).thenReturn(CREATE_TIME);
        when(info.getLastAccessTime()).thenReturn(LAST_ACCESS_TIME);
        when(info.getLastWriteTime()).thenReturn(LAST_WRITE_TIME);
        when(info.getChangeTime()).thenReturn(CHANGE_TIME);
    }

    private static void assertTimes(final SmbFile f) throws Exception {
        assertEquals(CREATE_TIME, f.createTime(), "createTime");
        assertEquals(LAST_ACCESS_TIME, f.lastAccess(), "lastAccess");
        assertEquals(LAST_WRITE_TIME, f.lastModified(), "lastModified");
        assertEquals(CHANGE_TIME, f.changeTime(), "changeTime");
    }

    /**
     * Fills a response the way the transport would, by decoding its parameter words (MS-CIFS 2.2.4.64.2).
     */
    private static void decodeNtCreateAndX(final SmbComNTCreateAndXResponse response) throws Exception {
        final byte[] words = new byte[72];
        SMBUtil.writeTime(CREATE_TIME, words, 7);
        SMBUtil.writeTime(LAST_ACCESS_TIME, words, 15);
        SMBUtil.writeTime(LAST_WRITE_TIME, words, 23);
        SMBUtil.writeTime(CHANGE_TIME, words, 31);
        final Method read = SmbComNTCreateAndXResponse.class.getDeclaredMethod("readParameterWordsWireFormat", byte[].class, int.class);
        read.setAccessible(true);
        read.invoke(response, words, 0);
    }
}
