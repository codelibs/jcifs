/*
 * © 2017 AgNO3 Gmbh & Co. KG
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

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.ResourceNameFilter;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.SmbResource;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CloseRequest;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateRequest;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateResponse;
import org.codelibs.jcifs.smb.internal.smb2.info.Smb2QueryDirectoryRequest;
import org.codelibs.jcifs.smb.internal.smb2.info.Smb2QueryDirectoryResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SMB2/SMB3 implementation of directory entry enumeration iterator.
 * Provides efficient directory listing capabilities for SMB2/SMB3 protocol versions.
 *
 * @author mbechler
 *
 */
public class DirFileEntryEnumIterator2 extends DirFileEntryEnumIteratorBase {

    private static final Logger log = LoggerFactory.getLogger(DirFileEntryEnumIterator2.class);

    private byte[] fileId;
    private Smb2QueryDirectoryResponse response;

    /**
     * Creates a directory entry enumeration iterator for SMB2 protocol.
     *
     * @param th the SMB tree handle for the connection
     * @param parent the parent resource being enumerated
     * @param wildcard the wildcard pattern for filtering entries
     * @param filter additional resource name filter to apply
     * @param searchAttributes the file attributes to search for
     * @throws CIFSException if an error occurs during initialization
     */
    public DirFileEntryEnumIterator2(final SmbTreeHandleImpl th, final SmbResource parent, final String wildcard,
            final ResourceNameFilter filter, final int searchAttributes) throws CIFSException {
        super(th, parent, wildcard, filter, searchAttributes);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.impl.DirFileEntryEnumIteratorBase#getResults()
     */
    @Override
    protected FileEntry[] getResults() {
        final FileEntry[] results = this.response.getResults();
        if (results == null) {
            return new FileEntry[0];
        }
        return results;
    }

    /**
     * Opens a directory for enumeration
     *
     * @return the opened directory file entry
     * @throws CIFSException if an error occurs opening the directory
     */
    @SuppressWarnings("resource")
    @Override
    protected FileEntry open() throws CIFSException {
        final SmbTreeHandleImpl th = getTreeHandle();
        final String uncPath = getParent().getLocator().getUNCPath();
        final Smb2CreateRequest create = new Smb2CreateRequest(th.getConfig(), uncPath);
        create.setCreateOptions(Smb2CreateRequest.FILE_DIRECTORY_FILE);
        create.setDesiredAccess(SmbConstants.FILE_READ_DATA | SmbConstants.FILE_READ_ATTRIBUTES);
        final Smb2QueryDirectoryRequest query = new Smb2QueryDirectoryRequest(th.getConfig());
        query.setFileName(getWildcard());
        create.chain(query);
        Smb2CreateResponse createResp;
        try {
            createResp = th.send(create);
        } catch (final SmbException e) {
            final Smb2CreateResponse cr = create.getResponse();
            if (cr != null && cr.isReceived() && cr.getStatus() == NtStatus.NT_STATUS_SUCCESS) {
                try {
                    th.send(new Smb2CloseRequest(th.getConfig(), cr.getFileId()));
                } catch (final SmbException e2) {
                    e.addSuppressed(e2);
                }
            }

            final Smb2QueryDirectoryResponse qr = query.getResponse();

            if (qr != null && qr.isReceived() && qr.getStatus() == NtStatus.NT_STATUS_NO_SUCH_FILE) {
                // this simply indicates an empty listing
                doClose();
                return null;
            }

            throw e;
        }
        this.fileId = createResp.getFileId();
        this.response = query.getResponse();
        final FileEntry n = advance(false);
        if (n == null) {
            doClose();
        }
        return n;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.impl.DirFileEntryEnumIteratorBase#fetchMore()
     */
    @SuppressWarnings("resource")
    @Override
    protected boolean fetchMore() throws CIFSException {
        final FileEntry[] results = this.response.getResults();
        final SmbTreeHandleImpl th = getTreeHandle();
        final Smb2QueryDirectoryRequest query = new Smb2QueryDirectoryRequest(th.getConfig(), this.fileId);
        query.setFileName(this.getWildcard());
        query.setFileIndex(results[results.length - 1].getFileIndex());
        query.setQueryFlags(Smb2QueryDirectoryRequest.SMB2_INDEX_SPECIFIED);
        try {
            final Smb2QueryDirectoryResponse r = th.send(query);
            if (r.getStatus() == NtStatus.NT_STATUS_NO_MORE_FILES) {
                return false;
            }
            this.response = r;
        } catch (final SmbException e) {
            if (e.getNtStatus() == NtStatus.NT_STATUS_NO_MORE_FILES) {
                log.debug("End of listing", e);
                return false;
            }
            throw e;
        }
        return true;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.impl.DirFileEntryEnumIteratorBase#isDone()
     */
    @Override
    protected boolean isDone() {
        return false;
    }

    /**
     * Performs internal closing operations for SMB2 enumeration.
     *
     * @throws CIFSException if an error occurs during closing
     */
    @Override
    protected void doCloseInternal() throws CIFSException {
        try {
            @SuppressWarnings("resource")
            final SmbTreeHandleImpl th = getTreeHandle();
            if (this.fileId != null && th.isConnected()) {
                th.send(new Smb2CloseRequest(th.getConfig(), this.fileId));
            }
        } finally {
            this.fileId = null;
        }
    }

}
