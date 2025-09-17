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
import org.codelibs.jcifs.smb.CloseableIterator;
import org.codelibs.jcifs.smb.ResourceNameFilter;
import org.codelibs.jcifs.smb.SmbResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for directory enumeration iterators.
 *
 * This abstract class provides common functionality for iterating
 * over directory entries in SMB file shares.
 *
 * @author mbechler
 */
public abstract class DirFileEntryEnumIteratorBase implements CloseableIterator<FileEntry> {

    private static final Logger log = LoggerFactory.getLogger(DirFileEntryEnumIteratorBase.class);

    private final SmbTreeHandleImpl treeHandle;
    private final ResourceNameFilter nameFilter;
    private final SmbResource parent;
    private final String wildcard;
    private final int searchAttributes;
    private FileEntry next;
    private int ridx;

    private boolean closed = false;

    /**
     * Creates a directory entry enumeration iterator.
     *
     * @param th the SMB tree handle for the connection
     * @param parent the parent resource being enumerated
     * @param wildcard the wildcard pattern for filtering entries
     * @param filter additional resource name filter to apply
     * @param searchAttributes the file attributes to search for
     * @throws CIFSException if an error occurs during initialization
     */
    public DirFileEntryEnumIteratorBase(final SmbTreeHandleImpl th, final SmbResource parent, final String wildcard,
            final ResourceNameFilter filter, final int searchAttributes) throws CIFSException {
        this.parent = parent;
        this.wildcard = wildcard;
        this.nameFilter = filter;
        this.searchAttributes = searchAttributes;

        this.treeHandle = th.acquire();
        try {
            this.next = open();
            if (this.next == null) {
                doClose();
            }
        } catch (final Exception e) {
            doClose();
            throw e;
        }

    }

    /**
     * Gets the SMB tree handle for this iterator.
     *
     * @return the treeHandle
     */
    public final SmbTreeHandleImpl getTreeHandle() {
        return this.treeHandle;
    }

    /**
     * Gets the search attributes for this iterator.
     *
     * @return the search attributes used for filtering directory entries
     */
    public final int getSearchAttributes() {
        return this.searchAttributes;
    }

    /**
     * Gets the wildcard pattern for this iterator.
     *
     * @return the wildcard
     */
    public final String getWildcard() {
        return this.wildcard;
    }

    /**
     * Gets the parent resource being enumerated.
     *
     * @return the parent
     */
    public final SmbResource getParent() {
        return this.parent;
    }

    private final boolean filter(final FileEntry fe) {
        final String name = fe.getName();
        if (name.length() < 3) {
            final int h = name.hashCode();
            if ((h == SmbFile.HASH_DOT || h == SmbFile.HASH_DOT_DOT) && (name.equals(".") || name.equals(".."))) {
                return false;
            }
        }
        if (this.nameFilter == null) {
            return true;
        }
        try {
            if (!this.nameFilter.accept(this.parent, name)) {
                return false;
            }
            return true;
        } catch (final CIFSException e) {
            log.error("Failed to apply name filter", e);
            return false;
        }
    }

    /**
     * Advances to the next file entry in the enumeration.
     *
     * @param last whether this is the last attempt to advance
     * @return the next file entry, or null if no more entries
     * @throws CIFSException if an error occurs during enumeration
     */
    protected final FileEntry advance(final boolean last) throws CIFSException {
        final FileEntry[] results = getResults();
        while (this.ridx < results.length) {
            final FileEntry itm = results[this.ridx];
            this.ridx++;
            if (filter(itm)) {
                return itm;
            }
        }

        if (!last && !isDone()) {
            if (!fetchMore()) {
                doClose();
                return null;
            }
            this.ridx = 0;
            return advance(true);
        }
        return null;
    }

    /**
     * Opens the enumeration and returns the first entry.
     *
     * @return the first file entry, or null if empty
     * @throws CIFSException if an error occurs during opening
     */
    protected abstract FileEntry open() throws CIFSException;

    /**
     * Checks if the enumeration is complete.
     *
     * @return true if enumeration is done, false otherwise
     */
    protected abstract boolean isDone();

    /**
     * Fetches more entries from the server.
     *
     * @return true if more entries were fetched, false otherwise
     * @throws CIFSException if an error occurs during fetching
     */
    protected abstract boolean fetchMore() throws CIFSException;

    /**
     * Gets the current batch of results.
     *
     * @return array of file entries in the current batch
     */
    protected abstract FileEntry[] getResults();

    /**
     * Closes the enumeration and releases resources.
     *
     * @throws CIFSException if an error occurs during closing
     */
    protected synchronized void doClose() throws CIFSException {
        // otherwise already closed
        if (!this.closed) {
            this.closed = true;
            try {
                doCloseInternal();
            } finally {
                this.next = null;
                this.treeHandle.release();
            }
        }
    }

    /**
     * Performs the internal closing operations specific to the implementation.
     *
     * @throws CIFSException if an error occurs during internal closing
     */
    protected abstract void doCloseInternal() throws CIFSException;

    /**
     * {@inheritDoc}
     *
     * @see java.util.Iterator#hasNext()
     */
    @Override
    public boolean hasNext() {
        return this.next != null;
    }

    /**
     * {@inheritDoc}
     *
     * @see java.util.Iterator#next()
     */
    @Override
    public FileEntry next() {
        final FileEntry n = this.next;
        try {
            final FileEntry ne = advance(false);
            if (ne == null) {
                doClose();
                return n;
            }
            this.next = ne;
        } catch (final CIFSException e) {
            log.warn("Enumeration failed", e);
            this.next = null;
            try {
                doClose();
            } catch (final CIFSException e1) {
                log.debug("Failed to close enum", e);
            }
        }
        return n;
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    public void close() throws CIFSException {
        if (this.next != null) {
            doClose();
        }
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException("remove");
    }
}
