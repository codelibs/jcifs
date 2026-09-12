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

import java.net.MalformedURLException;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.CloseableIterator;
import org.codelibs.jcifs.smb.ResourceFilter;
import org.codelibs.jcifs.smb.RuntimeCIFSException;
import org.codelibs.jcifs.smb.SmbResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

abstract class FileEntryAdapterIterator implements CloseableIterator<SmbResource> {

    private static final Logger log = LoggerFactory.getLogger(FileEntryAdapterIterator.class);

    private final CloseableIterator<FileEntry> delegate;
    private final ResourceFilter filter;
    private final SmbResource parent;
    private SmbResource next;

    /**
     * Set when the delegate reports that the listing failed, and thrown once the entry read before it has been
     * handed out. Every public listing API comes through this class, so deferring here is what makes that guarantee
     * visible to callers.
     */
    private RuntimeCIFSException failure;

    /**
     * @param parent
     * @param delegate
     * @param filter
     *
     */
    public FileEntryAdapterIterator(final SmbResource parent, final CloseableIterator<FileEntry> delegate, final ResourceFilter filter) {
        this.parent = parent;
        this.delegate = delegate;
        this.filter = filter;
        this.next = advance();
    }

    /**
     * @return the parent
     */
    protected final SmbResource getParent() {
        return this.parent;
    }

    /**
     * @return
     *
     */
    private SmbResource advance() {
        while (this.delegate.hasNext()) {
            final FileEntry fe = this.delegate.next();
            if (this.filter == null) {
                try {
                    return adapt(fe);
                } catch (final MalformedURLException e) {
                    log.error("Failed to create child URL", e);
                    continue;
                }
            }

            try (SmbResource r = adapt(fe)) {
                if (this.filter.accept(r)) {
                    return r;
                }
            } catch (final MalformedURLException e) {
                log.error("Failed to create child URL", e);
                continue;
            } catch (final CIFSException e) {
                log.error("Filter failed", e);
                continue;
            }
        }
        return null;
    }

    protected abstract SmbResource adapt(FileEntry e) throws MalformedURLException;

    /**
     * {@inheritDoc}
     *
     * @see java.util.Iterator#hasNext()
     */
    @Override
    public boolean hasNext() {
        return this.next != null || this.failure != null;
    }

    /**
     * {@inheritDoc}
     *
     * @throws RuntimeCIFSException if the listing could not be read to its end, thrown after every entry that was
     *             read has been returned
     * @see java.util.Iterator#next()
     */
    @Override
    public SmbResource next() {
        if (this.next == null) {
            // Nothing left to hand out: report the failure that ended the listing, once, and stay exhausted
            final RuntimeCIFSException pending = this.failure;
            if (pending != null) {
                this.failure = null;
                throw pending;
            }
            return null;
        }
        final SmbResource n = this.next;
        try {
            this.next = advance();
        } catch (final RuntimeCIFSException e) {
            // The delegate had already read this entry when the listing failed, so hand it out and report the
            // failure on the next call rather than losing it
            this.next = null;
            this.failure = e;
        }
        return n;
    }

    /**
     * {@inheritDoc}
     *
     * @throws CIFSException
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    public void close() throws CIFSException {
        this.delegate.close();
    }

    @Override
    public void remove() {
        this.delegate.remove();
    }
}