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
package org.codelibs.jcifs.smb;

import org.codelibs.jcifs.smb.internal.smb1.net.NetServerEnum2;
import org.codelibs.jcifs.smb.internal.smb1.net.NetServerEnum2Response;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransaction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Iterator for enumerating network servers.
 *
 * This class provides iteration over network servers discovered
 * through NetBIOS server enumeration requests.
 */
public class NetServerEnumIterator implements CloseableIterator<FileEntry> {

    private static final Logger log = LoggerFactory.getLogger(NetServerEnumIterator.class);

    private final NetServerEnum2 request;
    private final NetServerEnum2Response response;
    private final SmbResource parent;
    private final SmbTreeHandleImpl treeHandle;
    private final ResourceNameFilter nameFilter;
    private final boolean workgroup;
    private int ridx;
    private FileEntry next;

    /**
     * Constructs a NetServerEnumIterator for enumerating network servers
     * @param parent
     *            the parent SMB file
     * @param th
     *            the tree handle to use
     * @param wildcard
     *            wildcard pattern for filtering servers
     * @param searchAttributes
     *            attributes to search for
     * @param filter
     *            optional resource name filter
     * @throws CIFSException
     *            if enumeration fails
     */
    public NetServerEnumIterator(final SmbFile parent, final SmbTreeHandleImpl th, final String wildcard, final int searchAttributes,
            final ResourceNameFilter filter) throws CIFSException {
        this.parent = parent;
        this.nameFilter = filter;
        final SmbResourceLocator locator = parent.getLocator();
        this.workgroup = locator.getType() == SmbConstants.TYPE_WORKGROUP;
        if (locator.getURL().getHost().isEmpty()) {
            this.request = new NetServerEnum2(th.getConfig(), th.getOEMDomainName(), NetServerEnum2.SV_TYPE_DOMAIN_ENUM);
        } else if (this.workgroup) {
            this.request = new NetServerEnum2(th.getConfig(), locator.getURL().getHost(), NetServerEnum2.SV_TYPE_ALL);
        } else {
            throw new SmbException("The requested list operations is invalid: " + locator.getURL());
        }
        this.response = new NetServerEnum2Response(th.getConfig());

        this.treeHandle = th.acquire();
        try {
            this.next = open();
        } catch (final Exception e) {
            this.treeHandle.release();
            throw e;
        }

    }

    private FileEntry open() throws CIFSException {
        this.treeHandle.send(this.request, this.response);
        checkStatus();
        final FileEntry n = advance();
        if (n == null) {
            doClose();
        }
        return n;
    }

    /**
     * @throws SmbSystemException
     */
    private void checkStatus() throws SmbException {
        final int status = this.response.getStatus();
        if (status == WinError.ERROR_SERVICE_NOT_INSTALLED) {
            throw new SmbUnsupportedOperationException();
        }
        if (status != WinError.ERROR_SUCCESS && status != WinError.ERROR_MORE_DATA) {
            throw new SmbException(status, true);
        }
    }

    private FileEntry advance() throws CIFSException {
        final int n =
                this.response.getStatus() == WinError.ERROR_MORE_DATA ? this.response.getNumEntries() - 1 : this.response.getNumEntries();
        while (this.ridx < n) {
            final FileEntry itm = this.response.getResults()[this.ridx];
            this.ridx++;
            if (filter(itm)) {
                return itm;
            }
        }

        if (this.workgroup && this.response.getStatus() == WinError.ERROR_MORE_DATA) {
            this.request.reset(0, this.response.getLastName());
            this.response.reset();
            this.request.setSubCommand(SmbComTransaction.NET_SERVER_ENUM3);
            this.treeHandle.send(this.request, this.response);
            checkStatus();
            this.ridx = 0;
            return advance();
        }
        return null;
    }

    private final boolean filter(final FileEntry fe) {
        final String name = fe.getName();
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
            final FileEntry ne = advance();
            if (ne == null) {
                doClose();
                return n;
            }
            this.next = ne;
        } catch (final CIFSException e) {
            log.warn("Enumeration failed", e);
            this.next = null;
        }
        return n;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.CloseableIterator#close()
     */
    @Override
    public void close() throws CIFSException {
        if (this.next != null) {
            doClose();
        }
    }

    /**
     *
     */
    private void doClose() {
        this.treeHandle.release();
        this.next = null;
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException("remove");
    }
}