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
package jcifs.smb;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.CloseableIterator;
import jcifs.ResourceFilter;
import jcifs.ResourceNameFilter;
import jcifs.SmbConstants;
import jcifs.SmbResource;
import jcifs.SmbResourceLocator;
import jcifs.dcerpc.DcerpcException;
import jcifs.dcerpc.DcerpcHandle;
import jcifs.dcerpc.msrpc.MsrpcDfsRootEnum;
import jcifs.dcerpc.msrpc.MsrpcShareEnum;
import jcifs.internal.smb1.net.NetShareEnum;
import jcifs.internal.smb1.net.NetShareEnumResponse;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.smb1.trans.SmbComTransactionResponse;

/**
 * @author mbechler
 *
 */
final class SmbEnumerationUtil {

    private static final Logger log = LoggerFactory.getLogger(SmbEnumerationUtil.class);

    /**
     *
     */
    private SmbEnumerationUtil() {
    }

    private static DcerpcHandle getHandle(final CIFSContext ctx, final SmbResourceLocator loc, final Address address, final String ep)
            throws MalformedURLException, DcerpcException {
        return DcerpcHandle.getHandle(String.format("ncacn_np:%s[endpoint=%s,address=%s]", loc.getServer(), ep, address.getHostAddress()),
                ctx);
    }

    static FileEntry[] doDfsRootEnum(final CIFSContext ctx, final SmbResourceLocator loc, final Address address) throws IOException {
        try (DcerpcHandle handle = getHandle(ctx, loc, address, "\\PIPE\\netdfs")) {
            final MsrpcDfsRootEnum rpc = new MsrpcDfsRootEnum(loc.getServer());
            handle.sendrecv(rpc);
            if (rpc.retval != 0) {
                throw new SmbException(rpc.retval, true);
            }
            return rpc.getEntries();
        }
    }

    static FileEntry[] doMsrpcShareEnum(final CIFSContext ctx, final SmbResourceLocator loc, final Address address) throws IOException {
        try (DcerpcHandle handle = getHandle(ctx, loc, address, "\\PIPE\\srvsvc")) {
            final MsrpcShareEnum rpc = new MsrpcShareEnum(loc.getServer());
            handle.sendrecv(rpc);
            if (rpc.retval != 0) {
                throw new SmbException(rpc.retval, true);
            }
            return rpc.getEntries();
        }
    }

    static FileEntry[] doNetShareEnum(final SmbTreeHandleImpl th) throws CIFSException {
        final SmbComTransaction req = new NetShareEnum(th.getConfig());
        final SmbComTransactionResponse resp = new NetShareEnumResponse(th.getConfig());
        th.send(req, resp);
        if (resp.getStatus() != WinError.ERROR_SUCCESS) {
            throw new SmbException(resp.getStatus(), true);
        }

        return resp.getResults();
    }

    static CloseableIterator<SmbResource> doShareEnum(final SmbFile parent, final String wildcard, final int searchAttributes,
            final ResourceNameFilter fnf, final ResourceFilter ff) throws CIFSException {
        // clone the locator so that the address index is not modified
        final SmbResourceLocatorImpl locator = parent.fileLocator.clone();
        final CIFSContext tc = parent.getContext();
        final URL u = locator.getURL();

        FileEntry[] entries;

        if (u.getPath().lastIndexOf('/') != u.getPath().length() - 1) {
            throw new SmbException(u.toString() + " directory must end with '/'");
        }

        if (locator.getType() != SmbConstants.TYPE_SERVER) {
            throw new SmbException("The requested list operations is invalid: " + u.toString());
        }

        final Set<FileEntry> set = new HashSet<>();

        if (tc.getDfs().isTrustedDomain(tc, locator.getServer())) {
            /*
             * The server name is actually the name of a trusted
             * domain. Add DFS roots to the list.
             */
            try {
                entries = doDfsRootEnum(tc, locator, locator.getAddress());
                for (final FileEntry e : entries) {
                    if (!set.contains(e) && (fnf == null || fnf.accept(parent, e.getName()))) {
                        set.add(e);
                    }
                }
            } catch (final IOException ioe) {
                log.debug("DS enumeration failed", ioe);
            }
        }

        final SmbTreeConnection treeConn = SmbTreeConnection.create(tc);
        try (SmbTreeHandleImpl th = treeConn.connectHost(locator, locator.getServerWithDfs());
                SmbSessionImpl session = th.getSession();
                SmbTransportImpl transport = session.getTransport()) {
            try {
                entries = doMsrpcShareEnum(tc, locator, transport.getRemoteAddress());
            } catch (final IOException ioe) {
                if (th.isSMB2()) {
                    throw ioe;
                }
                log.debug("doMsrpcShareEnum failed", ioe);
                entries = doNetShareEnum(th);
            }
            for (final FileEntry e : entries) {
                if (!set.contains(e) && (fnf == null || fnf.accept(parent, e.getName()))) {
                    set.add(e);
                }
            }

        } catch (final SmbException e) {
            throw e;
        } catch (final IOException ioe) {
            log.debug("doNetShareEnum failed", ioe);
            throw new SmbException(u.toString(), ioe);
        }
        return new ShareEnumIterator(parent, set.iterator(), ff);
    }

    @SuppressWarnings("resource")
    static CloseableIterator<SmbResource> doEnum(final SmbFile parent, String wildcard, int searchAttributes, final ResourceNameFilter fnf,
            final ResourceFilter ff) throws CIFSException {
        final DosFileFilter dff = unwrapDOSFilter(ff);
        if (dff != null) {
            if (dff.wildcard != null) {
                wildcard = dff.wildcard;
            }
            searchAttributes = dff.attributes;
        }
        final SmbResourceLocator locator = parent.getLocator();
        if (locator.getURL().getHost().isEmpty()) {
            // smb:// -> enumerate servers through browsing
            Address addr;
            try {
                addr = locator.getAddress();
            } catch (final CIFSException e) {
                if (e.getCause() instanceof UnknownHostException) {
                    log.debug("Failed to find master browser", e);
                    throw new SmbUnsupportedOperationException();
                }
                throw e;
            }
            try (SmbFile browser = (SmbFile) parent.resolve(addr.getHostAddress())) {
                try (SmbTreeHandleImpl th = browser.ensureTreeConnected()) {
                    if (th.isSMB2()) {
                        throw new SmbUnsupportedOperationException();
                    }
                    return new NetServerFileEntryAdapterIterator(parent,
                            new NetServerEnumIterator(parent, th, wildcard, searchAttributes, fnf), ff);
                }
            }
        }
        if (locator.getType() == SmbConstants.TYPE_WORKGROUP) {
            try (SmbTreeHandleImpl th = parent.ensureTreeConnected()) {
                if (th.isSMB2()) {
                    throw new SmbUnsupportedOperationException();
                }
                return new NetServerFileEntryAdapterIterator(parent, new NetServerEnumIterator(parent, th, wildcard, searchAttributes, fnf),
                        ff);
            }
        } else if (locator.isRoot()) {
            return doShareEnum(parent, wildcard, searchAttributes, fnf, ff);
        }

        try (SmbTreeHandleImpl th = parent.ensureTreeConnected()) {
            if (th.isSMB2()) {
                return new DirFileEntryAdapterIterator(parent, new DirFileEntryEnumIterator2(th, parent, wildcard, fnf, searchAttributes),
                        ff);
            }
            return new DirFileEntryAdapterIterator(parent, new DirFileEntryEnumIterator1(th, parent, wildcard, fnf, searchAttributes), ff);
        }
    }

    private static DosFileFilter unwrapDOSFilter(final ResourceFilter ff) {
        if (ff instanceof ResourceFilterWrapper) {
            final SmbFileFilter sff = ((ResourceFilterWrapper) ff).getFileFilter();
            if (sff instanceof DosFileFilter) {
                return (DosFileFilter) sff;
            }
        }
        return null;
    }

    static String[] list(final SmbFile root, final String wildcard, final int searchAttributes, final SmbFilenameFilter fnf,
            final SmbFileFilter ff) throws SmbException {
        try (CloseableIterator<SmbResource> it = doEnum(root, wildcard, searchAttributes, fnf == null ? null : (parent, name) -> {
            if (!(parent instanceof SmbFile)) {
                return false;
            }
            return fnf.accept((SmbFile) parent, name);
        }, ff == null ? null : resource -> {
            if (!(resource instanceof SmbFile)) {
                return false;
            }
            return ff.accept((SmbFile) resource);
        })) {

            final List<String> list = new ArrayList<>();
            while (it.hasNext()) {
                try (SmbResource n = it.next()) {
                    list.add(n.getName());
                }
            }
            return list.toArray(new String[list.size()]);
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    static SmbFile[] listFiles(final SmbFile root, final String wildcard, final int searchAttributes, final SmbFilenameFilter fnf,
            final SmbFileFilter ff) throws SmbException {
        try (CloseableIterator<SmbResource> it = doEnum(root, wildcard, searchAttributes,
                fnf == null ? null : new ResourceNameFilterWrapper(fnf), ff == null ? null : new ResourceFilterWrapper(ff))) {

            final List<SmbFile> list = new ArrayList<>();
            while (it.hasNext()) {
                try (SmbResource n = it.next()) {
                    if (n instanceof SmbFile) {
                        list.add((SmbFile) n);
                    }
                }
            }
            return list.toArray(new SmbFile[list.size()]);
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    /**
     * @author mbechler
     *
     */
    private static final class ResourceFilterWrapper implements ResourceFilter {

        /**
         *
         */
        private final SmbFileFilter ff;

        /**
         * @param ff
         */
        ResourceFilterWrapper(final SmbFileFilter ff) {
            this.ff = ff;
        }

        SmbFileFilter getFileFilter() {
            return this.ff;
        }

        @Override
        public boolean accept(final SmbResource resource) throws CIFSException {
            if (!(resource instanceof SmbFile)) {
                return false;
            }
            return this.ff.accept((SmbFile) resource);
        }
    }

    /**
     * @author mbechler
     *
     */
    private static final class ResourceNameFilterWrapper implements ResourceNameFilter {

        /**
         *
         */
        private final SmbFilenameFilter fnf;

        /**
         * @param fnf
         */
        ResourceNameFilterWrapper(final SmbFilenameFilter fnf) {
            this.fnf = fnf;
        }

        @Override
        public boolean accept(final SmbResource parent, final String name) throws CIFSException {
            if (!(parent instanceof SmbFile)) {
                return false;
            }
            return this.fnf.accept((SmbFile) parent, name);
        }
    }

}
