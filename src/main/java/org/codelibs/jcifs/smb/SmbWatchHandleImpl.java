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

import java.util.List;

import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest;
import org.codelibs.jcifs.smb.internal.NotifyResponse;
import org.codelibs.jcifs.smb.internal.smb1.trans.nt.NtTransNotifyChange;
import org.codelibs.jcifs.smb.internal.smb1.trans.nt.NtTransNotifyChangeResponse;
import org.codelibs.jcifs.smb.internal.smb2.notify.Smb2ChangeNotifyRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author mbechler
 *
 */
class SmbWatchHandleImpl implements SmbWatchHandle {

    private static final Logger log = LoggerFactory.getLogger(SmbWatchHandleImpl.class);

    private final SmbFileHandleImpl handle;
    private final int filter;
    private final boolean recursive;

    /**
     * @param fh
     * @param filter
     * @param recursive
     *
     */
    public SmbWatchHandleImpl(final SmbFileHandleImpl fh, final int filter, final boolean recursive) {
        this.handle = fh;
        this.filter = filter;
        this.recursive = recursive;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbWatchHandle#watch()
     */
    @Override
    public List<FileNotifyInformation> watch() throws CIFSException {
        if (!this.handle.isValid()) {
            throw new SmbException("Watch was broken by tree disconnect");
        }
        try (SmbTreeHandleImpl th = this.handle.getTree()) {

            CommonServerMessageBlockRequest req;
            NotifyResponse resp = null;
            if (th.isSMB2()) {
                final Smb2ChangeNotifyRequest r = new Smb2ChangeNotifyRequest(th.getConfig(), this.handle.getFileId());
                r.setCompletionFilter(this.filter);
                r.setNotifyFlags(this.recursive ? Smb2ChangeNotifyRequest.SMB2_WATCH_TREE : 0);
                req = r;
            } else {
                if (!th.hasCapability(SmbConstants.CAP_NT_SMBS)) {
                    throw new SmbUnsupportedOperationException("Not supported without CAP_NT_SMBS");
                }

                /*
                 * NtTrans Notify Change Request / Response
                 */
                req = new NtTransNotifyChange(th.getConfig(), this.handle.getFid(), this.filter, this.recursive);
                resp = new NtTransNotifyChangeResponse(th.getConfig());
            }

            if (log.isTraceEnabled()) {
                log.trace("Sending NtTransNotifyChange for " + this.handle);
            }
            try {
                resp = th.send(req, resp, RequestParam.NO_TIMEOUT, RequestParam.NO_RETRY);
            } catch (final SmbException e) {
                if (e.getNtStatus() == 0xC0000120) {
                    // cancelled
                    log.debug("Request was cancelled", e);
                    return null;
                }
                throw e;
            }
            if (log.isTraceEnabled()) {
                log.trace("Returned from NtTransNotifyChange " + resp.getErrorCode());
            }

            if (!resp.isReceived()) {
                throw new CIFSException("Did not receive response");
            }

            if (resp.getErrorCode() == 0x10B) {
                this.handle.markClosed();
            }
            if (resp.getErrorCode() == 0x10C) {
                resp.getNotifyInformation().clear();
            }
            return resp.getNotifyInformation();
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbWatchHandle#call()
     */
    @Override
    public List<FileNotifyInformation> call() throws CIFSException {
        return watch();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbWatchHandle#close()
     */
    @Override
    public void close() throws CIFSException {
        if (this.handle.isValid()) {
            this.handle.close(0L);
        }
    }
}
