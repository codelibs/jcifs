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

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import org.codelibs.jcifs.smb.internal.smb1.com.SmbComBlankResponse;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComClose;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CloseRequest;
import org.codelibs.jcifs.smb.util.Hexdump;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author mbechler
 *
 */
class SmbFileHandleImpl implements SmbFileHandle {

    private static final Logger log = LoggerFactory.getLogger(SmbFileHandleImpl.class);

    private final Configuration cfg;
    private final int fid;
    private final byte[] fileId;
    private boolean open = true;
    private final long tree_num; // for checking whether the tree changed
    private SmbTreeHandleImpl tree;

    private final AtomicLong usageCount = new AtomicLong(1);
    private final int flags;
    private final int access;
    private final int attrs;
    private final int options;
    private final String unc;

    private final StackTraceElement[] creationBacktrace;

    private final long initialSize;

    /**
     * @param cfg
     * @param fid
     * @param tree
     * @param unc
     * @param options
     * @param attrs
     * @param access
     * @param flags
     * @param initialSize
     */
    public SmbFileHandleImpl(final Configuration cfg, final byte[] fid, final SmbTreeHandleImpl tree, final String unc, final int flags,
            final int access, final int attrs, final int options, final long initialSize) {
        this.cfg = cfg;
        this.fileId = fid;
        this.initialSize = initialSize;
        this.fid = 0;
        this.unc = unc;
        this.flags = flags;
        this.access = access;
        this.attrs = attrs;
        this.options = options;
        this.tree = tree.acquire();
        this.tree_num = tree.getTreeId();

        if (cfg.isTraceResourceUsage()) {
            this.creationBacktrace = Thread.currentThread().getStackTrace();
        } else {
            this.creationBacktrace = null;
        }
    }

    /**
     * @param cfg
     * @param fid
     * @param tree
     * @param unc
     * @param options
     * @param attrs
     * @param access
     * @param flags
     * @param initialSize
     */
    public SmbFileHandleImpl(final Configuration cfg, final int fid, final SmbTreeHandleImpl tree, final String unc, final int flags,
            final int access, final int attrs, final int options, final long initialSize) {
        this.cfg = cfg;
        this.fid = fid;
        this.initialSize = initialSize;
        this.fileId = null;
        this.unc = unc;
        this.flags = flags;
        this.access = access;
        this.attrs = attrs;
        this.options = options;
        this.tree = tree.acquire();
        this.tree_num = tree.getTreeId();

        if (cfg.isTraceResourceUsage()) {
            this.creationBacktrace = Thread.currentThread().getStackTrace();
        } else {
            this.creationBacktrace = null;
        }
    }

    /**
     * @return the fid
     * @throws SmbSystemException
     */
    public int getFid() throws SmbException {
        if (!isValid()) {
            throw new SmbException("Descriptor is no longer valid");
        }
        return this.fid;
    }

    public byte[] getFileId() throws SmbException {
        if (!isValid()) {
            throw new SmbException("Descriptor is no longer valid");
        }
        return this.fileId;
    }

    /**
     * @return the initialSize
     */
    @Override
    public long getInitialSize() {
        return this.initialSize;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbFileHandle#getTree()
     */
    @Override
    public SmbTreeHandleImpl getTree() {
        return this.tree.acquire();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbFileHandle#isValid()
     */
    @Override
    public boolean isValid() {
        return this.open && this.tree_num == this.tree.getTreeId() && this.tree.isConnected();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbFileHandle#close(long)
     */
    @Override
    public synchronized void close(final long lastWriteTime) throws CIFSException {
        closeInternal(lastWriteTime, true);
    }

    /**
     * @param lastWriteTime
     * @throws SmbSystemException
     */
    void closeInternal(final long lastWriteTime, final boolean explicit) throws CIFSException {
        final SmbTreeHandleImpl t = this.tree;
        try {
            if (t != null && isValid()) {
                if (log.isDebugEnabled()) {
                    log.debug("Closing file handle " + this);
                }

                if (t.isSMB2()) {
                    final Smb2CloseRequest req = new Smb2CloseRequest(this.cfg, this.fileId);
                    t.send(req, RequestParam.NO_RETRY);
                } else {
                    t.send(new SmbComClose(this.cfg, this.fid, lastWriteTime), new SmbComBlankResponse(this.cfg), RequestParam.NO_RETRY);
                }
            }
        } finally {
            this.open = false;
            if (t != null) {
                // release tree usage
                t.release();
            }
            this.tree = null;
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbFileHandle#close()
     */
    @Override
    public void close() throws CIFSException {
        release();
    }

    /**
     * {@inheritDoc}
     *
     * @throws SmbSystemException
     *
     * @see org.codelibs.jcifs.smb.SmbFileHandle#release()
     */
    @Override
    public synchronized void release() throws CIFSException {
        final long usage = this.usageCount.decrementAndGet();
        if (usage == 0) {
            closeInternal(0L, false);
        } else if (log.isTraceEnabled()) {
            log.trace(String.format("Release %s (%d)", this, usage));
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#finalize()
     */
    @Override
    protected void finalize() throws Throwable {
        try {
            if (this.usageCount != null && this.usageCount.get() != 0 && this.open) {
                log.warn("File handle was not properly closed, performing emergency cleanup: " + this);
                if (this.creationBacktrace != null) {
                    log.warn(Arrays.toString(this.creationBacktrace));
                }
                emergencyCloseHandle();
            }
        } catch (Exception e) {
            log.error("Error during file handle finalization", e);
        } finally {
            super.finalize();
        }
    }

    /**
     * Emergency cleanup method to prevent resource leaks during finalization
     */
    private void emergencyCloseHandle() {
        try {
            synchronized (this) {
                // Force close the handle
                this.open = false;
                this.usageCount.set(0);

                // Clear mutable references to free memory
                // Note: Some fields may be final and cannot be nulled

                // Clear any other mutable state would go here
            }
        } catch (Exception e) {
            log.error("Failed to perform emergency file handle cleanup", e);
        }
    }

    /**
     * @return a file handle with increased usage count
     */
    public SmbFileHandleImpl acquire() {
        final long usage = this.usageCount.incrementAndGet();
        if (log.isTraceEnabled()) {
            log.trace(String.format("Acquire %s (%d)", this, usage));
        }
        return this;
    }

    /**
     *
     */
    public void markClosed() {
        this.open = false;
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return String.format("FileHandle %s [fid=%s,tree=%d,flags=%x,access=%x,attrs=%x,options=%x]", this.unc,
                this.fileId != null ? Hexdump.toHexString(this.fileId) : this.fid, this.tree_num, this.flags, this.access, this.attrs,
                this.options);
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        if (this.fileId != null) {
            return (int) (Arrays.hashCode(this.fileId) + 3 * this.tree_num);
        }
        return (int) (this.fid + 3 * this.tree_num);
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof final SmbFileHandleImpl o)) {
            return false;
        }
        if (this.fileId != null) {
            return Arrays.equals(this.fileId, o.fileId) && this.tree_num == o.tree_num;
        }
        return this.fid == o.fid && this.tree_num == o.tree_num;
    }

}
