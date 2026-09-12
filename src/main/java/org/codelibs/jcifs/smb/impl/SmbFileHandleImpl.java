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

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.SmbFileHandle;
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

    /**
     * The session this open is registered with, or null when it is not registered.
     *
     * <p>
     * Only an open that is in its session's table can be found again from an oplock break, which names nothing but
     * the file id. Handles built without a session - every SMB1 handle, and anything that does not go through
     * {@link #registerWith(SmbSessionImpl)} - simply never appear there.
     * </p>
     */
    private volatile SmbSessionImpl registeredSession;

    /** The oplock level the server granted, {@code SMB2_OPLOCK_LEVEL_NONE} when none was asked for. */
    private volatile byte oplockLevel;

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
     * @throws SmbException
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
     * @throws SmbException
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
            unregister();
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
     * @throws SmbException
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
        if (this.usageCount.get() != 0 && this.open) {
            log.warn("File handle was not properly closed: " + this);
            if (this.creationBacktrace != null) {
                log.warn(Arrays.toString(this.creationBacktrace));
            }
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
        unregister();
        this.open = false;
    }

    /**
     * Adds this open to its session's open table, so that an oplock break naming its file id can be resolved back to
     * it.
     *
     * <p>
     * Only SMB2 opens are registered; an SMB1 handle has no file id for a break to name.
     * </p>
     *
     * @param session the session this open belongs to
     */
    void registerWith(final SmbSessionImpl session, final byte grantedOplockLevel) {
        if (session == null || this.fileId == null) {
            return;
        }
        this.oplockLevel = grantedOplockLevel;
        this.registeredSession = session;
        session.registerOpen(this.fileId, this);
    }

    /**
     * The oplock level the server granted this open, which decides whether a break of it has to be acknowledged.
     *
     * @return the granted oplock level, {@code SMB2_OPLOCK_LEVEL_NONE} unless an oplock was asked for and granted
     */
    byte getOplockLevel() {
        return this.oplockLevel;
    }

    /**
     * Whether this open holds an oplock at all.
     *
     * @return true when the server granted one and it has not been given up
     */
    boolean hasOplock() {
        return this.oplockLevel != 0; // SMB2_OPLOCK_LEVEL_NONE
    }

    /**
     * Records the level a break left this open at, so that a further break of it is answered - or not - on what it
     * actually holds now.
     *
     * @param oplockLevel the level the open now holds
     */
    void setOplockLevel(final byte oplockLevel) {
        this.oplockLevel = oplockLevel;
    }

    /**
     * Gives up any oplock on this open. MS-SMB2 3.2.5.19.3: an acknowledgement the server refuses leaves the open
     * holding nothing.
     */
    void dropOplock() {
        this.oplockLevel = 0; // SMB2_OPLOCK_LEVEL_NONE
    }

    /**
     * Takes this open back out of its session's open table. Doing nothing for a handle that was never registered is
     * what keeps this off the SMB1 path.
     */
    private void unregister() {
        final SmbSessionImpl session = this.registeredSession;
        if (session != null) {
            this.registeredSession = null;
            session.unregisterOpen(this.fileId);
        }
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
