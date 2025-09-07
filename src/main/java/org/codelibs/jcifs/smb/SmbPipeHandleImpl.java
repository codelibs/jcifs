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

import java.io.IOException;

import org.codelibs.jcifs.smb.internal.smb1.trans.TransCallNamedPipe;
import org.codelibs.jcifs.smb.internal.smb1.trans.TransCallNamedPipeResponse;
import org.codelibs.jcifs.smb.internal.smb1.trans.TransTransactNamedPipe;
import org.codelibs.jcifs.smb.internal.smb1.trans.TransTransactNamedPipeResponse;
import org.codelibs.jcifs.smb.internal.smb1.trans.TransWaitNamedPipe;
import org.codelibs.jcifs.smb.internal.smb1.trans.TransWaitNamedPipeResponse;
import org.codelibs.jcifs.smb.internal.smb2.ioctl.Smb2IoctlRequest;
import org.codelibs.jcifs.smb.internal.smb2.ioctl.Smb2IoctlResponse;
import org.codelibs.jcifs.smb.util.ByteEncodable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author mbechler
 *
 */
class SmbPipeHandleImpl implements SmbPipeHandleInternal {

    private static final Logger log = LoggerFactory.getLogger(SmbPipeHandleImpl.class);

    private final SmbNamedPipe pipe;
    private final boolean transact;
    private final boolean call;

    private final int openFlags;
    private final int access;
    private volatile boolean open = true;

    private SmbFileHandleImpl handle;
    private SmbPipeOutputStream output;
    private SmbPipeInputStream input;

    private final String uncPath;

    private SmbTreeHandleImpl treeHandle;

    private final int sharing = SmbConstants.DEFAULT_SHARING;

    /**
     * @param pipe
     */
    public SmbPipeHandleImpl(final SmbNamedPipe pipe) {
        this.pipe = pipe;
        this.transact = (pipe.getPipeType() & SmbPipeResource.PIPE_TYPE_TRANSACT) == SmbPipeResource.PIPE_TYPE_TRANSACT;
        this.call = (pipe.getPipeType() & SmbPipeResource.PIPE_TYPE_CALL) == SmbPipeResource.PIPE_TYPE_CALL;
        this.openFlags = pipe.getPipeType() & 0xFFFF00FF | SmbConstants.O_EXCL;
        this.access = pipe.getPipeType() & 7 | 0x20000;
        this.uncPath = this.pipe.getUncPath();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbPipeHandle#unwrap(java.lang.Class)
     */
    @SuppressWarnings("unchecked")
    @Override
    public <T extends SmbPipeHandle> T unwrap(final Class<T> type) {
        if (type.isAssignableFrom(this.getClass())) {
            return (T) this;
        }
        throw new ClassCastException();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbPipeHandle#getPipe()
     */
    @Override
    public SmbNamedPipe getPipe() {
        return this.pipe;
    }

    @Override
    public SmbTreeHandleImpl ensureTreeConnected() throws CIFSException {
        if (this.treeHandle == null) {
            // extra acquire to keep the tree alive
            this.treeHandle = this.pipe.ensureTreeConnected();
        }
        return this.treeHandle.acquire();
    }

    public String getUncPath() {
        return this.uncPath;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbPipeHandle#isOpen()
     */
    @Override
    public boolean isOpen() {
        // Use local copy to avoid race conditions with volatile field
        final boolean currentlyOpen = this.open;
        final SmbFileHandleImpl currentHandle = this.handle;
        return currentlyOpen && currentHandle != null && currentHandle.isValid();
    }

    /**
     *
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbPipeHandleInternal#getSessionKey()
     */
    @Override
    public byte[] getSessionKey() throws CIFSException {
        try (SmbTreeHandleImpl th = ensureTreeConnected(); SmbSessionImpl sess = th.getSession()) {
            return sess.getSessionKey();
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbPipeHandle#isStale()
     */
    @Override
    public boolean isStale() {
        // Use local copies to ensure consistent reads
        final boolean currentlyOpen = this.open;
        final SmbFileHandleImpl currentHandle = this.handle;
        return !currentlyOpen || (currentHandle != null && !currentHandle.isValid());
    }

    /**
     * Ensures that the pipe handle is open and ready for use.
     * This method is thread-safe and handles concurrent access properly.
     *
     * @return an acquired file handle for the pipe
     * @throws SmbException if the pipe is closed or cannot be opened
     * @throws CIFSException if there's an error establishing the connection
     */
    @Override
    public synchronized SmbFileHandleImpl ensureOpen() throws CIFSException {
        if (!this.open) {
            throw new SmbException("Pipe handle already closed");
        }

        // Check if we need to open the pipe
        final SmbFileHandleImpl currentHandle = this.handle;
        if (currentHandle == null || !currentHandle.isValid()) {
            try (SmbTreeHandleImpl th = ensureTreeConnected()) {
                log.debug("Opening pipe handle for {}", this.uncPath);

                SmbFileHandleImpl newHandle;
                if (th.isSMB2()) {
                    newHandle = this.pipe.openUnshared(this.uncPath, 0, this.access, this.sharing, SmbConstants.ATTR_NORMAL, 0);
                } else {
                    // SMB1 path
                    // Wait for named pipe availability - called when pipe is not immediately available
                    if (this.uncPath.startsWith("\\pipe\\")) {
                        th.send(new TransWaitNamedPipe(th.getConfig(), this.uncPath), new TransWaitNamedPipeResponse(th.getConfig()));
                    }

                    if (th.hasCapability(SmbConstants.CAP_NT_SMBS) || this.uncPath.startsWith("\\pipe\\")) {
                        newHandle = this.pipe.openUnshared(this.openFlags, this.access, this.sharing, SmbConstants.ATTR_NORMAL, 0);
                    } else {
                        // at least on samba, SmbComOpenAndX fails without the pipe prefix
                        newHandle = this.pipe.openUnshared("\\pipe" + getUncPath(), this.openFlags, this.access, this.sharing,
                                SmbConstants.ATTR_NORMAL, 0);
                    }
                }

                // Update the handle reference atomically
                this.handle = newHandle;

                // Return an acquired handle to keep it alive
                return newHandle.acquire();
            }
        } else {
            log.trace("Pipe already open");
            return currentHandle.acquire();
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbPipeHandle#getInput()
     */
    @Override
    public SmbPipeInputStream getInput() throws CIFSException {

        if (!this.open) {
            throw new SmbException("Already closed");
        }

        if (this.input != null) {
            return this.input;
        }

        try (SmbTreeHandleImpl th = ensureTreeConnected()) {
            this.input = new SmbPipeInputStream(this, th);
        }
        return this.input;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbPipeHandle#getOutput()
     */
    @Override
    public SmbPipeOutputStream getOutput() throws CIFSException {
        if (!this.open) {
            throw new SmbException("Already closed");
        }

        if (this.output != null) {
            return this.output;
        }

        try (SmbTreeHandleImpl th = ensureTreeConnected()) {
            this.output = new SmbPipeOutputStream(this, th);
        }
        return this.output;
    }

    /**
     *
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbPipeHandleInternal#sendrecv(byte[], int, int, byte[], int)
     */
    @SuppressWarnings("resource")
    @Override
    public int sendrecv(final byte[] buf, final int off, final int length, final byte[] inB, final int maxRecvSize) throws IOException {
        try (SmbFileHandleImpl fh = ensureOpen(); SmbTreeHandleImpl th = fh.getTree()) {

            if (th.isSMB2()) {
                final Smb2IoctlRequest req =
                        new Smb2IoctlRequest(th.getConfig(), Smb2IoctlRequest.FSCTL_PIPE_TRANSCEIVE, fh.getFileId(), inB);
                req.setFlags(Smb2IoctlRequest.SMB2_O_IOCTL_IS_FSCTL);
                req.setInputData(new ByteEncodable(buf, off, length));
                req.setMaxOutputResponse(maxRecvSize);
                final Smb2IoctlResponse resp = th.send(req, RequestParam.NO_RETRY);
                return resp.getOutputLength();
            }
            if (this.transact) {
                final TransTransactNamedPipe req = new TransTransactNamedPipe(th.getConfig(), fh.getFid(), buf, off, length);
                final TransTransactNamedPipeResponse resp = new TransTransactNamedPipeResponse(th.getConfig(), inB);
                if ((getPipeType() & SmbPipeResource.PIPE_TYPE_DCE_TRANSACT) == SmbPipeResource.PIPE_TYPE_DCE_TRANSACT) {
                    req.setMaxDataCount(1024);
                }
                th.send(req, resp, RequestParam.NO_RETRY);
                return resp.getResponseLength();
            }
            if (this.call) {
                th.send(new TransWaitNamedPipe(th.getConfig(), this.uncPath), new TransWaitNamedPipeResponse(th.getConfig()));
                final TransCallNamedPipeResponse resp = new TransCallNamedPipeResponse(th.getConfig(), inB);
                th.send(new TransCallNamedPipe(th.getConfig(), this.uncPath, buf, off, length), resp);
                return resp.getResponseLength();
            }
            final SmbPipeOutputStream out = getOutput();
            final SmbPipeInputStream in = getInput();
            out.write(buf, off, length);
            return in.read(inB);
        }
    }

    @Override
    public int recv(final byte[] buf, final int off, final int len) throws IOException {
        return getInput().readDirect(buf, off, len);

    }

    @Override
    public void send(final byte[] buf, final int off, final int length) throws IOException {
        getOutput().writeDirect(buf, off, length, 1);
    }

    /**
     *
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbPipeHandleInternal#getPipeType()
     */
    @Override
    public int getPipeType() {
        return this.pipe.getPipeType();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SmbPipeHandle#close()
     */
    @Override
    public synchronized void close() throws CIFSException {
        if (!this.open) {
            log.debug("Pipe handle already closed: {}", this.uncPath);
            return; // Already closed
        }

        log.debug("Closing pipe handle: {}", this.uncPath);

        // Mark as closed first to prevent new operations
        this.open = false;

        CIFSException closeException = null;

        try {
            // Close input stream
            if (this.input != null) {
                try {
                    this.input.close();
                } catch (Exception e) {
                    log.warn("Error closing pipe input stream", e);
                    if (closeException == null && e instanceof CIFSException) {
                        closeException = (CIFSException) e;
                    }
                } finally {
                    this.input = null;
                }
            }

            // Close output stream
            if (this.output != null) {
                try {
                    this.output.close();
                } catch (Exception e) {
                    log.warn("Error closing pipe output stream", e);
                    if (closeException == null && e instanceof CIFSException) {
                        closeException = (CIFSException) e;
                    }
                } finally {
                    this.output = null;
                }
            }

            // Close or release the file handle
            final SmbFileHandleImpl currentHandle = this.handle;
            if (currentHandle != null) {
                try {
                    if (currentHandle.isValid()) {
                        currentHandle.close();
                    } else {
                        currentHandle.release();
                    }
                } catch (Exception e) {
                    log.warn("Error closing pipe file handle", e);
                    if (closeException == null && e instanceof CIFSException) {
                        closeException = (CIFSException) e;
                    }
                } finally {
                    this.handle = null;
                }
            }
        } finally {
            // Always release tree handle
            if (this.treeHandle != null) {
                try {
                    this.treeHandle.release();
                } catch (Exception e) {
                    log.warn("Error releasing tree handle", e);
                    if (closeException == null && e instanceof CIFSException) {
                        closeException = (CIFSException) e;
                    }
                } finally {
                    this.treeHandle = null;
                }
            }
        }

        // Re-throw the first exception encountered, if any
        if (closeException != null) {
            throw closeException;
        }
    }

}
