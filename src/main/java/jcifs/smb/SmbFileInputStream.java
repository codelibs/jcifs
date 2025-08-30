/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.MalformedURLException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbConstants;
import jcifs.SmbFileHandle;
import jcifs.internal.smb1.com.SmbComReadAndX;
import jcifs.internal.smb1.com.SmbComReadAndXResponse;
import jcifs.internal.smb2.io.Smb2ReadRequest;
import jcifs.internal.smb2.io.Smb2ReadResponse;
import jcifs.util.transport.TransportException;

/**
 * This InputStream can read bytes from a file on an SMB file server. Offsets are 64 bits.
 */
public class SmbFileInputStream extends InputStream {

    private static final Logger log = LoggerFactory.getLogger(SmbFileInputStream.class);

    private SmbFileHandleImpl handle;
    private long fp;
    private int readSize, readSizeFile, openFlags, access, sharing;
    private byte[] tmp = new byte[1];

    SmbFile file;

    private boolean largeReadX;

    private final boolean unsharedFile;

    private boolean smb2;

    /**
     * Creates an input stream for reading from the specified SMB URL
     *
     * @param url the SMB URL to read from
     * @param tc
     *            context to use
     * @throws SmbException if an SMB error occurs
     * @throws MalformedURLException if the URL is malformed
     */
    @SuppressWarnings("resource")
    public SmbFileInputStream(final String url, final CIFSContext tc) throws SmbException, MalformedURLException {
        this(new SmbFile(url, tc), 0, SmbConstants.O_RDONLY, SmbConstants.DEFAULT_SHARING, true);
    }

    /**
     * Creates an {@link java.io.InputStream} for reading bytes from a file on
     * an SMB server represented by the {@link jcifs.smb.SmbFile} parameter. See
     * {@link jcifs.smb.SmbFile} for a detailed description and examples of
     * the smb URL syntax.
     *
     * @param file
     *            An <code>SmbFile</code> specifying the file to read from
     * @throws SmbException if an SMB error occurs
     */
    public SmbFileInputStream(final SmbFile file) throws SmbException {
        this(file, 0, SmbConstants.O_RDONLY, SmbConstants.DEFAULT_SHARING, false);
    }

    SmbFileInputStream(final SmbFile file, final int openFlags, final int access, final int sharing, final boolean unshared)
            throws SmbException {
        this.file = file;
        this.unsharedFile = unshared;
        this.openFlags = openFlags;
        this.access = access;
        this.sharing = sharing;

        try (SmbTreeHandleInternal th = file.ensureTreeConnected()) {
            this.smb2 = th.isSMB2();
            if (file.getType() != SmbConstants.TYPE_NAMED_PIPE) {
                try (SmbFileHandle h = ensureOpen()) {}
                this.openFlags &= ~(SmbConstants.O_CREAT | SmbConstants.O_TRUNC);
            }

            init(th);
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    /**
     * @throws SmbException
     *
     */
    SmbFileInputStream(final SmbFile file, final SmbTreeHandleImpl th, final SmbFileHandleImpl fh) throws SmbException {
        this.file = file;
        this.handle = fh;
        this.unsharedFile = false;
        this.smb2 = th.isSMB2();
        try {
            init(th);
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    /**
     * @param f
     * @param th
     * @throws SmbException
     */
    private void init(final SmbTreeHandleInternal th) throws CIFSException {
        if (this.smb2) {
            this.readSize = th.getReceiveBufferSize();
            this.readSizeFile = th.getReceiveBufferSize();
            return;
        }

        this.readSize = Math.min(th.getReceiveBufferSize() - 70, th.getMaximumBufferSize() - 70);

        if (th.hasCapability(SmbConstants.CAP_LARGE_READX)) {
            this.largeReadX = true;
            this.readSizeFile =
                    Math.min(th.getConfig().getReceiveBufferSize() - 70, th.areSignaturesActive() ? 0xFFFF - 70 : 0xFFFFFF - 70);
            log.debug("Enabling LARGE_READX with " + this.readSizeFile);
        } else {
            log.debug("LARGE_READX disabled");
            this.readSizeFile = this.readSize;
        }

        if (log.isDebugEnabled()) {
            log.debug("Negotiated file read size is " + this.readSizeFile);
        }
    }

    /**
     * Ensures that the file descriptor is openend
     *
     * @throws CIFSException if an error occurs while opening the file
     */
    public void open() throws CIFSException {
        try (SmbFileHandleImpl fh = ensureOpen()) {}
    }

    /**
     * @param file
     * @param openFlags
     * @return
     * @throws SmbException
     */
    synchronized SmbFileHandleImpl ensureOpen() throws CIFSException {
        if (this.handle == null || !this.handle.isValid()) {
            // one extra acquire to keep this open till the stream is released
            if (this.file instanceof SmbNamedPipe) {
                this.handle = this.file.openUnshared(SmbConstants.O_EXCL, ((SmbNamedPipe) this.file).getPipeType() & 0xFF0000, this.sharing,
                        SmbConstants.ATTR_NORMAL, 0);
            } else {
                this.handle = this.file.openUnshared(this.openFlags, this.access, this.sharing, SmbConstants.ATTR_NORMAL, 0).acquire();
            }
            return this.handle;
        }
        return this.handle.acquire();
    }

    /**
     * Converts an SmbException to an IOException
     *
     * @param se the SmbException to convert
     * @return an IOException wrapping the SmbException
     */
    protected static IOException seToIoe(final SmbException se) {
        IOException ioe = se;
        Throwable root = se.getCause();
        if (root instanceof TransportException) {
            ioe = (TransportException) root;
            root = ioe.getCause();
        }
        if (root instanceof InterruptedException) {
            ioe = new InterruptedIOException(root.getMessage());
            ioe.initCause(root);
        }
        return ioe;
    }

    /**
     * Closes this input stream and releases any system resources associated with the stream.
     *
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public void close() throws IOException {
        try {
            final SmbFileHandleImpl h = this.handle;
            if (h != null) {
                h.close();
            }
        } catch (final SmbException se) {
            throw seToIoe(se);
        } finally {
            this.tmp = null;
            this.handle = null;
            if (this.unsharedFile) {
                this.file.close();
            }
        }
    }

    /**
     * Reads a byte of data from this input stream.
     *
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public int read() throws IOException {
        // need oplocks to cache otherwise use BufferedInputStream
        if (read(this.tmp, 0, 1) == -1) {
            return -1;
        }
        return this.tmp[0] & 0xFF;
    }

    /**
     * Reads up to b.length bytes of data from this input stream into an array of bytes.
     *
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public int read(final byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    /**
     * Reads up to len bytes of data from this input stream into an array of bytes.
     *
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException {
        return readDirect(b, off, len);
    }

    /**
     * Reads up to len bytes of data from this input stream into an array of bytes.
     * Optimized for better performance with larger read sizes and reduced round trips.
     *
     * @param b the buffer to read into
     * @param off the offset in the buffer to start writing
     * @param len the maximum number of bytes to read
     * @return number of bytes read
     *
     * @throws IOException
     *             if a network error occurs
     */
    public int readDirect(final byte[] b, int off, int len) throws IOException {
        if (len <= 0) {
            return 0;
        }
        final long start = this.fp;

        if (this.tmp == null) {
            throw new IOException("Bad file descriptor");
        }
        // ensure file is open
        try (SmbFileHandleImpl fd = ensureOpen(); SmbTreeHandleImpl th = fd.getTree()) {

            if (log.isTraceEnabled()) {
                log.trace("read: fid=" + fd + ",off=" + off + ",len=" + len);
            }

            final int type = this.file.getType();
            int r, n;
            final int blockSize = type == SmbConstants.TYPE_FILESYSTEM ? this.readSizeFile : this.readSize;

            // Optimization: Use larger block sizes for better performance
            final int optimizedBlockSize = Math.min(blockSize * 2, 64 * 1024); // Cap at 64KB for memory efficiency
            final int effectiveBlockSize = Math.max(blockSize, optimizedBlockSize);

            SmbComReadAndXResponse response = null;
            if (!th.isSMB2()) {
                response = new SmbComReadAndXResponse(th.getConfig(), b, off);
            }

            do {
                r = len > effectiveBlockSize ? effectiveBlockSize : len;

                if (log.isTraceEnabled()) {
                    log.trace("read: len=" + len + ",r=" + r + ",fp=" + this.fp + ",effective_block=" + effectiveBlockSize);
                }

                try {
                    if (th.isSMB2()) {
                        final Smb2ReadRequest request = new Smb2ReadRequest(th.getConfig(), fd.getFileId(), b, off);
                        request.setOffset(type == SmbConstants.TYPE_NAMED_PIPE ? 0 : this.fp);
                        request.setReadLength(r);

                        // Optimization: Set remaining bytes hint for server read-ahead
                        request.setRemainingBytes(Math.min(len - r, 1024 * 1024)); // Hint up to 1MB for read-ahead

                        try {
                            final Smb2ReadResponse resp = th.send(request, RequestParam.NO_RETRY);
                            n = resp.getDataLength();
                        } catch (final SmbException e) {
                            if (e.getNtStatus() == 0xC0000011) { // NT_STATUS_END_OF_FILE
                                log.debug("Reached end of file", e);
                                n = -1;
                            } else {
                                throw e;
                            }
                        }
                        if (n <= 0) {
                            return (int) (this.fp - start > 0L ? this.fp - start : -1);
                        }
                        this.fp += n;
                        off += n;
                        len -= n;
                        continue;
                    }

                    // SMB1 path with optimization
                    final SmbComReadAndX request = new SmbComReadAndX(th.getConfig(), fd.getFid(), this.fp, r, null);

                    if (type == SmbConstants.TYPE_NAMED_PIPE) {
                        // Use fixed 1024 values for named pipes
                        request.setMinCount(1024);
                        request.setMaxCount(1024);
                        request.setRemaining(1024);
                    } else if (this.largeReadX) {
                        // Optimize large read requests
                        request.setMaxCount(r & 0xFFFF);
                        request.setOpenTimeout(r >> 16 & 0xFFFF);
                    }

                    th.send(request, response, RequestParam.NO_RETRY);
                    n = response.getDataLength();

                } catch (final SmbException se) {
                    if (type == SmbConstants.TYPE_NAMED_PIPE && se.getNtStatus() == NtStatus.NT_STATUS_PIPE_BROKEN) {
                        return -1;
                    }
                    throw seToIoe(se);
                }

                if (n <= 0) {
                    return (int) (this.fp - start > 0L ? this.fp - start : -1);
                }

                this.fp += n;
                len -= n;
                if (response != null) {
                    response.adjustOffset(n);
                }

            } while (len > effectiveBlockSize && n == r);

            // Optimization: Continue reading if we have small remaining data and got full blocks
            // This reduces round trips for slightly larger reads
            if (len > 0 && len <= (effectiveBlockSize / 4) && n == r) {
                try {
                    if (th.isSMB2()) {
                        final Smb2ReadRequest request = new Smb2ReadRequest(th.getConfig(), fd.getFileId(), b, off);
                        request.setOffset(type == SmbConstants.TYPE_NAMED_PIPE ? 0 : this.fp);
                        request.setReadLength(len);
                        request.setRemainingBytes(0);

                        final Smb2ReadResponse resp = th.send(request, RequestParam.NO_RETRY);
                        n = resp.getDataLength();
                        if (n > 0) {
                            this.fp += n;
                        }
                    } else {
                        final SmbComReadAndX smallRequest = new SmbComReadAndX(th.getConfig(), fd.getFid(), this.fp, len, null);
                        th.send(smallRequest, response, RequestParam.NO_RETRY);
                        n = response.getDataLength();
                        if (n > 0) {
                            this.fp += n;
                        }
                    }
                } catch (final SmbException se) {
                    // Ignore errors on the final small read - we already got substantial data
                    log.trace("Final small read failed, ignoring", se);
                }
            }

            return (int) (this.fp - start);
        }
    }

    /**
     * This stream class is unbuffered. Therefore this method will always
     * return 0 for streams connected to regular files. However, a
     * stream created from a Named Pipe this method will query the server using a
     * "peek named pipe" operation and return the number of available bytes
     * on the server.
     */
    @Override
    public int available() throws IOException {
        return 0;
    }

    /**
     * Skip n bytes of data on this stream. This operation will not result
     * in any IO with the server. Unlink <code>InputStream</code> value less than
     * the one provided will not be returned if it exceeds the end of the file
     * (if this is a problem let us know).
     */
    @Override
    public long skip(final long n) throws IOException {
        if (n > 0) {
            this.fp += n;
            return n;
        }
        return 0;
    }

}
