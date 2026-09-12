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

import java.io.DataInput;
import java.io.DataOutput;

import org.codelibs.jcifs.smb.impl.SmbException;

/**
 * File access that exposes random access semantics
 *
 * @author mbechler
 *
 */
public interface SmbRandomAccess extends DataOutput, DataInput, AutoCloseable {

    /**
     * Close the file
     *
     * @throws SmbException if an I/O error occurs during close
     */
    @Override
    void close() throws SmbException;

    /**
     * Read a single byte from the current position
     *
     * @return read byte, -1 if EOF
     * @throws SmbException if an I/O error occurs during read
     */
    int read() throws SmbException;

    /**
     * Read into buffer from current position
     *
     * @param b
     *            buffer
     * @return number of bytes read
     * @throws SmbException if an I/O error occurs during read
     */
    int read(byte[] b) throws SmbException;

    /**
     * Read into buffer from current position
     *
     * @param b
     *            buffer
     * @param off
     *            offset into buffer
     * @param len
     *            read up to <code>len</code> bytes
     * @return number of bytes read
     * @throws SmbException if an I/O error occurs during read
     */
    int read(byte[] b, int off, int len) throws SmbException;

    /**
     * Current position in file
     *
     * @return current position
     */
    long getFilePointer();

    /**
     * Seek to new position
     *
     * @param pos the new position to seek to
     */
    void seek(long pos);

    /**
     * Get the current file length
     *
     * @return file length
     * @throws SmbException if an I/O error occurs
     */
    long length() throws SmbException;

    /**
     * Expand/truncate file length
     *
     * @param newLength
     *            new file length
     * @throws SmbException if an I/O error occurs
     */
    void setLength(long newLength) throws SmbException;

    /**
     * Lock a range of bytes, waiting for it if another open holds it
     *
     * A lock belongs to the open it was taken on, so ranges locked through this instance never conflict with each
     * other, only with locks taken elsewhere. Requires SMB2 or later.
     *
     * @param position
     *            first byte of the range
     * @param size
     *            number of bytes to lock
     * @param shared
     *            take a shared lock, which other shared locks of the same range are allowed alongside, rather than
     *            an exclusive one
     * @throws SmbException if the lock cannot be taken
     */
    void lock(long position, long size, boolean shared) throws SmbException;

    /**
     * Lock a range of bytes, giving up at once if another open holds it
     *
     * Unlike {@link #lock(long, long, boolean)} this never waits: a range that is held is reported rather than
     * queued for. Requires SMB2 or later.
     *
     * @param position
     *            first byte of the range
     * @param size
     *            number of bytes to lock
     * @param shared
     *            take a shared lock rather than an exclusive one
     * @return whether the lock was taken
     * @throws SmbException if the attempt fails for any reason other than the range being held
     */
    boolean tryLock(long position, long size, boolean shared) throws SmbException;

    /**
     * Release a range locked earlier
     *
     * The range has to be one that was locked: a server matches an unlock against the ranges it recorded, not
     * against whatever bytes happen to overlap. Requires SMB2 or later.
     *
     * @param position
     *            first byte of the range, as it was given to the lock
     * @param size
     *            number of bytes, as it was given to the lock
     * @throws SmbException if the range was not locked or the unlock fails
     */
    void unlock(long position, long size) throws SmbException;

}
