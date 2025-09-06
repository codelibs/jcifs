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
package org.codelibs.jcifs.smb.internal.smb2.lock;

import org.codelibs.jcifs.smb.Encodable;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Lock data structure.
 *
 * This class represents a single lock element used in
 * SMB2 Lock requests for byte-range locking.
 *
 * @author mbechler
 */
public class Smb2Lock implements Encodable {

    /**
     * Flag indicating a shared lock that allows concurrent read access.
     */
    public static final int SMB2_LOCKFLAG_SHARED_LOCK = 0x1;

    /**
     * Flag indicating an exclusive lock that prevents any other access.
     */
    public static final int SMB2_LOCKFLAG_EXCLUSIVE_LOCK = 0x2;

    /**
     * Flag indicating an unlock operation to release a previously held lock.
     */
    public static final int SMB2_LOCKFLAG_UNLOCK = 0x4;

    /**
     * Flag indicating the lock should fail immediately if it cannot be granted.
     */
    public static final int SMB2_LOCKFLAG_FAIL_IMMEDIATELY = 0x10;

    private final long offset;
    private final long length;
    private final int flags;

    /**
     * Constructs an SMB2 lock element with the specified parameters.
     *
     * @param offset the byte offset in the file where the lock begins
     * @param length the number of bytes to lock
     * @param flags the lock flags (combination of SMB2_LOCKFLAG_* constants)
     */
    public Smb2Lock(final long offset, final long length, final int flags) {
        this.offset = offset;
        this.length = length;
        this.flags = flags;

    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Encodable#size()
     */
    @Override
    public int size() {
        return 24;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.Encodable#encode(byte[], int)
     */
    @Override
    public int encode(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt8(this.offset, dst, dstIndex);
        dstIndex += 8;
        SMBUtil.writeInt8(this.length, dst, dstIndex);
        dstIndex += 8;

        SMBUtil.writeInt4(this.flags, dst, dstIndex);
        dstIndex += 4;
        dstIndex += 4; // Reserved
        return dstIndex - start;
    }

}
