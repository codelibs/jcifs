/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.codelibs.jcifs.smb.impl;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateRequest;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateResponse;

/**
 * Test-only way to hold a file open with an oplock.
 *
 * <p>
 * Nothing in jcifs asks for an oplock - every CREATE requests {@code SMB2_OPLOCK_LEVEL_NONE} - so a conforming
 * server never has a reason to send a break. This opens a file the way a client that wanted one would, which is what
 * makes a real break arrive. It lives in the implementation package because {@code SmbTreeHandleImpl} and
 * {@code SmbFileHandleImpl} are package private.
 * </p>
 */
public final class SmbOplockProbe implements AutoCloseable {

    private final SmbFileHandleImpl handle;
    private final byte grantedOplockLevel;

    private SmbOplockProbe(final SmbFileHandleImpl handle, final byte grantedOplockLevel) {
        this.handle = handle;
        this.grantedOplockLevel = grantedOplockLevel;
    }

    /**
     * Opens an existing file asking for the given oplock level, and keeps it open.
     *
     * @param file                 an existing file
     * @param requestedOplockLevel one of the {@code SMB2_OPLOCK_LEVEL_*} values
     * @return the open, which the caller closes
     * @throws CIFSException if the server refuses the open
     */
    public static SmbOplockProbe open(final SmbFile file, final byte requestedOplockLevel) throws CIFSException {
        try (SmbTreeHandleImpl th = (SmbTreeHandleImpl) file.getTreeHandle()) {
            if (!th.isSMB2()) {
                throw new IllegalStateException("Oplocks need an SMB2 connection");
            }
            final Smb2CreateRequest create = new Smb2CreateRequest(th.getConfig(), file.getUncPath());
            create.setDesiredAccess(SmbConstants.FILE_READ_DATA | SmbConstants.FILE_WRITE_DATA);
            create.setShareAccess(SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE);
            create.setCreateDisposition(Smb2CreateRequest.FILE_OPEN);
            create.setRequestedOplockLevel(requestedOplockLevel);

            final Smb2CreateResponse response = th.send(create);
            final SmbFileHandleImpl handle = new SmbFileHandleImpl(th.getConfig(), response.getFileId(), th, file.getUncPath(), 0,
                    SmbConstants.FILE_READ_DATA, 0, 0, response.getEndOfFile());
            // openUnshared() does this for every ordinary open; the probe builds its own CREATE, so it has to do it
            // itself or the break would name an open nothing can resolve.
            try (SmbSessionImpl session = th.getSession()) {
                handle.registerWith(session, response.getOplockLevel());
            }
            return new SmbOplockProbe(handle, response.getOplockLevel());
        }
    }

    /**
     * @return the oplock level the server actually granted, which may be lower than the one asked for
     */
    public byte grantedOplockLevel() {
        return this.grantedOplockLevel;
    }

    /**
     * The level this open holds now.
     *
     * <p>
     * A break moves it to the level the server broke to. An acknowledgement the server refuses moves it to
     * {@code SMB2_OPLOCK_LEVEL_NONE} instead, so this tells a refused acknowledgement apart from an accepted break to
     * level II - which timing alone cannot, because the server completes the break either way.
     * </p>
     *
     * @return the current oplock level of the open
     */
    public byte currentOplockLevel() {
        return this.handle.getOplockLevel();
    }

    @Override
    public void close() throws CIFSException {
        this.handle.close();
    }
}
