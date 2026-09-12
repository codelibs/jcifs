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
package org.codelibs.jcifs.smb.internal.smb2.lock;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateRequest;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Oplock Break Acknowledgment, MS-SMB2 2.2.24.1.
 *
 * <p>
 * Answers an oplock break notification, telling the server which oplock level the client is keeping. The
 * acknowledgement travels on the same command as the notification, SMB2_OPLOCK_BREAK, and carries the file id of the
 * open being broken; its header has to name the session and tree of that open, which is why the open is looked up
 * rather than taken from the notification's own header (MS-SMB2 3.2.5.19.1).
 * </p>
 */
public class Smb2OplockBreakAcknowledgment extends ServerMessageBlock2Request<Smb2OplockBreakResponse> {

    private static final int STRUCTURE_SIZE = 24;

    private final byte[] fileId;
    private final byte oplockLevel;

    /**
     * Constructs an acknowledgement for a broken oplock.
     *
     * @param config      the configuration to use
     * @param fileId      the 16 byte file id of the open being broken
     * @param oplockLevel the oplock level the client keeps, one of the {@code SMB2_OPLOCK_LEVEL_*} values
     */
    public Smb2OplockBreakAcknowledgment(final Configuration config, final byte[] fileId, final byte oplockLevel) {
        super(config, SMB2_OPLOCK_BREAK);
        this.fileId = fileId;
        this.oplockLevel = oplockLevel;
    }

    /**
     * Whether a break of an open holding {@code currentOplockLevel} down to {@code newOplockLevel} has to be
     * acknowledged.
     *
     * <p>
     * A break from level II always transitions to none, so MS-SMB2 2.2.24.1 has the client make that transition
     * without telling the server: "there is no question how the transition was made". Answering one anyway is
     * refused - Samba does not arm its acknowledgement timer for a level II break. An open that holds no oplock has
     * nothing to give up either.
     * </p>
     *
     * @param currentOplockLevel the level the open holds
     * @param newOplockLevel     the level the server is breaking to
     * @return true when an acknowledgement has to be sent
     */
    public static boolean isRequired(final byte currentOplockLevel, final byte newOplockLevel) {
        if (currentOplockLevel == Smb2CreateRequest.SMB2_OPLOCK_LEVEL_NONE
                || currentOplockLevel == Smb2CreateRequest.SMB2_OPLOCK_LEVEL_II) {
            // Nothing is held, or a level II oplock is held and the only break it can take is to none, which
            // 2.2.24.1 says is made without telling the server.
            return false;
        }
        // Only an exclusive or batch oplock is left, and only a break that actually lowers it is one. Answering a
        // level the server did not break to would be refused: 2.2.24.1 allows none and level II only.
        return newOplockLevel != currentOplockLevel;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request#createResponse(org.codelibs.jcifs.smb.CIFSContext,
     *      org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request)
     */
    @Override
    protected Smb2OplockBreakResponse createResponse(final CIFSContext tc, final ServerMessageBlock2Request<Smb2OplockBreakResponse> req) {
        return new Smb2OplockBreakResponse(tc.getConfig());
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size() {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + STRUCTURE_SIZE);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        SMBUtil.writeInt2(STRUCTURE_SIZE, dst, dstIndex);
        dst[dstIndex + 2] = this.oplockLevel;
        dst[dstIndex + 3] = 0; // Reserved
        SMBUtil.writeInt4(0, dst, dstIndex + 4); // Reserved2
        System.arraycopy(this.fileId, 0, dst, dstIndex + 8, 16);
        return STRUCTURE_SIZE;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }
}
