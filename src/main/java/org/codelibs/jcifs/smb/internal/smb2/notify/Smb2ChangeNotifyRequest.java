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
package org.codelibs.jcifs.smb.internal.smb2.notify;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Change Notify request message.
 *
 * This command is used to monitor a directory for changes
 * and receive notifications when modifications occur.
 *
 * @author mbechler
 */
public class Smb2ChangeNotifyRequest extends ServerMessageBlock2Request<Smb2ChangeNotifyResponse> {

    /**
     * Flag to watch the directory tree recursively
     */
    public static final int SMB2_WATCH_TREE = 0x1;

    /**
     * Notify when a file name changes
     */
    public static final int FILE_NOTIFY_CHANGE_FILE_NAME = 0x1;
    /**
     * Notify when a directory name changes
     */
    public static final int FILE_NOTIFY_CHANGE_DIR_NAME = 0x2;
    /**
     * Notify when file attributes change
     */
    public static final int FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x4;
    /**
     * Notify when file size changes
     */
    public static final int FILE_NOTIFY_CHANGE_SIZE = 0x8;
    /**
     * Notify when last write time changes
     */
    public static final int FILE_NOTIFY_CHANGE_LAST_WRITE = 0x10;
    /**
     * Notify when last access time changes
     */
    public static final int FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x20;
    /**
     * Notify when creation time changes
     */
    public static final int FILE_NOTIFY_CHANGE_CREATION = 0x40;
    /**
     * Notify when extended attributes change
     */
    public static final int FILE_NOTIFY_CHANGE_EA = 0x80;
    /**
     * Notify when security descriptor changes
     */
    public static final int FILE_NOTIFY_CHANGE_SECURITY = 0x100;
    /**
     * Notify when alternate data stream name changes
     */
    public static final int FILE_NOTIFY_CHANGE_STREAM_NAME = 0x200;
    /**
     * Notify when alternate data stream size changes
     */
    public static final int FILE_NOTIFY_CHANGE_STREAM_SIZE = 0x400;
    /**
     * Notify when alternate data stream is written
     */
    public static final int FILE_NOTIFY_CHANGE_STREAM_WRITE = 0x800;

    private final byte[] fileId;
    private final int outputBufferLength;
    private int notifyFlags;
    private int completionFilter;

    /**
     * Constructs a change notify request
     *
     * @param config
     *            The configuration to use
     * @param fileId
     *            The file ID to monitor for changes
     */
    public Smb2ChangeNotifyRequest(final Configuration config, final byte[] fileId) {
        super(config, SMB2_CHANGE_NOTIFY);
        this.outputBufferLength = config.getNotifyBufferSize();
        this.fileId = fileId;
    }

    /**
     * Set the notification flags
     *
     * @param notifyFlags
     *            the notifyFlags to set
     */
    public void setNotifyFlags(final int notifyFlags) {
        this.notifyFlags = notifyFlags;
    }

    /**
     * Set the completion filter specifying which changes to monitor
     *
     * @param completionFilter
     *            the completionFilter to set
     */
    public void setCompletionFilter(final int completionFilter) {
        this.completionFilter = completionFilter;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request#createResponse(org.codelibs.jcifs.smb.CIFSContext,
     *      org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request)
     */
    @Override
    protected Smb2ChangeNotifyResponse createResponse(final CIFSContext tc,
            final ServerMessageBlock2Request<Smb2ChangeNotifyResponse> req) {
        return new Smb2ChangeNotifyResponse(tc.getConfig());
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest#size()
     */
    @Override
    public int size() {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + 32);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        SMBUtil.writeInt2(32, dst, dstIndex);
        SMBUtil.writeInt2(this.notifyFlags, dst, dstIndex + 2);
        dstIndex += 4;

        SMBUtil.writeInt4(this.outputBufferLength, dst, dstIndex);
        dstIndex += 4;

        System.arraycopy(this.fileId, 0, dst, dstIndex, 16);
        dstIndex += 16;

        SMBUtil.writeInt4(this.completionFilter, dst, dstIndex);
        dstIndex += 4;
        dstIndex += 4; // Reserved
        return dstIndex - start;
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
