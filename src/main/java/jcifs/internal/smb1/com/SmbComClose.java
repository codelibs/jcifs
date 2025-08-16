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

package jcifs.internal.smb1.com;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.Request;
import jcifs.internal.smb1.SMB1SigningDigest;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.util.SMBUtil;

/**
 * SMB1 Close file request message.
 *
 * This command is used to close a file that was previously opened
 * with an Open command.
 */
public class SmbComClose extends ServerMessageBlock implements Request<SmbComBlankResponse> {

    private static final Logger log = LoggerFactory.getLogger(SmbComClose.class);

    private final int fid;
    private final long lastWriteTime;

    /**
     * Creates a new SMB1 close file request.
     *
     * @param config the CIFS configuration
     * @param fid the file identifier to close
     * @param lastWriteTime the last write time to set on the file
     */
    public SmbComClose(final Configuration config, final int fid, final long lastWriteTime) {
        super(config, SMB_COM_CLOSE);
        this.fid = fid;
        this.lastWriteTime = lastWriteTime;
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb1.ServerMessageBlock#getResponse()
     */
    @Override
    public final SmbComBlankResponse getResponse() {
        return (SmbComBlankResponse) super.getResponse();
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.Request#initResponse(jcifs.CIFSContext)
     */
    @Override
    public SmbComBlankResponse initResponse(final CIFSContext tc) {
        final SmbComBlankResponse resp = new SmbComBlankResponse(tc.getConfig());
        setResponse(resp);
        return resp;
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, int dstIndex) {
        SMBUtil.writeInt2(this.fid, dst, dstIndex);
        dstIndex += 2;
        if (this.digest != null) {
            SMB1SigningDigest.writeUTime(getConfig(), this.lastWriteTime, dst, dstIndex);
        } else {
            log.trace("SmbComClose without a digest");
        }
        return 6;
    }

    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int readParameterWordsWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

    @Override
    protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
        return 0;
    }

    @Override
    public String toString() {
        return ("SmbComClose[" + super.toString() + ",fid=" + this.fid + ",lastWriteTime=" + this.lastWriteTime + "]");
    }
}
