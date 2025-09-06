/*
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

package org.codelibs.jcifs.smb.internal.smb1.com;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.internal.Request;
import org.codelibs.jcifs.smb.internal.smb1.AndXServerMessageBlock;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Hexdump;

/**
 * SMB1 NT Create AndX request message.
 *
 * This command is used to create or open a file with extended
 * capabilities including security descriptors and oplock support.
 */
public class SmbComNTCreateAndX extends AndXServerMessageBlock implements Request<SmbComNTCreateAndXResponse> {

    // share access specified in SmbFile

    // create disposition

    /*
     * Creates a new file or supersedes the existing one
     */

    static final int FILE_SUPERSEDE = 0x0;

    /*
     * Open the file or fail if it does not exist
     * aka OPEN_EXISTING
     */

    static final int FILE_OPEN = 0x1;

    /*
     * Create the file or fail if it does not exist
     * aka CREATE_NEW
     */

    static final int FILE_CREATE = 0x2;

    /*
     * Open the file or create it if it does not exist
     * aka OPEN_ALWAYS
     */

    static final int FILE_OPEN_IF = 0x3;

    /*
     * Open the file and overwrite it's contents or fail if it does not exist
     * aka TRUNCATE_EXISTING
     */

    static final int FILE_OVERWRITE = 0x4;

    /*
     * Open the file and overwrite it's contents or create it if it does not exist
     * aka CREATE_ALWAYS (according to the wire when calling CreateFile)
     */

    static final int FILE_OVERWRITE_IF = 0x5;

    // create options
    static final int FILE_WRITE_THROUGH = 0x00000002;
    static final int FILE_SEQUENTIAL_ONLY = 0x00000004;
    static final int FILE_SYNCHRONOUS_IO_ALERT = 0x00000010;
    static final int FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;

    // security flags
    static final int SECURITY_CONTEXT_TRACKING = 0x01;
    static final int SECURITY_EFFECTIVE_ONLY = 0x02;

    private int rootDirectoryFid;

    private final int extFileAttributes;

    private final int shareAccess;

    private int createDisposition;

    private int createOptions;

    private final int impersonationLevel;
    private long allocationSize;
    private final byte securityFlags;
    private int namelen_index;

    private int flags0, desiredAccess;

    /**
     * Constructs an NT Create AndX request.
     *
     * @param config the configuration
     * @param name the file name to create or open
     * @param flags the file open flags (O_CREAT, O_EXCL, O_TRUNC)
     * @param access the desired access rights
     * @param shareAccess the share access mode
     * @param extFileAttributes the extended file attributes
     * @param createOptions the create options
     * @param andx the next command in the chain
     */
    public SmbComNTCreateAndX(final Configuration config, final String name, final int flags, final int access, final int shareAccess,
            final int extFileAttributes, final int createOptions, final ServerMessageBlock andx) {
        super(config, SMB_COM_NT_CREATE_ANDX, name, andx);
        this.desiredAccess = access;
        this.desiredAccess |= SmbConstants.FILE_READ_DATA | SmbConstants.FILE_READ_EA | SmbConstants.FILE_READ_ATTRIBUTES;

        // extFileAttributes
        this.extFileAttributes = extFileAttributes;

        // shareAccess
        this.shareAccess = shareAccess;

        // createDisposition
        if ((flags & SmbConstants.O_TRUNC) == SmbConstants.O_TRUNC) {
            // truncate the file
            if ((flags & SmbConstants.O_CREAT) == SmbConstants.O_CREAT) {
                // create it if necessary
                this.createDisposition = FILE_OVERWRITE_IF;
            } else {
                this.createDisposition = FILE_OVERWRITE;
            }
        } else // don't truncate the file
        if ((flags & SmbConstants.O_CREAT) == SmbConstants.O_CREAT) {
            // create it if necessary
            if ((flags & SmbConstants.O_EXCL) == SmbConstants.O_EXCL) {
                // fail if already exists
                this.createDisposition = FILE_CREATE;
            } else {
                this.createDisposition = FILE_OPEN_IF;
            }
        } else {
            this.createDisposition = FILE_OPEN;
        }

        if ((createOptions & 0x0001) == 0) {
            this.createOptions = createOptions | 0x0040;
        } else {
            this.createOptions = createOptions;
        }
        this.impersonationLevel = 0x02; // As seen on NT :~)
        this.securityFlags = (byte) 0x03; // SECURITY_CONTEXT_TRACKING | SECURITY_EFFECTIVE_ONLY
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock#getResponse()
     */
    @Override
    public final SmbComNTCreateAndXResponse getResponse() {
        return (SmbComNTCreateAndXResponse) super.getResponse();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.Request#initResponse(org.codelibs.jcifs.smb.CIFSContext)
     */
    @Override
    public SmbComNTCreateAndXResponse initResponse(final CIFSContext tc) {
        final SmbComNTCreateAndXResponse resp = new SmbComNTCreateAndXResponse(tc.getConfig());
        setResponse(resp);
        return resp;
    }

    /**
     * Adds flags to the flags0 field.
     *
     * @param fl
     *            the flags0 to set
     */
    public final void addFlags0(final int fl) {
        this.flags0 |= fl;
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        dst[dstIndex] = (byte) 0x00;
        dstIndex++;
        // name length without counting null termination
        this.namelen_index = dstIndex;
        dstIndex += 2;
        SMBUtil.writeInt4(this.flags0, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.rootDirectoryFid, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.desiredAccess, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt8(this.allocationSize, dst, dstIndex);
        dstIndex += 8;
        SMBUtil.writeInt4(this.extFileAttributes, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.shareAccess, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.createDisposition, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.createOptions, dst, dstIndex);
        dstIndex += 4;
        SMBUtil.writeInt4(this.impersonationLevel, dst, dstIndex);
        dstIndex += 4;
        dst[dstIndex++] = this.securityFlags;

        return dstIndex - start;
    }

    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        int n = writeString(this.path, dst, dstIndex);
        SMBUtil.writeInt2(this.isUseUnicode() ? this.path.length() * 2 : n, dst, this.namelen_index);
        return n;
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
        return ("SmbComNTCreateAndX[" + super.toString() + ",flags=0x" + Hexdump.toHexString(this.flags0, 2) + ",rootDirectoryFid="
                + this.rootDirectoryFid + ",desiredAccess=0x" + Hexdump.toHexString(this.desiredAccess, 4) + ",allocationSize="
                + this.allocationSize + ",extFileAttributes=0x" + Hexdump.toHexString(this.extFileAttributes, 4) + ",shareAccess=0x"
                + Hexdump.toHexString(this.shareAccess, 4) + ",createDisposition=0x" + Hexdump.toHexString(this.createDisposition, 4)
                + ",createOptions=0x" + Hexdump.toHexString(this.createOptions, 8) + ",impersonationLevel=0x"
                + Hexdump.toHexString(this.impersonationLevel, 4) + ",securityFlags=0x" + Hexdump.toHexString(this.securityFlags, 2)
                + ",name=" + this.path + "]");
    }

}
