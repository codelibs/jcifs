/* jcifs smb client library in Java
 * Copyright (C) 2005  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.internal.smb1.trans.nt;

import java.util.ArrayList;
import java.util.List;

import jcifs.Configuration;
import jcifs.FileNotifyInformation;
import jcifs.internal.NotifyResponse;
import jcifs.internal.SMBProtocolDecodingException;

/**
 * Response for SMB1 NT Transaction change notification.
 *
 * This response contains file system change notifications that occurred
 * in the monitored directory, such as file creation, modification, or deletion.
 */
public class NtTransNotifyChangeResponse extends SmbComNtTransactionResponse implements NotifyResponse {

    private final List<FileNotifyInformation> notifyInformation = new ArrayList<>();

    /**
     * Constructs an NT transaction notify change response.
     * @param config the configuration context for this response
     */
    public NtTransNotifyChangeResponse(final Configuration config) {
        super(config);
    }

    /**
     * @return the notifyInformation
     */
    @Override
    public final List<FileNotifyInformation> getNotifyInformation() {
        return this.notifyInformation;
    }

    @Override
    protected int writeSetupWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int writeParametersWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int writeDataWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int readSetupWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    protected int readParametersWireFormat(final byte[] buffer, int bufferIndex, final int len) throws SMBProtocolDecodingException {
        final int start = bufferIndex;

        int elemStart = start;

        FileNotifyInformationImpl i = new FileNotifyInformationImpl();
        bufferIndex += i.decode(buffer, bufferIndex, len);
        this.notifyInformation.add(i);

        while (i.getNextEntryOffset() > 0) {
            bufferIndex = elemStart + i.getNextEntryOffset();
            elemStart = bufferIndex;

            i = new FileNotifyInformationImpl();
            bufferIndex += i.decode(buffer, bufferIndex, len);
            this.notifyInformation.add(i);
        }

        return bufferIndex - start;
    }

    @Override
    protected int readDataWireFormat(final byte[] buffer, final int bufferIndex, final int len) {
        return 0;
    }

    @Override
    public String toString() {
        return ("NtTransQuerySecurityResponse[" + super.toString() + "]");
    }
}
