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
import org.codelibs.jcifs.smb.internal.smb2.create.CreateContextRequest;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CloseRequest;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateRequest;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateResponse;

/**
 * Test-only way to put an SMB2 CREATE carrying create contexts on the wire.
 *
 * <p>
 * {@code SmbTreeHandleImpl} is package private, so this class lives in the
 * implementation package purely so integration tests can see how a real server
 * answers a hand-built list of create contexts.
 * </p>
 */
public final class SmbCreateContextProbe {

    private SmbCreateContextProbe() {
    }

    /**
     * Opens an existing file with the given create contexts and closes it again
     * in the same compound request.
     *
     * @param file     an existing file
     * @param contexts the create contexts to send, in order
     * @return the raw SMB2 CREATE response, starting at its SMB2 header
     * @throws CIFSException if the server refuses the request
     */
    public static byte[] openWithContexts(final SmbFile file, final CreateContextRequest... contexts) throws CIFSException {
        try (SmbTreeHandleImpl th = (SmbTreeHandleImpl) file.getTreeHandle()) {
            if (!th.isSMB2()) {
                throw new IllegalStateException("Create contexts need an SMB2 connection");
            }
            final Smb2CreateRequest create = new Smb2CreateRequest(th.getConfig(), file.getUncPath());
            create.setDesiredAccess(SmbConstants.FILE_READ_ATTRIBUTES);
            create.setShareAccess(SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE);
            create.setCreateContexts(contexts);
            create.chain(new Smb2CloseRequest(th.getConfig(), file.getUncPath()));
            final Smb2CreateResponse response = th.send(create, RequestParam.RETAIN_PAYLOAD);
            return response.getRawPayload();
        }
    }
}
