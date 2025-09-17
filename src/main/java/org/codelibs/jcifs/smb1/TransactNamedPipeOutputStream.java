/* org.codelibs.jcifs.smb smb client library in Java
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

package org.codelibs.jcifs.smb1;

import java.io.IOException;

class TransactNamedPipeOutputStream extends SmbFileOutputStream {

    private final String path;
    private final SmbNamedPipe pipe;
    private final byte[] tmp = new byte[1];
    private final boolean dcePipe;

    TransactNamedPipeOutputStream(final SmbNamedPipe pipe) throws IOException {
        super(pipe, false, pipe.pipeType & 0xFFFF00FF | SmbFile.O_EXCL);
        this.pipe = pipe;
        this.dcePipe = (pipe.pipeType & SmbNamedPipe.PIPE_TYPE_DCE_TRANSACT) == SmbNamedPipe.PIPE_TYPE_DCE_TRANSACT;
        path = pipe.unc;
    }

    @Override
    public void close() throws IOException {
        pipe.close();
    }

    @Override
    public void write(final int b) throws IOException {
        tmp[0] = (byte) b;
        write(tmp, 0, 1);
    }

    @Override
    public void write(final byte[] b) throws IOException {
        write(b, 0, b.length);
    }

    @Override
    public void write(final byte[] b, final int off, int len) throws IOException {
        if (len < 0) {
            len = 0;
        }

        if ((pipe.pipeType & SmbNamedPipe.PIPE_TYPE_CALL) == SmbNamedPipe.PIPE_TYPE_CALL) {
            pipe.send(new TransWaitNamedPipe(path), new TransWaitNamedPipeResponse());
            pipe.send(new TransCallNamedPipe(path, b, off, len), new TransCallNamedPipeResponse(pipe));
        } else if ((pipe.pipeType & SmbNamedPipe.PIPE_TYPE_TRANSACT) == SmbNamedPipe.PIPE_TYPE_TRANSACT) {
            ensureOpen();
            final TransTransactNamedPipe req = new TransTransactNamedPipe(pipe.fid, b, off, len);
            if (dcePipe) {
                req.maxDataCount = 1024;
            }
            pipe.send(req, new TransTransactNamedPipeResponse(pipe));
        }
    }
}
