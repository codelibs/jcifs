/* org.codelibs.jcifs.smb smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Paul Walker" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb.impl;

import java.net.MalformedURLException;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.SmbPipeHandle;
import org.codelibs.jcifs.smb.SmbPipeResource;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComNTCreateAndX;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComNTCreateAndXResponse;

/**
 * This class will allow a Java program to read and write data to Named
 * Pipes and Transact NamedPipes.
 *
 * <p>
 * There are three Win32 function calls provided by the Windows SDK
 * that are important in the context of using jCIFS. They are:
 *
 * <ul>
 * <li><code>CallNamedPipe</code> A message-type pipe call that opens,
 * writes to, reads from, and closes the pipe in a single operation.
 * <li><code>TransactNamedPipe</code> A message-type pipe call that
 * writes to and reads from an existing pipe descriptor in one operation.
 * <li><code>CreateFile</code>, <code>ReadFile</code>,
 * <code>WriteFile</code>, and <code>CloseFile</code> A byte-type pipe can
 * be opened, written to, read from and closed using the standard Win32
 * file operations.
 * </ul>
 *
 * <p>
 * The jCIFS API maps all of these operations into the standard Java
 * <code>XxxputStream</code> interface. A special <code>PIPE_TYPE</code>
 * flags is necessary to distinguish which type of Named Pipe behavior
 * is desired.
 *
 * <table border="1">
 * <caption>SmbNamedPipe Constructor Examples</caption>
 * <tr >
 * <td colspan="2"><b><code>SmbNamedPipe</code> Constructor Examples</b></td>
 * <tr>
 * <td ><b>Code Sample</b></td>
 * <td><b>Description</b></td>
 * </tr>
 * <tr>
 * <td >
 *
 * <pre>
 * new SmbNamedPipe("smb://server/IPC$/PIPE/foo", SmbNamedPipe.PIPE_TYPE_RDWR | SmbNamedPipe.PIPE_TYPE_CALL, context);
 * </pre>
 *
 * </td>
 * <td>
 * Open the Named Pipe foo for reading and writing. The pipe will behave like the <code>CallNamedPipe</code> interface.
 * </td>
 * </tr>
 * <tr>
 * <td >
 *
 * <pre>
 * new SmbNamedPipe("smb://server/IPC$/foo", SmbNamedPipe.PIPE_TYPE_RDWR | SmbNamedPipe.PIPE_TYPE_TRANSACT, context);
 * </pre>
 *
 * </td>
 * <td>
 * Open the Named Pipe foo for reading and writing. The pipe will behave like the <code>TransactNamedPipe</code>
 * interface.
 * </td>
 * </tr>
 * <tr>
 * <td >
 *
 * <pre>
 * new SmbNamedPipe("smb://server/IPC$/foo", SmbNamedPipe.PIPE_TYPE_RDWR, context);
 * </pre>
 *
 * </td>
 * <td>
 * Open the Named Pipe foo for reading and writing. The pipe will
 * behave as though the <code>CreateFile</code>, <code>ReadFile</code>,
 * <code>WriteFile</code>, and <code>CloseFile</code> interface was
 * being used.
 * </td>
 * </tr>
 * </table>
 *
 * <p>
 * See <a href="../../../pipes.html">Using jCIFS to Connect to Win32
 * Named Pipes</a> for a detailed description of how to use jCIFS with
 * Win32 Named Pipe server processes.
 *
 */

public class SmbNamedPipe extends SmbFile implements SmbPipeResource {

    private final int pipeType;

    /**
     * Open the Named Pipe resource specified by the url
     * parameter. The pipeType parameter should be at least one of
     * the <code>PIPE_TYPE</code> flags combined with the bitwise OR
     * operator <code>|</code>. See the examples listed above.
     *
     * @param url the SMB URL for the named pipe
     * @param pipeType the type of the pipe
     * @param unshared
     *            whether to use an exclusive connection for this pipe
     * @param tc the CIFS context to use
     * @throws MalformedURLException if the URL is not properly formatted
     */

    public SmbNamedPipe(final String url, final int pipeType, final boolean unshared, final CIFSContext tc) throws MalformedURLException {
        super(url, tc);
        this.pipeType = pipeType;
        setNonPooled(unshared);
        if (!getLocator().isIPC()) {
            throw new MalformedURLException("Named pipes are only valid on IPC$");
        }
        this.fileLocator.updateType(TYPE_NAMED_PIPE);
    }

    /**
     * Open the Named Pipe resource specified by the url
     * parameter. The pipeType parameter should be at least one of
     * the <code>PIPE_TYPE</code> flags combined with the bitwise OR
     * operator <code>|</code>. See the examples listed above.
     *
     * @param url the SMB URL for the named pipe
     * @param pipeType the type of the pipe
     * @param tc the CIFS context to use
     * @throws MalformedURLException if the URL is not properly formatted
     */
    public SmbNamedPipe(final String url, final int pipeType, final CIFSContext tc) throws MalformedURLException {
        this(url, pipeType, (pipeType & SmbPipeResource.PIPE_TYPE_UNSHARED) != 0, tc);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.impl.SmbFile#customizeCreate(org.codelibs.jcifs.smb.internal.smb1.com.SmbComNTCreateAndX,
     *      org.codelibs.jcifs.smb.internal.smb1.com.SmbComNTCreateAndXResponse)
     */
    @Override
    protected void customizeCreate(final SmbComNTCreateAndX request, final SmbComNTCreateAndXResponse response) {
        request.addFlags0(0x16);
        response.setExtended(true);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.impl.SmbFile#getType()
     */
    @Override
    public int getType() throws SmbException {
        return TYPE_NAMED_PIPE;
    }

    /**
     * @return the pipe type
     */
    @Override
    public int getPipeType() {
        return this.pipeType;
    }

    /**
     * @return a handle for interacting with the pipe
     */
    @Override
    public SmbPipeHandle openPipe() {
        return new SmbPipeHandleImpl(this);
    }

}
