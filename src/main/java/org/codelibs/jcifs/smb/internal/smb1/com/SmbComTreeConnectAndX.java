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

package org.codelibs.jcifs.smb.internal.smb1.com;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.NtlmPasswordAuthenticator;
import org.codelibs.jcifs.smb.RuntimeCIFSException;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.internal.smb1.AndXServerMessageBlock;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Hexdump;

/**
 * SMB1 Tree Connect AndX request message.
 *
 * This command is used to connect to a shared resource
 * on the server, such as a file share or printer.
 */
public class SmbComTreeConnectAndX extends AndXServerMessageBlock {

    private final boolean disconnectTid = false;
    private final String service;
    private byte[] password;
    private int passwordLength;
    private final CIFSContext ctx;
    private final ServerData server;

    /**
     * Constructs a tree connect AndX request to establish a connection to a shared resource.
     *
     * @param ctx the CIFS context containing configuration
     * @param server the server data containing security information
     * @param path the UNC path to the shared resource
     * @param service the service type (e.g., "A:" for disk share, "LPT1:" for printer)
     * @param andx the next command in the AndX chain, or null
     */
    public SmbComTreeConnectAndX(final CIFSContext ctx, final ServerData server, final String path, final String service,
            final ServerMessageBlock andx) {
        super(ctx.getConfig(), SMB_COM_TREE_CONNECT_ANDX, andx);
        this.ctx = ctx;
        this.server = server;
        this.path = path;
        this.service = service;
    }

    @Override
    protected int getBatchLimit(final Configuration cfg, final byte cmd) {
        final int c = cmd & 0xFF;
        switch (c) {
        case SMB_COM_CHECK_DIRECTORY:
            return cfg.getBatchLimit("TreeConnectAndX.CheckDirectory");
        case SMB_COM_CREATE_DIRECTORY:
            return cfg.getBatchLimit("TreeConnectAndX.CreateDirectory");
        case SMB_COM_DELETE:
            return cfg.getBatchLimit("TreeConnectAndX.Delete");
        case SMB_COM_DELETE_DIRECTORY:
            return cfg.getBatchLimit("TreeConnectAndX.DeleteDirectory");
        case SMB_COM_OPEN_ANDX:
            return cfg.getBatchLimit("TreeConnectAndX.OpenAndX");
        case SMB_COM_RENAME:
            return cfg.getBatchLimit("TreeConnectAndX.Rename");
        case SMB_COM_TRANSACTION:
            return cfg.getBatchLimit("TreeConnectAndX.Transaction");
        case SMB_COM_QUERY_INFORMATION:
            return cfg.getBatchLimit("TreeConnectAndX.QueryInformation");
        }
        return 0;
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, int dstIndex) {
        if (this.server.security == SmbConstants.SECURITY_SHARE && this.ctx.getCredentials() instanceof NtlmPasswordAuthenticator) {
            final NtlmPasswordAuthenticator pwAuth = (NtlmPasswordAuthenticator) this.ctx.getCredentials();
            if (isExternalAuth(pwAuth)) {
                this.passwordLength = 1;
            } else if (this.server.encryptedPasswords) {
                // encrypted
                try {
                    this.password = pwAuth.getAnsiHash(this.ctx, this.server.encryptionKey);
                } catch (final GeneralSecurityException e) {
                    throw new RuntimeCIFSException("Failed to encrypt password", e);
                }
                this.passwordLength = this.password.length;
            } else if (this.ctx.getConfig().isDisablePlainTextPasswords()) {
                throw new RuntimeCIFSException("Plain text passwords are disabled");
            } else {
                // plain text
                this.password = new byte[(pwAuth.getPassword().length() + 1) * 2];
                this.passwordLength = writeString(pwAuth.getPassword(), this.password, 0);
            }
        } else {
            // no password in tree connect
            this.passwordLength = 1;
        }

        dst[dstIndex] = this.disconnectTid ? (byte) 0x01 : (byte) 0x00;
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00;
        SMBUtil.writeInt2(this.passwordLength, dst, dstIndex);
        return 4;
    }

    @SuppressWarnings("deprecation")
    private static boolean isExternalAuth(final NtlmPasswordAuthenticator pwAuth) {
        return pwAuth instanceof org.codelibs.jcifs.smb.NtlmPasswordAuthentication
                && !((org.codelibs.jcifs.smb.NtlmPasswordAuthentication) pwAuth).areHashesExternal() && pwAuth.getPassword().isEmpty();
    }

    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        if (this.server.security == SmbConstants.SECURITY_SHARE && this.ctx.getCredentials() instanceof NtlmPasswordAuthenticator) {
            final NtlmPasswordAuthenticator pwAuth = (NtlmPasswordAuthenticator) this.ctx.getCredentials();
            if (isExternalAuth(pwAuth)) {
                dst[dstIndex++] = (byte) 0x00;
            } else {
                System.arraycopy(this.password, 0, dst, dstIndex, this.passwordLength);
                dstIndex += this.passwordLength;
            }
        } else {
            // no password in tree connect
            dst[dstIndex++] = (byte) 0x00;
        }
        dstIndex += writeString(this.path, dst, dstIndex);
        try {
            System.arraycopy(this.service.getBytes("ASCII"), 0, dst, dstIndex, this.service.length());
        } catch (final UnsupportedEncodingException uee) {
            return 0;
        }
        dstIndex += this.service.length();
        dst[dstIndex] = (byte) '\0';
        dstIndex++;

        return dstIndex - start;
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
        return ("SmbComTreeConnectAndX[" + super.toString() + ",disconnectTid=" + this.disconnectTid + ",passwordLength="
                + this.passwordLength + ",password=" + Hexdump.toHexString(this.password, this.passwordLength, 0) + ",path=" + this.path
                + ",service=" + this.service + "]");
    }
}
