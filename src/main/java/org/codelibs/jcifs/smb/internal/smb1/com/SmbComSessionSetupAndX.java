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

import java.security.GeneralSecurityException;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.NtlmPasswordAuthenticator;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.SmbException;
import org.codelibs.jcifs.smb.internal.smb1.AndXServerMessageBlock;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB1 Session Setup AndX request message.
 *
 * This command is used to authenticate a user session and
 * establish security context for subsequent operations.
 */
public class SmbComSessionSetupAndX extends AndXServerMessageBlock {

    private byte[] lmHash, ntHash, blob = null;
    private String accountName, primaryDomain;
    private final SmbComNegotiateResponse negotiated;
    private int capabilities;

    /**
     * Constructs a session setup AndX request.
     *
     * @param tc the CIFS context containing configuration and credentials
     * @param negotiated the negotiation response containing server capabilities
     * @param andx the next command in the AndX chain, or null
     * @param cred the authentication credentials to use for the session
     * @throws SmbException if an SMB protocol error occurs
     * @throws GeneralSecurityException if a security error occurs during authentication
     */
    public SmbComSessionSetupAndX(final CIFSContext tc, final SmbComNegotiateResponse negotiated, final ServerMessageBlock andx,
            final Object cred) throws SmbException, GeneralSecurityException {
        super(tc.getConfig(), SMB_COM_SESSION_SETUP_ANDX, andx);
        this.negotiated = negotiated;
        this.capabilities = negotiated.getNegotiatedCapabilities();
        final ServerData server = negotiated.getServerData();
        if (server.security == SmbConstants.SECURITY_USER) {
            if (cred instanceof final NtlmPasswordAuthenticator a) {
                if (a.isAnonymous()) {
                    this.lmHash = new byte[0];
                    this.ntHash = new byte[0];
                    this.capabilities &= ~SmbConstants.CAP_EXTENDED_SECURITY;
                    if (a.isGuest()) {
                        this.accountName = a.getUsername();
                        if (this.isUseUnicode()) {
                            this.accountName = this.accountName.toUpperCase();
                        }
                        this.primaryDomain = a.getUserDomain() != null ? a.getUserDomain().toUpperCase() : "?";
                    } else {
                        this.accountName = "";
                        this.primaryDomain = "";
                    }
                } else {
                    this.accountName = a.getUsername();
                    if (this.isUseUnicode()) {
                        this.accountName = this.accountName.toUpperCase();
                    }
                    this.primaryDomain = a.getUserDomain() != null ? a.getUserDomain().toUpperCase() : "?";
                    if (server.encryptedPasswords) {
                        this.lmHash = a.getAnsiHash(tc, server.encryptionKey);
                        this.ntHash = a.getUnicodeHash(tc, server.encryptionKey);
                        // prohibit HTTP auth attempts for the null session
                        if (this.lmHash.length == 0 && this.ntHash.length == 0) {
                            throw new RuntimeException("Null setup prohibited.");
                        }
                    } else if (tc.getConfig().isDisablePlainTextPasswords()) {
                        throw new RuntimeException("Plain text passwords are disabled");
                    } else {
                        // plain text
                        final String password = a.getPassword();
                        this.lmHash = new byte[(password.length() + 1) * 2];
                        this.ntHash = new byte[0];
                        writeString(password, this.lmHash, 0);
                    }
                }

            } else if (cred instanceof byte[]) {
                this.blob = (byte[]) cred;
            } else {
                throw new SmbException("Unsupported credential type " + (cred != null ? cred.getClass() : "NULL"));
            }
        } else if (server.security == SmbConstants.SECURITY_SHARE) {
            if (!(cred instanceof final NtlmPasswordAuthenticator a)) {
                throw new SmbException("Unsupported credential type");
            }
            this.lmHash = new byte[0];
            this.ntHash = new byte[0];
            if (!a.isAnonymous()) {
                this.accountName = a.getUsername();
                if (this.isUseUnicode()) {
                    this.accountName = this.accountName.toUpperCase();
                }
                this.primaryDomain = a.getUserDomain() != null ? a.getUserDomain().toUpperCase() : "?";
            } else {
                this.accountName = "";
                this.primaryDomain = "";
            }
        } else {
            throw new SmbException("Unsupported");
        }
    }

    @Override
    protected int getBatchLimit(final Configuration cfg, final byte cmd) {
        return cmd == SMB_COM_TREE_CONNECT_ANDX ? cfg.getBatchLimit("SessionSetupAndX.TreeConnectAndX") : 0;
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        SMBUtil.writeInt2(this.negotiated.getNegotiatedSendBufferSize(), dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(this.negotiated.getNegotiatedMpxCount(), dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt2(getConfig().getVcNumber(), dst, dstIndex);
        dstIndex += 2;
        SMBUtil.writeInt4(this.negotiated.getNegotiatedSessionKey(), dst, dstIndex);
        dstIndex += 4;
        if (this.blob != null) {
            SMBUtil.writeInt2(this.blob.length, dst, dstIndex);
        } else {
            SMBUtil.writeInt2(this.lmHash.length, dst, dstIndex);
            dstIndex += 2;
            SMBUtil.writeInt2(this.ntHash.length, dst, dstIndex);
        }
        dstIndex += 2;
        dst[dstIndex] = (byte) 0x00;
        dstIndex++;
        dst[dstIndex++] = (byte) 0x00;
        dst[dstIndex++] = (byte) 0x00;
        dst[dstIndex++] = (byte) 0x00;
        SMBUtil.writeInt4(this.capabilities, dst, dstIndex);
        dstIndex += 4;

        return dstIndex - start;
    }

    @Override
    protected int writeBytesWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;

        if (this.blob != null) {
            System.arraycopy(this.blob, 0, dst, dstIndex, this.blob.length);
            dstIndex += this.blob.length;
        } else {
            System.arraycopy(this.lmHash, 0, dst, dstIndex, this.lmHash.length);
            dstIndex += this.lmHash.length;
            System.arraycopy(this.ntHash, 0, dst, dstIndex, this.ntHash.length);
            dstIndex += this.ntHash.length;

            dstIndex += writeString(this.accountName, dst, dstIndex);
            dstIndex += writeString(this.primaryDomain, dst, dstIndex);
        }
        dstIndex += writeString(getConfig().getNativeOs(), dst, dstIndex);
        dstIndex += writeString(getConfig().getNativeLanman(), dst, dstIndex);

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
        return ("SmbComSessionSetupAndX[" + super.toString() + ",snd_buf_size=" + this.negotiated.getNegotiatedSendBufferSize()
                + ",maxMpxCount=" + this.negotiated.getNegotiatedMpxCount() + ",VC_NUMBER=" + getConfig().getVcNumber() + ",sessionKey="
                + this.negotiated.getNegotiatedSessionKey() + ",lmHash.length=" + (this.lmHash == null ? 0 : this.lmHash.length)
                + ",ntHash.length=" + (this.ntHash == null ? 0 : this.ntHash.length) + ",capabilities=" + this.capabilities
                + ",accountName=" + this.accountName + ",primaryDomain=" + this.primaryDomain + ",NATIVE_OS=" + getConfig().getNativeOs()
                + ",NATIVE_LANMAN=" + getConfig().getNativeLanman() + "]");
    }
}
