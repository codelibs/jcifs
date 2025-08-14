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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import jcifs.Configuration;
import jcifs.RuntimeCIFSException;
import jcifs.internal.SmbNegotiationRequest;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.util.Strings;

/**
 *
 */
public class SmbComNegotiate extends ServerMessageBlock implements SmbNegotiationRequest {

    private final boolean signingEnforced;
    private String[] dialects;

    /**
     *
     * @param config
     * @param signingEnforced
     */
    public SmbComNegotiate(final Configuration config, final boolean signingEnforced) {
        super(config, SMB_COM_NEGOTIATE);
        this.signingEnforced = signingEnforced;
        setFlags2(config.getFlags2());

        if (config.getMinimumVersion().isSMB2()) {
            this.dialects = new String[] { "SMB 2.???", "SMB 2.002" };
        } else if (config.getMaximumVersion().isSMB2()) {
            this.dialects = new String[] { "NT LM 0.12", "SMB 2.???", "SMB 2.002" };
        } else {
            this.dialects = new String[] { "NT LM 0.12" };
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.SmbNegotiationRequest#isSigningEnforced()
     */
    @Override
    public boolean isSigningEnforced() {
        return this.signingEnforced;
    }

    @Override
    protected int writeParameterWordsWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();

        for (final String dialect : this.dialects) {
            bos.write(0x02);
            try {
                bos.write(Strings.getASCIIBytes(dialect));
            } catch (final IOException e) {
                throw new RuntimeCIFSException(e);
            }
            bos.write(0x0);
        }

        System.arraycopy(bos.toByteArray(), 0, dst, dstIndex, bos.size());
        return bos.size();
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
        return ("SmbComNegotiate[" + super.toString() + ",wordCount=" + this.wordCount + ",dialects=NT LM 0.12]");
    }
}
