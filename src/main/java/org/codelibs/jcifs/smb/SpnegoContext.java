/*
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
package org.codelibs.jcifs.smb;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.codelibs.jcifs.smb.spnego.NegTokenInit;
import org.codelibs.jcifs.smb.spnego.NegTokenTarg;
import org.codelibs.jcifs.smb.spnego.SpnegoException;
import org.codelibs.jcifs.smb.spnego.SpnegoToken;
import org.codelibs.jcifs.smb.util.Hexdump;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class used to wrap a {@link SSPContext} to provide SPNEGO feature.
 *
 * @author Shun
 *
 */
class SpnegoContext implements SSPContext {

    private static final Logger log = LoggerFactory.getLogger(SpnegoContext.class);

    private static ASN1ObjectIdentifier SPNEGO_MECH_OID;

    static {
        try {
            SPNEGO_MECH_OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.2");
        } catch (final IllegalArgumentException e) {
            log.error("Failed to initialize OID", e);
        }
    }

    private final SSPContext mechContext;

    private boolean firstResponse = true;
    private boolean completed;

    private ASN1ObjectIdentifier[] mechs;
    private ASN1ObjectIdentifier selectedMech;
    private ASN1ObjectIdentifier[] remoteMechs;

    private final boolean disableMic;
    private boolean requireMic;

    /**
     * Instance a <code>SpnegoContext</code> object by wrapping a {@link SSPContext}
     * with the same mechanism this {@link SSPContext} used.
     *
     * @param source
     *            the {@link SSPContext} to be wrapped
     */
    SpnegoContext(final Configuration config, final SSPContext source) {
        this(config, source, source.getSupportedMechs());
    }

    /**
     * Instance a <code>SpnegoContext</code> object by wrapping a {@link SSPContext}
     * with specified mechanism.
     *
     * @param source
     *            the {@link SSPContext} to be wrapped
     * @param mech
     *            the mechanism is being used for this context.
     */
    SpnegoContext(final Configuration config, final SSPContext source, final ASN1ObjectIdentifier[] mech) {
        this.mechContext = source;
        this.mechs = mech;
        this.disableMic = !config.isEnforceSpnegoIntegrity() && config.isDisableSpnegoIntegrity();
        this.requireMic = config.isEnforceSpnegoIntegrity();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SSPContext#getSupportedMechs()
     */
    @Override
    public ASN1ObjectIdentifier[] getSupportedMechs() {
        return new ASN1ObjectIdentifier[] { SPNEGO_MECH_OID };
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SSPContext#getFlags()
     */
    @Override
    public int getFlags() {
        return this.mechContext.getFlags();
    }

    @Override
    public boolean isSupported(final ASN1ObjectIdentifier mechanism) {
        // prevent nesting
        return false;
    }

    /**
     * Determines what mechanism is being used for this context.
     *
     * @return the Oid of the mechanism being used
     */
    ASN1ObjectIdentifier[] getMechs() {
        return this.mechs;
    }

    /**
     * @return the mechanisms announced by the remote end
     */
    ASN1ObjectIdentifier[] getRemoteMechs() {
        return this.remoteMechs;
    }

    /**
     * Set what mechanism is being used for this context.
     *
     * @param mechs
     */
    void setMechs(final ASN1ObjectIdentifier[] mechs) {
        this.mechs = mechs;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SSPContext#getNetbiosName()
     */
    @Override
    public String getNetbiosName() {
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SSPContext#getSigningKey()
     */
    @Override
    public byte[] getSigningKey() throws CIFSException {
        return this.mechContext.getSigningKey();
    }

    /**
     * Initialize the GSSContext to provide SPNEGO feature.
     *
     * @param inputBuf
     * @param offset
     * @param len
     * @return response token
     */
    @Override
    public byte[] initSecContext(final byte[] inputBuf, final int offset, final int len) throws CIFSException {
        SpnegoToken resp;
        if (this.completed) {
            throw new CIFSException("Already complete");
        }
        if (len == 0) {
            resp = initialToken();
        } else {
            resp = negotitate(inputBuf, offset, len);
        }

        if (resp == null) {
            return null;
        }
        return resp.toByteArray();
    }

    private SpnegoToken negotitate(final byte[] inputBuf, final int offset, final int len) throws CIFSException {
        final SpnegoToken spToken = getToken(inputBuf, offset, len);
        byte[] inputToken = null;
        if (spToken instanceof final NegTokenInit tinit) {
            final ASN1ObjectIdentifier[] rm = tinit.getMechanisms();
            this.remoteMechs = rm;
            final ASN1ObjectIdentifier prefMech = rm[0];
            // only use token if the optimistic mechanism is supported
            if (this.mechContext.isSupported(prefMech)) {
                inputToken = tinit.getMechanismToken();
            } else {
                ASN1ObjectIdentifier found = null;
                for (final ASN1ObjectIdentifier mech : rm) {
                    if (this.mechContext.isSupported(mech)) {
                        found = mech;
                        break;
                    }
                }
                if (found == null) {
                    throw new SmbException("Server does advertise any supported mechanism");
                }
            }
        } else if (spToken instanceof final NegTokenTarg targ) {
            if (this.firstResponse) {
                if (!this.mechContext.isSupported(targ.getMechanism())) {
                    throw new SmbException("Server chose an unsupported mechanism " + targ.getMechanism());
                }
                this.selectedMech = targ.getMechanism();
                if (targ.getResult() == NegTokenTarg.REQUEST_MIC) {
                    this.requireMic = true;
                }
                this.firstResponse = false;
            } else if (targ.getMechanism() != null && !targ.getMechanism().equals(this.selectedMech)) {
                throw new SmbException("Server switched mechanism");
            }
            inputToken = targ.getMechanismToken();
        } else {
            throw new SmbException("Invalid token");
        }

        if (spToken instanceof final NegTokenTarg targ && this.mechContext.isEstablished()) {
            // already established, but server hasn't completed yet
            if (targ.getResult() == NegTokenTarg.ACCEPT_INCOMPLETE && targ.getMechanismToken() == null
                    && targ.getMechanismListMIC() != null) {
                // this indicates that mechlistMIC is required by the server
                verifyMechListMIC(targ.getMechanismListMIC());
                return new NegTokenTarg(NegTokenTarg.UNSPECIFIED_RESULT, null, null, calculateMechListMIC());
            }
            if (targ.getResult() != NegTokenTarg.ACCEPT_COMPLETED) {
                throw new SmbException("SPNEGO negotiation did not complete");
            }
            verifyMechListMIC(targ.getMechanismListMIC());
            this.completed = true;
            return null;
        }

        if (inputToken == null) {
            return initialToken();
        }

        byte[] mechMIC = null;
        final byte[] responseToken = this.mechContext.initSecContext(inputToken, 0, inputToken.length);

        if (spToken instanceof final NegTokenTarg targ) {
            if (targ.getResult() == NegTokenTarg.ACCEPT_COMPLETED && this.mechContext.isEstablished()) {
                // server sent final token
                verifyMechListMIC(targ.getMechanismListMIC());
                if (!this.disableMic || this.requireMic) {
                    mechMIC = calculateMechListMIC();
                }
                this.completed = true;
            } else if (this.mechContext.isMICAvailable() && (!this.disableMic || this.requireMic)) {
                // we need to send our final data
                mechMIC = calculateMechListMIC();
            } else if (targ.getResult() == NegTokenTarg.REJECTED) {
                throw new SmbException("SPNEGO mechanism was rejected");
            }
        }

        if (responseToken == null && this.mechContext.isEstablished()) {
            return null;
        }

        return new NegTokenTarg(NegTokenTarg.UNSPECIFIED_RESULT, null, responseToken, mechMIC);
    }

    private byte[] calculateMechListMIC() throws CIFSException {
        if (!this.mechContext.isMICAvailable()) {
            return null;
        }

        final ASN1ObjectIdentifier[] lm = this.mechs;
        final byte[] ml = encodeMechs(lm);
        final byte[] mechanismListMIC = this.mechContext.calculateMIC(ml);
        if (log.isDebugEnabled()) {
            log.debug("Out Mech list " + Arrays.toString(lm));
            log.debug("Out Mech list encoded " + Hexdump.toHexString(ml));
            log.debug("Out Mech list MIC " + Hexdump.toHexString(mechanismListMIC));
        }
        return mechanismListMIC;
    }

    private void verifyMechListMIC(final byte[] mechanismListMIC) throws CIFSException {
        if (this.disableMic) {
            return;
        }

        // No MIC verification if not present and not required
        // or if the chosen mechanism is our preferred one
        if ((mechanismListMIC == null || !this.mechContext.supportsIntegrity()) && this.requireMic
                && !this.mechContext.isPreferredMech(this.selectedMech)) {
            throw new CIFSException("SPNEGO integrity is required but not available");
        }

        // otherwise we ignore the absence of a MIC
        if (!this.mechContext.isMICAvailable() || mechanismListMIC == null) {
            return;
        }

        try {
            final ASN1ObjectIdentifier[] lm = this.mechs;
            final byte[] ml = encodeMechs(lm);
            if (log.isInfoEnabled()) {
                log.debug("In Mech list " + Arrays.toString(lm));
                log.debug("In Mech list encoded " + Hexdump.toHexString(ml));
                log.debug("In Mech list MIC " + Hexdump.toHexString(mechanismListMIC));
            }
            this.mechContext.verifyMIC(ml, mechanismListMIC);
        } catch (final CIFSException e) {
            throw new CIFSException("Failed to verify mechanismListMIC", e);
        }
    }

    /**
     * @param mechs
     * @return
     * @throws CIFSException
     */
    private static byte[] encodeMechs(final ASN1ObjectIdentifier[] mechs) throws CIFSException {
        try {
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
            final ASN1OutputStream dos = ASN1OutputStream.create(bos, ASN1Encoding.DER);
            dos.writeObject(new DERSequence(mechs));
            dos.close();
            return bos.toByteArray();
        } catch (final IOException e) {
            throw new CIFSException("Failed to encode mechList", e);
        }
    }

    private SpnegoToken initialToken() throws CIFSException {
        final byte[] mechToken = this.mechContext.initSecContext(new byte[0], 0, 0);
        return new NegTokenInit(this.mechs, this.mechContext.getFlags(), mechToken, null);
    }

    @Override
    public boolean isEstablished() {
        return this.completed && this.mechContext.isEstablished();
    }

    private static SpnegoToken getToken(final byte[] token, final int off, final int len) throws SpnegoException {
        byte[] b = new byte[len];
        if (off == 0 && token.length == len) {
            b = token;
        } else {
            System.arraycopy(token, off, b, 0, len);
        }
        return getToken(b);
    }

    private static SpnegoToken getToken(final byte[] token) throws SpnegoException {
        SpnegoToken spnegoToken = null;
        try {
            spnegoToken = switch (token[0]) {
            case (byte) 0x60 -> new NegTokenInit(token);
            case (byte) 0xa1 -> new NegTokenTarg(token);
            default -> throw new SpnegoException("Invalid token type");
            };
            return spnegoToken;
        } catch (final IOException e) {
            throw new SpnegoException("Invalid token");
        }
    }

    @Override
    public boolean supportsIntegrity() {
        return this.mechContext.supportsIntegrity();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SSPContext#isPreferredMech(org.bouncycastle.asn1.ASN1ObjectIdentifier)
     */
    @Override
    public boolean isPreferredMech(final ASN1ObjectIdentifier mech) {
        return this.mechContext.isPreferredMech(mech);
    }

    @Override
    public byte[] calculateMIC(final byte[] data) throws CIFSException {
        if (!this.completed) {
            throw new CIFSException("Context is not established");
        }
        return this.mechContext.calculateMIC(data);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SSPContext#verifyMIC(byte[], byte[])
     */
    @Override
    public void verifyMIC(final byte[] data, final byte[] mic) throws CIFSException {
        if (!this.completed) {
            throw new CIFSException("Context is not established");
        }
        this.mechContext.verifyMIC(data, mic);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.SSPContext#isMICAvailable()
     */
    @Override
    public boolean isMICAvailable() {
        if (!this.completed) {
            return false;
        }
        return this.mechContext.isMICAvailable();
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "SPNEGO[" + this.mechContext + "]";
    }

    /**
     *
     */
    @Override
    public void dispose() throws CIFSException {
        this.mechContext.dispose();
    }
}
