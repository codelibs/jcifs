/* jcifs smb client library in Java
 * Copyright (C) 2004  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
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

package jcifs.spnego;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

import jcifs.util.Hexdump;

/**
 * SPNEGO initial token
 */
public class NegTokenInit extends SpnegoToken {

    /**
     * Context flag for delegation capability
     */
    public static final int DELEGATION = 0x80;
    /**
     * Context flag for mutual authentication requirement
     */
    public static final int MUTUAL_AUTHENTICATION = 0x40;
    /**
     * Context flag for replay detection capability
     */
    public static final int REPLAY_DETECTION = 0x20;
    /**
     * Context flag for sequence checking capability
     */
    public static final int SEQUENCE_CHECKING = 0x10;
    /**
     * Context flag for anonymity capability
     */
    public static final int ANONYMITY = 0x08;
    /**
     * Context flag for confidentiality (encryption) capability
     */
    public static final int CONFIDENTIALITY = 0x04;
    /**
     * Context flag for integrity (signing) capability
     */
    public static final int INTEGRITY = 0x02;

    private static final ASN1ObjectIdentifier SPNEGO_OID = new ASN1ObjectIdentifier(SpnegoConstants.SPNEGO_MECHANISM);

    private ASN1ObjectIdentifier[] mechanisms;

    private int contextFlags;

    /**
     * Default constructor for NegTokenInit
     */
    public NegTokenInit() {
    }

    /**
     * Constructs a NegTokenInit with the specified parameters
     * @param mechanisms the array of supported authentication mechanisms
     * @param contextFlags the context flags indicating security capabilities
     * @param mechanismToken the initial token for the selected mechanism
     * @param mechanismListMIC the MIC over the mechanism list
     */
    public NegTokenInit(final ASN1ObjectIdentifier[] mechanisms, final int contextFlags, final byte[] mechanismToken,
            final byte[] mechanismListMIC) {
        setMechanisms(mechanisms);
        setContextFlags(contextFlags);
        setMechanismToken(mechanismToken);
        setMechanismListMIC(mechanismListMIC);
    }

    /**
     * Constructs a NegTokenInit by parsing the provided token bytes
     * @param token the SPNEGO token bytes to parse
     * @throws IOException if parsing fails
     */
    public NegTokenInit(final byte[] token) throws IOException {
        parse(token);
    }

    /**
     * Gets the context flags indicating security capabilities
     * @return the context flags
     */
    public int getContextFlags() {
        return this.contextFlags;
    }

    /**
     * Sets the context flags indicating security capabilities
     * @param contextFlags the context flags to set
     */
    public void setContextFlags(final int contextFlags) {
        this.contextFlags = contextFlags;
    }

    /**
     * Checks if a specific context flag is set
     * @param flag the context flag to check
     * @return true if the flag is set, false otherwise
     */
    public boolean getContextFlag(final int flag) {
        return (getContextFlags() & flag) == flag;
    }

    /**
     * Sets or clears a specific context flag
     * @param flag the context flag to set or clear
     * @param value true to set the flag, false to clear it
     */
    public void setContextFlag(final int flag, final boolean value) {
        setContextFlags(value ? getContextFlags() | flag : getContextFlags() & (0xffffffff ^ flag));
    }

    /**
     * Gets the array of supported authentication mechanisms
     * @return the mechanisms array
     */
    public ASN1ObjectIdentifier[] getMechanisms() {
        return this.mechanisms;
    }

    /**
     * Sets the array of supported authentication mechanisms
     * @param mechanisms the mechanisms to set
     */
    public void setMechanisms(final ASN1ObjectIdentifier[] mechanisms) {
        this.mechanisms = mechanisms;
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        String mic = null;
        if (this.getMechanismListMIC() != null) {
            mic = Hexdump.toHexString(this.getMechanismListMIC(), 0, this.getMechanismListMIC().length);
        }
        return String.format("NegTokenInit[flags=%d,mechs=%s,mic=%s]", this.getContextFlags(), Arrays.toString(this.getMechanisms()), mic);
    }

    @Override
    public byte[] toByteArray() {
        try {
            final ASN1EncodableVector fields = new ASN1EncodableVector();
            final ASN1ObjectIdentifier[] mechs = getMechanisms();
            if (mechs != null) {
                final ASN1EncodableVector vector = new ASN1EncodableVector();
                for (final ASN1ObjectIdentifier mech : mechs) {
                    vector.add(mech);
                }
                fields.add(new DERTaggedObject(true, 0, new DERSequence(vector)));
            }
            final int ctxFlags = getContextFlags();
            if (ctxFlags != 0) {
                fields.add(new DERTaggedObject(true, 1, new DERBitString(ctxFlags)));
            }
            final byte[] mechanismToken = getMechanismToken();
            if (mechanismToken != null) {
                fields.add(new DERTaggedObject(true, 2, new DEROctetString(mechanismToken)));
            }
            final byte[] mechanismListMIC = getMechanismListMIC();
            if (mechanismListMIC != null) {
                fields.add(new DERTaggedObject(true, 3, new DEROctetString(mechanismListMIC)));
            }

            final ASN1EncodableVector ev = new ASN1EncodableVector();
            ev.add(SPNEGO_OID);
            ev.add(new DERTaggedObject(true, 0, new DERSequence(fields)));
            final ByteArrayOutputStream collector = new ByteArrayOutputStream();
            final ASN1OutputStream der = ASN1OutputStream.create(collector, ASN1Encoding.DER);
            final DERTaggedObject derApplicationSpecific = new DERTaggedObject(false, BERTags.APPLICATION, 0, new DERSequence(ev));
            der.writeObject(derApplicationSpecific);
            return collector.toByteArray();
        } catch (final IOException ex) {
            throw new IllegalStateException(ex.getMessage());
        }
    }

    @Override
    protected void parse(final byte[] token) throws IOException {

        try (ASN1InputStream is = new ASN1InputStream(token)) {
            final ASN1TaggedObject constructed = (ASN1TaggedObject) is.readObject();
            if (constructed == null || constructed.getTagClass() != BERTags.APPLICATION
                    || !(constructed.getBaseObject() instanceof ASN1Sequence)) {
                throw new IOException("Malformed SPNEGO token " + constructed);
            }

            final ASN1Sequence vec = (ASN1Sequence) constructed.getBaseObject();

            final ASN1ObjectIdentifier spnego = (ASN1ObjectIdentifier) vec.getObjectAt(0);
            if (!SPNEGO_OID.equals(spnego)) {
                throw new IOException("Malformed SPNEGO token, OID " + spnego);
            }
            ASN1TaggedObject tagged = (ASN1TaggedObject) vec.getObjectAt(1);
            if (tagged.getTagNo() != 0) {
                throw new IOException("Malformed SPNEGO token: tag " + tagged.getTagNo() + " " + tagged);
            }
            ASN1Sequence sequence = ASN1Sequence.getInstance(tagged, true);
            final Enumeration<ASN1Object> fields = sequence.getObjects();
            while (fields.hasMoreElements()) {
                tagged = (ASN1TaggedObject) fields.nextElement();
                switch (tagged.getTagNo()) {
                case 0:
                    sequence = ASN1Sequence.getInstance(tagged, true);
                    final ASN1ObjectIdentifier[] mechs = new ASN1ObjectIdentifier[sequence.size()];
                    for (int i = mechs.length - 1; i >= 0; i--) {
                        mechs[i] = (ASN1ObjectIdentifier) sequence.getObjectAt(i);
                    }
                    setMechanisms(mechs);
                    break;
                case 1:
                    final ASN1BitString ctxFlags = ASN1BitString.getInstance(tagged, true);
                    setContextFlags(ctxFlags.getBytes()[0] & 0xff);
                    break;
                case 2:
                    final ASN1OctetString mechanismToken = ASN1OctetString.getInstance(tagged, true);
                    setMechanismToken(mechanismToken.getOctets());
                    break;

                case 3:
                    if (!(tagged.getBaseObject() instanceof DEROctetString)) {
                        break;
                    }
                case 4:
                    final ASN1OctetString mechanismListMIC = ASN1OctetString.getInstance(tagged, true);
                    setMechanismListMIC(mechanismListMIC.getOctets());
                    break;
                default:
                    throw new IOException("Malformed token field.");
                }
            }
        }
    }

}
