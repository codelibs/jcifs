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
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.internal.smb2.nego.Smb2NegotiateResponse;

/**
 * Test-only window onto the negotiated connection state.
 *
 * <p>
 * {@code SmbTransportImpl.getNegotiateResponse()} is package private, so this
 * class lives in the implementation package purely so integration tests can ask
 * what was actually negotiated. Without it a test can only assert that a
 * connection succeeded, which is not enough to catch a configuration property
 * that is silently ignored.
 * </p>
 */
public final class SmbNegotiationProbe {

    private SmbNegotiationProbe() {
    }

    /**
     * Returns the dialect the server and client actually settled on.
     *
     * @param file any connected resource on the tree of interest
     * @return the negotiated dialect
     * @throws CIFSException if the connection cannot be established
     */
    public static DialectVersion negotiatedDialect(final SmbFile file) throws CIFSException {
        try (SmbTreeHandleImpl tree = (SmbTreeHandleImpl) file.getTreeHandle();
                SmbSessionImpl session = tree.getSession();
                SmbTransportImpl transport = session.getTransport()) {
            return transport.getNegotiateResponse().getSelectedDialect();
        }
    }

    /**
     * Returns whether signing was negotiated for the connection.
     *
     * @param file any connected resource on the tree of interest
     * @return true if signatures are in use
     * @throws CIFSException if the connection cannot be established
     */
    public static boolean signingNegotiated(final SmbFile file) throws CIFSException {
        try (SmbTreeHandleImpl tree = (SmbTreeHandleImpl) file.getTreeHandle();
                SmbSessionImpl session = tree.getSession();
                SmbTransportImpl transport = session.getTransport()) {
            return transport.getNegotiateResponse().isSigningNegotiated();
        }
    }

    /**
     * Returns the signing algorithm the server selected, or {@code -1} if the response carried no
     * SIGNING_CAPABILITIES context.
     *
     * <p>
     * As with the cipher, this is the only observable that distinguishes a successful negotiation from a silent
     * fallback: a signed session works identically under AES-CMAC and AES-GMAC, so asserting that traffic flows
     * says nothing about which algorithm protected it.
     * </p>
     *
     * @param file any connected resource on the tree of interest
     * @return the selected signing algorithm identifier, or -1 if none was negotiated
     * @throws CIFSException if the connection cannot be established
     */
    public static int negotiatedSigningAlgorithm(final SmbFile file) throws CIFSException {
        try (SmbTreeHandleImpl tree = (SmbTreeHandleImpl) file.getTreeHandle();
                SmbSessionImpl session = tree.getSession();
                SmbTransportImpl transport = session.getTransport()) {
            if (transport.getNegotiateResponse() instanceof final Smb2NegotiateResponse resp) {
                return resp.getSelectedSigningAlgorithm();
            }
            return -1;
        }
    }

    /**
     * Returns the encryption cipher the server selected, or {@code -1} if the response carried no encryption
     * negotiate context.
     *
     * <p>
     * Without this a test can only assert that encrypted traffic round trips, which passes identically whichever
     * cipher is in force - so a client that asked for AES-256 and silently got AES-128 would look correct. The
     * cipher is the only observable that tells those two apart.
     * </p>
     *
     * @param file any connected resource on the tree of interest
     * @return the selected cipher identifier, or -1 if none was negotiated
     * @throws CIFSException if the connection cannot be established
     */
    public static int negotiatedCipher(final SmbFile file) throws CIFSException {
        try (SmbTreeHandleImpl tree = (SmbTreeHandleImpl) file.getTreeHandle();
                SmbSessionImpl session = tree.getSession();
                SmbTransportImpl transport = session.getTransport()) {
            // The cipher is on the SMB2 response, not on the SmbNegotiationResponse interface, which is also what
            // an SMB1 negotiation returns. Answering -1 there matches what the SMB2 response itself reports when
            // no encryption context was negotiated, rather than making a cast failure the contract.
            if (transport.getNegotiateResponse() instanceof final Smb2NegotiateResponse resp) {
                return resp.getSelectedCipher();
            }
            return -1;
        }
    }
}
