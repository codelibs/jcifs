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
package org.codelibs.jcifs.smb.impl;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import javax.security.auth.Subject;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.RuntimeCIFSException;
import org.codelibs.jcifs.smb.spnego.NegTokenInit;
import org.codelibs.jcifs.smb.util.Crypto;
import org.codelibs.jcifs.smb.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class stores and encrypts NTLM user credentials.
 *
 * Contrary to {@link NtlmPasswordAuthentication} this does not cause guest authentication
 * when the "guest" username is supplied. Use {@link AuthenticationType} instead.
 *
 * @author mbechler
 */
public class NtlmPasswordAuthenticator implements Principal, CredentialsInternal, Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -4090263879887877186L;

    private static final Logger log = LoggerFactory.getLogger(NtlmPasswordAuthenticator.class);

    /** The authentication type */
    private AuthenticationType type;
    /** The authentication domain */
    private String domain;
    /** The username for authentication */
    private String username;
    /** The password for authentication */
    private String password;
    /** The client challenge for NTLM authentication */
    private byte[] clientChallenge = null;

    /**
     * Construct anonymous credentials
     */
    public NtlmPasswordAuthenticator() {
        this(AuthenticationType.NULL);
    }

    /**
     * Create an NtlmPasswordAuthenticator with the specified authentication type.
     *
     * @param type the authentication type to use
     */
    public NtlmPasswordAuthenticator(AuthenticationType type) {
        this.domain = "";
        this.username = "";
        this.password = "";
        this.type = type;
    }

    /**
     * Create username/password credentials
     *
     * @param username the username for authentication
     * @param password the password for authentication
     */
    public NtlmPasswordAuthenticator(String username, String password) {
        this(null, username, password);
    }

    /**
     * Create username/password credentials with specified domain
     *
     * @param domain the domain for authentication
     * @param username the username for authentication
     * @param password the password for authentication
     */
    public NtlmPasswordAuthenticator(String domain, String username, String password) {
        this(domain, username, password, AuthenticationType.USER);
    }

    /**
     * Create username/password credentials with specified domain
     *
     * @param domain the authentication domain
     * @param username the username for authentication
     * @param password the password for authentication
     * @param type
     *            authentication type
     */
    public NtlmPasswordAuthenticator(String domain, String username, String password, AuthenticationType type) {
        if (username != null) {
            int ci = username.indexOf('@');
            if (ci > 0) {
                domain = username.substring(ci + 1);
                username = username.substring(0, ci);
            } else {
                ci = username.indexOf('\\');
                if (ci > 0) {
                    domain = username.substring(0, ci);
                    username = username.substring(ci + 1);
                }
            }
        }

        this.domain = domain != null ? domain : "";
        this.username = username != null ? username : "";
        this.password = password != null ? password : "";
        if (type == null) {
            this.type = guessAuthenticationType();
        } else {
            this.type = type;
        }
    }

    /**
     * Create an NtlmPasswordAuthenticator from user info with defaults.
     *
     * @param userInfo the user information string
     * @param defDomain the default domain if not specified
     * @param defUser the default username if not specified
     * @param defPassword the default password if not specified
     */
    protected NtlmPasswordAuthenticator(String userInfo, String defDomain, String defUser, String defPassword) {
        this(userInfo, defDomain, defUser, defPassword, null);
    }

    /**
     * Create authenticator from URL userInfo string
     *
     * @param userInfo the userInfo string from URL
     * @param defDomain the default domain to use if not specified
     * @param defUser the default username to use if not specified
     * @param defPassword the default password to use if not specified
     * @param type the authentication type to use
     */
    protected NtlmPasswordAuthenticator(String userInfo, String defDomain, String defUser, String defPassword, AuthenticationType type) {
        String dom = null, user = null, pass = null;
        if (userInfo != null) {
            try {
                userInfo = unescape(userInfo);
            } catch (UnsupportedEncodingException uee) {
                throw new RuntimeCIFSException(uee);
            }
            int i, u;
            int end = userInfo.length();
            for (i = 0, u = 0; i < end; i++) {
                char c = userInfo.charAt(i);
                if (c == ';') {
                    dom = userInfo.substring(0, i);
                    u = i + 1;
                } else if (c == ':') {
                    pass = userInfo.substring(i + 1);
                    break;
                }
            }
            user = userInfo.substring(u, i);
        }

        this.domain = dom != null ? dom : defDomain != null ? defDomain : "";
        this.username = user != null ? user : defUser != null ? defUser : "";
        this.password = pass != null ? pass : defPassword != null ? defPassword : "";

        if (type == null) {
            this.type = guessAuthenticationType();
        } else {
            this.type = type;
        }
    }

    /**
     * Guess the authentication type based on the username format
     *
     * @return the guessed authentication type
     */
    protected AuthenticationType guessAuthenticationType() {
        AuthenticationType t = AuthenticationType.USER;
        if ("guest".equalsIgnoreCase(this.username)) {
            t = AuthenticationType.GUEST;
        } else if ((getUserDomain() == null || getUserDomain().isEmpty()) && getUsername().isEmpty() && getPassword().isEmpty()) {
            t = AuthenticationType.NULL;
        }
        return t;
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T extends Credentials> T unwrap(Class<T> t) {
        if (t.isAssignableFrom(this.getClass())) {
            return (T) this;
        }
        return null;
    }

    @Override
    public Subject getSubject() {
        return null;
    }

    @Override
    public void refresh() throws CIFSException {
    }

    /**
     *
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.impl.CredentialsInternal#createContext(org.codelibs.jcifs.smb.CIFSContext, java.lang.String, java.lang.String, byte[],
     *      boolean)
     */
    @Override
    public SSPContext createContext(CIFSContext tc, String targetDomain, String host, byte[] initialToken, boolean doSigning)
            throws SmbException {
        if (tc.getConfig().isUseRawNTLM()) {
            return setupTargetName(tc, host, new NtlmContext(tc, this, doSigning));
        }

        try {
            if (initialToken != null && initialToken.length > 0) {
                NegTokenInit tok = new NegTokenInit(initialToken);
                if (log.isDebugEnabled()) {
                    log.debug("Have initial token " + tok);
                }
                if (tok.getMechanisms() != null) {
                    Set<ASN1ObjectIdentifier> mechs = new HashSet<>(Arrays.asList(tok.getMechanisms()));
                    if (!mechs.contains(NtlmContext.NTLMSSP_OID)) {
                        throw new SmbUnsupportedOperationException("Server does not support NTLM authentication");
                    }
                }
            }
        } catch (SmbException e) {
            throw e;
        } catch (IOException e1) {
            log.debug("Ignoring invalid initial token", e1);
        }

        return new SpnegoContext(tc.getConfig(), setupTargetName(tc, host, new NtlmContext(tc, this, doSigning)));
    }

    private static SSPContext setupTargetName(CIFSContext tc, String host, NtlmContext ntlmContext) {
        if (host != null && tc.getConfig().isSendNTLMTargetName()) {
            ntlmContext.setTargetName(String.format("cifs/%s", host));
        }
        return ntlmContext;
    }

    @Override
    public NtlmPasswordAuthenticator clone() {
        NtlmPasswordAuthenticator cloned = new NtlmPasswordAuthenticator();
        cloneInternal(cloned, this);
        return cloned;
    }

    /**
     * Clone internal fields from one authenticator to another.
     *
     * @param cloned the target authenticator to copy to
     * @param toClone the source authenticator to copy from
     */
    protected static void cloneInternal(NtlmPasswordAuthenticator cloned, NtlmPasswordAuthenticator toClone) {
        cloned.domain = toClone.domain;
        cloned.username = toClone.username;
        cloned.password = toClone.password;
        cloned.type = toClone.type;
    }

    /**
     * Returns the domain.
     */
    @Override
    public String getUserDomain() {
        return this.domain;
    }

    /**
     * Get the original specified user domain
     *
     * @return the original specified user domain
     */
    public String getSpecifiedUserDomain() {
        return this.domain;
    }

    /**
     * Returns the username.
     *
     * @return the username
     */
    public String getUsername() {
        return this.username;
    }

    /**
     * Returns the password in plain text or <code>null</code> if the raw password
     * hashes were used to construct this <code>NtlmPasswordAuthentication</code>
     * object which will be the case when NTLM HTTP Authentication is
     * used. There is no way to retrieve a users password in plain text unless
     * it is supplied by the user at runtime.
     *
     * @return the password
     */
    public String getPassword() {
        return this.password;
    }

    /**
     * Return the domain and username in the format:
     * <code>domain\\username</code>. This is equivalent to <code>toString()</code>.
     */
    @Override
    public String getName() {
        boolean d = this.domain != null && this.domain.length() > 0;
        return d ? this.domain + "\\" + this.username : this.username;
    }

    /**
     * Compares two <code>NtlmPasswordAuthentication</code> objects for equality.
     *
     * Two <code>NtlmPasswordAuthentication</code> objects are equal if their caseless domain and username fields are equal
     *
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof NtlmPasswordAuthenticator ntlm) {
            String domA = ntlm.getUserDomain() != null ? ntlm.getUserDomain().toUpperCase() : null;
            String domB = this.getUserDomain() != null ? this.getUserDomain().toUpperCase() : null;
            return ntlm.type == this.type && Objects.equals(domA, domB) && ntlm.getUsername().equalsIgnoreCase(this.getUsername())
                    && Objects.equals(getPassword(), ntlm.getPassword());
        }
        return false;
    }

    /**
     * Return the upcased username hash code.
     */
    @Override
    public int hashCode() {
        return getName().toUpperCase().hashCode();
    }

    /**
     * Return the domain and username in the format:
     * <code>domain\\username</code>. This is equivalent to <code>getName()</code>.
     */
    @Override
    public String toString() {
        return getName();
    }

    @Override
    public boolean isAnonymous() {
        return this.type == AuthenticationType.NULL;
    }

    @Override
    public boolean isGuest() {
        return this.type == AuthenticationType.GUEST;
    }

    static String unescape(String str) throws NumberFormatException, UnsupportedEncodingException {
        char ch;
        int i, j, state, len;
        char[] out;
        byte[] b = new byte[1];

        if (str == null) {
            return null;
        }

        len = str.length();
        out = new char[len];
        state = 0;
        for (i = j = 0; i < len; i++) {
            switch (state) {
            case 0:
                ch = str.charAt(i);
                if (ch == '%') {
                    state = 1;
                } else {
                    out[j++] = ch;
                }
                break;
            case 1:
                /*
                 * Get ASCII hex value and convert to platform dependent
                 * encoding like EBCDIC perhaps
                 */
                b[0] = (byte) (Integer.parseInt(str.substring(i, i + 2), 16) & 0xFF);
                out[j] = new String(b, 0, 1, "ASCII").charAt(0);
                j++;
                i++;
                state = 0;
            }
        }

        return new String(out, 0, j);
    }

    /**
     * Check if the given mechanism is preferred for this credential
     *
     * @param mechanism the mechanism to check
     * @return whether the given mechanism is the preferred one for this credential
     */
    public boolean isPreferredMech(ASN1ObjectIdentifier mechanism) {
        return NtlmContext.NTLMSSP_OID.equals(mechanism);
    }

    /**
     * Computes the 24 byte ANSI password hash given the 8 byte server challenge.
     *
     * @param tc the CIFS context
     * @param chlng the server challenge
     * @return the hash for the given challenge
     * @throws GeneralSecurityException if a security error occurs
     */
    public byte[] getAnsiHash(CIFSContext tc, byte[] chlng) throws GeneralSecurityException {
        switch (tc.getConfig().getLanManCompatibility()) {
        case 0:
        case 1:
            return NtlmUtil.getPreNTLMResponse(tc, this.password, chlng);
        case 2:
            return NtlmUtil.getNTLMResponse(this.password, chlng);
        case 3:
        case 4:
        case 5:
            if (this.clientChallenge == null) {
                this.clientChallenge = new byte[8];
                tc.getConfig().getRandom().nextBytes(this.clientChallenge);
            }
            return NtlmUtil.getLMv2Response(this.domain, this.username, this.password, chlng, this.clientChallenge);
        default:
            return NtlmUtil.getPreNTLMResponse(tc, this.password, chlng);
        }
    }

    /**
     * Computes the 24 byte Unicode password hash given the 8 byte server challenge.
     *
     * @param tc the CIFS context
     * @param chlng the server challenge
     * @return the hash for the given challenge
     * @throws GeneralSecurityException if a security error occurs
     */
    public byte[] getUnicodeHash(CIFSContext tc, byte[] chlng) throws GeneralSecurityException {
        return switch (tc.getConfig().getLanManCompatibility()) {
        case 0, 1, 2 -> NtlmUtil.getNTLMResponse(this.password, chlng);
        case 3, 4, 5 -> new byte[0];
        default -> NtlmUtil.getNTLMResponse(this.password, chlng);
        };
    }

    /**
     * Get the signing key for this authentication
     *
     * @param tc the CIFS context
     * @param chlng the server challenge
     * @return the signing key
     * @throws SmbException if an SMB error occurs
     * @throws GeneralSecurityException if a security error occurs
     */
    public byte[] getSigningKey(CIFSContext tc, byte[] chlng) throws SmbException, GeneralSecurityException {
        switch (tc.getConfig().getLanManCompatibility()) {
        case 0:
        case 1:
        case 2:
            byte[] signingKey = new byte[40];
            getUserSessionKey(tc, chlng, signingKey, 0);
            System.arraycopy(getUnicodeHash(tc, chlng), 0, signingKey, 16, 24);
            return signingKey;
        case 3:
        case 4:
        case 5:
            /*
             * This code is only called if extended security is not on. This will
             * all be cleaned up an normalized in JCIFS 2.x.
             */
            throw new SmbException(
                    "NTLMv2 requires extended security (org.codelibs.jcifs.smb.impl.client.useExtendedSecurity must be true if org.codelibs.jcifs.smb.impl.lmCompatibility >= 3)");
        }
        return null;
    }

    /**
     * Returns the effective user session key.
     *
     * @param tc the CIFS context
     * @param chlng
     *            The server challenge.
     * @return A <code>byte[]</code> containing the effective user session key,
     *         used in SMB MAC signing and NTLMSSP signing and sealing.
     */
    public byte[] getUserSessionKey(CIFSContext tc, byte[] chlng) {
        byte[] key = new byte[16];
        try {
            getUserSessionKey(tc, chlng, key, 0);
        } catch (Exception ex) {
            log.error("Failed to get session key", ex);
        }
        return key;
    }

    /**
     * Calculates the effective user session key.
     *
     * @param tc
     *            context to use
     * @param chlng
     *            The server challenge.
     * @param dest
     *            The destination array in which the user session key will be
     *            placed.
     * @param offset
     *            The offset in the destination array at which the
     *            session key will start.
     * @throws SmbException if an SMB error occurs
     */
    public void getUserSessionKey(CIFSContext tc, byte[] chlng, byte[] dest, int offset) throws SmbException {
        try {
            MessageDigest md4 = Crypto.getMD4();
            byte[] ntHash = getNTHash();
            switch (tc.getConfig().getLanManCompatibility()) {
            case 0:
            case 1:
            case 2:
                md4.update(ntHash);
                md4.digest(dest, offset, 16);
                break;
            case 3:
            case 4:
            case 5:
                synchronized (this) {
                    if (this.clientChallenge == null) {
                        this.clientChallenge = new byte[8];
                        tc.getConfig().getRandom().nextBytes(this.clientChallenge);
                    }
                }

                MessageDigest hmac = Crypto.getHMACT64(ntHash);
                hmac.update(Strings.getUNIBytes(this.username.toUpperCase()));
                hmac.update(Strings.getUNIBytes(this.domain.toUpperCase()));
                byte[] ntlmv2Hash = hmac.digest();
                hmac = Crypto.getHMACT64(ntlmv2Hash);
                hmac.update(chlng);
                hmac.update(this.clientChallenge);
                MessageDigest userKey = Crypto.getHMACT64(ntlmv2Hash);
                userKey.update(hmac.digest());
                userKey.digest(dest, offset, 16);
                break;
            default:
                md4.update(ntHash);
                md4.digest(dest, offset, 16);
                break;
            }
        } catch (Exception e) {
            throw new SmbException("", e);
        }
    }

    /**
     * Get the NT hash of the password
     *
     * @return the NT hash
     */
    protected byte[] getNTHash() {
        MessageDigest md4 = Crypto.getMD4();
        md4.update(Strings.getUNIBytes(this.password));
        return md4.digest();
    }

    /**
     * Authentication strategy
     *
     *
     */
    public enum AuthenticationType {
        /**
         * Null/anonymous authentication
         *
         * Login with no credentials
         */
        NULL,
        /**
         * Guest authentication
         *
         * Allows login with invalid credentials (username and/or password)
         * Fallback to anonymous authentication is permitted
         */
        GUEST,
        /**
         * Regular user authentication
         */
        USER
    }
}
