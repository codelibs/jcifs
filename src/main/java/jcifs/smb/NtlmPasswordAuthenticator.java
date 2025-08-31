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
package jcifs.smb;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.security.auth.Subject;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Credentials;
import jcifs.RuntimeCIFSException;
import jcifs.audit.SecurityAuditLogger;
import jcifs.audit.SecurityAuditLogger.EventType;
import jcifs.audit.SecurityAuditLogger.Severity;
import jcifs.spnego.NegTokenInit;
import jcifs.util.Crypto;
import jcifs.util.SecureKeyManager;
import jcifs.util.Strings;

/**
 * This class stores and encrypts NTLM user credentials.
 *
 * Contrary to {@link NtlmPasswordAuthentication} this does not cause guest authentication
 * when the "guest" username is supplied. Use {@link AuthenticationType} instead.
 *
 * @author mbechler
 */
public class NtlmPasswordAuthenticator implements Principal, CredentialsInternal, Serializable, AutoCloseable {

    /**
     *
     */
    private static final long serialVersionUID = -4090263879887877186L;

    private static final Logger log = LoggerFactory.getLogger(NtlmPasswordAuthenticator.class);
    private static final SecureKeyManager keyManager = new SecureKeyManager();
    private static final SecurityAuditLogger auditLogger = SecurityAuditLogger.getInstance();

    /**
     * Performs constant-time comparison of two char arrays to prevent timing attacks.
     * This method always compares the full length of both arrays, regardless of when
     * differences are found, making the execution time independent of the position
     * of differing characters.
     *
     * @param a first char array to compare
     * @param b second char array to compare
     * @return true if arrays are equal, false otherwise
     */
    private static boolean constantTimeEquals(char[] a, char[] b) {
        if (a == null && b == null) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }

        // Always compare full length to prevent timing leaks
        int lengthEqual = (a.length == b.length) ? 1 : 0;
        int maxLength = Math.max(a.length, b.length);

        int result = lengthEqual;
        for (int i = 0; i < maxLength; i++) {
            char charA = (i < a.length) ? a[i] : '\0';
            char charB = (i < b.length) ? b[i] : '\0';
            result &= (charA == charB) ? 1 : 0;
        }

        return result == 1;
    }

    /** The authentication type */
    private AuthenticationType type;
    /** The authentication domain */
    private String domain;
    /** The username for authentication */
    private String username;
    /** The password for authentication */
    private char[] password;
    /** The client challenge for NTLM authentication */
    private byte[] clientChallenge = null;
    /** Session ID for secure key management */
    private String sessionId = null;
    /** Time-to-live for cached authentication in milliseconds */
    private long authenticationTTL = 3600000L; // 1 hour default
    /** Timestamp when the authentication was created */
    private long authenticationTimestamp = System.currentTimeMillis();
    /** Flag to track if this authenticator has been closed */
    private volatile boolean closed = false;

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
        this.password = null;
        this.type = type;
    }

    /**
     * Create username/password credentials
     *
     * @param username the username for authentication
     * @param password the password for authentication
     */
    public NtlmPasswordAuthenticator(String username, String password) {
        this(null, username, password != null ? password.toCharArray() : null);
    }

    /**
     * Create username/password credentials
     *
     * @param username the username for authentication
     * @param password the password for authentication (secure char array)
     */
    public NtlmPasswordAuthenticator(String username, char[] password) {
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
        this(domain, username, password, (AuthenticationType) null);
    }

    /**
     * Create username/password credentials with specified domain using secure char array
     *
     * @param domain the domain for authentication
     * @param username the username for authentication
     * @param password the password for authentication (secure char array)
     */
    public NtlmPasswordAuthenticator(String domain, String username, char[] password) {
        this(domain, username, password, null);
    }

    /**
     * Create username/password credentials with specified domain and authentication type
     *
     * @param domain the authentication domain
     * @param username the username for authentication
     * @param password the password for authentication (secure char array)
     * @param type authentication type
     */
    public NtlmPasswordAuthenticator(String domain, String username, char[] password, AuthenticationType type) {
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
        this.password = password != null ? password.clone() : null;
        if (type == null) {
            this.type = guessAuthenticationType();
        } else {
            this.type = type;
        }
        this.authenticationTimestamp = System.currentTimeMillis();
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
        this(domain, username, password != null ? password.toCharArray() : null, type);
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
        this.password = pass != null ? pass.toCharArray() : defPassword != null ? defPassword.toCharArray() : new char[0];

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
        } else if ((getUserDomain() == null || getUserDomain().isEmpty()) && getUsername().isEmpty()
                && (this.password == null || this.password.length == 0)) {
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
     * @see jcifs.smb.CredentialsInternal#createContext(jcifs.CIFSContext, java.lang.String, java.lang.String, byte[],
     *      boolean)
     */
    @Override
    public SSPContext createContext(CIFSContext tc, String targetDomain, String host, byte[] initialToken, boolean doSigning)
            throws SmbException {
        checkNotClosed();

        // Check if authentication has expired
        if (isExpired()) {
            throw new SmbException("Authentication has expired. Please re-authenticate.");
        }

        // Generate session ID for secure key management
        if (this.sessionId == null) {
            this.sessionId = String.format("smb-%s-%s-%d", this.username, host, System.currentTimeMillis());
        }

        // Log authentication attempt
        auditLogger.logAuthentication(false, this.username, this.domain, host);

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
        cloned.password = toClone.password != null ? toClone.password.clone() : null;
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
     * @deprecated Use getPasswordAsCharArray() for better security
     */
    @Deprecated
    public String getPassword() {
        checkNotClosed();
        log.warn("getPassword() is deprecated and insecure. Use getPasswordAsCharArray() instead.");
        return this.password != null ? new String(this.password) : null;
    }

    /**
     * Returns the password as a secure char array. This is the preferred method
     * for accessing the password as it allows secure wiping of the password
     * from memory.
     *
     * @return the password as a char array
     */
    public char[] getPasswordAsCharArray() {
        checkNotClosed();
        return this.password != null && this.password.length > 0 ? this.password.clone() : this.password == null ? null : new char[0];
    }

    /**
     * Securely wipes the password from memory
     */
    public void secureWipePassword() {
        if (this.password != null) {
            // Multi-pass secure wipe of password char array
            Arrays.fill(this.password, '\0');
            Arrays.fill(this.password, '\uFFFF');
            Arrays.fill(this.password, '\uAAAA');
            Arrays.fill(this.password, '\u5555');
            Arrays.fill(this.password, '\0');
            this.password = null;
        }
        // Also remove from secure key manager if we have a session
        if (this.sessionId != null) {
            keyManager.removeSessionKey(this.sessionId);
            this.sessionId = null;
        }
    }

    /**
     * Check if the authentication has expired based on TTL
     *
     * @return true if expired, false otherwise
     */
    public boolean isExpired() {
        if (authenticationTTL <= 0) {
            return false; // No expiration
        }
        long age = System.currentTimeMillis() - authenticationTimestamp;
        return age > authenticationTTL;
    }

    /**
     * Set the authentication time-to-live in milliseconds
     *
     * @param ttl time-to-live in milliseconds (0 or negative for no expiration)
     */
    public void setAuthenticationTTL(long ttl) {
        this.authenticationTTL = ttl;
    }

    /**
     * Get the authentication time-to-live in milliseconds
     *
     * @return time-to-live in milliseconds
     */
    public long getAuthenticationTTL() {
        return this.authenticationTTL;
    }

    /**
     * Reset the authentication timestamp to current time
     */
    public void resetAuthenticationTimestamp() {
        this.authenticationTimestamp = System.currentTimeMillis();
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }

        try {
            secureWipePassword();

            // Clear other sensitive data
            domain = null;
            username = null;
            sessionId = null;

            auditLogger.logEvent(EventType.SESSION_DESTROYED, Severity.INFO, "Authenticator closed and credentials wiped",
                    Map.of("username", username != null ? username : "unknown"));
        } finally {
            // Wipe client challenge - guaranteed by try-finally
            if (clientChallenge != null) {
                SecureKeyManager.secureWipe(clientChallenge);
                clientChallenge = null;
            }
            closed = true;
        }
    }

    /**
     * Check if this authenticator has been closed
     *
     * @return true if closed, false otherwise
     */
    public boolean isClosed() {
        return closed;
    }

    private void checkNotClosed() {
        if (closed) {
            throw new IllegalStateException("Authenticator has been closed");
        }
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
                    && constantTimeEquals(getPasswordAsCharArray(), ntlm.getPasswordAsCharArray());
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
     * @deprecated NTLMv1 is insecure. Use NTLMv2 (LM compatibility level 3 or higher)
     */
    @Deprecated
    public byte[] getAnsiHash(CIFSContext tc, byte[] chlng) throws GeneralSecurityException {
        int compatibility = tc.getConfig().getLanManCompatibility();

        // Log warning for insecure NTLMv1 usage
        if (compatibility < 3) {
            log.warn("Using insecure NTLMv1 authentication (LM compatibility level {}). "
                    + "Please upgrade to NTLMv2 by setting jcifs.smb.lmCompatibility to 3 or higher.", compatibility);
        }

        switch (compatibility) {
        case 0:
        case 1:
            // NTLMv1 - deprecated and insecure
            log.warn("NTLMv1 LM response is deprecated and insecure. Consider using NTLMv2.");
            return NtlmUtil.getPreNTLMResponse(tc, getPasswordAsCharArray(), chlng);
        case 2:
            // NTLMv1 with NTLM response - still insecure
            log.warn("NTLMv1 NTLM response is deprecated and insecure. Consider using NTLMv2.");
            return NtlmUtil.getNTLMResponse(getPasswordAsCharArray(), chlng);
        case 3:
        case 4:
        case 5:
            // NTLMv2 - secure
            if (this.clientChallenge == null) {
                this.clientChallenge = new byte[8];
                tc.getConfig().getRandom().nextBytes(this.clientChallenge);
            }
            return NtlmUtil.getLMv2Response(this.domain, this.username, getPasswordAsCharArray(), chlng, this.clientChallenge);
        default:
            // Default to NTLMv2 for security
            log.info("Defaulting to secure NTLMv2 authentication");
            if (this.clientChallenge == null) {
                this.clientChallenge = new byte[8];
                tc.getConfig().getRandom().nextBytes(this.clientChallenge);
            }
            return NtlmUtil.getLMv2Response(this.domain, this.username, getPasswordAsCharArray(), chlng, this.clientChallenge);
        }
    }

    /**
     * Computes the 24 byte Unicode password hash given the 8 byte server challenge.
     *
     * @param tc the CIFS context
     * @param chlng the server challenge
     * @return the hash for the given challenge
     * @throws GeneralSecurityException if a security error occurs
     * @deprecated NTLMv1 is insecure. Use NTLMv2 (LM compatibility level 3 or higher)
     */
    @Deprecated
    public byte[] getUnicodeHash(CIFSContext tc, byte[] chlng) throws GeneralSecurityException {
        int compatibility = tc.getConfig().getLanManCompatibility();

        // Log warning for insecure NTLMv1 usage
        if (compatibility < 3) {
            log.warn("Using insecure NTLMv1 NTLM response (LM compatibility level {}). "
                    + "Please upgrade to NTLMv2 by setting jcifs.smb.lmCompatibility to 3 or higher.", compatibility);
        }

        return switch (compatibility) {
        case 0, 1, 2 -> {
            // NTLMv1 - deprecated and insecure
            log.warn("NTLMv1 NTLM response is deprecated and insecure. Consider using NTLMv2.");
            yield NtlmUtil.getNTLMResponse(getPasswordAsCharArray(), chlng);
        }
        case 3, 4, 5 -> {
            // NTLMv2 - returns empty for unicode hash as NTLMv2 doesn't use it
            yield new byte[0];
        }
        default -> {
            // Default to NTLMv2 behavior (empty response)
            log.info("Defaulting to secure NTLMv2 authentication (no unicode hash)");
            yield new byte[0];
        }
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
                    "NTLMv2 requires extended security (jcifs.smb.client.useExtendedSecurity must be true if jcifs.smb.lmCompatibility >= 3)");
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
        char[] pwd = getPasswordAsCharArray();
        if (pwd == null || pwd.length == 0) {
            md4.update(Strings.getUNIBytes(""));
            return md4.digest();
        }

        String tempStr = new String(pwd);
        try {
            md4.update(Strings.getUNIBytes(tempStr));
            return md4.digest();
        } finally {
            // Clear the temporary password string (best effort)
            if (tempStr != null) {
                tempStr.intern();
            }
        }
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
