/* jcifs smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
 *                  "Eric Glass" <jcifs at samba dot org>
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

package jcifs.smb1.smb1;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Principal;
import java.util.Arrays;
import java.util.Random;

import jcifs.smb1.Config;
import jcifs.smb1.util.DES;
import jcifs.smb1.util.Encdec;
import jcifs.smb1.util.HMACT64;
import jcifs.smb1.util.LogStream;
import jcifs.smb1.util.MD4;

/**
 * This class stores and encrypts NTLM user credentials. The default
 * credentials are retrieved from the <tt>jcifs.smb1.smb1.client.domain</tt>,
 * <tt>jcifs.smb1.smb1.client.username</tt>, and <tt>jcifs.smb1.smb1.client.password</tt>
 * properties.
 * <p>
 * Read <a href="../../../authhandler.html">jCIFS Exceptions and
 * NtlmAuthenticator</a> for related information.
 */

public final class NtlmPasswordAuthentication implements Principal, Serializable {

    private static final int LM_COMPATIBILITY = Config.getInt("jcifs.smb1.smb.lmCompatibility", 3);

    private static final Random RANDOM = new Random();

    private static LogStream log = LogStream.getInstance();

    // KGS!@#$%
    private static final byte[] S8 =
            { (byte) 0x4b, (byte) 0x47, (byte) 0x53, (byte) 0x21, (byte) 0x40, (byte) 0x23, (byte) 0x24, (byte) 0x25 };

    /* Accepts key multiple of 7
     * Returns enc multiple of 8
     * Multiple is the same like: 21 byte key gives 24 byte result
     */
    private static void E(final byte[] key, final byte[] data, final byte[] e) {
        final byte[] key7 = new byte[7];
        final byte[] e8 = new byte[8];

        for (int i = 0; i < key.length / 7; i++) {
            System.arraycopy(key, i * 7, key7, 0, 7);
            final DES des = new DES(key7);
            des.encrypt(data, e8);
            System.arraycopy(e8, 0, e, i * 8, 8);
        }
    }

    static String DEFAULT_DOMAIN;
    static String DEFAULT_USERNAME;
    static String DEFAULT_PASSWORD;
    static final String BLANK = "";

    public static final NtlmPasswordAuthentication ANONYMOUS = new NtlmPasswordAuthentication("", "", "");

    static void initDefaults() {
        if (DEFAULT_DOMAIN != null) {
            return;
        }
        DEFAULT_DOMAIN = Config.getProperty("jcifs.smb1.smb.client.domain", "?");
        DEFAULT_USERNAME = Config.getProperty("jcifs.smb1.smb.client.username", "GUEST");
        DEFAULT_PASSWORD = Config.getProperty("jcifs.smb1.smb.client.password", BLANK);
    }

    /**
     * Generate the ANSI DES hash for the password associated with these credentials.
     */
    static public byte[] getPreNTLMResponse(final String password, final byte[] challenge) {
        final byte[] p14 = new byte[14];
        final byte[] p21 = new byte[21];
        final byte[] p24 = new byte[24];
        byte[] passwordBytes;
        try {
            passwordBytes = password.toUpperCase().getBytes(SmbConstants.OEM_ENCODING);
        } catch (final UnsupportedEncodingException uee) {
            throw new RuntimeException("Try setting jcifs.smb1.encoding=US-ASCII", uee);
        }
        int passwordLength = passwordBytes.length;

        // Only encrypt the first 14 bytes of the password for Pre 0.12 NT LM
        if (passwordLength > 14) {
            passwordLength = 14;
        }
        System.arraycopy(passwordBytes, 0, p14, 0, passwordLength);
        E(p14, S8, p21);
        E(p21, challenge, p24);
        return p24;
    }

    /**
     * Generate the Unicode MD4 hash for the password associated with these credentials.
     */
    static public byte[] getNTLMResponse(final String password, final byte[] challenge) {
        byte[] uni = null;
        final byte[] p21 = new byte[21];
        final byte[] p24 = new byte[24];

        try {
            uni = password.getBytes(SmbConstants.UNI_ENCODING);
        } catch (final UnsupportedEncodingException uee) {
            if (LogStream.level > 0) {
                uee.printStackTrace(log);
            }
        }
        final MD4 md4 = new MD4();
        md4.update(uni);
        try {
            md4.digest(p21, 0, 16);
        } catch (final Exception ex) {
            if (LogStream.level > 0) {
                ex.printStackTrace(log);
            }
        }
        E(p21, challenge, p24);
        return p24;
    }

    /**
     * Creates the LMv2 response for the supplied information.
     *
     * @param domain The domain in which the username exists.
     * @param user The username.
     * @param password The user's password.
     * @param challenge The server challenge.
     * @param clientChallenge The client challenge (nonce).
     */
    public static byte[] getLMv2Response(final String domain, final String user, final String password, final byte[] challenge,
            final byte[] clientChallenge) {
        try {
            final byte[] hash = new byte[16];
            final byte[] response = new byte[24];
            // The next 2-1/2 lines of this should be placed with nTOWFv1 in place of password
            final MD4 md4 = new MD4();
            md4.update(password.getBytes(SmbConstants.UNI_ENCODING));
            HMACT64 hmac = new HMACT64(md4.digest());
            hmac.update(user.toUpperCase().getBytes(SmbConstants.UNI_ENCODING));
            hmac.update(domain.toUpperCase().getBytes(SmbConstants.UNI_ENCODING));
            hmac = new HMACT64(hmac.digest());
            hmac.update(challenge);
            hmac.update(clientChallenge);
            hmac.digest(response, 0, 16);
            System.arraycopy(clientChallenge, 0, response, 16, 8);
            return response;
        } catch (final Exception ex) {
            if (LogStream.level > 0) {
                ex.printStackTrace(log);
            }
            return null;
        }
    }

    public static byte[] getNTLM2Response(final byte[] nTOWFv1, final byte[] serverChallenge, final byte[] clientChallenge) {
        final byte[] sessionHash = new byte[8];

        try {
            MessageDigest md5;
            md5 = MessageDigest.getInstance("MD5");
            md5.update(serverChallenge);
            md5.update(clientChallenge, 0, 8);
            System.arraycopy(md5.digest(), 0, sessionHash, 0, 8);
        } catch (final GeneralSecurityException gse) {
            if (LogStream.level > 0) {
                gse.printStackTrace(log);
            }
            throw new RuntimeException("MD5", gse);
        }

        final byte[] key = new byte[21];
        System.arraycopy(nTOWFv1, 0, key, 0, 16);
        final byte[] ntResponse = new byte[24];
        E(key, sessionHash, ntResponse);

        return ntResponse;
    }

    public static byte[] nTOWFv1(final String password) {
        if (password == null) {
            throw new RuntimeException("Password parameter is required");
        }
        try {
            final MD4 md4 = new MD4();
            md4.update(password.getBytes(SmbConstants.UNI_ENCODING));
            return md4.digest();
        } catch (final UnsupportedEncodingException uee) {
            throw new RuntimeException(uee.getMessage());
        }
    }

    public static byte[] nTOWFv2(final String domain, final String username, final String password) {
        try {
            final MD4 md4 = new MD4();
            md4.update(password.getBytes(SmbConstants.UNI_ENCODING));
            final HMACT64 hmac = new HMACT64(md4.digest());
            hmac.update(username.toUpperCase().getBytes(SmbConstants.UNI_ENCODING));
            hmac.update(domain.getBytes(SmbConstants.UNI_ENCODING));
            return hmac.digest();
        } catch (final UnsupportedEncodingException uee) {
            throw new RuntimeException(uee.getMessage());
        }
    }

    static byte[] computeResponse(final byte[] responseKey, final byte[] serverChallenge, final byte[] clientData, final int offset,
            final int length) {
        final HMACT64 hmac = new HMACT64(responseKey);
        hmac.update(serverChallenge);
        hmac.update(clientData, offset, length);
        final byte[] mac = hmac.digest();
        final byte[] ret = new byte[mac.length + clientData.length];
        System.arraycopy(mac, 0, ret, 0, mac.length);
        System.arraycopy(clientData, 0, ret, mac.length, clientData.length);
        return ret;
    }

    public static byte[] getLMv2Response(final byte[] responseKeyLM, final byte[] serverChallenge, final byte[] clientChallenge) {
        return NtlmPasswordAuthentication.computeResponse(responseKeyLM, serverChallenge, clientChallenge, 0, clientChallenge.length);
    }

    public static byte[] getNTLMv2Response(final byte[] responseKeyNT, final byte[] serverChallenge, final byte[] clientChallenge,
            final long nanos1601, final byte[] targetInfo) {
        final int targetInfoLength = targetInfo != null ? targetInfo.length : 0;
        final byte[] temp = new byte[28 + targetInfoLength + 4];

        Encdec.enc_uint32le(0x00000101, temp, 0); // Header
        Encdec.enc_uint32le(0x00000000, temp, 4); // Reserved
        Encdec.enc_uint64le(nanos1601, temp, 8);
        System.arraycopy(clientChallenge, 0, temp, 16, 8);
        Encdec.enc_uint32le(0x00000000, temp, 24); // Unknown
        if (targetInfo != null) {
            System.arraycopy(targetInfo, 0, temp, 28, targetInfoLength);
        }
        Encdec.enc_uint32le(0x00000000, temp, 28 + targetInfoLength); // mystery bytes!

        return NtlmPasswordAuthentication.computeResponse(responseKeyNT, serverChallenge, temp, 0, temp.length);
    }

    static final NtlmPasswordAuthentication NULL = new NtlmPasswordAuthentication("", "", "");
    static final NtlmPasswordAuthentication GUEST = new NtlmPasswordAuthentication("?", "GUEST", "");
    static final NtlmPasswordAuthentication DEFAULT = new NtlmPasswordAuthentication(null);

    String domain;
    String username;
    String password;
    byte[] ansiHash;
    byte[] unicodeHash;
    boolean hashesExternal = false;
    byte[] clientChallenge = null;
    byte[] challenge = null;

    /**
     * Create an <tt>NtlmPasswordAuthentication</tt> object from the userinfo
     * component of an SMB URL like "<tt>domain;user:pass</tt>". This constructor
     * is used internally be jCIFS when parsing SMB URLs.
     */

    public NtlmPasswordAuthentication(String userInfo) {
        domain = username = password = null;

        if (userInfo != null) {
            try {
                userInfo = unescape(userInfo);
            } catch (final UnsupportedEncodingException uee) {}
            int i, u, end;
            char c;

            end = userInfo.length();
            for (i = 0, u = 0; i < end; i++) {
                c = userInfo.charAt(i);
                if (c == ';') {
                    domain = userInfo.substring(0, i);
                    u = i + 1;
                } else if (c == ':') {
                    password = userInfo.substring(i + 1);
                    break;
                }
            }
            username = userInfo.substring(u, i);
        }

        initDefaults();

        if (domain == null) {
            this.domain = DEFAULT_DOMAIN;
        }
        if (username == null) {
            this.username = DEFAULT_USERNAME;
        }
        if (password == null) {
            this.password = DEFAULT_PASSWORD;
        }
    }

    /**
     * Create an <tt>NtlmPasswordAuthentication</tt> object from a
     * domain, username, and password. Parameters that are <tt>null</tt>
     * will be substituted with <tt>jcifs.smb1.smb1.client.domain</tt>,
     * <tt>jcifs.smb1.smb1.client.username</tt>, <tt>jcifs.smb1.smb1.client.password</tt>
     * property values.
     */
    public NtlmPasswordAuthentication(String domain, String username, final String password) {
        int ci;

        if (username != null) {
            ci = username.indexOf('@');
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

        this.domain = domain;
        this.username = username;
        this.password = password;

        initDefaults();

        if (domain == null) {
            this.domain = DEFAULT_DOMAIN;
        }
        if (username == null) {
            this.username = DEFAULT_USERNAME;
        }
        if (password == null) {
            this.password = DEFAULT_PASSWORD;
        }
    }

    /**
     * Create an <tt>NtlmPasswordAuthentication</tt> object with raw password
     * hashes. This is used exclusively by the <tt>jcifs.smb1.http.NtlmSsp</tt>
     * class which is in turn used by NTLM HTTP authentication functionality.
     */
    public NtlmPasswordAuthentication(final String domain, final String username, final byte[] challenge, final byte[] ansiHash,
            final byte[] unicodeHash) {
        if (domain == null || username == null || ansiHash == null || unicodeHash == null) {
            throw new IllegalArgumentException("External credentials cannot be null");
        }
        this.domain = domain;
        this.username = username;
        this.password = null;
        this.challenge = challenge;
        this.ansiHash = ansiHash;
        this.unicodeHash = unicodeHash;
        hashesExternal = true;
    }

    /**
     * Returns the domain.
     */
    public String getDomain() {
        return domain;
    }

    /**
     * Returns the username.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Returns the password in plain text or <tt>null</tt> if the raw password
     * hashes were used to construct this <tt>NtlmPasswordAuthentication</tt>
     * object which will be the case when NTLM HTTP Authentication is
     * used. There is no way to retrieve a users password in plain text unless
     * it is supplied by the user at runtime.
     */
    public String getPassword() {
        return password;
    }

    /**
     * Return the domain and username in the format:
     * <tt>domain\\username</tt>. This is equivalent to <tt>toString()</tt>.
     */
    @Override
    public String getName() {
        final boolean d = domain.length() > 0 && !domain.equals("?");
        return d ? domain + "\\" + username : username;
    }

    /**
     * Computes the 24 byte ANSI password hash given the 8 byte server challenge.
     */
    public byte[] getAnsiHash(final byte[] challenge) {
        if (hashesExternal) {
            return ansiHash;
        }
        switch (LM_COMPATIBILITY) {
        case 0:
        case 1:
            return getPreNTLMResponse(password, challenge);
        case 2:
            return getNTLMResponse(password, challenge);
        case 3:
        case 4:
        case 5:
            if (clientChallenge == null) {
                clientChallenge = new byte[8];
                RANDOM.nextBytes(clientChallenge);
            }
            return getLMv2Response(domain, username, password, challenge, clientChallenge);
        default:
            return getPreNTLMResponse(password, challenge);
        }
    }

    /**
     * Computes the 24 byte Unicode password hash given the 8 byte server challenge.
     */
    public byte[] getUnicodeHash(final byte[] challenge) {
        if (hashesExternal) {
            return unicodeHash;
        }
        return switch (LM_COMPATIBILITY) {
        case 0, 1, 2 -> getNTLMResponse(password, challenge);
        case 3, 4, 5 -> /*
                        if( clientChallenge == null ) {
                        clientChallenge = new byte[8];
                        RANDOM.nextBytes( clientChallenge );
                        }
                        return getNTLMv2Response(domain, username, password, null,
                            challenge, clientChallenge);
                        */ new byte[0];
        default -> getNTLMResponse(password, challenge);
        };
    }

    public byte[] getSigningKey(final byte[] challenge) throws SmbException {
        switch (LM_COMPATIBILITY) {
        case 0:
        case 1:
        case 2:
            final byte[] signingKey = new byte[40];
            getUserSessionKey(challenge, signingKey, 0);
            System.arraycopy(getUnicodeHash(challenge), 0, signingKey, 16, 24);
            return signingKey;
        case 3:
        case 4:
        case 5:
            /* This code is only called if extended security is not on. This will
             * all be cleaned up an normalized in JCIFS 2.x.
             */
            throw new SmbException(
                    "NTLMv2 requires extended security (jcifs.smb1.smb1.client.useExtendedSecurity must be true if jcifs.smb1.smb1.lmCompatibility >= 3)");
        }
        return null;
    }

    /**
     * Returns the effective user session key.
     *
     * @param challenge The server challenge.
     * @return A <code>byte[]</code> containing the effective user session key,
     * used in SMB MAC signing and NTLMSSP signing and sealing.
     */
    public byte[] getUserSessionKey(final byte[] challenge) {
        if (hashesExternal) {
            return null;
        }
        final byte[] key = new byte[16];
        try {
            getUserSessionKey(challenge, key, 0);
        } catch (final Exception ex) {
            if (LogStream.level > 0) {
                ex.printStackTrace(log);
            }
        }
        return key;
    }

    /**
     * Calculates the effective user session key.
     *
     * @param challenge The server challenge.
     * @param dest The destination array in which the user session key will be
     * placed.
     * @param offset The offset in the destination array at which the
     * session key will start.
     */
    void getUserSessionKey(final byte[] challenge, final byte[] dest, final int offset) throws SmbException {
        if (hashesExternal) {
            return;
        }
        try {
            final MD4 md4 = new MD4();
            md4.update(password.getBytes(SmbConstants.UNI_ENCODING));
            switch (LM_COMPATIBILITY) {
            case 0:
            case 1:
            case 2:
                md4.update(md4.digest());
                md4.digest(dest, offset, 16);
                break;
            case 3:
            case 4:
            case 5:
                if (clientChallenge == null) {
                    clientChallenge = new byte[8];
                    RANDOM.nextBytes(clientChallenge);
                }

                HMACT64 hmac = new HMACT64(md4.digest());
                hmac.update(username.toUpperCase().getBytes(SmbConstants.UNI_ENCODING));
                hmac.update(domain.toUpperCase().getBytes(SmbConstants.UNI_ENCODING));
                final byte[] ntlmv2Hash = hmac.digest();
                hmac = new HMACT64(ntlmv2Hash);
                hmac.update(challenge);
                hmac.update(clientChallenge);
                final HMACT64 userKey = new HMACT64(ntlmv2Hash);
                userKey.update(hmac.digest());
                userKey.digest(dest, offset, 16);
                break;
            default:
                md4.update(md4.digest());
                md4.digest(dest, offset, 16);
                break;
            }
        } catch (final Exception e) {
            throw new SmbException("", e);
        }
    }

    /**
     * Compares two <tt>NtlmPasswordAuthentication</tt> objects for
     * equality. Two <tt>NtlmPasswordAuthentication</tt> objects are equal if
     * their caseless domain and username fields are equal and either both hashes are external and they are equal or both internally supplied passwords are equal. If one <tt>NtlmPasswordAuthentication</tt> object has external hashes (meaning negotiated via NTLM HTTP Authentication) and the other does not they will not be equal. This is technically not correct however the server 8 byte challage would be required to compute and compare the password hashes but that it not available with this method.
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj instanceof final NtlmPasswordAuthentication ntlm) {
            if (ntlm.domain.toUpperCase().equals(domain.toUpperCase()) && ntlm.username.toUpperCase().equals(username.toUpperCase())) {
                if (hashesExternal && ntlm.hashesExternal) {
                    return Arrays.equals(ansiHash, ntlm.ansiHash) && Arrays.equals(unicodeHash, ntlm.unicodeHash);
                    /* This still isn't quite right. If one npa object does not have external
                     * hashes and the other does then they will not be considered equal even
                     * though they may be.
                     */
                }
                if (!hashesExternal && password.equals(ntlm.password)) {
                    return true;
                }
            }
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
     * <tt>domain\\username</tt>. This is equivalent to <tt>getName()</tt>.
     */
    @Override
    public String toString() {
        return getName();
    }

    static String unescape(final String str) throws NumberFormatException, UnsupportedEncodingException {
        char ch;
        int i, j, state, len;
        char[] out;
        final byte[] b = new byte[1];

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
                /* Get ASCII hex value and convert to platform dependant
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

}
