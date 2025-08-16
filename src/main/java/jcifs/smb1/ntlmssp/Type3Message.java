/* jcifs smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
 *                 "Eric Glass" <jcifs at samba dot org>
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

package jcifs.smb1.ntlmssp;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.SecureRandom;

import jcifs.smb1.Config;
import jcifs.smb1.netbios.NbtAddress;
import jcifs.smb1.smb1.NtlmPasswordAuthentication;
import jcifs.smb1.util.HMACT64;
import jcifs.smb1.util.MD4;
import jcifs.smb1.util.RC4;

/**
 * Represents an NTLMSSP Type-3 message.
 */
public class Type3Message extends NtlmMessage {

    static final long MILLISECONDS_BETWEEN_1970_AND_1601 = 11644473600000L;

    private static final int DEFAULT_FLAGS;

    private static final String DEFAULT_DOMAIN;

    private static final String DEFAULT_USER;

    private static final String DEFAULT_PASSWORD;

    private static final String DEFAULT_WORKSTATION;

    private static final int LM_COMPATIBILITY;

    private static final SecureRandom RANDOM = new SecureRandom();

    private byte[] lmResponse;

    private byte[] ntResponse;

    private String domain;

    private String user;

    private String workstation;

    private byte[] masterKey = null;
    private byte[] sessionKey = null;

    static {
        DEFAULT_FLAGS = NTLMSSP_NEGOTIATE_NTLM
                | (Config.getBoolean("jcifs.smb1.smb.client.useUnicode", true) ? NTLMSSP_NEGOTIATE_UNICODE : NTLMSSP_NEGOTIATE_OEM);
        DEFAULT_DOMAIN = Config.getProperty("jcifs.smb1.smb.client.domain", null);
        DEFAULT_USER = Config.getProperty("jcifs.smb1.smb.client.username", null);
        DEFAULT_PASSWORD = Config.getProperty("jcifs.smb1.smb.client.password", null);
        String defaultWorkstation = null;
        try {
            defaultWorkstation = NbtAddress.getLocalHost().getHostName();
        } catch (final UnknownHostException ex) {}
        DEFAULT_WORKSTATION = defaultWorkstation;
        LM_COMPATIBILITY = Config.getInt("jcifs.smb1.smb.lmCompatibility", 3);
    }

    /**
     * Creates a Type-3 message using default values from the current
     * environment.
     */
    public Type3Message() {
        setFlags(getDefaultFlags());
        setDomain(getDefaultDomain());
        setUser(getDefaultUser());
        setWorkstation(getDefaultWorkstation());
    }

    /**
     * Creates a Type-3 message in response to the given Type-2 message
     * using default values from the current environment.
     *
     * @param type2 The Type-2 message which this represents a response to.
     */
    public Type3Message(final Type2Message type2) {
        setFlags(getDefaultFlags(type2));
        setWorkstation(getDefaultWorkstation());
        final String domain = getDefaultDomain();
        setDomain(domain);
        final String user = getDefaultUser();
        setUser(user);
        final String password = getDefaultPassword();
        switch (LM_COMPATIBILITY) {
        case 0:
        case 1:
            setLMResponse(getLMResponse(type2, password));
            setNTResponse(getNTResponse(type2, password));
            break;
        case 2:
            final byte[] nt = getNTResponse(type2, password);
            setLMResponse(nt);
            setNTResponse(nt);
            break;
        case 3:
        case 4:
        case 5:
            final byte[] clientChallenge = new byte[8];
            RANDOM.nextBytes(clientChallenge);
            setLMResponse(getLMv2Response(type2, domain, user, password, clientChallenge));
            /*
            setNTResponse(getNTLMv2Response(type2, domain, user, password,
                    clientChallenge));
            */
            break;
        default:
            setLMResponse(getLMResponse(type2, password));
            setNTResponse(getNTResponse(type2, password));
        }
    }

    /**
     * Creates a Type-3 message in response to the given Type-2 message.
     *
     * @param type2 The Type-2 message which this represents a response to.
     * @param password The password to use when constructing the response.
     * @param domain The domain in which the user has an account.
     * @param user The username for the authenticating user.
     * @param workstation The workstation from which authentication is
     * taking place.
     */
    /**
     * Creates a Type-3 message in response to the given Type-2 message.
     *
     * @param type2 the Type-2 message to respond to
     * @param password the user's password
     * @param domain the domain name
     * @param user the username
     * @param workstation the workstation name
     * @param flags the flags to use for the Type-3 message
     */
    public Type3Message(final Type2Message type2, final String password, final String domain, final String user, String workstation,
            final int flags) {
        setFlags(flags | getDefaultFlags(type2));
        if (workstation == null) {
            workstation = getDefaultWorkstation();
        }
        setWorkstation(workstation);
        setDomain(domain);
        setUser(user);

        switch (LM_COMPATIBILITY) {
        case 0:
        case 1:
            if ((getFlags() & NTLMSSP_NEGOTIATE_NTLM2) == 0) {
                setLMResponse(getLMResponse(type2, password));
                setNTResponse(getNTResponse(type2, password));
            } else {
                // NTLM2 Session Response

                final byte[] clientChallenge = new byte[24];
                RANDOM.nextBytes(clientChallenge);
                java.util.Arrays.fill(clientChallenge, 8, 24, (byte) 0x00);

                // NTLMv1 w/ NTLM2 session sec and key exch all been verified with a debug build of smbclient

                final byte[] responseKeyNT = NtlmPasswordAuthentication.nTOWFv1(password);
                final byte[] ntlm2Response =
                        NtlmPasswordAuthentication.getNTLM2Response(responseKeyNT, type2.getChallenge(), clientChallenge);

                setLMResponse(clientChallenge);
                setNTResponse(ntlm2Response);

                if ((getFlags() & NTLMSSP_NEGOTIATE_SIGN) == NTLMSSP_NEGOTIATE_SIGN) {
                    final byte[] sessionNonce = new byte[16];
                    System.arraycopy(type2.getChallenge(), 0, sessionNonce, 0, 8);
                    System.arraycopy(clientChallenge, 0, sessionNonce, 8, 8);

                    final MD4 md4 = new MD4();
                    md4.update(responseKeyNT);
                    final byte[] userSessionKey = md4.digest();

                    final HMACT64 hmac = new HMACT64(userSessionKey);
                    hmac.update(sessionNonce);
                    final byte[] ntlm2SessionKey = hmac.digest();

                    if ((getFlags() & NTLMSSP_NEGOTIATE_KEY_EXCH) != 0) {
                        masterKey = new byte[16];
                        RANDOM.nextBytes(masterKey);

                        final byte[] exchangedKey = new byte[16];
                        final RC4 rc4 = new RC4(ntlm2SessionKey);
                        rc4.update(masterKey, 0, 16, exchangedKey, 0);
                        /* RC4 was not added to Java until 1.5u7 so let's use our own for a little while longer ...
                        try {
                            Cipher rc4 = Cipher.getInstance("RC4");
                            rc4.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(ntlm2SessionKey, "RC4"));
                            rc4.update(masterKey, 0, 16, exchangedKey, 0);
                        } catch (GeneralSecurityException gse) {
                            throw new RuntimeException("", gse);
                        }
                        */

                        setSessionKey(exchangedKey);
                    } else {
                        masterKey = ntlm2SessionKey;
                        setSessionKey(masterKey);
                    }
                }
            }
            break;
        case 2:
            final byte[] nt = getNTResponse(type2, password);
            setLMResponse(nt);
            setNTResponse(nt);
            break;
        case 3:
        case 4:
        case 5:
            final byte[] responseKeyNT = NtlmPasswordAuthentication.nTOWFv2(domain, user, password);

            final byte[] clientChallenge = new byte[8];
            RANDOM.nextBytes(clientChallenge);
            setLMResponse(getLMv2Response(type2, domain, user, password, clientChallenge));

            final byte[] clientChallenge2 = new byte[8];
            RANDOM.nextBytes(clientChallenge2);
            setNTResponse(getNTLMv2Response(type2, responseKeyNT, clientChallenge2));

            if ((getFlags() & NTLMSSP_NEGOTIATE_SIGN) == NTLMSSP_NEGOTIATE_SIGN) {
                final HMACT64 hmac = new HMACT64(responseKeyNT);
                hmac.update(ntResponse, 0, 16); // only first 16 bytes of ntResponse
                final byte[] userSessionKey = hmac.digest();

                if ((getFlags() & NTLMSSP_NEGOTIATE_KEY_EXCH) != 0) {
                    masterKey = new byte[16];
                    RANDOM.nextBytes(masterKey);

                    final byte[] exchangedKey = new byte[16];
                    final RC4 rc4 = new RC4(userSessionKey);
                    rc4.update(masterKey, 0, 16, exchangedKey, 0);
                    /* RC4 was not added to Java until 1.5u7 so let's use our own for a little while longer ...
                    try {
                        Cipher rc4 = Cipher.getInstance("RC4");
                        rc4.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(userSessionKey, "RC4"));
                        rc4.update(masterKey, 0, 16, exchangedKey, 0);
                    } catch (GeneralSecurityException gse) {
                        throw new RuntimeException("", gse);
                    }
                    */

                    setSessionKey(exchangedKey);
                } else {
                    masterKey = userSessionKey;
                    setSessionKey(masterKey);
                }
            }

            break;
        default:
            setLMResponse(getLMResponse(type2, password));
            setNTResponse(getNTResponse(type2, password));
        }
    }

    /**
     * Creates a Type-3 message with the specified parameters.
     *
     * @param flags The flags to apply to this message.
     * @param lmResponse The LanManager/LMv2 response.
     * @param ntResponse The NT/NTLMv2 response.
     * @param domain The domain in which the user has an account.
     * @param user The username for the authenticating user.
     * @param workstation The workstation from which authentication is
     * taking place.
     */
    public Type3Message(final int flags, final byte[] lmResponse, final byte[] ntResponse, final String domain, final String user,
            final String workstation) {
        setFlags(flags);
        setLMResponse(lmResponse);
        setNTResponse(ntResponse);
        setDomain(domain);
        setUser(user);
        setWorkstation(workstation);
    }

    /**
     * Creates a Type-3 message using the given raw Type-3 material.
     *
     * @param material The raw Type-3 material used to construct this message.
     * @throws IOException If an error occurs while parsing the material.
     */
    public Type3Message(final byte[] material) throws IOException {
        parse(material);
    }

    /**
     * Returns the LanManager/LMv2 response.
     *
     * @return A <code>byte[]</code> containing the LanManager response.
     */
    public byte[] getLMResponse() {
        return lmResponse;
    }

    /**
     * Sets the LanManager/LMv2 response for this message.
     *
     * @param lmResponse The LanManager response.
     */
    public void setLMResponse(final byte[] lmResponse) {
        this.lmResponse = lmResponse;
    }

    /**
     * Returns the NT/NTLMv2 response.
     *
     * @return A <code>byte[]</code> containing the NT/NTLMv2 response.
     */
    public byte[] getNTResponse() {
        return ntResponse;
    }

    /**
     * Sets the NT/NTLMv2 response for this message.
     *
     * @param ntResponse The NT/NTLMv2 response.
     */
    public void setNTResponse(final byte[] ntResponse) {
        this.ntResponse = ntResponse;
    }

    /**
     * Returns the domain in which the user has an account.
     *
     * @return A <code>String</code> containing the domain for the user.
     */
    public String getDomain() {
        return domain;
    }

    /**
     * Sets the domain for this message.
     *
     * @param domain The domain.
     */
    public void setDomain(final String domain) {
        this.domain = domain;
    }

    /**
     * Returns the username for the authenticating user.
     *
     * @return A <code>String</code> containing the user for this message.
     */
    public String getUser() {
        return user;
    }

    /**
     * Sets the user for this message.
     *
     * @param user The user.
     */
    public void setUser(final String user) {
        this.user = user;
    }

    /**
     * Returns the workstation from which authentication is being performed.
     *
     * @return A <code>String</code> containing the workstation.
     */
    public String getWorkstation() {
        return workstation;
    }

    /**
     * Sets the workstation for this message.
     *
     * @param workstation The workstation.
     */
    public void setWorkstation(final String workstation) {
        this.workstation = workstation;
    }

    /**
     * The real session key if the regular session key is actually
     * the encrypted version used for key exchange.
     *
     * @return A <code>byte[]</code> containing the session key.
     */
    public byte[] getMasterKey() {
        return masterKey;
    }

    /**
     * Returns the session key.
     *
     * @return A <code>byte[]</code> containing the session key.
     */
    public byte[] getSessionKey() {
        return sessionKey;
    }

    /**
     * Sets the session key.
     *
     * @param sessionKey The session key.
     */
    public void setSessionKey(final byte[] sessionKey) {
        this.sessionKey = sessionKey;
    }

    @Override
    public byte[] toByteArray() {
        try {
            final int flags = getFlags();
            final boolean unicode = (flags & NTLMSSP_NEGOTIATE_UNICODE) != 0;
            final String oem = unicode ? null : getOEMEncoding();
            final String domainName = getDomain();
            byte[] domain = null;
            if (domainName != null && domainName.length() != 0) {
                domain = unicode ? domainName.getBytes(UNI_ENCODING) : domainName.getBytes(oem);
            }
            final int domainLength = domain != null ? domain.length : 0;
            final String userName = getUser();
            byte[] user = null;
            if (userName != null && userName.length() != 0) {
                user = unicode ? userName.getBytes(UNI_ENCODING) : userName.toUpperCase().getBytes(oem);
            }
            final int userLength = user != null ? user.length : 0;
            final String workstationName = getWorkstation();
            byte[] workstation = null;
            if (workstationName != null && workstationName.length() != 0) {
                workstation = unicode ? workstationName.getBytes(UNI_ENCODING) : workstationName.toUpperCase().getBytes(oem);
            }
            final int workstationLength = workstation != null ? workstation.length : 0;
            final byte[] lmResponse = getLMResponse();
            final int lmLength = lmResponse != null ? lmResponse.length : 0;
            final byte[] ntResponse = getNTResponse();
            final int ntLength = ntResponse != null ? ntResponse.length : 0;
            final byte[] sessionKey = getSessionKey();
            final int keyLength = sessionKey != null ? sessionKey.length : 0;
            final byte[] type3 = new byte[64 + domainLength + userLength + workstationLength + lmLength + ntLength + keyLength];
            System.arraycopy(NTLMSSP_SIGNATURE, 0, type3, 0, 8);
            writeULong(type3, 8, 3);
            int offset = 64;
            writeSecurityBuffer(type3, 12, offset, lmResponse);
            offset += lmLength;
            writeSecurityBuffer(type3, 20, offset, ntResponse);
            offset += ntLength;
            writeSecurityBuffer(type3, 28, offset, domain);
            offset += domainLength;
            writeSecurityBuffer(type3, 36, offset, user);
            offset += userLength;
            writeSecurityBuffer(type3, 44, offset, workstation);
            offset += workstationLength;
            writeSecurityBuffer(type3, 52, offset, sessionKey);
            writeULong(type3, 60, flags);
            return type3;
        } catch (final IOException ex) {
            throw new IllegalStateException(ex.getMessage());
        }
    }

    @Override
    public String toString() {
        final String user = getUser();
        final String domain = getDomain();
        final String workstation = getWorkstation();
        final byte[] lmResponse = getLMResponse();
        final byte[] ntResponse = getNTResponse();
        final byte[] sessionKey = getSessionKey();

        return "Type3Message[domain=" + domain + ",user=" + user + ",workstation=" + workstation + ",lmResponse="
                + (lmResponse == null ? "null" : "<" + lmResponse.length + " bytes>") + ",ntResponse="
                + (ntResponse == null ? "null" : "<" + ntResponse.length + " bytes>") + ",sessionKey="
                + (sessionKey == null ? "null" : "<" + sessionKey.length + " bytes>") + ",flags=0x"
                + jcifs.smb1.util.Hexdump.toHexString(getFlags(), 8) + "]";
    }

    /**
     * Returns the default flags for a generic Type-3 message in the
     * current environment.
     *
     * @return An <code>int</code> containing the default flags.
     */
    public static int getDefaultFlags() {
        return DEFAULT_FLAGS;
    }

    /**
     * Returns the default flags for a Type-3 message created in response
     * to the given Type-2 message in the current environment.
     *
     * @param type2 the Type-2 message to respond to
     * @return An <code>int</code> containing the default flags.
     */
    public static int getDefaultFlags(final Type2Message type2) {
        if (type2 == null) {
            return DEFAULT_FLAGS;
        }
        int flags = NTLMSSP_NEGOTIATE_NTLM;
        flags |= (type2.getFlags() & NTLMSSP_NEGOTIATE_UNICODE) != 0 ? NTLMSSP_NEGOTIATE_UNICODE : NTLMSSP_NEGOTIATE_OEM;
        return flags;
    }

    /**
     * Constructs the LanManager response to the given Type-2 message using
     * the supplied password.
     *
     * @param type2 The Type-2 message.
     * @param password The password.
     * @return A <code>byte[]</code> containing the LanManager response.
     */
    public static byte[] getLMResponse(final Type2Message type2, final String password) {
        if (type2 == null || password == null) {
            return null;
        }
        return NtlmPasswordAuthentication.getPreNTLMResponse(password, type2.getChallenge());
    }

    /**
     * Calculates the LMv2 response for NTLM authentication.
     *
     * @param type2 the Type-2 message containing the server challenge
     * @param domain the domain name
     * @param user the username
     * @param password the user's password
     * @param clientChallenge the client challenge bytes
     * @return the calculated LMv2 response
     */
    public static byte[] getLMv2Response(final Type2Message type2, final String domain, final String user, final String password,
            final byte[] clientChallenge) {
        if (type2 == null || domain == null || user == null || password == null || clientChallenge == null) {
            return null;
        }
        return NtlmPasswordAuthentication.getLMv2Response(domain, user, password, type2.getChallenge(), clientChallenge);
    }

    /**
     * Calculates the NTLMv2 response for authentication.
     *
     * @param type2 the Type-2 message containing the server challenge
     * @param responseKeyNT the NT response key
     * @param clientChallenge the client challenge bytes
     * @return the calculated NTLMv2 response
     */
    public static byte[] getNTLMv2Response(final Type2Message type2, final byte[] responseKeyNT, final byte[] clientChallenge) {
        if (type2 == null || responseKeyNT == null || clientChallenge == null) {
            return null;
        }
        final long nanos1601 = (System.currentTimeMillis() + MILLISECONDS_BETWEEN_1970_AND_1601) * 10000L;
        return NtlmPasswordAuthentication.getNTLMv2Response(responseKeyNT, type2.getChallenge(), clientChallenge, nanos1601,
                type2.getTargetInformation());
    }

    /**
     * Constructs the NT response to the given Type-2 message using
     * the supplied password.
     *
     * @param type2 The Type-2 message.
     * @param password The password.
     * @return A <code>byte[]</code> containing the NT response.
     */
    public static byte[] getNTResponse(final Type2Message type2, final String password) {
        if (type2 == null || password == null) {
            return null;
        }
        return NtlmPasswordAuthentication.getNTLMResponse(password, type2.getChallenge());
    }

    /**
     * Returns the default domain from the current environment.
     *
     * @return The default domain.
     */
    public static String getDefaultDomain() {
        return DEFAULT_DOMAIN;
    }

    /**
     * Returns the default user from the current environment.
     *
     * @return The default user.
     */
    public static String getDefaultUser() {
        return DEFAULT_USER;
    }

    /**
     * Returns the default password from the current environment.
     *
     * @return The default password.
     */
    public static String getDefaultPassword() {
        return DEFAULT_PASSWORD;
    }

    /**
     * Returns the default workstation from the current environment.
     *
     * @return The default workstation.
     */
    public static String getDefaultWorkstation() {
        return DEFAULT_WORKSTATION;
    }

    private void parse(final byte[] material) throws IOException {
        for (int i = 0; i < 8; i++) {
            if (material[i] != NTLMSSP_SIGNATURE[i]) {
                throw new IOException("Not an NTLMSSP message.");
            }
        }
        if (readULong(material, 8) != 3) {
            throw new IOException("Not a Type 3 message.");
        }
        final byte[] lmResponse = readSecurityBuffer(material, 12);
        final int lmResponseOffset = readULong(material, 16);
        final byte[] ntResponse = readSecurityBuffer(material, 20);
        final int ntResponseOffset = readULong(material, 24);
        final byte[] domain = readSecurityBuffer(material, 28);
        final int domainOffset = readULong(material, 32);
        final byte[] user = readSecurityBuffer(material, 36);
        final int userOffset = readULong(material, 40);
        final byte[] workstation = readSecurityBuffer(material, 44);
        final int workstationOffset = readULong(material, 48);
        int flags;
        String charset;
        byte[] _sessionKey = null;
        if (lmResponseOffset == 52 || ntResponseOffset == 52 || domainOffset == 52 || userOffset == 52 || workstationOffset == 52) {
            flags = NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_OEM;
            charset = getOEMEncoding();
        } else {
            _sessionKey = readSecurityBuffer(material, 52);
            flags = readULong(material, 60);
            charset = (flags & NTLMSSP_NEGOTIATE_UNICODE) != 0 ? UNI_ENCODING : getOEMEncoding();
        }
        setSessionKey(_sessionKey);
        setFlags(flags);
        setLMResponse(lmResponse);
        setNTResponse(ntResponse);
        setDomain(new String(domain, charset));
        setUser(new String(user, charset));
        setWorkstation(new String(workstation, charset));
    }
}
