/* org.codelibs.jcifs.smb smb client library in Java
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

package org.codelibs.jcifs.smb.ntlmssp;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.Cipher;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.NtlmUtil;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.ntlmssp.av.AvFlags;
import org.codelibs.jcifs.smb.ntlmssp.av.AvPair;
import org.codelibs.jcifs.smb.ntlmssp.av.AvPairs;
import org.codelibs.jcifs.smb.ntlmssp.av.AvSingleHost;
import org.codelibs.jcifs.smb.ntlmssp.av.AvTargetName;
import org.codelibs.jcifs.smb.ntlmssp.av.AvTimestamp;
import org.codelibs.jcifs.smb.util.Crypto;

/**
 * Represents an NTLMSSP Type-3 message.
 */
public class Type3Message extends NtlmMessage {

    private byte[] lmResponse;
    private byte[] ntResponse;
    private String domain;
    private String user;
    private String workstation;
    private byte[] masterKey = null;
    private byte[] sessionKey = null;
    private byte[] mic = null;
    private boolean micRequired;

    /**
     * Creates a Type-3 message using default values from the current
     * environment.
     *
     * @param tc
     *            context to use
     */
    public Type3Message(final CIFSContext tc) {
        setFlags(getDefaultFlags(tc));
        setDomain(tc.getConfig().getDefaultDomain());
        setUser(tc.getConfig().getDefaultUsername());
        setWorkstation(tc.getNameServiceClient().getLocalHost().getHostName());
    }

    /**
     * Creates a Type-3 message in response to the given Type-2 message.
     *
     * @param tc
     *            context to use
     * @param type2
     *            The Type-2 message which this represents a response to.
     * @param targetName
     *            SPN of the target system, optional
     * @param password
     *            The password to use when constructing the response.
     * @param domain
     *            The domain in which the user has an account.
     * @param user
     *            The username for the authenticating user.
     * @param workstation
     *            The workstation from which authentication is
     *            taking place.
     * @param flags the flags to use for the Type-3 message
     * @throws GeneralSecurityException if a cryptographic error occurs
     * @throws CIFSException if a CIFS protocol error occurs
     */
    public Type3Message(final CIFSContext tc, final Type2Message type2, final String targetName, final String password, final String domain,
            final String user, final String workstation, final int flags) throws GeneralSecurityException, CIFSException {
        // keep old behavior of anonymous auth when no password is provided
        this(tc, type2, targetName, password, domain, user, workstation, flags, false);
    }

    /**
     * Creates a Type-3 message in response to the given Type-2 message.
     *
     * @param tc
     *            context to use
     * @param type2
     *            The Type-2 message which this represents a response to.
     * @param targetName
     *            SPN of the target system, optional
     * @param password
     *            The password to use when constructing the response.
     * @param domain
     *            The domain in which the user has an account.
     * @param user
     *            The username for the authenticating user.
     * @param workstation
     *            The workstation from which authentication is
     *            taking place.
     * @param flags the flags to use for the Type-3 message
     * @param nonAnonymous
     *            actually perform authentication with empty password
     * @throws GeneralSecurityException if a cryptographic error occurs
     * @throws CIFSException if a CIFS protocol error occurs
     */
    public Type3Message(final CIFSContext tc, final Type2Message type2, final String targetName, final String password, final String domain,
            final String user, final String workstation, final int flags, final boolean nonAnonymous)
            throws GeneralSecurityException, CIFSException {
        this(tc, type2, targetName, null, password, domain, user, workstation, flags, nonAnonymous);
    }

    /**
     * Creates a Type-3 message in response to the given Type-2 message.
     *
     * @param tc
     *            context to use
     * @param type2
     *            The Type-2 message which this represents a response to.
     * @param targetName
     *            SPN of the target system, optional
     * @param passwordHash
     *            The NT password hash to use when constructing the response.
     * @param domain
     *            The domain in which the user has an account.
     * @param user
     *            The username for the authenticating user.
     * @param workstation
     *            The workstation from which authentication is
     *            taking place.
     * @param flags the flags to use for the Type-3 message
     * @throws GeneralSecurityException if a cryptographic error occurs
     * @throws CIFSException if a CIFS protocol error occurs
     */
    public Type3Message(final CIFSContext tc, final Type2Message type2, final String targetName, final byte[] passwordHash,
            final String domain, final String user, final String workstation, final int flags)
            throws CIFSException, GeneralSecurityException {
        this(tc, type2, targetName, passwordHash, null, domain, user, workstation, flags, true);
    }

    /**
     * Creates a Type-3 message in response to the given Type-2 message.
     *
     * @param tc
     *            context to use
     * @param type2
     *            The Type-2 message which this represents a response to.
     * @param targetName
     *            SPN of the target system, optional
     * @param passwordHash
     *            The NT password hash, takes precedence over password (which is no longer required unless legacy LM
     *            authentication is needed)
     * @param password
     *            The password to use when constructing the response.
     * @param domain
     *            The domain in which the user has an account.
     * @param user
     *            The username for the authenticating user.
     * @param workstation
     *            The workstation from which authentication is
     *            taking place.
     * @param flags the flags to use for the Type-3 message
     * @param nonAnonymous
     *            actually perform authentication with empty password
     * @throws GeneralSecurityException if a cryptographic error occurs
     * @throws CIFSException if a CIFS protocol error occurs
     */
    public Type3Message(final CIFSContext tc, final Type2Message type2, final String targetName, byte[] passwordHash, final String password,
            final String domain, final String user, final String workstation, final int flags, final boolean nonAnonymous)
            throws GeneralSecurityException, CIFSException {
        setFlags(flags | getDefaultFlags(tc, type2));
        setWorkstation(workstation);
        setDomain(domain);
        setUser(user);

        if (password == null && passwordHash == null || !nonAnonymous && password != null && password.length() == 0) {
            setLMResponse(null);
            setNTResponse(null);
            return;
        }

        if (passwordHash == null) {
            passwordHash = NtlmUtil.getNTHash(password);
        }

        switch (tc.getConfig().getLanManCompatibility()) {
        case 0:
        case 1:
            if (!getFlag(NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)) {
                setLMResponse(getLMResponse(tc, type2, password));
                setNTResponse(getNTResponse(tc, type2, passwordHash));
            } else {
                // NTLM2 Session Response

                final byte[] clientChallenge = new byte[24];
                tc.getConfig().getRandom().nextBytes(clientChallenge);
                java.util.Arrays.fill(clientChallenge, 8, 24, (byte) 0x00);

                final byte[] ntlm2Response = NtlmUtil.getNTLM2Response(passwordHash, type2.getChallenge(), clientChallenge);

                setLMResponse(clientChallenge);
                setNTResponse(ntlm2Response);

                final byte[] sessionNonce = new byte[16];
                System.arraycopy(type2.getChallenge(), 0, sessionNonce, 0, 8);
                System.arraycopy(clientChallenge, 0, sessionNonce, 8, 8);

                final MessageDigest md4 = Crypto.getMD4();
                md4.update(passwordHash);
                final byte[] userSessionKey = md4.digest();

                final MessageDigest hmac = Crypto.getHMACT64(userSessionKey);
                hmac.update(sessionNonce);
                final byte[] ntlm2SessionKey = hmac.digest();

                if (getFlag(NTLMSSP_NEGOTIATE_KEY_EXCH)) {
                    this.masterKey = new byte[16];
                    tc.getConfig().getRandom().nextBytes(this.masterKey);

                    final byte[] exchangedKey = new byte[16];
                    final Cipher arcfour = Crypto.getArcfour(ntlm2SessionKey);
                    arcfour.update(this.masterKey, 0, 16, exchangedKey, 0);
                    setEncryptedSessionKey(exchangedKey);
                } else {
                    this.masterKey = ntlm2SessionKey;
                }
            }
            break;
        case 2:
            final byte[] nt = getNTResponse(tc, type2, passwordHash);
            setLMResponse(nt);
            setNTResponse(nt);
            break;
        case 3:
        case 4:
        case 5:
            final byte[] ntlmClientChallengeInfo = type2.getTargetInformation();
            final List<AvPair> avPairs = ntlmClientChallengeInfo != null ? AvPairs.decode(ntlmClientChallengeInfo) : null;

            // if targetInfo has an MsvAvTimestamp
            // client should not send LmChallengeResponse
            final boolean haveTimestamp = AvPairs.contains(avPairs, AvPair.MsvAvTimestamp);
            if (!haveTimestamp) {
                final byte[] lmClientChallenge = new byte[8];
                tc.getConfig().getRandom().nextBytes(lmClientChallenge);
                setLMResponse(getLMv2Response(tc, type2, domain, user, passwordHash, lmClientChallenge));
            } else {
                setLMResponse(new byte[24]);
            }

            if (avPairs != null) {
                // make sure to set the TARGET_INFO flag as we are sending
                setFlag(NtlmFlags.NTLMSSP_NEGOTIATE_TARGET_INFO, true);
            }

            final byte[] responseKeyNT = NtlmUtil.nTOWFv2(domain, user, passwordHash);
            final byte[] ntlmClientChallenge = new byte[8];
            tc.getConfig().getRandom().nextBytes(ntlmClientChallenge);

            long ts = (System.currentTimeMillis() + SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601) * 10000;
            if (haveTimestamp) {
                ts = ((AvTimestamp) AvPairs.get(avPairs, AvPair.MsvAvTimestamp)).getTimestamp();
            }

            setNTResponse(getNTLMv2Response(tc, type2, responseKeyNT, ntlmClientChallenge,
                    makeAvPairs(tc, targetName, avPairs, haveTimestamp, ts), ts));

            final MessageDigest hmac = Crypto.getHMACT64(responseKeyNT);
            hmac.update(this.ntResponse, 0, 16); // only first 16 bytes of ntResponse
            final byte[] userSessionKey = hmac.digest();

            if (getFlag(NTLMSSP_NEGOTIATE_KEY_EXCH)) {
                this.masterKey = new byte[16];
                tc.getConfig().getRandom().nextBytes(this.masterKey);

                final byte[] encryptedKey = new byte[16];
                final Cipher rc4 = Crypto.getArcfour(userSessionKey);
                rc4.update(this.masterKey, 0, 16, encryptedKey, 0);
                setEncryptedSessionKey(encryptedKey);
            } else {
                this.masterKey = userSessionKey;
            }

            break;
        default:
            setLMResponse(getLMResponse(tc, type2, password));
            setNTResponse(getNTResponse(tc, type2, passwordHash));
        }

    }

    private byte[] makeAvPairs(final CIFSContext tc, final String targetName, List<AvPair> serverAvPairs, final boolean haveServerTimestamp,
            final long ts) {
        if (!tc.getConfig().isEnforceSpnegoIntegrity() && serverAvPairs == null) {
            return null;
        }
        if (serverAvPairs == null) {
            serverAvPairs = new LinkedList<>();
        }

        if (getFlag(NTLMSSP_NEGOTIATE_SIGN)
                && (tc.getConfig().isEnforceSpnegoIntegrity() || haveServerTimestamp && !tc.getConfig().isDisableSpnegoIntegrity())) {
            // should provide MIC
            this.micRequired = true;
            this.mic = new byte[16];
            int curFlags = 0;
            final AvFlags cur = (AvFlags) AvPairs.get(serverAvPairs, AvPair.MsvAvFlags);
            if (cur != null) {
                curFlags = cur.getFlags();
            }
            curFlags |= 0x2; // MAC present
            AvPairs.replace(serverAvPairs, new AvFlags(curFlags));
        }

        AvPairs.replace(serverAvPairs, new AvTimestamp(ts));

        if (targetName != null) {
            AvPairs.replace(serverAvPairs, new AvTargetName(targetName));
        }

        // possibly add channel bindings
        AvPairs.replace(serverAvPairs, new AvPair(0xa, new byte[16]));
        AvPairs.replace(serverAvPairs, new AvSingleHost(tc.getConfig()));

        return AvPairs.encode(serverAvPairs);
    }

    /**
     * Sets the MIC
     *
     * @param type1 the Type-1 message bytes
     * @param type2 the Type-2 message bytes
     * @throws GeneralSecurityException if a cryptographic error occurs
     * @throws IOException if an I/O error occurs
     */
    public void setupMIC(final byte[] type1, final byte[] type2) throws GeneralSecurityException, IOException {
        final byte[] sk = this.masterKey;
        if (sk == null) {
            return;
        }
        final MessageDigest mac = Crypto.getHMACT64(sk);
        mac.update(type1);
        mac.update(type2);
        final byte[] type3 = toByteArray();
        mac.update(type3);
        setMic(mac.digest());
    }

    /**
     * Creates a Type-3 message with the specified parameters.
     *
     * @param flags
     *            The flags to apply to this message.
     * @param lmResponse
     *            The LanManager/LMv2 response.
     * @param ntResponse
     *            The NT/NTLMv2 response.
     * @param domain
     *            The domain in which the user has an account.
     * @param user
     *            The username for the authenticating user.
     * @param workstation
     *            The workstation from which authentication is
     *            taking place.
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
     * @param material
     *            The raw Type-3 material used to construct this message.
     * @throws IOException
     *             If an error occurs while parsing the material.
     */
    public Type3Message(final byte[] material) throws IOException {
        parse(material);
    }

    /**
     * Returns the default flags for a generic Type-3 message in the
     * current environment.
     *
     * @param tc
     *            context to use
     * @return An <code>int</code> containing the default flags.
     */
    public static int getDefaultFlags(final CIFSContext tc) {
        return NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_VERSION
                | (tc.getConfig().isUseUnicode() ? NTLMSSP_NEGOTIATE_UNICODE : NTLMSSP_NEGOTIATE_OEM);
    }

    /**
     * Returns the default flags for a Type-3 message created in response
     * to the given Type-2 message in the current environment.
     *
     * @param tc
     *            context to use
     * @param type2
     *            The Type-2 message.
     * @return An <code>int</code> containing the default flags.
     */
    public static int getDefaultFlags(final CIFSContext tc, final Type2Message type2) {
        if (type2 == null) {
            return getDefaultFlags(tc);
        }
        int flags = NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_VERSION;
        flags |= type2.getFlag(NTLMSSP_NEGOTIATE_UNICODE) ? NTLMSSP_NEGOTIATE_UNICODE : NTLMSSP_NEGOTIATE_OEM;
        return flags;
    }

    /**
     * Returns the LanManager/LMv2 response.
     *
     * @return A <code>byte[]</code> containing the LanManager response.
     */
    public byte[] getLMResponse() {
        return this.lmResponse;
    }

    /**
     * Sets the LanManager/LMv2 response for this message.
     *
     * @param lmResponse
     *            The LanManager response.
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
        return this.ntResponse;
    }

    /**
     * Sets the NT/NTLMv2 response for this message.
     *
     * @param ntResponse
     *            The NT/NTLMv2 response.
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
        return this.domain;
    }

    /**
     * Sets the domain for this message.
     *
     * @param domain
     *            The domain.
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
        return this.user;
    }

    /**
     * Sets the user for this message.
     *
     * @param user
     *            The user.
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
        return this.workstation;
    }

    /**
     * Sets the workstation for this message.
     *
     * @param workstation
     *            The workstation.
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
        return this.masterKey;
    }

    /**
     * Returns the session key.
     *
     * This is the encrypted session key included in the message,
     * if the actual session key is desired use {@link #getMasterKey()} instead.
     *
     * @return A <code>byte[]</code> containing the encrypted session key.
     */
    public byte[] getEncryptedSessionKey() {
        return this.sessionKey;
    }

    /**
     * Sets the session key.
     *
     * @param sessionKey
     *            The session key.
     */
    public void setEncryptedSessionKey(final byte[] sessionKey) {
        this.sessionKey = sessionKey;
    }

    /**
     * Returns the message integrity code (MIC) for this Type-3 message.
     *
     * @return A <code>byte[]</code> containing the message integrity code.
     */
    public byte[] getMic() {
        return this.mic;
    }

    /**
     * Sets the message integrity code (MIC) for this Type-3 message.
     *
     * @param mic
     *            NTLM mic to set (16 bytes)
     */
    public void setMic(final byte[] mic) {
        this.mic = mic;
    }

    /**
     * Checks whether a message integrity code (MIC) should be calculated for this message.
     *
     * @return whether a MIC should be calculated
     */
    public boolean isMICRequired() {
        return this.micRequired;
    }

    @Override
    public byte[] toByteArray() throws IOException {
        int size = 64;
        final boolean unicode = getFlag(NTLMSSP_NEGOTIATE_UNICODE);
        final String oemCp = unicode ? null : getOEMEncoding();

        final String domainName = getDomain();
        byte[] domainBytes = null;
        if (domainName != null && domainName.length() != 0) {
            domainBytes = unicode ? domainName.getBytes(UNI_ENCODING) : domainName.getBytes(oemCp);
            size += domainBytes.length;
        }

        final String userName = getUser();
        byte[] userBytes = null;
        if (userName != null && userName.length() != 0) {
            userBytes = unicode ? userName.getBytes(UNI_ENCODING) : userName.toUpperCase().getBytes(oemCp);
            size += userBytes.length;
        }

        final String workstationName = getWorkstation();
        byte[] workstationBytes = null;
        if (workstationName != null && workstationName.length() != 0) {
            workstationBytes = unicode ? workstationName.getBytes(UNI_ENCODING) : workstationName.toUpperCase().getBytes(oemCp);
            size += workstationBytes.length;
        }

        final byte[] micBytes = getMic();
        if (micBytes != null) {
            size += 8 + 16;
        } else if (getFlag(NTLMSSP_NEGOTIATE_VERSION)) {
            size += 8;
        }

        final byte[] lmResponseBytes = getLMResponse();
        size += lmResponseBytes != null ? lmResponseBytes.length : 0;

        final byte[] ntResponseBytes = getNTResponse();
        size += ntResponseBytes != null ? ntResponseBytes.length : 0;

        final byte[] sessionKeyBytes = getEncryptedSessionKey();
        size += sessionKeyBytes != null ? sessionKeyBytes.length : 0;

        final byte[] type3 = new byte[size];
        int pos = 0;

        System.arraycopy(NTLMSSP_SIGNATURE, 0, type3, 0, 8);
        pos += 8;

        writeULong(type3, pos, NTLMSSP_TYPE3);
        pos += 4;

        final int lmOff = writeSecurityBuffer(type3, 12, lmResponseBytes);
        pos += 8;
        final int ntOff = writeSecurityBuffer(type3, 20, ntResponseBytes);
        pos += 8;
        final int domOff = writeSecurityBuffer(type3, 28, domainBytes);
        pos += 8;
        final int userOff = writeSecurityBuffer(type3, 36, userBytes);
        pos += 8;
        final int wsOff = writeSecurityBuffer(type3, 44, workstationBytes);
        pos += 8;
        final int skOff = writeSecurityBuffer(type3, 52, sessionKeyBytes);
        pos += 8;

        writeULong(type3, pos, getFlags());
        pos += 4;

        if (getFlag(NTLMSSP_NEGOTIATE_VERSION)) {
            System.arraycopy(NTLMSSP_VERSION, 0, type3, pos, NTLMSSP_VERSION.length);
            pos += NTLMSSP_VERSION.length;
        } else if (micBytes != null) {
            pos += NTLMSSP_VERSION.length;
        }

        if (micBytes != null) {
            System.arraycopy(micBytes, 0, type3, pos, 16);
            pos += 16;
        }

        pos += writeSecurityBufferContent(type3, pos, lmOff, lmResponseBytes);
        pos += writeSecurityBufferContent(type3, pos, ntOff, ntResponseBytes);
        pos += writeSecurityBufferContent(type3, pos, domOff, domainBytes);
        pos += writeSecurityBufferContent(type3, pos, userOff, userBytes);
        pos += writeSecurityBufferContent(type3, pos, wsOff, workstationBytes);
        pos += writeSecurityBufferContent(type3, pos, skOff, sessionKeyBytes);

        return type3;

    }

    @Override
    public String toString() {
        final String userString = getUser();
        final String domainString = getDomain();
        final String workstationString = getWorkstation();
        final byte[] lmResponseBytes = getLMResponse();
        final byte[] ntResponseBytes = getNTResponse();
        final byte[] sessionKeyBytes = getEncryptedSessionKey();

        return "Type3Message[domain=" + domainString + ",user=" + userString + ",workstation=" + workstationString + ",lmResponse="
                + (lmResponseBytes == null ? "null" : "<" + lmResponseBytes.length + " bytes>") + ",ntResponse="
                + (ntResponseBytes == null ? "null" : "<" + ntResponseBytes.length + " bytes>") + ",sessionKey="
                + (sessionKeyBytes == null ? "null" : "<" + sessionKeyBytes.length + " bytes>") + ",flags=0x"
                + org.codelibs.jcifs.smb.util.Hexdump.toHexString(getFlags(), 8) + "]";
    }

    /**
     * Constructs the LanManager response to the given Type-2 message using
     * the supplied password.
     *
     * @param tc
     *            context to use
     * @param type2
     *            The Type-2 message.
     * @param password
     *            The password.
     * @return A <code>byte[]</code> containing the LanManager response.
     * @throws GeneralSecurityException if a cryptographic error occurs
     */
    public static byte[] getLMResponse(final CIFSContext tc, final Type2Message type2, final String password)
            throws GeneralSecurityException {
        if (type2 == null || password == null) {
            return null;
        }
        return NtlmUtil.getPreNTLMResponse(tc, password, type2.getChallenge());
    }

    /**
     * Calculates the LMv2 response for NTLM authentication.
     *
     * @param tc the CIFS context
     * @param type2 the Type-2 message containing the server challenge
     * @param domain the domain name
     * @param user the username
     * @param password the user's password
     * @param clientChallenge the client challenge bytes
     * @return the calculated response
     * @throws GeneralSecurityException if a cryptographic error occurs
     */
    public static byte[] getLMv2Response(final CIFSContext tc, final Type2Message type2, final String domain, final String user,
            final String password, final byte[] clientChallenge) throws GeneralSecurityException {
        if (password == null) {
            return null;
        }
        return getLMv2Response(tc, type2, domain, user, NtlmUtil.getNTHash(password), clientChallenge);
    }

    /**
     * Calculates the LMv2 response using a pre-computed NT password hash.
     *
     * @param tc the CIFS context
     * @param type2 the Type-2 message containing the server challenge
     * @param domain the domain name
     * @param user the username
     * @param passwordHash
     *            NT password hash
     * @param clientChallenge the client challenge bytes
     * @return the calculated response
     * @throws GeneralSecurityException if a cryptographic error occurs
     */
    public static byte[] getLMv2Response(final CIFSContext tc, final Type2Message type2, final String domain, final String user,
            final byte[] passwordHash, final byte[] clientChallenge) throws GeneralSecurityException {
        if (type2 == null || domain == null || user == null || passwordHash == null || clientChallenge == null) {
            return null;
        }
        return NtlmUtil.getLMv2Response(domain, user, passwordHash, type2.getChallenge(), clientChallenge);
    }

    /**
     * Calculates the NTLMv2 response for authentication.
     *
     * @param tc
     *            context to use
     * @param type2
     *            The Type-2 message.
     * @param responseKeyNT the NT response key
     * @param clientChallenge the client challenge bytes
     * @param clientChallengeInfo additional client challenge information
     * @param ts
     *            timestamp (nanos since 1601)
     * @return A <code>byte[]</code> containing the NTLMv2 response.
     */
    public static byte[] getNTLMv2Response(final CIFSContext tc, final Type2Message type2, final byte[] responseKeyNT,
            final byte[] clientChallenge, final byte[] clientChallengeInfo, final long ts) {
        if (type2 == null || responseKeyNT == null || clientChallenge == null) {
            return null;
        }
        return NtlmUtil.getNTLMv2Response(responseKeyNT, type2.getChallenge(), clientChallenge, ts, clientChallengeInfo);
    }

    /**
     * Constructs the NT response to the given Type-2 message using
     * the supplied password.
     *
     * @param tc
     *            context to use
     * @param type2
     *            The Type-2 message.
     * @param password
     *            The password.
     * @return A <code>byte[]</code> containing the NT response.
     * @throws GeneralSecurityException if a cryptographic error occurs
     */
    public static byte[] getNTResponse(final CIFSContext tc, final Type2Message type2, final String password)
            throws GeneralSecurityException {
        if (password == null) {
            return null;
        }
        return getNTResponse(tc, type2, NtlmUtil.getNTHash(password));
    }

    /**
     * Constructs the NT response to the given Type-2 message using
     * the supplied password.
     *
     * @param tc
     *            context to use
     * @param type2
     *            The Type-2 message.
     * @param passwordHash
     *            The NT password hash.
     * @return A <code>byte[]</code> containing the NT response.
     * @throws GeneralSecurityException if a cryptographic error occurs
     */
    public static byte[] getNTResponse(final CIFSContext tc, final Type2Message type2, final byte[] passwordHash)
            throws GeneralSecurityException {
        if (type2 == null || passwordHash == null) {
            return null;
        }
        return NtlmUtil.getNTLMResponse(passwordHash, type2.getChallenge());
    }

    private void parse(final byte[] material) throws IOException {
        int pos = 0;
        for (int i = 0; i < 8; i++) {
            if (material[i] != NTLMSSP_SIGNATURE[i]) {
                throw new IOException("Not an NTLMSSP message.");
            }
        }

        pos += 8;
        if (readULong(material, pos) != NTLMSSP_TYPE3) {
            throw new IOException("Not a Type 3 message.");
        }
        pos += 4;

        final byte[] lmResponseBytes = readSecurityBuffer(material, pos);
        setLMResponse(lmResponseBytes);
        final int lmResponseOffset = readULong(material, pos + 4);
        pos += 8;

        final byte[] ntResponseBytes = readSecurityBuffer(material, pos);
        setNTResponse(ntResponseBytes);
        final int ntResponseOffset = readULong(material, pos + 4);
        pos += 8;

        final byte[] domainBytes = readSecurityBuffer(material, pos);
        final int domainOffset = readULong(material, pos + 4);
        pos += 8;

        final byte[] userBytes = readSecurityBuffer(material, pos);
        final int userOffset = readULong(material, pos + 4);
        pos += 8;

        final byte[] workstationBytes = readSecurityBuffer(material, pos);
        final int workstationOffset = readULong(material, pos + 4);
        pos += 8;

        boolean end = false;
        int flags;
        String charset;
        if (lmResponseOffset < pos + 12 || ntResponseOffset < pos + 12 || domainOffset < pos + 12 || userOffset < pos + 12
                || workstationOffset < pos + 12) {
            // no room for SK/Flags
            flags = NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_OEM;
            setFlags(flags);
            charset = getOEMEncoding();
            end = true;
        } else {
            setEncryptedSessionKey(readSecurityBuffer(material, pos));
            pos += 8;

            flags = readULong(material, pos);
            setFlags(flags);
            pos += 4;

            charset = (flags & NTLMSSP_NEGOTIATE_UNICODE) != 0 ? UNI_ENCODING : getOEMEncoding();
        }

        setDomain(new String(domainBytes, charset));
        setUser(new String(userBytes, charset));
        setWorkstation(new String(workstationBytes, charset));

        final int micLen = pos + 24; // Version + MIC
        if (end || lmResponseOffset < micLen || ntResponseOffset < micLen || domainOffset < micLen || userOffset < micLen
                || workstationOffset < micLen) {
            return;
        }

        pos += 8; // Version

        final byte[] m = new byte[16];
        System.arraycopy(material, pos, m, 0, m.length);
        setMic(m);
    }

}
