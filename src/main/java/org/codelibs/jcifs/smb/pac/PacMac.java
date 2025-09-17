/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package org.codelibs.jcifs.smb.pac;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.KerberosKey;

/**
 * Utility class for calculating and verifying PAC (Privilege Attribute Certificate) message authentication codes.
 * This class provides methods for computing MACs using various Kerberos encryption types including
 * ARCFOUR-HMAC-MD5 and AES-based HMAC algorithms.
 */
public class PacMac {

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private PacMac() {
        // Utility class
    }

    /**
     *
     */
    private static final String HMAC_KEY = "HMAC";
    private static final byte[] MD5_CONSTANT = "signaturekey\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] ZERO_IV = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    /**
     * Calculates a MAC using the ARCFOUR-HMAC-MD5 algorithm.
     * This method implements the Microsoft variant of the Kerberos ARCFOUR-HMAC-MD5 checksum.
     *
     * @param keyusage the Kerberos key usage number for this operation
     * @param key the encryption key to use for MAC calculation
     * @param data the data to calculate the MAC for
     * @return the calculated MAC bytes
     * @throws GeneralSecurityException if cryptographic operations fail
     */
    public static byte[] calculateMacArcfourHMACMD5(int keyusage, Key key, byte[] data) throws GeneralSecurityException {
        int ms_usage = mapArcfourMD5KeyUsage(keyusage);
        Mac mac = Mac.getInstance("HmacMD5");
        MessageDigest md = MessageDigest.getInstance("MD5");
        mac.init(key);
        byte[] dk = mac.doFinal(MD5_CONSTANT);
        try {
            // little endian
            md.update((byte) (ms_usage & 0xFF));
            md.update((byte) (ms_usage >> 8 & 0xFF));
            md.update((byte) (ms_usage >> 16 & 0xFF));
            md.update((byte) (ms_usage >> 24 & 0xFF));
            byte[] dgst = md.digest(data);
            mac.reset();
            mac.init(new SecretKeySpec(dk, HMAC_KEY));
            return mac.doFinal(dgst);
        } finally {
            Arrays.fill(dk, 0, dk.length, (byte) 0);
        }
    }

    private static int mapArcfourMD5KeyUsage(int keyusage) {
        int ms_usage = keyusage;
        switch (ms_usage) {
        case 3:
            ms_usage = 8;
        case 9:
            ms_usage = 8;
        case 23:
            ms_usage = 13;
        }
        return ms_usage;
    }

    /**
     * Calculates a MAC using HMAC-SHA1 with AES key derivation.
     * This method supports both AES-128 and AES-256 encryption types.
     *
     * @param usage the Kerberos key usage number for this operation
     * @param baseKey the base Kerberos key for key derivation
     * @param input the data to calculate the MAC for
     * @return the calculated MAC bytes (truncated to 12 bytes)
     * @throws GeneralSecurityException if cryptographic operations fail
     */
    public static byte[] calculateMacHMACAES(int usage, KerberosKey baseKey, byte[] input) throws GeneralSecurityException {
        byte[] cst = { (byte) (usage >> 24 & 0xFF), (byte) (usage >> 16 & 0xFF), (byte) (usage >> 8 & 0xFF), (byte) (usage & 0xFF),
                (byte) 0x99 };

        byte[] output = new byte[12];
        byte[] dk = deriveKeyAES(baseKey, cst); // Checksum key
        try {
            Mac m = Mac.getInstance("HmacSHA1");
            m.init(new SecretKeySpec(dk, HMAC_KEY));
            System.arraycopy(m.doFinal(input), 0, output, 0, 12);
            return output;
        } finally {
            Arrays.fill(dk, 0, dk.length, (byte) 0);
        }
    }

    /**
     * Derives an AES key using the Kerberos key derivation function.
     * This method implements the simplified key derivation for AES encryption types.
     *
     * @param key the base Kerberos key
     * @param constant the key derivation constant
     * @return the derived key bytes
     * @throws GeneralSecurityException if cryptographic operations fail
     */
    public static byte[] deriveKeyAES(KerberosKey key, byte[] constant) throws GeneralSecurityException {
        byte[] keybytes = key.getEncoded();
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keybytes, "AES"), new IvParameterSpec(ZERO_IV, 0, ZERO_IV.length));
        if (constant.length != cipher.getBlockSize()) {
            constant = expandNFold(constant, cipher.getBlockSize());
        }
        byte[] enc = constant;
        int klen = keybytes.length;
        byte[] dk = new byte[klen];
        for (int n = 0; n < klen;) {
            byte[] block = cipher.doFinal(enc);
            int len = Math.min(klen - n, block.length);
            System.arraycopy(block, 0, dk, n, len);
            n += len;
            enc = block;
        }
        return dk;
    }

    /**
     * Performs n-fold expansion of data as specified in RFC 3961.
     * This operation is used in Kerberos key derivation to expand or compress
     * input data to a specific output length.
     *
     * @param data the input data to expand
     * @param outlen the desired output length in bytes
     * @return the n-folded data of the specified length
     */
    public static byte[] expandNFold(byte[] data, int outlen) {
        int lcm = lcm(outlen, data.length);
        byte[] buf = new byte[outlen];
        int carry = 0;
        for (int i = lcm - 1; i >= 0; i--) {
            carry = carry_add(data, buf, carry, i);
        }

        if (carry != 0) {
            for (int i = outlen - 1; i >= 0; i--) {
                carry += buf[i] & 0xff;
                buf[i] = (byte) (carry & 0xff);
                carry >>>= 8;
            }
        }
        return buf;
    }

    private static int carry_add(byte[] data, byte[] out, int c, int i) {
        int ilen = data.length, olen = out.length;
        int msbit = ((ilen << 3) - 1 + ((ilen << 3) + 13) * (i / ilen) + (ilen - i % ilen << 3)) % (ilen << 3);
        int mshigh = msbit >>> 3, mslow = msbit & 7;
        int b = c + (out[i % olen] & 0xff)
                + (((data[(ilen - 1 - mshigh) % ilen] & 0xff) << 8 | data[(ilen - mshigh) % ilen] & 0xff) >>> mslow + 1 & 0xff);
        out[i % olen] = (byte) (b & 0xff);
        return b >>>= 8;
    }

    private static int lcm(int u, int v) {
        int a = u, b = v, c;
        while (b != 0) {
            c = b;
            b = a % b;
            a = c;
        }
        return u * v / a;
    }

    /**
     * Calculates a MAC (Message Authentication Code) for PAC data validation.
     * @param type the checksum type to use
     * @param keys map of available Kerberos keys indexed by encryption type
     * @param data the data to calculate the MAC for
     * @return the calculated mac bytes
     * @throws PACDecodingException if the MAC calculation fails or required keys are missing
     */
    public static byte[] calculateMac(int type, Map<Integer, KerberosKey> keys, byte[] data) throws PACDecodingException {
        try {
            int usage = 17;
            if (type == PacSignature.KERB_CHECKSUM_HMAC_MD5) {
                KerberosKey key = keys.get(PacSignature.ETYPE_ARCFOUR_HMAC);
                if (key == null) {
                    throw new PACDecodingException("Missing key");
                }
                return calculateMacArcfourHMACMD5(usage, key, data);
            } else {
                if ((type != PacSignature.HMAC_SHA1_96_AES128) && (type != PacSignature.HMAC_SHA1_96_AES256)) {
                    throw new PACDecodingException("Invalid MAC algorithm");
                }
                KerberosKey key = type == PacSignature.HMAC_SHA1_96_AES128 ? keys.get(PacSignature.ETYPE_AES128_CTS_HMAC_SHA1_96)
                        : keys.get(PacSignature.ETYPE_AES256_CTS_HMAC_SHA1_96);
                if (key == null) {
                    throw new PACDecodingException("Missing key");
                }
                return calculateMacHMACAES(usage, key, data);
            }

        } catch (GeneralSecurityException e) {
            throw new PACDecodingException("Failed to calculate MAC", e);
        }
    }

}
