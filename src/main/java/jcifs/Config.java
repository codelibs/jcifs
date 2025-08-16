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

package jcifs;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;
import java.util.StringTokenizer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.context.SingletonContext;

/**
 * This class now contains only utilities for config parsing.
 *
 * We strongly suggest that you create an explicit {@link jcifs.context.CIFSContextWrapper}
 * with your desired config. It's base implementation {@link jcifs.context.BaseContext}
 * should be sufficient for most needs.
 *
 * If you want to retain the classic singleton behavior you can use
 * {@link jcifs.context.SingletonContext#getInstance()}
 * witch is initialized using system properties.
 *
 */
public class Config {

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private Config() {
        // Utility class - not instantiable
    }

    private static final Logger log = LoggerFactory.getLogger(Config.class);

    /**
     * This static method registers the SMB URL protocol handler which is
     * required to use SMB URLs with the <code>java.net.URL</code> class. If this
     * method is not called before attempting to create an SMB URL with the
     * URL class the following exception will occur:
     * <blockquote>
     *
     * <pre>
     * Exception MalformedURLException: unknown protocol: smb
     *     at java.net.URL.&lt;init&gt;(URL.java:480)
     *     at java.net.URL.&lt;init&gt;(URL.java:376)
     *     at java.net.URL.&lt;init&gt;(URL.java:330)
     *     at jcifs.smb.SmbFile.&lt;init&gt;(SmbFile.java:355)
     *     ...
     * </pre>
     * </blockquote>
     */
    public static void registerSmbURLHandler() {
        SingletonContext.registerSmbURLHandler();
    }

    /**
     * Retrieve an <code>int</code>. If the key does not exist or
     * cannot be converted to an <code>int</code>, the provided default
     * argument will be returned.
     *
     * @param props the properties to search in
     * @param key the property key to look up
     * @param def the default value to return if key is not found or cannot be parsed
     * @return the integer value of the property or the default value
     */
    public static int getInt(final Properties props, final String key, int def) {
        final String s = props.getProperty(key);
        if (s != null) {
            try {
                def = Integer.parseInt(s);
            } catch (final NumberFormatException nfe) {
                log.error("Not a number", nfe);
            }
        }
        return def;
    }

    /**
     * Retrieve an <code>int</code>. If the property is not found, <code>-1</code> is returned.
     *
     * @param props the properties to search in
     * @param key the property key to look up
     * @return the integer value of the property or -1 if not found
     */
    public static int getInt(final Properties props, final String key) {
        final String s = props.getProperty(key);
        int result = -1;
        if (s != null) {
            try {
                result = Integer.parseInt(s);
            } catch (final NumberFormatException nfe) {
                log.error("Not a number", nfe);
            }
        }
        return result;
    }

    /**
     * Retrieve a <code>long</code>. If the key does not exist or
     * cannot be converted to a <code>long</code>, the provided default
     * argument will be returned.
     *
     * @param props the properties to search in
     * @param key the property key to look up
     * @param def the default value to return if key is not found or cannot be parsed
     * @return the long value of the property or the default value
     */
    public static long getLong(final Properties props, final String key, long def) {
        final String s = props.getProperty(key);
        if (s != null) {
            try {
                def = Long.parseLong(s);
            } catch (final NumberFormatException nfe) {
                log.error("Not a number", nfe);
            }
        }
        return def;
    }

    /**
     * Retrieve an <code>InetAddress</code>. If the address is not
     * an IP address and cannot be resolved <code>null</code> will
     * be returned.
     *
     * @param props the properties to search in
     * @param key the property key to look up
     * @param def the default value to return if key is not found or cannot be resolved
     * @return the InetAddress for the property or the default value
     */
    public static InetAddress getInetAddress(final Properties props, final String key, InetAddress def) {
        final String addr = props.getProperty(key);
        if (addr != null) {
            try {
                def = InetAddress.getByName(addr);
            } catch (final UnknownHostException uhe) {
                log.error("Unknown host " + addr, uhe);
            }
        }
        return def;
    }

    /**
     * Get the local host address based on the provided properties.
     *
     * @param props the properties to use for configuration
     * @return the local host InetAddress
     */
    public static InetAddress getLocalHost(final Properties props) {
        final String addr = props.getProperty("jcifs.smb.client.laddr");

        if (addr != null) {
            try {
                return InetAddress.getByName(addr);
            } catch (final UnknownHostException uhe) {
                log.error("Ignoring jcifs.smb.client.laddr address: " + addr, uhe);
            }
        }

        return null;
    }

    /**
     * Retrieve a boolean value. If the property is not found, the value of <code>def</code> is returned.
     *
     * @param props the properties to search in
     * @param key the property key to look up
     * @param def the default value to return if key is not found
     * @return the boolean value of the property or the default value
     */
    public static boolean getBoolean(final Properties props, final String key, boolean def) {
        final String b = props.getProperty(key);
        if (b != null) {
            def = b.toLowerCase().equals("true");
        }
        return def;
    }

    /**
     * Retrieve an array of <code>InetAddress</code> created from a property
     * value containing a <code>delim</code> separated list of host names and/or
     * ip addresses.
     *
     * @param props the properties to search in
     * @param key the property key to look up
     * @param delim the delimiter to use for splitting the property value
     * @param def the default value to return if key is not found
     * @return an array of InetAddress objects or the default value
     */
    public static InetAddress[] getInetAddressArray(final Properties props, final String key, final String delim, final InetAddress[] def) {
        final String p = props.getProperty(key);
        if (p != null) {
            final StringTokenizer tok = new StringTokenizer(p, delim);
            final int len = tok.countTokens();
            final InetAddress[] arr = new InetAddress[len];
            for (int i = 0; i < len; i++) {
                final String addr = tok.nextToken();
                try {
                    arr[i] = InetAddress.getByName(addr);
                } catch (final UnknownHostException uhe) {
                    log.error("Unknown host " + addr, uhe);
                    return def;
                }
            }
            return arr;
        }
        return def;
    }

}
