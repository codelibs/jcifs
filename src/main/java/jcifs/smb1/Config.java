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

package jcifs.smb1;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;
import java.util.StringTokenizer;

import jcifs.smb1.util.LogStream;

/**
 * This class uses a static {@link java.util.Properties} to act
 * as a cental repository for all jCIFS configuration properties. It cannot be
 * instantiated. Similar to <code>System</code> properties the namespace
 * is global therefore property names should be unique. Before use,
 * the <code>load</code> method should be called with the name of a
 * <code>Properties</code> file (or <code>null</code> indicating no
 * file) to initialize the <code>Config</code>. The <code>System</code>
 * properties will then populate the <code>Config</code> as well potentially
 * overwriting properties from the file. Thus properties provided on the
 * commandline with the <code>-Dproperty.name=value</code> VM parameter
 * will override properties from the configuration file.
 * <p>
 * There are several ways to set jCIFS properties. See
 * the <a href="../overview-summary.html#scp">overview page of the API
 * documentation</a> for details.
 */

public class Config {

    /**
     * Counter for tracking socket connections.
     */
    public static int socketCount = 0;

    /**
     * The static <code>Properties</code>.
     */

    private static Properties prp = new Properties();
    private static LogStream log;
    /**
     * Default OEM encoding used for SMB communication.
     */
    public static String DEFAULT_OEM_ENCODING = "Cp850";

    static {
        String filename;
        int level;
        FileInputStream in = null;

        log = LogStream.getInstance();

        try {
            filename = System.getProperty("jcifs_smb1.properties");
            if (filename != null && filename.length() > 1) {
                in = new FileInputStream(filename);
            }
            Config.load(in);
            if (in != null) {
                in.close();
            }
        } catch (final IOException ioe) {
            if (LogStream.level > 0) {
                ioe.printStackTrace(log);
            }
        }

        level = Config.getInt("jcifs.smb1.util.loglevel", -1);
        if (level != -1) {
            LogStream.setLevel(level);
        }

        try {
            "".getBytes(DEFAULT_OEM_ENCODING);
        } catch (final UnsupportedEncodingException uee) {
            if (LogStream.level >= 2) {
                log.println("WARNING: The default OEM encoding " + DEFAULT_OEM_ENCODING
                        + " does not appear to be supported by this JRE. The default encoding will be US-ASCII.");
            }
            DEFAULT_OEM_ENCODING = "US-ASCII";
        }

        if (LogStream.level >= 4) {
            try {
                prp.store(log, "JCIFS PROPERTIES");
            } catch (final IOException ioe) {}
        }
    }

    /**
     * This static method registers the SMB URL protocol handler which is
     * required to use SMB URLs with the <code>java.net.URL</code> class. If this
     * method is not called before attempting to create an SMB URL with the
     * URL class the following exception will occur:
     * <blockquote><pre>
     * Exception MalformedURLException: unknown protocol: smb
     *     at java.net.URL.&lt;init&gt;(URL.java:480)
     *     at java.net.URL.&lt;init&gt;(URL.java:376)
     *     at java.net.URL.&lt;init&gt;(URL.java:330)
     *     at jcifs.smb1.smb1.SmbFile.&lt;init&gt;(SmbFile.java:355)
     *     ...
     * </pre></blockquote>
     */

    public static void registerSmbURLHandler() {
        String ver, pkgs;

        ver = System.getProperty("java.version");
        if (ver.startsWith("1.1.") || ver.startsWith("1.2.")) {
            throw new RuntimeException("jcifs.smb1-0.7.0b4+ requires Java 1.3 or above. You are running " + ver);
        }
        pkgs = System.getProperty("java.protocol.handler.pkgs");
        if (pkgs == null) {
            System.setProperty("java.protocol.handler.pkgs", "jcifs.smb1");
        } else if (pkgs.indexOf("jcifs.smb1") == -1) {
            pkgs += "|jcifs.smb1";
            System.setProperty("java.protocol.handler.pkgs", pkgs);
        }
    }

    // supress javadoc constructor summary by removing 'protected'
    Config() {
    }

    /**
     * Set the default properties of the static Properties used by <code>Config</code>. This permits
     * a different Properties object/file to be used as the source of properties for
     * use by the jCIFS library. The Properties must be set <i>before jCIFS
     * classes are accessed</i> as most jCIFS classes load properties statically once.
     * Using this method will also override properties loaded
     * using the <code>-Djcifs.properties=</code> commandline parameter.
     */

    /**
     * Set the properties to be used for configuration.
     *
     * @param prp the properties to set
     */
    public static void setProperties(final Properties prp) {
        Config.prp = new Properties(prp);
        try {
            Config.prp.putAll(System.getProperties());
        } catch (final SecurityException se) {
            if (LogStream.level > 1) {
                log.println("SecurityException: jcifs.smb1 will ignore System properties");
            }
        }
    }

    /**
     * Load the <code>Config</code> with properties from the stream
     * <code>in</code> from a <code>Properties</code> file.
     *
     * @param in the input stream to load properties from
     * @throws IOException if an I/O error occurs
     */

    public static void load(final InputStream in) throws IOException {
        if (in != null) {
            prp.load(in);
        }
        try {
            prp.putAll((java.util.Map) System.getProperties().clone());
        } catch (final SecurityException se) {
            if (LogStream.level > 1) {
                log.println("SecurityException: jcifs.smb1 will ignore System properties");
            }
        }
    }

    /**
     * Save the configuration properties to an output stream.
     *
     * @param out the output stream to write properties to
     * @param header a descriptive header for the properties
     * @throws IOException if an I/O error occurs
     */
    public static void store(final OutputStream out, final String header) throws IOException {
        prp.store(out, header);
    }

    /**
     * List the properties in the <code>Config</code>.
     *
     * @param out the print stream to write the properties to
     * @throws IOException if an I/O error occurs
     */

    public static void list(final PrintStream out) throws IOException {
        prp.list(out);
    }

    /**
     * Add a property.
     *
     * @param key the property key
     * @param value the property value
     * @return the previous value of the property, or null if it did not have one
     */

    public static Object setProperty(final String key, final String value) {
        return prp.setProperty(key, value);
    }

    /**
     * Retrieve a property as an <code>Object</code>.
     *
     * @param key the property key to look up
     * @return the property value as an Object, or null if not found
     */

    public static Object get(final String key) {
        return prp.get(key);
    }

    /**
     * Retrieve a <code>String</code>. If the key cannot be found,
     * the provided <code>def</code> default parameter will be returned.
     *
     * @param key the property key to look up
     * @param def the default value to return if the property is not found
     * @return the property value, or the default value if not found
     */

    public static String getProperty(final String key, final String def) {
        return prp.getProperty(key, def);
    }

    /**
     * Retrieve a <code>String</code>. If the property is not found, <code>null</code> is returned.
     *
     * @param key the property key to look up
     * @return the property value, or null if not found
     */

    public static String getProperty(final String key) {
        return prp.getProperty(key);
    }

    /**
     * Retrieve an <code>int</code>. If the key does not exist or
     * cannot be converted to an <code>int</code>, the provided default
     * argument will be returned.
     *
     * @param key the property key to look up
     * @param def the default value to return if the property is not found or cannot be parsed
     * @return the property value as an int, or the default value
     */

    public static int getInt(final String key, int def) {
        final String s = prp.getProperty(key);
        if (s != null) {
            try {
                def = Integer.parseInt(s);
            } catch (final NumberFormatException nfe) {
                if (LogStream.level > 0) {
                    nfe.printStackTrace(log);
                }
            }
        }
        return def;
    }

    /**
     * Retrieve an <code>int</code>. If the property is not found, <code>-1</code> is returned.
     *
     * @param key the property key to look up
     * @return the property value as an int, or -1 if not found
     */

    public static int getInt(final String key) {
        final String s = prp.getProperty(key);
        int result = -1;
        if (s != null) {
            try {
                result = Integer.parseInt(s);
            } catch (final NumberFormatException nfe) {
                if (LogStream.level > 0) {
                    nfe.printStackTrace(log);
                }
            }
        }
        return result;
    }

    /**
     * Retrieve a <code>long</code>. If the key does not exist or
     * cannot be converted to a <code>long</code>, the provided default
     * argument will be returned.
     *
     * @param key the property key to look up
     * @param def the default value to return if the property is not found or cannot be parsed
     * @return the property value as a long, or the default value
     */

    public static long getLong(final String key, long def) {
        final String s = prp.getProperty(key);
        if (s != null) {
            try {
                def = Long.parseLong(s);
            } catch (final NumberFormatException nfe) {
                if (LogStream.level > 0) {
                    nfe.printStackTrace(log);
                }
            }
        }
        return def;
    }

    /**
     * Retrieve an <code>InetAddress</code>. If the address is not
     * an IP address and cannot be resolved <code>null</code> will
     * be returned.
     *
     * @param key the property key to look up
     * @param def the default InetAddress to return if the property is not found or cannot be resolved
     * @return the property value as an InetAddress, or the default value
     */

    public static InetAddress getInetAddress(final String key, InetAddress def) {
        final String addr = prp.getProperty(key);
        if (addr != null) {
            try {
                def = InetAddress.getByName(addr);
            } catch (final UnknownHostException uhe) {
                if (LogStream.level > 0) {
                    log.println(addr);
                    uhe.printStackTrace(log);
                }
            }
        }
        return def;
    }

    /**
     * Get the local host address configured for the client.
     *
     * @return the configured local InetAddress, or null if not configured
     */
    public static InetAddress getLocalHost() {
        final String addr = prp.getProperty("jcifs.smb1.smb.client.laddr");

        if (addr != null) {
            try {
                return InetAddress.getByName(addr);
            } catch (final UnknownHostException uhe) {
                if (LogStream.level > 0) {
                    log.println("Ignoring jcifs.smb1.smb.client.laddr address: " + addr);
                    uhe.printStackTrace(log);
                }
            }
        }

        return null;
    }

    /**
     * Retrieve a boolean value. If the property is not found, the value of <code>def</code> is returned.
     *
     * @param key the property key to look up
     * @param def the default value to return if the property is not found
     * @return the property value as a boolean, or the default value
     */

    public static boolean getBoolean(final String key, boolean def) {
        final String b = getProperty(key);
        if (b != null) {
            def = b.toLowerCase().equals("true");
        }
        return def;
    }

    /**
     * Retrieve an array of <code>InetAddress</code> created from a property
     * value containting a <code>delim</code> separated list of hostnames and/or
     * ipaddresses.
     *
     * @param key the property key to look up
     * @param delim the delimiter used to separate addresses in the property value
     * @param def the default array to return if the property is not found or cannot be parsed
     * @return an array of InetAddress objects, or the default array
     */

    public static InetAddress[] getInetAddressArray(final String key, final String delim, final InetAddress[] def) {
        final String p = getProperty(key);
        if (p != null) {
            final StringTokenizer tok = new StringTokenizer(p, delim);
            final int len = tok.countTokens();
            final InetAddress[] arr = new InetAddress[len];
            for (int i = 0; i < len; i++) {
                final String addr = tok.nextToken();
                try {
                    arr[i] = InetAddress.getByName(addr);
                } catch (final UnknownHostException uhe) {
                    if (LogStream.level > 0) {
                        log.println(addr);
                        uhe.printStackTrace(log);
                    }
                    return def;
                }
            }
            return arr;
        }
        return def;
    }
}
