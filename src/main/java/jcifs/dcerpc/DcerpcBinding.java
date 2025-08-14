/* jcifs msrpc client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Eric Glass" <jcifs at samba dot org>
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

package jcifs.dcerpc;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;

import jcifs.dcerpc.msrpc.lsarpc;
import jcifs.dcerpc.msrpc.netdfs;
import jcifs.dcerpc.msrpc.samr;
import jcifs.dcerpc.msrpc.srvsvc;

/**
 * DCE/RPC binding information for connecting to remote endpoints.
 * This class encapsulates the details needed to establish a DCE/RPC connection.
 */
public class DcerpcBinding {

    private static final Map<String, String> INTERFACES = new HashMap<>();

    static {
        INTERFACES.put("srvsvc", srvsvc.getSyntax());
        INTERFACES.put("lsarpc", lsarpc.getSyntax());
        INTERFACES.put("samr", samr.getSyntax());
        INTERFACES.put("netdfs", netdfs.getSyntax());
        INTERFACES.put("netlogon", "12345678-1234-abcd-ef00-01234567cffb:1.0");
        INTERFACES.put("wkssvc", "6BFFD098-A112-3610-9833-46C3F87E345A:1.0");
        INTERFACES.put("samr", "12345778-1234-ABCD-EF00-0123456789AC:1.0");
    }

    /**
     * Add an interface to the registry
     *
     * @param name the interface name
     * @param syntax the interface syntax (UUID:version)
     */
    public static void addInterface(final String name, final String syntax) {
        INTERFACES.put(name, syntax);
    }

    private final String proto;
    private Map<String, Object> options = null;
    private final String server;
    private String endpoint = null;
    private UUID uuid = null;
    private int major;
    private int minor;

    DcerpcBinding(final String proto, final String server) {
        this.proto = proto;
        this.server = server;
    }

    /**
     * Get the protocol for this binding.
     * @return the proto
     */
    public String getProto() {
        return this.proto;
    }

    /**
     * Get the options for this binding.
     * @return the options
     */
    public Map<String, Object> getOptions() {
        return this.options;
    }

    /**
     * Get the server for this binding.
     * @return the server
     */
    public String getServer() {
        return this.server;
    }

    /**
     * Get the endpoint for this binding.
     * @return the endpoint
     */
    public String getEndpoint() {
        return this.endpoint;
    }

    /**
     * @return the uuid
     */
    UUID getUuid() {
        return this.uuid;
    }

    /**
     * @return the major
     */
    int getMajor() {
        return this.major;
    }

    /**
     * @return the minor
     */
    int getMinor() {
        return this.minor;
    }

    void setOption(final String key, final Object val) throws DcerpcException {
        if (key.equals("endpoint")) {
            this.endpoint = val.toString();
            final String lep = this.endpoint.toLowerCase(Locale.ENGLISH);
            if (lep.startsWith("\\pipe\\")) {
                final String iface = INTERFACES.get(lep.substring(6));
                if (iface != null) {
                    int c, p;
                    c = iface.indexOf(':');
                    p = iface.indexOf('.', c + 1);
                    this.uuid = new UUID(iface.substring(0, c));
                    this.major = Integer.parseInt(iface.substring(c + 1, p));
                    this.minor = Integer.parseInt(iface.substring(p + 1));
                    return;
                }
            }
            throw new DcerpcException("Bad endpoint: " + this.endpoint);
        }
        if (this.options == null) {
            this.options = new HashMap<>();
        }
        this.options.put(key, val);
    }

    Object getOption(final String key) {
        if (key.equals("endpoint")) {
            return this.endpoint;
        }
        if (this.options != null) {
            return this.options.get(key);
        }
        return null;
    }

    @Override
    public String toString() {
        StringBuilder ret = new StringBuilder().append(this.proto).append(":").append(this.server).append("[").append(this.endpoint);
        if (this.options != null) {
            for (final Entry<String, Object> entry : this.options.entrySet()) {
                ret.append(",").append(entry.getKey()).append("=").append(entry.getValue());
            }
        }
        ret.append("]");
        return ret.toString();
    }
}
