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

package jcifs.smb1.dcerpc;

import java.util.HashMap;
import java.util.Iterator;

import jcifs.smb1.dcerpc.msrpc.lsarpc;
import jcifs.smb1.dcerpc.msrpc.netdfs;
import jcifs.smb1.dcerpc.msrpc.samr;
import jcifs.smb1.dcerpc.msrpc.srvsvc;

public class DcerpcBinding {

    private static HashMap INTERFACES;

    static {
        INTERFACES = new HashMap();
        INTERFACES.put("srvsvc", srvsvc.getSyntax());
        INTERFACES.put("lsarpc", lsarpc.getSyntax());
        INTERFACES.put("samr", samr.getSyntax());
        INTERFACES.put("netdfs", netdfs.getSyntax());
    }

    public static void addInterface(final String name, final String syntax) {
        INTERFACES.put(name, syntax);
    }

    String proto;
    String server;
    String endpoint = null;
    HashMap options = null;
    UUID uuid = null;
    int major;
    int minor;

    DcerpcBinding(final String proto, final String server) {
        this.proto = proto;
        this.server = server;
    }

    void setOption(final String key, final Object val) throws DcerpcException {
        if (key.equals("endpoint")) {
            endpoint = val.toString();
            final String lep = endpoint.toLowerCase();
            if (lep.startsWith("\\pipe\\")) {
                final String iface = (String) INTERFACES.get(lep.substring(6));
                if (iface != null) {
                    int c, p;
                    c = iface.indexOf(':');
                    p = iface.indexOf('.', c + 1);
                    uuid = new UUID(iface.substring(0, c));
                    major = Integer.parseInt(iface.substring(c + 1, p));
                    minor = Integer.parseInt(iface.substring(p + 1));
                    return;
                }
            }
            throw new DcerpcException("Bad endpoint: " + endpoint);
        }
        if (options == null) {
            options = new HashMap();
        }
        options.put(key, val);
    }

    Object getOption(final String key) {
        if (key.equals("endpoint")) {
            return endpoint;
        }
        if (options != null) {
            return options.get(key);
        }
        return null;
    }

    @Override
    public String toString() {
        StringBuilder ret = new StringBuilder().append(proto).append(":").append(server).append("[").append(endpoint);
        if (options != null) {
            final Iterator iter = options.keySet().iterator();
            while (iter.hasNext()) {
                final Object key = iter.next();
                final Object val = options.get(key);
                ret.append(",").append(key).append("=").append(val);
            }
        }
        ret.append("]");
        return ret.toString();
    }
}
