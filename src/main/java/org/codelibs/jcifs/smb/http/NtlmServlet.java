/* org.codelibs.jcifs.smb smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb.http;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Properties;

import org.bouncycastle.util.encoders.Base64;
import org.codelibs.jcifs.smb.Address;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Config;
import org.codelibs.jcifs.smb.NtlmPasswordAuthentication;
import org.codelibs.jcifs.smb.SmbAuthException;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.context.BaseContext;
import org.codelibs.jcifs.smb.netbios.UniAddress;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * This servlet may be used with pre-2.3 servlet containers
 * to protect content with NTLM HTTP Authentication. Servlets that
 * extend this abstract base class may be authenticated against an SMB
 * server or domain controller depending on how the
 * {@code jcifs.client.domain} or {@code org.codelibs.jcifs.smb.http.domainController}
 * properties are be specified. <b>With later containers the
 * {@code NtlmHttpFilter} should be used</b>. For custom NTLM HTTP Authentication schemes the {@code NtlmSsp} may be
 * used.
 * <p>
 * Read <a href="../../../ntlmhttpauth.html">jCIFS NTLM HTTP Authentication and the Network Explorer Servlet</a> related
 * information.
 *
 * @deprecated NTLMv1 only
 */
@Deprecated
public abstract class NtlmServlet extends HttpServlet {

    /**
     * Default constructor.
     */
    protected NtlmServlet() {
        super();
    }

    /**
     *
     */
    private static final long serialVersionUID = -4686770199446333333L;

    /** The default domain for NTLM authentication */
    private String defaultDomain;

    /** The domain controller for authentication */
    private String domainController;

    /** Flag to enable load balancing across domain controllers */
    private boolean loadBalance;

    /** Flag to enable basic authentication */
    private boolean enableBasic;

    /** Flag to allow insecure basic authentication */
    private boolean insecureBasic;

    /** The authentication realm */
    private String realm;

    /** The CIFS context for transport operations */
    private CIFSContext transportContext;

    @Override
    public void init(final ServletConfig config) throws ServletException {
        super.init(config);

        final Properties p = new Properties();
        p.putAll(System.getProperties());
        /*
         * Set org.codelibs.jcifs.smb properties we know we want; soTimeout and cachePolicy to 10min.
         */
        p.setProperty("jcifs.client.soTimeout", "300000");
        p.setProperty("jcifs.netbios.cachePolicy", "600");

        final Enumeration<String> e = config.getInitParameterNames();
        String name;
        while (e.hasMoreElements()) {
            name = e.nextElement();
            if (name.startsWith("jcifs.")) {
                p.setProperty(name, config.getInitParameter(name));
            }
        }

        try {
            this.defaultDomain = p.getProperty("jcifs.client.domain");
            this.domainController = p.getProperty("jcifs.http.domainController");
            if (this.domainController == null) {
                this.domainController = this.defaultDomain;
                this.loadBalance = Config.getBoolean(p, "jcifs.http.loadBalance", true);
            }
            this.enableBasic = Boolean.parseBoolean(p.getProperty("jcifs.http.enableBasic"));
            this.insecureBasic = Boolean.parseBoolean(p.getProperty("jcifs.http.insecureBasic"));
            this.realm = p.getProperty("jcifs.http.basicRealm");
            if (this.realm == null) {
                this.realm = "jCIFS";
            }

            this.transportContext = new BaseContext(new PropertyConfiguration(p));

        } catch (final CIFSException ex) {
            throw new ServletException("Failed to initialize config", ex);
        }
    }

    @Override
    protected void service(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        Address dc;
        final boolean offerBasic = this.enableBasic && (this.insecureBasic || request.isSecure());
        final String msg = request.getHeader("Authorization");
        if (msg != null && (msg.startsWith("NTLM ") || offerBasic && msg.startsWith("Basic "))) {
            if (this.loadBalance) {
                dc = new UniAddress(getTransportContext().getNameServiceClient().getNbtByName(this.domainController, 0x1C, null));
            } else {
                dc = getTransportContext().getNameServiceClient().getByName(this.domainController, true);
            }
            NtlmPasswordAuthentication ntlm;
            if (msg.startsWith("NTLM ")) {
                final byte[] challenge = getTransportContext().getTransportPool().getChallenge(getTransportContext(), dc);
                ntlm = NtlmSsp.authenticate(getTransportContext(), request, response, challenge);
                if (ntlm == null) {
                    return;
                }
            } else {
                final String auth = new String(Base64.decode(msg.substring(6)), "US-ASCII");
                int index = auth.indexOf(':');
                String user = index != -1 ? auth.substring(0, index) : auth;
                final String password = index != -1 ? auth.substring(index + 1) : "";
                index = user.indexOf('\\');
                if (index == -1) {
                    index = user.indexOf('/');
                }
                final String domain = index != -1 ? user.substring(0, index) : this.defaultDomain;
                user = index != -1 ? user.substring(index + 1) : user;
                ntlm = new NtlmPasswordAuthentication(getTransportContext(), domain, user, password);
            }
            try {
                getTransportContext().getTransportPool().logon(getTransportContext(), dc);
            } catch (final SmbAuthException sae) {
                response.setHeader("WWW-Authenticate", "NTLM");
                if (offerBasic) {
                    response.addHeader("WWW-Authenticate", "Basic realm=\"" + this.realm + "\"");
                }
                response.setHeader("Connection", "close");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.flushBuffer();
                return;
            }
            final HttpSession ssn = request.getSession();
            ssn.setAttribute("NtlmHttpAuth", ntlm);
            ssn.setAttribute("ntlmdomain", ntlm.getUserDomain());
            ssn.setAttribute("ntlmuser", ntlm.getUsername());
        } else {
            final HttpSession ssn = request.getSession(false);
            if (ssn == null || ssn.getAttribute("NtlmHttpAuth") == null) {
                response.setHeader("WWW-Authenticate", "NTLM");
                if (offerBasic) {
                    response.addHeader("WWW-Authenticate", "Basic realm=\"" + this.realm + "\"");
                }
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.flushBuffer();
                return;
            }
        }
        super.service(request, response);
    }

    /**
     * @return
     */
    private CIFSContext getTransportContext() {
        return this.transportContext;
    }
}
