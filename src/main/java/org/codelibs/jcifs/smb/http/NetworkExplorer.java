/* org.codelibs.jcifs.smb smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
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
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URLConnection;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Properties;

import org.bouncycastle.util.encoders.Base64;
import org.codelibs.jcifs.smb.Address;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Config;
import org.codelibs.jcifs.smb.DfsReferral;
import org.codelibs.jcifs.smb.DfsReferralData;
import org.codelibs.jcifs.smb.NameServiceClient;
import org.codelibs.jcifs.smb.NtStatus;
import org.codelibs.jcifs.smb.NtlmPasswordAuthentication;
import org.codelibs.jcifs.smb.SmbAuthException;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.SmbException;
import org.codelibs.jcifs.smb.SmbFile;
import org.codelibs.jcifs.smb.SmbFileInputStream;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.context.BaseContext;
import org.codelibs.jcifs.smb.netbios.NbtAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * This servlet may be used to "browse" the entire hierarchy of resources
 * on an SMB network like one might with Network Neighborhood or Windows
 * Explorer. The users credentials with be negotiated using NTLM SSP if
 * the client is Microsoft Internet Explorer.
 *
 * @deprecated Unsupported
 */
@Deprecated
/**
 * A servlet that provides network browsing capabilities for SMB shares.
 * This servlet allows users to browse SMB network resources through a web interface.
 */
public class NetworkExplorer extends HttpServlet {

    /**
     * Default constructor.
     */
    public NetworkExplorer() {
        super();
    }

    /**
     *
     */
    private static final long serialVersionUID = -3847521461674504364L;

    private static final Logger log = LoggerFactory.getLogger(NetworkExplorer.class);

    /** The CSS style for HTML rendering */
    private String style;
    /** Flag indicating if credentials were supplied */
    private boolean credentialsSupplied;
    /** Flag to enable basic authentication */
    private boolean enableBasic;
    /** Flag to allow insecure basic authentication */
    private boolean insecureBasic;
    /** The authentication realm */
    private String realm;
    /** The default domain for authentication */
    private String defaultDomain;

    /** The CIFS context for transport operations */
    private CIFSContext transportContext;

    @Override
    public void init() throws ServletException {

        final StringBuilder sb = new StringBuilder();
        final byte[] buf = new byte[1024];
        int n;
        String name;

        final Properties p = new Properties();
        p.putAll(System.getProperties());
        p.setProperty("jcifs.client.soTimeout", "600000");
        p.setProperty("jcifs.client.attrExpirationPeriod", "300000");

        final Enumeration<String> e = getInitParameterNames();
        while (e.hasMoreElements()) {
            name = e.nextElement();
            if (name.startsWith("jcifs.")) {
                p.setProperty(name, getInitParameter(name));
            }
        }

        try {
            if (p.getProperty("jcifs.client.username") == null) {
                new NtlmSsp();
            } else {
                this.credentialsSupplied = true;
            }

            try {
                try (InputStream is = getClass().getClassLoader().getResourceAsStream("org/codelibs/jcifs/smb/http/ne.css");) {
                    while ((n = is.read(buf)) != -1) {
                        sb.append(new String(buf, 0, n, "ISO8859_1"));
                    }
                    this.style = sb.toString();
                }
            } catch (final IOException ioe) {
                throw new ServletException(ioe.getMessage());
            }

            this.enableBasic = Config.getBoolean(p, "jcifs.http.enableBasic", false);
            this.insecureBasic = Config.getBoolean(p, "jcifs.http.insecureBasic", false);
            this.realm = p.getProperty("jcifs.http.basicRealm");
            if (this.realm == null) {
                this.realm = "jCIFS";
            }
            this.defaultDomain = p.getProperty("jcifs.client.domain");
            this.transportContext = new BaseContext(new PropertyConfiguration(p));
        } catch (final CIFSException ex) {
            throw new ServletException("Failed to initialize CIFS context", ex);
        }
    }

    /**
     * Handles file download requests for SMB files.
     * @param req the HTTP servlet request
     * @param resp the HTTP servlet response
     * @param file the SMB file to download
     * @throws IOException if an I/O error occurs
     */
    protected void doFile(final HttpServletRequest req, final HttpServletResponse resp, final SmbFile file) throws IOException {
        final byte[] buf = new byte[8192];

        @SuppressWarnings("resource")
        final ServletOutputStream out = resp.getOutputStream();
        String url;
        int n;
        try (SmbFileInputStream in = new SmbFileInputStream(file)) {
            url = file.getLocator().getPath();
            resp.setContentType("text/plain");
            resp.setContentType(URLConnection.guessContentTypeFromName(url));
            resp.setHeader("Content-Length", file.length() + "");
            resp.setHeader("Accept-Ranges", "Bytes");

            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
        }
    }

    /**
     * Compares two SMB files by name
     * @param f1 first file to compare
     * @param f1name name of first file
     * @param f2 second file to compare
     * @return comparison result for sorting
     * @throws IOException if an I/O error occurs
     */
    protected int compareNames(final SmbFile f1, final String f1name, final SmbFile f2) throws IOException {
        if (f1.isDirectory() != f2.isDirectory()) {
            return f1.isDirectory() ? -1 : 1;
        }
        return f1name.compareToIgnoreCase(f2.getName());
    }

    /**
     * Compares two SMB files by size
     * @param f1 first file to compare
     * @param f1name name of first file
     * @param f2 second file to compare
     * @return comparison result for sorting
     * @throws IOException if an I/O error occurs
     */
    protected int compareSizes(final SmbFile f1, final String f1name, final SmbFile f2) throws IOException {
        long diff;

        if (f1.isDirectory() != f2.isDirectory()) {
            return f1.isDirectory() ? -1 : 1;
        }
        if (f1.isDirectory()) {
            return f1name.compareToIgnoreCase(f2.getName());
        }
        diff = f1.length() - f2.length();
        if (diff == 0) {
            return f1name.compareToIgnoreCase(f2.getName());
        }
        return diff > 0 ? -1 : 1;
    }

    /**
     * Compares two SMB files by file type/extension.
     * @param f1 first file to compare
     * @param f1name name of first file
     * @param f2 second file to compare
     * @return comparison result for sorting
     * @throws IOException if an I/O error occurs
     */
    protected int compareTypes(final SmbFile f1, final String f1name, final SmbFile f2) throws IOException {
        String f2name, t1, t2;
        int i;

        if (f1.isDirectory() != f2.isDirectory()) {
            return f1.isDirectory() ? -1 : 1;
        }
        f2name = f2.getName();
        if (f1.isDirectory()) {
            return f1name.compareToIgnoreCase(f2name);
        }
        i = f1name.lastIndexOf('.');
        t1 = i == -1 ? "" : f1name.substring(i + 1);
        i = f2name.lastIndexOf('.');
        t2 = i == -1 ? "" : f2name.substring(i + 1);

        i = t1.compareToIgnoreCase(t2);
        if (i == 0) {
            return f1name.compareToIgnoreCase(f2name);
        }
        return i;
    }

    /**
     * Compares two SMB files by modification date.
     * @param f1 first file to compare
     * @param f1name name of first file
     * @param f2 second file to compare
     * @return comparison result for sorting
     * @throws IOException if an I/O error occurs
     */
    protected int compareDates(final SmbFile f1, final String f1name, final SmbFile f2) throws IOException {
        if (f1.isDirectory() != f2.isDirectory()) {
            return f1.isDirectory() ? -1 : 1;
        }
        if (f1.isDirectory()) {
            return f1name.compareToIgnoreCase(f2.getName());
        }
        return f1.lastModified() > f2.lastModified() ? -1 : 1;
    }

    /**
     * Handles directory listing requests for SMB directories.
     * @param req the HTTP servlet request
     * @param resp the HTTP servlet response
     * @param dir the SMB directory to list
     * @throws IOException if an I/O error occurs
     */
    @SuppressWarnings("resource")
    protected void doDirectory(final HttpServletRequest req, final HttpServletResponse resp, final SmbFile dir) throws IOException {
        final PrintWriter out = resp.getWriter();
        SmbFile[] dirents;
        SmbFile f;
        int i, j, len, maxLen, dirCount, fileCount, sort;
        String str, name, path, fmt;
        LinkedList<SmbFile> sorted;
        ListIterator<SmbFile> iter;
        final SimpleDateFormat sdf = new SimpleDateFormat("MM/d/yy h:mm a");
        final GregorianCalendar cal = new GregorianCalendar();

        sdf.setCalendar(cal);

        dirents = dir.listFiles();
        if (log.isDebugEnabled()) {
            log.debug(dirents.length + " items listed");
        }
        sorted = new LinkedList<>();
        fmt = req.getParameter("fmt");
        if (fmt == null) {
            fmt = "col";
        }
        sort = 0;
        if ((str = req.getParameter("sort")) == null || str.equals("name")) {
            sort = 0;
        } else if (str != null) {
            switch (str) {
            case "size":
                sort = 1;
                break;
            case "type":
                sort = 2;
                break;
            case "date":
                sort = 3;
                break;
            default:
                break;
            }
        }
        dirCount = fileCount = 0;
        maxLen = 28;
        for (i = 0; i < dirents.length; i++) {
            try {
                if (dirents[i].getType() == SmbConstants.TYPE_NAMED_PIPE) {
                    continue;
                }
            } catch (final SmbAuthException sae) {
                log.warn("Auth failed", sae);
            } catch (final SmbException se) {
                log.warn("Connection failed", se);
                if (se.getNtStatus() != NtStatus.NT_STATUS_UNSUCCESSFUL) {
                    throw se;
                }
            }
            if (dirents[i].isDirectory()) {
                dirCount++;
            } else {
                fileCount++;
            }

            name = dirents[i].getName();
            if (log.isDebugEnabled()) {
                log.debug(i + ": " + name);
            }
            len = name.length();
            if (len > maxLen) {
                maxLen = len;
            }

            iter = sorted.listIterator();
            for (j = 0; iter.hasNext(); j++) {
                if (sort == 0) {
                    if (compareNames(dirents[i], name, iter.next()) < 0) {
                        break;
                    }
                } else if (sort == 1) {
                    if (compareSizes(dirents[i], name, iter.next()) < 0) {
                        break;
                    }
                } else if (sort == 2) {
                    if (compareTypes(dirents[i], name, iter.next()) < 0) {
                        break;
                    }
                } else if (sort == 3 && compareDates(dirents[i], name, iter.next()) < 0) {
                    break;
                }
            }
            sorted.add(j, dirents[i]);
        }
        if (maxLen > 50) {
            maxLen = 50;
        }
        maxLen *= 9; /* convert to px */

        resp.setContentType("text/html");

        out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">");
        out.println("<html><head><title>Network Explorer</title>");
        out.println("<meta HTTP-EQUIV=\"Pragma\" CONTENT=\"no-cache\">");
        out.println("<style TYPE=\"text/css\">");

        out.println(this.style);

        if (dirents.length < 200) {
            out.println("    a:hover {");
            out.println("        background: #a2ff01;");
            out.println("    }");
        }

        out.println("</STYLE>");
        out.println("</head><body>");

        out.print("<a class=\"sort\" style=\"width: " + maxLen + ";\" href=\"?fmt=detail&sort=name\">Name</a>");
        out.println("<a class=\"sort\" href=\"?fmt=detail&sort=size\">Size</a>");
        out.println("<a class=\"sort\" href=\"?fmt=detail&sort=type\">Type</a>");
        out.println("<a class=\"sort\" style=\"width: 180\" href=\"?fmt=detail&sort=date\">Modified</a><br clear='all'><p>");

        path = dir.getLocator().getCanonicalURL();

        if (path.length() < 7) {
            out.println("<b><big>smb://</big></b><br>");
            path = ".";
        } else {
            out.println("<b><big>" + path + "</big></b><br>");
            path = "../";
        }
        out.println(dirCount + fileCount + " objects (" + dirCount + " directories, " + fileCount + " files)<br>");
        out.println("<b><a class=\"plain\" href=\".\">normal</a> | <a class=\"plain\" href=\"?fmt=detail\">detailed</a></b>");
        out.println("<p><table border='0' cellspacing='0' cellpadding='0'><tr><td>");

        out.print("<A style=\"width: " + maxLen);
        out.print("; height: 18;\" HREF=\"");
        out.print(path);
        out.println("\"><b>&uarr;</b></a>");
        if (fmt.equals("detail")) {
            out.println("<br clear='all'>");
        }

        if (path.length() == 1 || dir.getType() != SmbConstants.TYPE_WORKGROUP) {
            path = "";
        }

        iter = sorted.listIterator();
        while (iter.hasNext()) {
            f = iter.next();
            name = f.getName();

            if (fmt.equals("detail")) {
                out.print("<A style=\"width: " + maxLen);
                out.print("; height: 18;\" HREF=\"");
                out.print(path);
                out.print(name);

                if (f.isDirectory()) {
                    out.print("?fmt=detail\"><b>");
                    out.print(name);
                    out.print("</b></a>");
                } else {
                    out.print("\"><b>");
                    out.print(name);
                    out.print("</b></a><div align='right'>");
                    out.print(f.length() / 1024 + " KB </div><div>");
                    i = name.lastIndexOf('.') + 1;
                    if (i > 1 && name.length() - i < 6) {
                        out.print(name.substring(i).toUpperCase() + "</div class='ext'>");
                    } else {
                        out.print("&nbsp;</div>");
                    }
                    out.print("<div style='width: 180'>");
                    out.print(sdf.format(new Date(f.lastModified())));
                    out.print("</div>");
                }
                out.println("<br clear='all'>");
            } else {
                out.print("<A style=\"width: " + maxLen);
                if (f.isDirectory()) {
                    out.print("; height: 18;\" HREF=\"");
                    out.print(path);
                    out.print(name);
                    out.print("\"><b>");
                    out.print(name);
                    out.print("</b></a>");
                } else {
                    out.print(";\" HREF=\"");
                    out.print(path);
                    out.print(name);
                    out.print("\"><b>");
                    out.print(name);
                    out.print("</b><br><small>");
                    out.print(f.length() / 1024 + "KB <br>");
                    out.print(sdf.format(new Date(f.lastModified())));
                    out.print("</small>");
                    out.println("</a>");
                }
            }
        }

        out.println("</td></tr></table>");
        out.println("</BODY></HTML>");
        out.close();
    }

    private static String parseServerAndShare(final String pathInfo) {
        final char[] out = new char[256];
        char ch;
        int len, p, i;

        if (pathInfo == null) {
            return null;
        }
        len = pathInfo.length();

        p = i = 0;
        while (p < len && pathInfo.charAt(p) == '/') {
            p++;
        }
        if (p == len) {
            return null;
        }

        /* collect server name */
        while (p < len && (ch = pathInfo.charAt(p)) != '/') {
            out[i] = ch;
            i++;
            p++;
        }
        while (p < len && pathInfo.charAt(p) == '/') {
            p++;
        }
        if (p < len) { /* then there must be a share */
            out[i] = '/';
            i++;
            do { /* collect the share name */
                out[i++] = ch = pathInfo.charAt(p++);
            } while (p < len && ch != '/');
        }
        return new String(out, 0, i);
    }

    @Override
    public void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws IOException, ServletException {
        Address dc;
        String msg, pathInfo, server = null;
        boolean offerBasic, possibleWorkgroup = true;
        NtlmPasswordAuthentication ntlm = null;
        final HttpSession ssn = req.getSession(false);

        pathInfo = req.getPathInfo();
        if (pathInfo != null) {
            int i;
            server = parseServerAndShare(pathInfo);
            if (server != null && (i = server.indexOf('/')) > 0) {
                server = server.substring(0, i).toLowerCase();
                possibleWorkgroup = false;
            }
        }

        msg = req.getHeader("Authorization");
        offerBasic = this.enableBasic && (this.insecureBasic || req.isSecure());

        if (msg != null && (msg.startsWith("NTLM ") || offerBasic && msg.startsWith("Basic "))) {

            if (msg.startsWith("NTLM ")) {
                byte[] challenge;
                final NameServiceClient nameServiceClient = getTransportContext().getNameServiceClient();
                if (pathInfo == null || server == null) {
                    final String mb = nameServiceClient.getNbtByName(NbtAddress.MASTER_BROWSER_NAME, 0x01, null).getHostAddress();
                    dc = nameServiceClient.getByName(mb);
                } else {
                    dc = nameServiceClient.getByName(server, possibleWorkgroup);
                }

                req.getSession(); /* ensure session id is set for cluster env. */
                challenge = getTransportContext().getTransportPool().getChallenge(getTransportContext(), dc);
                if ((ntlm = NtlmSsp.authenticate(getTransportContext(), req, resp, challenge)) == null) {
                    return;
                }
            } else { /* Basic */
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

            req.getSession().setAttribute("npa-" + server, ntlm);

        } else if (!this.credentialsSupplied) {
            if (ssn != null) {
                ntlm = (NtlmPasswordAuthentication) ssn.getAttribute("npa-" + server);
            }
            if (ntlm == null) {
                resp.setHeader("WWW-Authenticate", "NTLM");
                if (offerBasic) {
                    resp.addHeader("WWW-Authenticate", "Basic realm=\"" + this.realm + "\"");
                }
                resp.setHeader("Connection", "close");
                resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                resp.flushBuffer();
                return;
            }
        }

        try (SmbFile file = openFile(pathInfo, server)) {
            if (file.isDirectory()) {
                doDirectory(req, resp, file);
            } else {
                doFile(req, resp, file);
            }
        } catch (final SmbAuthException sae) {
            if (ssn != null) {
                ssn.removeAttribute("npa-" + server);
            }
            if (sae.getNtStatus() == NtStatus.NT_STATUS_ACCESS_VIOLATION) {
                /*
                 * Server challenge no longer valid for
                 * externally supplied password hashes.
                 */
                resp.sendRedirect(req.getRequestURL().toString());
                return;
            }
            resp.setHeader("WWW-Authenticate", "NTLM");
            if (offerBasic) {
                resp.addHeader("WWW-Authenticate", "Basic realm=\"" + this.realm + "\"");
            }
            resp.setHeader("Connection", "close");
            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resp.flushBuffer();
            return;
        } catch (final DfsReferral dr) {
            StringBuffer redir = req.getRequestURL();
            final String qs = req.getQueryString();
            final DfsReferralData refdata = dr.getData();
            redir = new StringBuffer(redir.substring(0, redir.length() - req.getPathInfo().length()));
            redir.append('/');
            redir.append(refdata.getServer());
            redir.append('/');
            redir.append(refdata.getShare());
            redir.append('/');
            if (qs != null) {
                redir.append(req.getQueryString());
            }
            resp.sendRedirect(redir.toString());
            resp.flushBuffer();
            return;
        }
    }

    /**
     * @param pathInfo
     * @param server
     * @return
     * @throws MalformedURLException
     */
    private SmbFile openFile(final String pathInfo, final String server) throws MalformedURLException {
        SmbFile file;

        if (server == null) {
            file = new SmbFile("smb://", getTransportContext());
        } else {
            file = new SmbFile("smb:/" + pathInfo, getTransportContext());
        }
        return file;
    }

    /**
     * @return
     */
    private CIFSContext getTransportContext() {
        return this.transportContext;
    }
}
