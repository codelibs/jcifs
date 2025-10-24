/* org.codelibs.jcifs.smb smb client library in Java
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

package org.codelibs.jcifs.smb.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.util.Objects;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.CloseableIterator;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.ResourceFilter;
import org.codelibs.jcifs.smb.ResourceNameFilter;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.SmbFileHandle;
import org.codelibs.jcifs.smb.SmbResource;
import org.codelibs.jcifs.smb.SmbResourceLocator;
import org.codelibs.jcifs.smb.SmbTreeHandle;
import org.codelibs.jcifs.smb.SmbWatchHandle;
import org.codelibs.jcifs.smb.context.SingletonContext;
import org.codelibs.jcifs.smb.dcerpc.DcerpcHandle;
import org.codelibs.jcifs.smb.dcerpc.msrpc.MsrpcShareGetInfo;
import org.codelibs.jcifs.smb.internal.AllocInfo;
import org.codelibs.jcifs.smb.internal.SmbBasicFileInfo;
import org.codelibs.jcifs.smb.internal.dtyp.ACE;
import org.codelibs.jcifs.smb.internal.dtyp.SecurityDescriptor;
import org.codelibs.jcifs.smb.internal.dtyp.SecurityInfo;
import org.codelibs.jcifs.smb.internal.fscc.BasicFileInformation;
import org.codelibs.jcifs.smb.internal.fscc.FileBasicInfo;
import org.codelibs.jcifs.smb.internal.fscc.FileInformation;
import org.codelibs.jcifs.smb.internal.fscc.FileInternalInfo;
import org.codelibs.jcifs.smb.internal.fscc.FileRenameInformation2;
import org.codelibs.jcifs.smb.internal.fscc.FileStandardInfo;
import org.codelibs.jcifs.smb.internal.fscc.FileSystemInformation;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComBlankResponse;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComCreateDirectory;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComDelete;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComDeleteDirectory;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComNTCreateAndX;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComNTCreateAndXResponse;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComOpenAndX;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComOpenAndXResponse;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComQueryInformation;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComQueryInformationResponse;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComRename;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComSeek;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComSeekResponse;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComSetInformation;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComSetInformationResponse;
import org.codelibs.jcifs.smb.internal.smb1.trans.nt.NtTransQuerySecurityDesc;
import org.codelibs.jcifs.smb.internal.smb1.trans.nt.NtTransQuerySecurityDescResponse;
import org.codelibs.jcifs.smb.internal.smb1.trans2.Trans2QueryFSInformation;
import org.codelibs.jcifs.smb.internal.smb1.trans2.Trans2QueryFSInformationResponse;
import org.codelibs.jcifs.smb.internal.smb1.trans2.Trans2QueryPathInformation;
import org.codelibs.jcifs.smb.internal.smb1.trans2.Trans2QueryPathInformationResponse;
import org.codelibs.jcifs.smb.internal.smb1.trans2.Trans2SetFileInformation;
import org.codelibs.jcifs.smb.internal.smb1.trans2.Trans2SetFileInformationResponse;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Response;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CloseRequest;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CloseResponse;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateRequest;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateResponse;
import org.codelibs.jcifs.smb.internal.smb2.info.Smb2QueryInfoRequest;
import org.codelibs.jcifs.smb.internal.smb2.info.Smb2QueryInfoResponse;
import org.codelibs.jcifs.smb.internal.smb2.info.Smb2SetInfoRequest;
import org.codelibs.jcifs.smb.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class represents a resource on an SMB network. Mainly these
 * resources are files and directories however an <code>SmbFile</code>
 * may also refer to servers and workgroups. If the resource is a file or
 * directory the methods of <code>SmbFile</code> follow the behavior of
 * the well known {@link java.io.File} class. One fundamental difference
 * is the usage of a URL scheme [1] to specify the target file or
 * directory. SmbFile URLs have the following syntax:
 *
 * <blockquote>
 *
 * <pre>
 *     smb://[[[domain;]username[:password]@]server[:port]/[[share/[dir/]file]]][?param=value[param2=value2[...]]]
 * </pre>
 *
 * </blockquote>
 *
 * This example:
 *
 * <blockquote>
 *
 * <pre>
 *     smb://storage15/public/foo.txt
 * </pre>
 *
 * </blockquote>
 *
 * would reference the file <code>foo.txt</code> in the share
 * <code>public</code> on the server <code>storage15</code>. In addition
 * to referencing files and directories, jCIFS can also address servers,
 * and workgroups.
 * <p>
 * <strong><i>Important: all SMB URLs that represent
 * workgroups, servers, shares, or directories require a trailing slash '/'.
 * </i></strong>
 * <p>
 * When using the {@code java.net.URL} class with
 * 'smb://' URLs it is necessary to first call the static
 * {@code org.codelibs.jcifs.smb.Config.registerSmbURLHandler();} method. This is required
 * to register the SMB protocol handler.
 * <p>
 * The userinfo component of the SMB URL ({@code domain;user:pass}) must
 * be URL encoded if it contains reserved characters. According to RFC 2396
 * these characters are non US-ASCII characters and most meta characters
 * however jCIFS will work correctly with anything but '@' which is used
 * to delimit the userinfo component from the server and '%' which is the
 * URL escape character itself.
 * <p>
 * The server
 * component may a traditional NetBIOS name, a DNS name, or IP
 * address. These name resolution mechanisms and their resolution order
 * can be changed (See <a href="../../../resolver.html">Setting Name
 * Resolution Properties</a>). The servername and path components are
 * not case sensitive but the domain, username, and password components
 * are. It is also likely that properties must be specified for org.codelibs.jcifs.smb
 * to function (See <a href="../../overview-summary.html#scp">Setting
 * JCIFS Properties</a>). Here are some examples of SMB URLs with brief
 * descriptions of what they do:
 *
 * <p>
 * [1] This URL scheme is based largely on the <i>SMB
 * Filesharing URL Scheme</i> IETF draft.
 *
 * <table border="1">
 * <caption>SMB URL Examples</caption>
 * <tr >
 * <td colspan="2"><b>SMB URL Examples</b></td>
 * <tr>
 * <td ><b>URL</b></td>
 * <td><b>Description</b></td>
 * </tr>
 *
 * <tr>
 * <td ><code>smb://users-nyc;miallen:mypass@angus/tmp/</code></td>
 * <td>
 * This URL references a share called <code>tmp</code> on the server
 * <code>angus</code> as user <code>miallen</code> who's password is
 * <code>mypass</code>.
 * </td>
 * </tr>
 *
 * <tr>
 * <td >
 * <code>smb://Administrator:P%40ss@msmith1/c/WINDOWS/Desktop/foo.txt</code></td>
 * <td>
 * A relatively sophisticated example that references a file
 * <code>msmith1</code>'s desktop as user <code>Administrator</code>. Notice the '@' is URL encoded with the '%40'
 * hexcode escape.
 * </td>
 * </tr>
 *
 * <tr>
 * <td ><code>smb://angus/</code></td>
 * <td>
 * This references only a server. The behavior of some methods is different
 * in this context(e.g. you cannot <code>delete</code> a server) however
 * as you might expect the <code>list</code> method will list the available
 * shares on this server.
 * </td>
 * </tr>
 *
 * <tr>
 * <td ><code>smb://angus.foo.net/d/org.codelibs.jcifs.smb/pipes.doc</code></td>
 * <td>
 * The server name may also be a DNS name as it is in this example. See
 * <a href="../../../resolver.html">Setting Name Resolution Properties</a>
 * for details.
 * </td>
 * </tr>
 *
 * <tr>
 * <td ><code>smb://192.168.1.15/ADMIN$/</code></td>
 * <td>
 * The server name may also be an IP address. See <a
 * href="../../../resolver.html">Setting Name Resolution Properties</a>
 * for details.
 * </td>
 * </tr>
 *
 * <tr>
 * <td >
 * <code>smb://domain;username:password@server/share/path/to/file.txt</code></td>
 * <td>
 * A prototypical example that uses all the fields.
 * </td>
 * </tr>
 *
 * <tr>
 * <td >
 * <code>smb://server/share/path/to/dir &lt;-- ILLEGAL </code></td>
 * <td>
 * URLs that represent servers, shares, or directories require a trailing slash '/'.
 * </td>
 * </tr>
 *
 * </table>
 *
 * <p>
 * A second constructor argument may be specified to augment the URL
 * for better programmatic control when processing many files under
 * a common base. This is slightly different from the corresponding
 * <code>java.io.File</code> usage; a '/' at the beginning of the second
 * parameter will still use the server component of the first parameter. The
 * examples below illustrate the resulting URLs when this second constructor
 * argument is used.
 *
 * <table border="1">
 * <caption>Examples Of SMB URLs When Augmented With A Second Constructor Parameter</caption>
 * <tr >
 * <td colspan="3">
 * <b>Examples Of SMB URLs When Augmented With A Second Constructor Parameter</b></td>
 * <tr>
 * <td >
 * <b>First Parameter</b></td>
 * <td><b>Second Parameter</b></td>
 * <td><b>Result</b></td>
 * </tr>
 *
 * <tr>
 * <td ><code>
 *  smb://host/share/a/b/
 * </code></td>
 * <td ><code>
 *  c/d/
 * </code></td>
 * <td><code>
 *  smb://host/share/a/b/c/d/
 * </code></td>
 * </tr>
 *
 * <tr>
 * <td ><code>
 *  smb://host/share/foo/bar/
 * </code></td>
 * <td ><code>
 *  /share2/zig/zag
 * </code></td>
 * <td><code>
 *  smb://host/share2/zig/zag
 * </code></td>
 * </tr>
 *
 * <tr>
 * <td ><code>
 *  smb://host/share/foo/bar/
 * </code></td>
 * <td ><code>
 *  ../zip/
 * </code></td>
 * <td><code>
 *  smb://host/share/foo/zip/
 * </code></td>
 * </tr>
 *
 * <tr>
 * <td ><code>
 *  smb://host/share/zig/zag
 * </code></td>
 * <td ><code>
 *  smb://foo/bar/
 * </code></td>
 * <td><code>
 *  smb://foo/bar/
 * </code></td>
 * </tr>
 *
 * <tr>
 * <td ><code>
 *  smb://host/share/foo/
 * </code></td>
 * <td ><code>
 *  ../.././.././../foo/
 * </code></td>
 * <td><code>
 *  smb://host/foo/
 * </code></td>
 * </tr>
 *
 * <tr>
 * <td ><code>
 *  smb://host/share/zig/zag
 * </code></td>
 * <td ><code>
 *  /
 * </code></td>
 * <td><code>
 *  smb://host/
 * </code></td>
 * </tr>
 *
 * <tr>
 * <td ><code>
 *  smb://server/
 * </code></td>
 * <td ><code>
 *  ../
 * </code></td>
 * <td><code>
 *  smb://server/
 * </code></td>
 * </tr>
 *
 * </table>
 *
 * <p>
 * Instances of the <code>SmbFile</code> class are immutable; that is,
 * once created, the abstract pathname represented by an SmbFile object
 * will never change.
 *
 * @see java.io.File
 */

public class SmbFile extends URLConnection implements SmbResource, SmbConstants {
    /**
     * Mask for attributes that can be retrieved from the server
     */
    protected static final int ATTR_GET_MASK = 0x7FFF;
    /**
     * Mask for attributes that can be set on the server
     */
    protected static final int ATTR_SET_MASK = 0x30A7;
    /**
     * Default expiration period for cached attributes in milliseconds
     */
    protected static final int DEFAULT_ATTR_EXPIRATION_PERIOD = 5000;

    /**
     * Hash code for the "." directory entry
     */
    protected static final int HASH_DOT = ".".hashCode();
    /**
     * Hash code for the ".." directory entry
     */
    protected static final int HASH_DOT_DOT = "..".hashCode();

    private static Logger log = LoggerFactory.getLogger(SmbFile.class);

    private long createTime;
    private long lastModified;
    private long lastAccess;
    private int attributes;
    private long attrExpiration;
    private long size;
    private long sizeExpiration;
    private boolean isExists;

    private final CIFSContext transportContext;
    private SmbTreeConnection treeConnection;
    /**
     * The resource locator containing the parsed SMB URL components
     */
    protected final SmbResourceLocatorImpl fileLocator;
    private SmbTreeHandleImpl treeHandle;

    /**
     * Constructs an SmbFile representing a resource on an SMB network such as
     * a file or directory. See the description and examples of smb URLs above.
     *
     * @param url
     *            A URL string
     * @throws MalformedURLException
     *             if the URL string cannot be parsed as a valid SMB URL
     *             do not follow the prescribed syntax
     */
    @Deprecated
    public SmbFile(final String url) throws MalformedURLException {
        this(new URL(null, url, SingletonContext.getInstance().getUrlHandler()));
    }

    /**
     * Constructs an SmbFile representing a resource on an SMB network such
     * as a file or directory from a {@code URL} object.
     *
     * @param url
     *            The URL of the target resource
     * @throws MalformedURLException if the URL is not properly formatted
     */
    @Deprecated
    public SmbFile(final URL url) throws MalformedURLException {
        this(url, SingletonContext.getInstance()
                .withCredentials(new NtlmPasswordAuthentication(SingletonContext.getInstance(), url.getUserInfo())));
    }

    /**
     * Constructs an SmbFile representing a resource on an SMB network such
     * as a file or directory. The second parameter is a relative path from
     * the <code>parent SmbFile</code>. See the description above for examples
     * of using the second <code>name</code> parameter.
     *
     * @param context
     *            A base <code>SmbFile</code> that serves as the parent resource
     * @param name
     *            A path string relative to the <code>parent</code> parameter
     * @throws MalformedURLException
     *             if the resulting URL is not properly formatted
     *             do not follow the prescribed syntax
     * @throws UnknownHostException
     *             If the server or workgroup of the {@code context} file cannot be determined
     */
    public SmbFile(final SmbResource context, final String name) throws MalformedURLException, UnknownHostException {
        this(isWorkgroup(context) ? new URL(null, "smb://" + checkName(name), context.getContext().getUrlHandler())
                : new URL(context.getLocator().getURL(), encodeRelativePath(checkName(name)), context.getContext().getUrlHandler()),
                context.getContext());
        setContext(context, name);
    }

    /**
     * Construct from string URL
     *
     * @param url the SMB URL string
     * @param tc
     *            context to use
     * @throws MalformedURLException if the URL is not properly formatted
     */
    public SmbFile(final String url, final CIFSContext tc) throws MalformedURLException {
        this(new URL(null, url, tc.getUrlHandler()), tc);
    }

    /**
     * Construct from URL
     *
     * @param url the URL object representing the SMB resource
     * @param tc
     *            context to use
     * @throws MalformedURLException if the URL is not properly formatted
     */
    public SmbFile(final URL url, final CIFSContext tc) throws MalformedURLException {
        super(url);
        if (url.getPath() != null && !url.getPath().isEmpty() && url.getPath().charAt(0) != '/') {
            throw new MalformedURLException("Invalid SMB URL: " + url);
        }
        this.transportContext = tc;
        this.fileLocator = new SmbResourceLocatorImpl(tc, url);
        this.treeConnection = SmbTreeConnection.create(tc);
    }

    SmbFile(final SmbResource context, final String name, final boolean loadedAttributes, final int type, final int attributes,
            final long createTime, final long lastModified, final long lastAccess, final long size) throws MalformedURLException {
        this(isWorkgroup(context) ? new URL(null, "smb://" + checkName(name) + "/", context.getContext().getUrlHandler())
                : new URL(context.getLocator().getURL(),
                        encodeRelativePath(checkName(name)) + ((attributes & ATTR_DIRECTORY) > 0 ? "/" : "")),
                context.getContext());

        if (!isWorkgroup(context)) {
            setContext(context, name + ((attributes & ATTR_DIRECTORY) > 0 ? "/" : ""));
        }

        /*
         * why? am I going around in circles?
         * this.type = type == TYPE_WORKGROUP ? 0 : type;
         */
        this.fileLocator.updateType(type);
        this.attributes = attributes;
        this.createTime = createTime;
        this.lastModified = lastModified;
        this.lastAccess = lastAccess;
        this.size = size;
        this.isExists = true;

        if (loadedAttributes) {
            this.attrExpiration = this.sizeExpiration = System.currentTimeMillis() + getContext().getConfig().getAttributeCacheTimeout();
        }
    }

    private static String encodeRelativePath(String name) {
        // workaround fix
        if (name == null) {
            return null;
        }
        if (name.endsWith(" ")) {
            final StringBuilder suffix = new StringBuilder();
            for (int i = name.length() - 1; i >= 0; i--) {
                if (name.charAt(i) != ' ') {
                    break;
                }
                suffix.append("%20");
            }
            name = name.replaceAll(" +$", suffix.toString());
        }
        return "URL:" + name.replace("?", "%3f");
    }

    /**
     * @return
     */
    private static boolean isWorkgroup(final SmbResource r) {
        try {
            return r.getLocator().isWorkgroup();
        } catch (final CIFSException e) {
            log.debug("Failed to check for workgroup", e);
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see java.net.URLConnection#connect()
     */
    @Override
    public void connect() throws IOException {
        try (SmbTreeHandle th = ensureTreeConnected()) {}
    }

    /**
     * Retrieves the tree handle for this SMB resource
     *
     * @return a tree handle
     * @throws CIFSException if the tree connection cannot be established
     */
    public SmbTreeHandle getTreeHandle() throws CIFSException {
        return ensureTreeConnected();
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    public synchronized void close() {
        final SmbTreeHandleImpl th = this.treeHandle;
        if (th != null) {
            this.treeHandle = null;
            if (this.transportContext.getConfig().isStrictResourceLifecycle()) {
                th.close();
            }
        }
    }

    /**
     * @return
     * @throws CIFSException
     *
     */
    synchronized SmbTreeHandleImpl ensureTreeConnected() throws CIFSException {
        if (this.treeHandle == null || !this.treeHandle.isConnected()) {
            if (this.treeHandle != null && this.transportContext.getConfig().isStrictResourceLifecycle()) {
                this.treeHandle.release();
            }
            this.treeHandle = this.treeConnection.connectWrapException(this.fileLocator);
            this.treeHandle.ensureDFSResolved();
            if (this.transportContext.getConfig().isStrictResourceLifecycle()) {
                // one extra share to keep the tree alive
                return this.treeHandle.acquire();
            }
            return this.treeHandle;
        }
        return this.treeHandle.acquire();
    }

    /**
     * @param context
     * @param name
     */
    private void setContext(final SmbResource context, final String name) {
        this.fileLocator.resolveInContext(context.getLocator(), name);
        if (context.getLocator().getShare() != null && context instanceof SmbFile) {
            this.treeConnection = SmbTreeConnection.create(((SmbFile) context).treeConnection);
        } else {
            this.treeConnection = SmbTreeConnection.create(context.getContext());
        }
    }

    private static String checkName(final String name) throws MalformedURLException {
        if (name == null || name.length() == 0) {
            throw new MalformedURLException("Name must not be empty");
        }
        return name;
    }

    /**
     * Sets whether this file should use an exclusive (non-pooled) connection
     *
     * @param nonPooled
     *            whether this file will use an exclusive connection
     */
    protected void setNonPooled(final boolean nonPooled) {
        this.treeConnection.setNonPooled(nonPooled);
    }

    /**
     * Returns the transport context for this resource
     *
     * @return the transportContext
     */
    @Deprecated
    public CIFSContext getTransportContext() {
        return this.getContext();
    }

    @Override
    public CIFSContext getContext() {
        return this.transportContext;
    }

    @Override
    public SmbResourceLocator getLocator() {
        return this.fileLocator;
    }

    @Override
    public SmbResource resolve(final String name) throws CIFSException {
        try {
            if (name == null || name.length() == 0) {
                throw new SmbException("Name must not be empty");
            }
            return new SmbFile(this, name);
        } catch (MalformedURLException | UnknownHostException e) {
            // this should not actually happen
            throw new SmbException("Failed to resolve child element", e);
        }
    }

    SmbFileHandleImpl openUnshared(final int flags, final int access, final int sharing, final int attrs, final int options)
            throws CIFSException {
        return openUnshared(getUncPath(), flags, access, sharing, attrs, options);
    }

    SmbFileHandleImpl openUnshared(final String uncPath, final int flags, final int access, final int sharing, final int attrs,
            final int options) throws CIFSException {
        SmbFileHandleImpl fh = null;
        try (SmbTreeHandleImpl h = ensureTreeConnected()) {

            if (log.isDebugEnabled()) {
                log.debug(String.format("openUnshared: %s flags: %x access: %x attrs: %x options: %x", uncPath, flags, access, attrs,
                        options));
            }

            final Configuration config = h.getConfig();
            SmbBasicFileInfo info;
            boolean haveSize = true, haveAttributes = true;
            long fileSize = 0;
            if (h.isSMB2()) {
                final Smb2CreateRequest req = new Smb2CreateRequest(config, uncPath);
                req.setDesiredAccess(access);

                if ((flags & SmbConstants.O_TRUNC) == O_TRUNC && (flags & SmbConstants.O_CREAT) == O_CREAT) {
                    req.setCreateDisposition(Smb2CreateRequest.FILE_OVERWRITE_IF);
                } else if ((flags & SmbConstants.O_TRUNC) == O_TRUNC) {
                    req.setCreateDisposition(Smb2CreateRequest.FILE_OVERWRITE);
                } else if ((flags & SmbConstants.O_EXCL) == O_EXCL) {
                    req.setCreateDisposition(Smb2CreateRequest.FILE_CREATE);
                } else if ((flags & SmbConstants.O_CREAT) == O_CREAT) {
                    req.setCreateDisposition(Smb2CreateRequest.FILE_OPEN_IF);
                } else {
                    req.setCreateDisposition(Smb2CreateRequest.FILE_OPEN);
                }

                req.setShareAccess(sharing);
                req.setFileAttributes(attrs);
                final Smb2CreateResponse resp = h.send(req);
                info = resp;
                fileSize = resp.getEndOfFile();
                fh = new SmbFileHandleImpl(config, resp.getFileId(), h, uncPath, flags, access, 0, 0, resp.getEndOfFile());
            } else if (h.hasCapability(SmbConstants.CAP_NT_SMBS)) {
                final SmbComNTCreateAndXResponse resp = new SmbComNTCreateAndXResponse(config);
                final SmbComNTCreateAndX req = new SmbComNTCreateAndX(config, uncPath, flags, access, sharing, attrs, options, null);
                customizeCreate(req, resp);

                h.send(req, resp);
                info = resp;
                fileSize = resp.getEndOfFile();
                this.fileLocator.updateType(resp.getFileType());
                fh = new SmbFileHandleImpl(config, resp.getFid(), h, uncPath, flags, access, attrs, options, resp.getEndOfFile());
            } else {
                final SmbComOpenAndXResponse response = new SmbComOpenAndXResponse(config);
                h.send(new SmbComOpenAndX(config, uncPath, access, sharing, flags, attrs, null), response);
                this.fileLocator.updateType(response.getFileType());
                info = response;
                fileSize = response.getDataSize();

                // this is so damn unreliable, needs another race-prone query if required
                haveAttributes = false;

                // This seems to be the only way to obtain a reliable (with respect to locking) file size here
                // It is more critical than other attributes because append mode depends on it.
                // We do only really care if we open for writing and not shared for writing
                // otherwise there are no guarantees anyway, but this stuff is legacy anyways.
                final SmbComSeek seekReq = new SmbComSeek(config, 0);
                seekReq.setMode(0x2); // from EOF
                final SmbComSeekResponse seekResp = new SmbComSeekResponse(config);
                seekReq.setFid(response.getFid());
                try {
                    h.send(seekReq, seekResp);
                    if (log.isDebugEnabled() && seekResp.getOffset() != fileSize) {
                        log.debug(String.format("Open returned wrong size %d != %d", fileSize, seekResp.getOffset()));
                    }
                    fileSize = seekResp.getOffset();
                } catch (final Exception e) {
                    log.debug("Seek failed", e);
                    haveSize = false;
                }
                fh = new SmbFileHandleImpl(config, response.getFid(), h, uncPath, flags, access, 0, 0, fileSize);
            }

            final long attrTimeout = System.currentTimeMillis() + config.getAttributeCacheTimeout();

            if (haveSize) {
                this.size = fileSize;
                this.sizeExpiration = attrTimeout;

            }
            if (haveAttributes) {
                this.createTime = info.getCreateTime();
                this.lastModified = info.getLastWriteTime();
                this.lastAccess = info.getLastAccessTime();
                this.attributes = info.getAttributes() & ATTR_GET_MASK;
                this.attrExpiration = attrTimeout;
            }

            this.isExists = true;
            return fh;
        }
    }

    /**
     * Returns the UNC path of this resource relative to the share
     *
     * @return this file's unc path below the share
     */
    public String getUncPath() {
        return this.fileLocator.getUNCPath();
    }

    /**
     * Customizes the NT create request and response for subclass-specific behavior
     *
     * @param request the create request to customize
     * @param response the create response to customize
     */
    protected void customizeCreate(final SmbComNTCreateAndX request, final SmbComNTCreateAndXResponse response) {
    }

    SmbBasicFileInfo queryPath(final SmbTreeHandleImpl th, final String path, final int infoLevel) throws CIFSException {
        if (log.isDebugEnabled()) {
            log.debug("queryPath: " + path);
        }

        /*
         * We really should do the referral before this in case
         * the redirected target has different capabilities. But
         * the way we have been doing that is to call exists() which
         * calls this method so another technique will be necessary
         * to support DFS referral _to_ Win95/98/ME.
         */

        if (th.isSMB2()) {
            // just open and close. withOpen will store the attributes
            return (SmbBasicFileInfo) withOpen(th, Smb2CreateRequest.FILE_OPEN, SmbConstants.FILE_READ_ATTRIBUTES,
                    SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE, null);
        }
        if (th.hasCapability(SmbConstants.CAP_NT_SMBS)) {
            /*
             * Trans2 Query Path Information Request / Response
             */
            Trans2QueryPathInformationResponse response = new Trans2QueryPathInformationResponse(th.getConfig(), infoLevel);
            response = th.send(new Trans2QueryPathInformation(th.getConfig(), path, infoLevel), response);

            if (log.isDebugEnabled()) {
                log.debug("Path information " + response);
            }
            final BasicFileInformation info = response.getInfo(BasicFileInformation.class);
            this.isExists = true;
            if (info instanceof FileBasicInfo) {
                this.attributes = info.getAttributes() & ATTR_GET_MASK;
                this.createTime = info.getCreateTime();
                this.lastModified = info.getLastWriteTime();
                this.lastAccess = info.getLastAccessTime();
                this.attrExpiration = System.currentTimeMillis() + th.getConfig().getAttributeCacheTimeout();
            } else if (info instanceof FileStandardInfo) {
                this.size = info.getSize();
                this.sizeExpiration = System.currentTimeMillis() + th.getConfig().getAttributeCacheTimeout();
            }
            return info;
        }

        /*
         * Query Information Request / Response
         */
        SmbComQueryInformationResponse response = new SmbComQueryInformationResponse(th.getConfig(), th.getServerTimeZoneOffset());
        response = th.send(new SmbComQueryInformation(th.getConfig(), path), response);
        if (log.isDebugEnabled()) {
            log.debug("Legacy path information " + response);
        }

        this.isExists = true;
        this.attributes = response.getAttributes() & ATTR_GET_MASK;
        this.lastModified = response.getLastWriteTime();
        this.attrExpiration = System.currentTimeMillis() + th.getConfig().getAttributeCacheTimeout();

        this.size = response.getSize();
        this.sizeExpiration = System.currentTimeMillis() + th.getConfig().getAttributeCacheTimeout();
        return response;
    }

    @Override
    public boolean exists() throws SmbException {

        if (this.attrExpiration > System.currentTimeMillis()) {
            log.trace("Using cached attributes");
            return this.isExists;
        }

        this.attributes = ATTR_READONLY | ATTR_DIRECTORY;
        this.createTime = 0L;
        this.lastModified = 0L;
        this.lastAccess = 0L;
        this.isExists = false;

        try {
            if (this.url.getHost().length() == 0) {} else if (this.fileLocator.getShare() == null) {
                if (this.fileLocator.getType() == TYPE_WORKGROUP) {
                    getContext().getNameServiceClient().getByName(this.url.getHost(), true);
                } else {
                    getContext().getNameServiceClient().getByName(this.url.getHost()).getHostName();
                }
            } else {
                // queryPath on a share root will fail, we only know whether this is one after we have resolved DFS
                // referrals.
                try (SmbTreeHandleImpl th = ensureTreeConnected()) {
                    if (this.fileLocator.getType() == TYPE_SHARE) {
                        // treeConnect is good enough, but we need to do this after resolving DFS
                        try (SmbTreeHandleImpl th2 = ensureTreeConnected()) {}
                    } else {
                        queryPath(th, this.fileLocator.getUNCPath(), FileInformation.FILE_BASIC_INFO);
                    }
                }
            }

            /*
             * If any of the above fail, isExists will not be set true
             */

            this.isExists = true;

        } catch (final UnknownHostException uhe) {
            log.debug("Unknown host", uhe);
        } catch (final SmbException se) {
            log.trace("exists:", se);
            switch (se.getNtStatus()) {
            case NtStatus.NT_STATUS_NO_SUCH_FILE:
            case NtStatus.NT_STATUS_OBJECT_NAME_INVALID:
            case NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND:
            case NtStatus.NT_STATUS_OBJECT_PATH_NOT_FOUND:
                break;
            default:
                throw se;
            }
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }

        this.attrExpiration = System.currentTimeMillis() + getContext().getConfig().getAttributeCacheTimeout();
        return this.isExists;
    }

    @Override
    public int getType() throws SmbException {
        try {
            final int t = this.fileLocator.getType();
            if (t == TYPE_SHARE) {
                try (SmbTreeHandle th = ensureTreeConnected()) {
                    this.fileLocator.updateType(th.getTreeType());
                }
            }
            return t;
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    @Override
    public String getName() {
        return this.fileLocator.getName();
    }

    /**
     * Everything but the last component of the URL representing this SMB
     * resource is effectively it's parent. The root URL <code>smb://</code>
     * does not have a parent. In this case <code>smb://</code> is returned.
     *
     * @return The parent directory of this SMB resource or
     *         <code>smb://</code> if the resource refers to the root of the URL
     *         hierarchy which incidentally is also <code>smb://</code>.
     */
    public String getParent() {
        return this.fileLocator.getParent();
    }

    /**
     * Returns the full uncanonicalized URL of this SMB resource. An
     * <code>SmbFile</code> constructed with the result of this method will
     * result in an <code>SmbFile</code> that is equal to the original.
     *
     * @return The uncanonicalized full URL of this SMB resource.
     */

    public String getPath() {
        return this.fileLocator.getPath();
    }

    /**
     * Returns the Windows UNC style path with backslashes instead of forward slashes.
     *
     * @return The UNC path.
     */
    public String getCanonicalUncPath() {
        return this.fileLocator.getCanonicalURL();
    }

    /**
     * If the path of this <code>SmbFile</code> falls within a DFS volume,
     * this method will return the referral path to which it maps. Otherwise
     * <code>null</code> is returned.
     *
     * @return URL to the DFS volume
     * @throws SmbException if an error occurs while resolving the DFS path
     */
    public String getDfsPath() throws SmbException {
        try {
            String path = this.treeConnection.ensureDFSResolved(this.fileLocator).getDfsPath();
            if (path != null && isDirectory() && !path.endsWith("/")) {
                path += '/';
            }
            return path;
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    /**
     * Returns the full URL of this SMB resource with '.' and '..' components
     * factored out. An <code>SmbFile</code> constructed with the result of
     * this method will result in an <code>SmbFile</code> that is equal to
     * the original.
     *
     * @return The canonicalized URL of this SMB resource.
     */
    public String getCanonicalPath() {
        return this.fileLocator.getCanonicalURL();
    }

    /**
     * Retrieves the share associated with this SMB resource. In
     * the case of <code>smb://</code>, <code>smb://workgroup/</code>,
     * and <code>smb://server/</code> URLs which do not specify a share,
     * <code>null</code> will be returned.
     *
     * @return The share component or <code>null</code> if there is no share
     */
    public String getShare() {
        return this.fileLocator.getShare();
    }

    /**
     * Retrieve the hostname of the server for this SMB resource. If the resources has been resolved by DFS this will
     * return the target name.
     *
     * @return The server name
     */
    public String getServerWithDfs() {
        return this.fileLocator.getServerWithDfs();
    }

    /**
     * Retrieve the hostname of the server for this SMB resource. If this
     * <code>SmbFile</code> references a workgroup, the name of the workgroup
     * is returned. If this <code>SmbFile</code> refers to the root of this
     * SMB network hierarchy, <code>null</code> is returned.
     *
     * @return The server or workgroup name or <code>null</code> if this
     *         <code>SmbFile</code> refers to the root <code>smb://</code> resource.
     */
    public String getServer() {
        return this.fileLocator.getServer();
    }

    @Override
    public SmbWatchHandle watch(final int filter, final boolean recursive) throws CIFSException {

        if (filter == 0) {
            throw new IllegalArgumentException("filter must not be 0");
        }

        if (!isDirectory()) {
            throw new SmbException("Is not a directory");
        }

        try (SmbTreeHandleImpl th = ensureTreeConnected()) {
            if (!th.isSMB2() && !th.hasCapability(SmbConstants.CAP_NT_SMBS)) {
                throw new SmbUnsupportedOperationException("Not supported without CAP_NT_SMBS");
            }
            return new SmbWatchHandleImpl(openUnshared(O_RDONLY, READ_CONTROL | GENERIC_READ, DEFAULT_SHARING, 0, 1), filter, recursive);
        }
    }

    @Override
    public boolean canRead() throws SmbException {
        if (getType() == TYPE_NAMED_PIPE) { // try opening the pipe for reading?
            return true;
        }
        return exists(); // try opening and catch sharing violation?
    }

    @Override
    public boolean canWrite() throws SmbException {
        if (getType() == TYPE_NAMED_PIPE) { // try opening the pipe for writing?
            return true;
        }
        return exists() && (this.attributes & ATTR_READONLY) == 0;
    }

    @Override
    public boolean isDirectory() throws SmbException {
        if (this.fileLocator.isRootOrShare()) {
            return true;
        }
        if (!exists()) {
            return false;
        }
        return (this.attributes & ATTR_DIRECTORY) == ATTR_DIRECTORY;
    }

    @Override
    public boolean isFile() throws SmbException {
        if (this.fileLocator.isRootOrShare()) {
            return false;
        }
        exists();
        return (this.attributes & ATTR_DIRECTORY) == 0;
    }

    @Override
    public boolean isHidden() throws SmbException {
        if (this.fileLocator.getShare() == null) {
            return false;
        }
        if (this.fileLocator.isRootOrShare()) {
            if (this.fileLocator.getShare().endsWith("$")) {
                return true;
            }
            return false;
        }
        exists();
        return (this.attributes & ATTR_HIDDEN) == ATTR_HIDDEN;
    }

    @Override
    public long createTime() throws SmbException {
        if (!this.fileLocator.isRootOrShare()) {
            exists();
            return this.createTime;
        }
        return 0L;
    }

    @Override
    public long lastModified() throws SmbException {
        if (!this.fileLocator.isRootOrShare()) {
            exists();
            return this.lastModified;
        }
        return 0L;
    }

    @Override
    public long lastAccess() throws SmbException {
        if (!this.fileLocator.isRootOrShare()) {
            exists();
            return this.lastAccess;
        }
        return 0L;
    }

    /**
     * List the contents of this SMB resource. The list returned by this
     * method will be;
     *
     * <ul>
     * <li>files and directories contained within this resource if the
     * resource is a normal disk file directory,
     * <li>all available NetBIOS workgroups or domains if this resource is
     * the top level URL <code>smb://</code>,
     * <li>all servers registered as members of a NetBIOS workgroup if this
     * resource refers to a workgroup in a <code>smb://workgroup/</code> URL,
     * <li>all browseable shares of a server including printers, IPC
     * services, or disk volumes if this resource is a server URL in the form
     * <code>smb://server/</code>,
     * <li>or <code>null</code> if the resource cannot be resolved.
     * </ul>
     *
     * @return A <code>String[]</code> array of files and directories,
     *         workgroups, servers, or shares depending on the context of the
     *         resource URL
     * @throws SmbException if an error occurs while listing the contents
     */
    public String[] list() throws SmbException {
        return SmbEnumerationUtil.list(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
    }

    /**
     * List the contents of this SMB resource. The list returned will be
     * identical to the list returned by the parameterless <code>list()</code>
     * method minus filenames filtered by the specified filter.
     *
     * @param filter
     *            a filename filter to exclude filenames from the results
     * @return <code>String[]</code> array of matching files and directories,
     *         workgroups, servers, or shares depending on the context of the
     *         resource URL
     * @throws SmbException
     *             # @return An array of filenames
     */
    public String[] list(final SmbFilenameFilter filter) throws SmbException {
        return SmbEnumerationUtil.list(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, filter, null);
    }

    /**
     * List the contents of this SMB resource as an array of
     * <code>SmbResource</code> objects. This method is much more efficient than
     * the regular <code>list</code> method when querying attributes of each
     * file in the result set.
     * <p>
     * The list of <code>SmbResource</code>s returned by this method will be;
     *
     * <ul>
     * <li>files and directories contained within this resource if the
     * resource is a normal disk file directory,
     * <li>all available NetBIOS workgroups or domains if this resource is
     * the top level URL <code>smb://</code>,
     * <li>all servers registered as members of a NetBIOS workgroup if this
     * resource refers to a workgroup in a <code>smb://workgroup/</code> URL,
     * <li>all browseable shares of a server including printers, IPC
     * services, or disk volumes if this resource is a server URL in the form
     * <code>smb://server/</code>,
     * <li>or <code>null</code> if the resource cannot be resolved.
     * </ul>
     *
     * If strict resource lifecycle is used, make sure you close the individual files after use.
     *
     * @return An array of <code>SmbResource</code> objects representing file
     *         and directories, workgroups, servers, or shares depending on the context
     *         of the resource URL
     * @throws SmbException if an error occurs while listing the files
     */
    public SmbFile[] listFiles() throws SmbException {
        return SmbEnumerationUtil.listFiles(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
    }

    /**
     * The CIFS protocol provides for DOS "wildcards" to be used as
     * a performance enhancement. The client does not have to filter
     * the names and the server does not have to return all directory
     * entries.
     * <p>
     * The wildcard expression may consist of two special meta
     * characters in addition to the normal filename characters. The '*'
     * character matches any number of characters in part of a name. If
     * the expression begins with one or more '?'s then exactly that
     * many characters will be matched whereas if it ends with '?'s
     * it will match that many characters <i>or less</i>.
     * <p>
     * Wildcard expressions will not filter workgroup names or server names.
     *
     * <blockquote>
     *
     * <pre>
     * winnt&gt; ls c?o*
     * clock.avi                  -rw--      82944 Mon Oct 14 1996 1:38 AM
     * Cookies                    drw--          0 Fri Nov 13 1998 9:42 PM
     * 2 items in 5ms
     * </pre>
     *
     * </blockquote>
     *
     * If strict resource lifecycle is used, make sure you close the individual files after use.
     *
     * @param wildcard
     *            a wildcard expression
     * @throws SmbException if an error occurs while listing the files
     * @return An array of <code>SmbResource</code> objects representing file
     *         and directories, workgroups, servers, or shares depending on the context
     *         of the resource URL
     */
    public SmbFile[] listFiles(final String wildcard) throws SmbException {
        return SmbEnumerationUtil.listFiles(this, wildcard, ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
    }

    /**
     * List the contents of this SMB resource. The list returned will be
     * identical to the list returned by the parameterless <code>listFiles()</code>
     * method minus files filtered by the specified filename filter.
     *
     * If strict resource lifecycle is used, make sure you close the individual files after use.
     *
     * @param filter
     *            a filter to exclude files from the results
     * @return An array of {@code SmbResource} objects
     * @throws SmbException if an error occurs while listing the files
     */
    public SmbFile[] listFiles(final SmbFilenameFilter filter) throws SmbException {
        return SmbEnumerationUtil.listFiles(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, filter, null);
    }

    /**
     * List the contents of this SMB resource. The list returned will be
     * identical to the list returned by the parameterless <code>listFiles()</code>
     * method minus filenames filtered by the specified filter.
     *
     * If strict resource lifecycle is used, make sure you close the individual files after use.
     *
     * @param filter
     *            a file filter to exclude files from the results
     * @return An array of {@code SmbResource} objects
     * @throws SmbException if an error occurs while listing the files
     */
    public SmbFile[] listFiles(final SmbFileFilter filter) throws SmbException {
        return SmbEnumerationUtil.listFiles(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, filter);
    }

    @Override
    public CloseableIterator<SmbResource> children() throws CIFSException {
        return SmbEnumerationUtil.doEnum(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
    }

    @Override
    public CloseableIterator<SmbResource> children(final String wildcard) throws CIFSException {
        return SmbEnumerationUtil.doEnum(this, wildcard, ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
    }

    @Override
    public CloseableIterator<SmbResource> children(final ResourceNameFilter filter) throws CIFSException {
        return SmbEnumerationUtil.doEnum(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, filter, null);
    }

    @Override
    public CloseableIterator<SmbResource> children(final ResourceFilter filter) throws CIFSException {
        return SmbEnumerationUtil.doEnum(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, filter);
    }

    @Override
    public void renameTo(final SmbResource d) throws SmbException {
        renameTo(d, false);
    }

    @Override
    public void renameTo(final SmbResource d, final boolean replace) throws SmbException {
        if (!(d instanceof final SmbFile dest)) {
            throw new SmbException("Invalid target resource");
        }
        try (SmbTreeHandleImpl sh = ensureTreeConnected(); SmbTreeHandleImpl th = dest.ensureTreeConnected()) {

            // this still might be required for standalone DFS
            if (!exists()) {
                throw new SmbException(NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND, null);
            }
            dest.exists();

            if (this.fileLocator.isRootOrShare() || dest.fileLocator.isRootOrShare()) {
                throw new SmbException("Invalid operation for workgroups, servers, or shares");
            }

            if (!sh.isSameTree(th)) {
                // trigger requests to resolve the actual target
                exists();
                dest.exists();

                if (!Objects.equals(getServerWithDfs(), dest.getServerWithDfs()) || !Objects.equals(getShare(), dest.getShare())) {
                    throw new SmbException("Cannot rename between different trees");
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("renameTo: " + getUncPath() + " -> " + dest.getUncPath());
            }

            dest.attrExpiration = dest.sizeExpiration = 0;
            /*
             * Rename Request / Response
             */
            if (sh.isSMB2()) {
                final Smb2SetInfoRequest req = new Smb2SetInfoRequest(sh.getConfig());
                req.setFileInformation(new FileRenameInformation2(dest.getUncPath().substring(1), replace));
                withOpen(sh, Smb2CreateRequest.FILE_OPEN, FILE_WRITE_ATTRIBUTES | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE, req);
            } else {
                if (replace) {
                    // TRANS2_SET_FILE_INFORMATION does not seem to support the SMB1 RENAME_INFO
                    throw new SmbUnsupportedOperationException("Replacing rename only supported with SMB2");
                }
                sh.send(new SmbComRename(sh.getConfig(), getUncPath(), dest.getUncPath()), new SmbComBlankResponse(sh.getConfig()));
            }

            this.attrExpiration = this.sizeExpiration = 0;
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    void copyRecursive(final SmbFile dest, final byte[][] b, final int bsize, final WriterThread w, final SmbTreeHandleImpl sh,
            final SmbTreeHandleImpl dh) throws CIFSException {
        if (isDirectory()) {
            SmbCopyUtil.copyDir(this, dest, b, bsize, w, sh, dh);
        } else {
            SmbCopyUtil.copyFile(this, dest, b, bsize, w, sh, dh);
        }

        dest.clearAttributeCache();
    }

    /**
     *
     */
    void clearAttributeCache() {
        this.attrExpiration = 0;
        this.sizeExpiration = 0;
    }

    @Override
    public void copyTo(final SmbResource d) throws SmbException {
        if (!(d instanceof final SmbFile dest)) {
            throw new SmbException("Invalid target resource");
        }
        try (SmbTreeHandleImpl sh = ensureTreeConnected(); SmbTreeHandleImpl dh = dest.ensureTreeConnected()) {
            if (!exists()) {
                throw new SmbException(NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND, null);
            }

            /*
             * Should be able to copy an entire share actually
             */
            if (this.fileLocator.getShare() == null || dest.getLocator().getShare() == null) {
                throw new SmbException("Invalid operation for workgroups or servers");
            }

            /*
             * It is invalid for the source path to be a child of the destination
             * path or visa versa.
             */
            if (this.fileLocator.overlaps(dest.getLocator())) {
                throw new SmbException("Source and destination paths overlap.");
            }

            final WriterThread w = new WriterThread();
            w.setDaemon(true);

            try {
                w.start();
                // use commonly acceptable buffer size
                final int bsize = Math.min(sh.getReceiveBufferSize() - 70, dh.getSendBufferSize() - 70);
                final byte[][] b = new byte[2][bsize];
                copyRecursive(dest, b, bsize, w, sh, dh);
            } finally {
                w.write(null, -1, null);
                w.interrupt();
                try {
                    w.join();
                } catch (final InterruptedException e) {
                    log.warn("Interrupted while joining copy thread", e);
                }
            }
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    @Override
    public void delete() throws SmbException {
        try {
            delete(this.fileLocator.getUNCPath());
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
        close();
    }

    void delete(final String fileName) throws CIFSException {
        if (this.fileLocator.isRootOrShare()) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        try (SmbTreeHandleImpl th = ensureTreeConnected()) {
            if (!exists()) {
                throw new SmbException(NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND, null);
            }

            if ((this.attributes & ATTR_READONLY) != 0) {
                setReadWrite();
            }

            /*
             * Delete or Delete Directory Request / Response
             */

            if (log.isDebugEnabled()) {
                log.debug("delete: " + fileName);
            }

            if ((this.attributes & ATTR_DIRECTORY) != 0) {

                /*
                 * Recursively delete directory contents
                 */

                try (CloseableIterator<SmbResource> it =
                        SmbEnumerationUtil.doEnum(this, "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null)) {
                    while (it.hasNext()) {
                        try (SmbResource r = it.next()) {
                            try {
                                r.delete();
                            } catch (final CIFSException e) {
                                throw SmbException.wrap(e);
                            }
                        }
                    }
                } catch (final SmbException se) {
                    /*
                     * Oracle FilesOnline version 9.0.4 doesn't send '.' and '..' so
                     * listFiles may generate undesirable "cannot find
                     * the file specified".
                     */
                    log.debug("delete", se);
                    if (se.getNtStatus() != NtStatus.NT_STATUS_NO_SUCH_FILE) {
                        throw se;
                    }
                }

                if (th.isSMB2()) {
                    final Smb2CreateRequest req = new Smb2CreateRequest(th.getConfig(), fileName);
                    req.setDesiredAccess(0x10000); // delete
                    req.setCreateOptions(Smb2CreateRequest.FILE_DELETE_ON_CLOSE | Smb2CreateRequest.FILE_DIRECTORY_FILE);
                    req.setCreateDisposition(Smb2CreateRequest.FILE_OPEN);
                    req.chain(new Smb2CloseRequest(th.getConfig(), fileName));
                    th.send(req);
                } else {
                    th.send(new SmbComDeleteDirectory(th.getConfig(), fileName), new SmbComBlankResponse(th.getConfig()));
                }
            } else if (th.isSMB2()) {
                final Smb2CreateRequest req = new Smb2CreateRequest(th.getConfig(), fileName.substring(1));
                req.setDesiredAccess(0x10000); // delete
                req.setCreateOptions(Smb2CreateRequest.FILE_DELETE_ON_CLOSE);
                req.chain(new Smb2CloseRequest(th.getConfig(), fileName));
                th.send(req);
            } else {
                th.send(new SmbComDelete(th.getConfig(), fileName), new SmbComBlankResponse(th.getConfig()));
            }
            this.attrExpiration = this.sizeExpiration = 0;
        }

    }

    @Override
    public long length() throws SmbException {
        if (this.sizeExpiration > System.currentTimeMillis()) {
            return this.size;
        }

        try (SmbTreeHandleImpl th = ensureTreeConnected()) {
            final int t = getType();
            if (t == TYPE_SHARE) {
                this.size = fetchAllocationInfo(th).getCapacity();
            } else if (!this.fileLocator.isRoot() && t != TYPE_NAMED_PIPE) {
                queryPath(th, this.fileLocator.getUNCPath(), FileInformation.FILE_STANDARD_INFO);
            } else {
                this.size = 0L;
            }
            this.sizeExpiration = System.currentTimeMillis() + getContext().getConfig().getAttributeCacheTimeout();
            return this.size;
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    @Override
    public long getDiskFreeSpace() throws SmbException {
        try (SmbTreeHandleImpl th = ensureTreeConnected()) {
            final int t = getType();
            if (t == TYPE_SHARE || t == TYPE_FILESYSTEM) {
                final AllocInfo allocInfo = fetchAllocationInfo(th);
                this.size = allocInfo.getCapacity();
                this.sizeExpiration = System.currentTimeMillis() + getContext().getConfig().getAttributeCacheTimeout();
                return allocInfo.getFree();
            }
            return 0L;
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    /**
     * @return
     * @throws CIFSException
     * @throws SmbException
     */
    private AllocInfo fetchAllocationInfo(final SmbTreeHandleImpl th) throws CIFSException, SmbException {
        AllocInfo ai;
        try {
            ai = queryFSInformation(th, AllocInfo.class, FileSystemInformation.FS_SIZE_INFO);
        } catch (final SmbException ex) {
            log.debug("getDiskFreeSpace", ex);
            switch (ex.getNtStatus()) {
            case NtStatus.NT_STATUS_INVALID_INFO_CLASS:
            case NtStatus.NT_STATUS_UNSUCCESSFUL: // NetApp Filer
                if (!th.isSMB2()) {
                    // SMB_FS_FULL_SIZE_INFORMATION not supported by the server.
                    ai = queryFSInformation(th, AllocInfo.class, FileSystemInformation.SMB_INFO_ALLOCATION);
                    break;
                }
            default:
                throw ex;
            }
        }
        return ai;
    }

    private <T extends FileSystemInformation> T queryFSInformation(final SmbTreeHandleImpl th, final Class<T> clazz, final byte level)
            throws CIFSException {
        if (th.isSMB2()) {
            final Smb2QueryInfoRequest qreq = new Smb2QueryInfoRequest(th.getConfig());
            qreq.setFilesystemInfoClass(level);
            final Smb2QueryInfoResponse resp = withOpen(th, Smb2CreateRequest.FILE_OPEN, SmbConstants.FILE_READ_ATTRIBUTES,
                    SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE, qreq);
            return resp.getInfo(clazz);
        }
        final Trans2QueryFSInformationResponse response = new Trans2QueryFSInformationResponse(th.getConfig(), level);
        th.send(new Trans2QueryFSInformation(th.getConfig(), level), response);
        return response.getInfo(clazz);
    }

    @Override
    public void mkdir() throws SmbException {
        String path = this.fileLocator.getUNCPath();

        if (path.length() == 1) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        try (SmbTreeHandleImpl th = ensureTreeConnected()) {
            // should not normally be required, but samba without NTStatus does not properly resolve the path and fails
            // with
            // STATUS_UNSUCCESSFUL
            exists();
            // get the path again, this may have changed through DFS referrals
            path = this.fileLocator.getUNCPath();

            /*
             * Create Directory Request / Response
             */

            if (log.isDebugEnabled()) {
                log.debug("mkdir: " + path);
            }

            if (th.isSMB2()) {
                final Smb2CreateRequest req = new Smb2CreateRequest(th.getConfig(), path);
                req.setCreateDisposition(Smb2CreateRequest.FILE_CREATE);
                req.setCreateOptions(Smb2CreateRequest.FILE_DIRECTORY_FILE);
                req.chain(new Smb2CloseRequest(th.getConfig(), path));
                th.send(req);
            } else {
                th.send(new SmbComCreateDirectory(th.getConfig(), path), new SmbComBlankResponse(th.getConfig()));
            }
            this.attrExpiration = this.sizeExpiration = 0;
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    @Override
    public void mkdirs() throws SmbException {
        final String p = this.fileLocator.getParent();
        try (SmbTreeHandle th = ensureTreeConnected(); SmbFile parent = new SmbFile(p, getContext())) {
            try {
                if (!parent.exists()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Parent does not exist " + p);
                    }
                    parent.mkdirs();
                }
            } catch (final SmbException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to ensure parent exists " + p, e);
                }
                throw e;
            }
            try {
                mkdir();
            } catch (final SmbException e) {
                log.debug("mkdirs", e);
                // Ignore "Cannot create a file when that file already exists." errors for now as
                // they seem to be show up under some conditions most likely due to timing issues.
                if (e.getNtStatus() != NtStatus.NT_STATUS_OBJECT_NAME_COLLISION) {
                    throw e;
                }
            }
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        } catch (final MalformedURLException e) {
            throw new SmbException("Invalid URL in mkdirs", e);
        }
    }

    /**
     * Executes a request within the context of an open file handle
     *
     * @param <T> the response type
     * @param th the tree handle
     * @param first the first request to execute
     * @param others additional requests to chain
     * @return the response from the first request
     * @throws CIFSException if an error occurs
     */
    protected <T extends ServerMessageBlock2Response> T withOpen(final SmbTreeHandleImpl th, final ServerMessageBlock2Request<T> first,
            final ServerMessageBlock2Request<?>... others) throws CIFSException {
        return withOpen(th, Smb2CreateRequest.FILE_OPEN, 0x00120089, SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE, first,
                others);
    }

    /**
     * Executes a request within the context of an open file handle with specified access
     *
     * @param <T> the response type
     * @param th the tree handle
     * @param createDisposition the create disposition
     * @param desiredAccess the desired access flags
     * @param shareAccess the share access flags
     * @param first the first request to execute
     * @param others additional requests to chain
     * @return the response from the first request
     * @throws CIFSException if an error occurs
     */
    protected <T extends ServerMessageBlock2Response> T withOpen(final SmbTreeHandleImpl th, final int createDisposition,
            final int desiredAccess, final int shareAccess, final ServerMessageBlock2Request<T> first,
            final ServerMessageBlock2Request<?>... others) throws CIFSException {
        return withOpen(th, createDisposition, 0, SmbConstants.ATTR_NORMAL, desiredAccess, shareAccess, first, others);
    }

    /**
     * Executes a request within the context of an open file handle with full control over creation parameters
     *
     * @param <T> the response type
     * @param th the tree handle
     * @param createDisposition the create disposition
     * @param createOptions the create options
     * @param fileAttributes the file attributes
     * @param desiredAccess the desired access flags
     * @param shareAccess the share access flags
     * @param first the first request to execute
     * @param others additional requests to chain
     * @return the response from the first request
     * @throws CIFSException if an error occurs
     */
    @SuppressWarnings("unchecked")
    protected <T extends ServerMessageBlock2Response> T withOpen(final SmbTreeHandleImpl th, final int createDisposition,
            final int createOptions, final int fileAttributes, final int desiredAccess, final int shareAccess,
            final ServerMessageBlock2Request<T> first, final ServerMessageBlock2Request<?>... others) throws CIFSException {
        final Smb2CreateRequest cr = new Smb2CreateRequest(th.getConfig(), getUncPath());
        try {
            cr.setCreateDisposition(createDisposition);
            cr.setCreateOptions(createOptions);
            cr.setFileAttributes(fileAttributes);
            cr.setDesiredAccess(desiredAccess);
            cr.setShareAccess(shareAccess);

            ServerMessageBlock2Request<?> cur = cr;

            if (first != null) {
                cr.chain(first);
                cur = first;

                for (final ServerMessageBlock2Request<?> req : others) {
                    cur.chain(req);
                    cur = req;
                }
            }

            final Smb2CloseRequest closeReq = new Smb2CloseRequest(th.getConfig(), getUncPath());
            closeReq.setCloseFlags(Smb2CloseResponse.SMB2_CLOSE_FLAG_POSTQUERY_ATTIB);
            cur.chain(closeReq);

            final Smb2CreateResponse createResp = th.send(cr);

            final Smb2CloseResponse closeResp = closeReq.getResponse();
            SmbBasicFileInfo info;

            if ((closeResp.getCloseFlags() & Smb2CloseResponse.SMB2_CLOSE_FLAG_POSTQUERY_ATTIB) != 0) {
                info = closeResp;
            } else {
                info = createResp;
            }

            this.isExists = true;
            this.createTime = info.getCreateTime();
            this.lastModified = info.getLastWriteTime();
            this.lastAccess = info.getLastAccessTime();
            this.attributes = info.getAttributes() & ATTR_GET_MASK;
            this.attrExpiration = System.currentTimeMillis() + th.getConfig().getAttributeCacheTimeout();

            this.size = info.getSize();
            this.sizeExpiration = System.currentTimeMillis() + th.getConfig().getAttributeCacheTimeout();
            return (T) createResp.getNextResponse();
        } catch (CIFSException | RuntimeException e) {
            try {
                // make sure that the handle is closed when one of the requests fails
                final Smb2CreateResponse createResp = cr.getResponse();
                if (createResp.isReceived() && createResp.getStatus() == NtStatus.NT_STATUS_SUCCESS) {
                    th.send(new Smb2CloseRequest(th.getConfig(), createResp.getFileId()), RequestParam.NO_RETRY);
                }
            } catch (final Exception e2) {
                log.debug("Failed to close after failure", e2);
                e.addSuppressed(e2);
            }
            throw e;
        }
    }

    @Override
    public void createNewFile() throws SmbException {
        if (this.fileLocator.isRootOrShare()) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        try (SmbTreeHandleImpl th = ensureTreeConnected()) {

            if (th.isSMB2()) {
                withOpen(th, Smb2CreateRequest.FILE_OPEN_IF, O_RDWR, 0, null);
            } else {
                try (SmbFileHandle fd = openUnshared(O_RDWR | O_CREAT | O_EXCL, O_RDWR, FILE_NO_SHARE, ATTR_NORMAL, 0)) {
                    // close explicitly
                    fd.close(0L);
                }
            }
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    void setPathInformation(final int attrs, final long ctime, final long mtime, final long atime) throws CIFSException {
        try (SmbTreeHandleImpl th = ensureTreeConnected()) {
            if (!exists()) {
                throw new SmbException(NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND, null);
            }

            final int dir = this.attributes & ATTR_DIRECTORY;

            if (th.isSMB2()) {

                final Smb2SetInfoRequest req = new Smb2SetInfoRequest(th.getConfig());
                req.setFileInformation(new FileBasicInfo(ctime, atime, mtime, 0L, attrs | dir));
                withOpen(th, Smb2CreateRequest.FILE_OPEN, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, req);
            } else if (th.hasCapability(SmbConstants.CAP_NT_SMBS)) {

                try (SmbFileHandleImpl f = openUnshared(O_RDONLY, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, dir,
                        dir != 0 ? 0x0001 : 0x0040)) {
                    th.send(new Trans2SetFileInformation(th.getConfig(), f.getFid(), attrs | dir, ctime, mtime, atime),
                            new Trans2SetFileInformationResponse(th.getConfig()), RequestParam.NO_RETRY);
                }
            } else {
                if (ctime != 0 || atime != 0) {
                    throw new SmbUnsupportedOperationException("Cannot set creation or access time without CAP_NT_SMBS");
                }
                th.send(new SmbComSetInformation(th.getConfig(), getUncPath(), attrs, mtime - th.getServerTimeZoneOffset()),
                        new SmbComSetInformationResponse(th.getConfig()));
            }

            this.attrExpiration = 0;
        }
    }

    @Override
    public void setFileTimes(final long createTime, final long lastLastModified, final long lastLastAccess) throws SmbException {
        if (this.fileLocator.isRootOrShare()) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        try {
            setPathInformation(0, createTime, lastLastModified, lastLastAccess);
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    @Override
    public void setCreateTime(final long time) throws SmbException {
        if (this.fileLocator.isRootOrShare()) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        try {
            setPathInformation(0, time, 0L, 0L);
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    @Override
    public void setLastModified(final long time) throws SmbException {
        if (this.fileLocator.isRootOrShare()) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        try {
            setPathInformation(0, 0L, time, 0L);
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    @Override
    public void setLastAccess(final long time) throws SmbException {
        if (this.fileLocator.isRootOrShare()) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }

        try {
            setPathInformation(0, 0L, 0L, time);
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    @Override
    public int getAttributes() throws SmbException {
        if (this.fileLocator.isRootOrShare()) {
            return 0;
        }
        exists();
        return this.attributes & ATTR_GET_MASK;
    }

    @Override
    public void setAttributes(final int attrs) throws SmbException {
        if (this.fileLocator.isRootOrShare()) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }
        try {
            setPathInformation(attrs & ATTR_SET_MASK, 0L, 0L, 0L);
        } catch (final SmbException e) {
            if (e.getNtStatus() != 0xC00000BB) {
                throw e;
            }
            throw new SmbUnsupportedOperationException("Attribute not supported by server");
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    @Override
    public void setReadOnly() throws SmbException {
        setAttributes(getAttributes() | ATTR_READONLY);
    }

    @Override
    public void setReadWrite() throws SmbException {
        setAttributes(getAttributes() & ~ATTR_READONLY);
    }

    /**
     * Returns a {@link java.net.URL} for this <code>SmbFile</code>. The
     * <code>URL</code> may be used as any other <code>URL</code> might to
     * access an SMB resource. Currently only retrieving data and information
     * is supported (i.e. no {@code doOutput}).
     *
     * @deprecated Use getURL() instead
     * @return A new <code>{@link java.net.URL}</code> for this <code>SmbFile</code>
     */
    @Deprecated
    public URL toURL() {
        return getURL();
    }

    /**
     * Computes a hashCode for this file based on the URL string and IP
     * address if the server. The hashing function uses the hashcode of the
     * server address, the canonical representation of the URL, and does not
     * compare authentication information. In essence, two
     * <code>SmbFile</code> objects that refer to
     * the same file should generate the same hashcode provided it is possible
     * to make such a determination.
     *
     * @return A hashcode for this abstract file
     */
    @Override
    public int hashCode() {
        return this.fileLocator.hashCode();
    }

    /**
     * Tests to see if two <code>SmbFile</code> objects are equal. Two
     * SmbFile objects are equal when they reference the same SMB
     * resource. More specifically, two <code>SmbFile</code> objects are
     * equals if their server IP addresses are equal and the canonicalized
     * representation of their URLs, minus authentication parameters, are
     * case insensitively and lexographically equal.
     * <br>
     * For example, assuming the server <code>angus</code> resolves to the
     * <code>192.168.1.15</code> IP address, the below URLs would result in
     * <code>SmbFile</code>s that are equal.
     *
     * <blockquote>
     *
     * <pre>
     * smb://192.168.1.15/share/DIR/foo.txt
     * smb://angus/share/data/../dir/foo.txt
     * </pre>
     *
     * </blockquote>
     *
     * @param obj
     *            Another <code>SmbFile</code> object to compare for equality
     * @return <code>true</code> if the two objects refer to the same SMB resource
     *         and <code>false</code> otherwise
     */

    @Override
    public boolean equals(final Object obj) {
        if (obj instanceof SmbFile) {
            final SmbResource f = (SmbResource) obj;

            if (this == f) {
                return true;
            }

            return this.fileLocator.equals(f.getLocator());
        }

        return false;
    }

    /**
     * Returns the string representation of this SmbFile object. This will
     * be the same as the URL used to construct this <code>SmbFile</code>.
     * This method will return the same value
     * as <code>getPath</code>.
     *
     * @return The original URL representation of this SMB resource
     */

    @Override
    public String toString() {
        return Strings.maskSecretValue(url.toString());
    }

    /* URLConnection implementation */
    /**
     * This URLConnection method just returns the result of {@code length()}.
     *
     * @return the length of this file or 0 if it refers to a directory
     */
    @Deprecated
    @Override
    public int getContentLength() {
        try {
            return (int) (length() & 0xFFFFFFFFL);
        } catch (final SmbException se) {
            log.debug("getContentLength", se);
        }
        return 0;
    }

    /**
     * {@inheritDoc}
     *
     * @see java.net.URLConnection#getContentLengthLong()
     */
    @Override
    public long getContentLengthLong() {
        try {
            return length();
        } catch (final SmbException se) {
            log.debug("getContentLength", se);
        }
        return 0;
    }

    /**
     * This URLConnection method just returns the result of {@code lastModified}.
     *
     * @return the last modified data as milliseconds since Jan 1, 1970
     */
    @Override
    public long getDate() {
        try {
            return lastModified();
        } catch (final SmbException se) {
            log.debug("getDate", se);
        }
        return 0L;
    }

    /**
     * This URLConnection method just returns the result of {@code lastModified}.
     *
     * @return the last modified data as milliseconds since Jan 1, 1970
     */
    @Override
    public long getLastModified() {
        try {
            return lastModified();
        } catch (final SmbException se) {
            log.debug("getLastModified", se);
        }
        return 0L;
    }

    /**
     * This URLConnection method just returns a new {@code SmbFileInputStream} created with this file.
     *
     * @throws IOException
     *             thrown by {@code SmbFileInputStream} constructor
     */
    @Override
    public InputStream getInputStream() throws IOException {
        return new SmbFileInputStream(this);
    }

    @Override
    public SmbFileInputStream openInputStream() throws SmbException {
        return new SmbFileInputStream(this);
    }

    @Override
    public SmbFileInputStream openInputStream(final int sharing) throws SmbException {
        return openInputStream(0, O_RDONLY, sharing);
    }

    @Override
    public SmbFileInputStream openInputStream(final int flags, final int access, final int sharing) throws SmbException {
        return new SmbFileInputStream(this, flags, access, sharing, false);
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return new SmbFileOutputStream(this);
    }

    @Override
    public SmbFileOutputStream openOutputStream() throws SmbException {
        return new SmbFileOutputStream(this);
    }

    @Override
    public SmbFileOutputStream openOutputStream(final boolean append) throws SmbException {
        return openOutputStream(append, FILE_SHARE_READ);
    }

    @Override
    public SmbFileOutputStream openOutputStream(final boolean append, final int sharing) throws SmbException {
        return openOutputStream(append, append ? O_CREAT | O_WRONLY | O_APPEND : O_CREAT | O_WRONLY | O_TRUNC, 0, sharing);
    }

    @Override
    public SmbFileOutputStream openOutputStream(final boolean append, final int openFlags, final int access, final int sharing)
            throws SmbException {
        return new SmbFileOutputStream(this, append, openFlags, access, sharing);
    }

    @Override
    public SmbRandomAccessFile openRandomAccess(final String mode) throws SmbException {
        return new SmbRandomAccessFile(this, mode);
    }

    @Override
    public SmbRandomAccessFile openRandomAccess(final String mode, final int sharing) throws SmbException {
        return new SmbRandomAccessFile(this, mode, sharing, false);
    }

    private void processAces(final ACE[] aces, final boolean resolveSids) throws IOException {
        String server = this.fileLocator.getServerWithDfs();
        int ai;

        if (resolveSids) {
            if (this.fileLocator.getDfsPath() == null && this.fileLocator.getPort() != -1) {
                server = server + ":" + this.fileLocator.getPort();
            }
            final SID[] sids = new SID[aces.length];
            for (ai = 0; ai < aces.length; ai++) {
                sids[ai] = aces[ai].getSID();
            }

            for (int off = 0; off < sids.length; off += 64) {
                int len = sids.length - off;
                if (len > 64) {
                    len = 64;
                }

                getContext().getSIDResolver().resolveSids(getContext(), server, sids, off, len);
            }
        } else {
            for (ai = 0; ai < aces.length; ai++) {
                aces[ai].getSID().initContext(server, getContext());
            }
        }
    }

    @Override
    public long fileIndex() throws SmbException {

        try (SmbTreeHandleImpl th = ensureTreeConnected()) {

            if (th.isSMB2()) {
                final Smb2QueryInfoRequest req = new Smb2QueryInfoRequest(th.getConfig());
                req.setFileInfoClass(FileInformation.FILE_INTERNAL_INFO);
                final Smb2QueryInfoResponse resp = withOpen(th, Smb2CreateRequest.FILE_OPEN, SmbConstants.FILE_READ_ATTRIBUTES,
                        SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE, req);
                final FileInternalInfo info = resp.getInfo(FileInternalInfo.class);
                return info.getIndexNumber();
            }
        } catch (final CIFSException e) {
            throw SmbException.wrap(e);
        }

        return 0;
    }

    SecurityDescriptor querySecurity(final SmbTreeHandleImpl th, final int types) throws CIFSException {
        if (th.isSMB2()) {
            final Smb2QueryInfoRequest req = new Smb2QueryInfoRequest(th.getConfig());
            req.setInfoType(Smb2Constants.SMB2_0_INFO_SECURITY);
            req.setAdditionalInformation(types);
            final Smb2QueryInfoResponse resp =
                    withOpen(th, Smb2CreateRequest.FILE_OPEN, SmbConstants.FILE_READ_ATTRIBUTES | SmbConstants.READ_CONTROL,
                            SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE, req);
            return resp.getInfo(SecurityDescriptor.class);
        }

        if (!th.hasCapability(SmbConstants.CAP_NT_SMBS)) {
            throw new SmbUnsupportedOperationException("Not supported without CAP_NT_SMBS/SMB2");
        }
        NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse(getContext().getConfig());

        try (SmbFileHandleImpl f = openUnshared(O_RDONLY, READ_CONTROL, DEFAULT_SHARING, 0, isDirectory() ? 1 : 0)) {
            /*
             * NtTrans Query Security Desc Request / Response
             */
            final NtTransQuerySecurityDesc request = new NtTransQuerySecurityDesc(getContext().getConfig(), f.getFid(), types);
            response = th.send(request, response, RequestParam.NO_RETRY);
            return response.getSecurityDescriptor();
        }
    }

    @Override
    public ACE[] getSecurity() throws IOException {
        return getSecurity(false);
    }

    @Override
    public ACE[] getSecurity(final boolean resolveSids) throws IOException {
        try (SmbTreeHandleImpl th = ensureTreeConnected()) {
            final SecurityDescriptor desc = querySecurity(th, SecurityInfo.DACL_SECURITY_INFO);
            final ACE[] aces = desc.getAces();
            if (aces != null) {
                processAces(aces, resolveSids);
            }

            return aces;
        }
    }

    @Override
    public SID getOwnerUser() throws IOException {
        return getOwnerUser(true);
    }

    @Override
    public SID getOwnerUser(final boolean resolve) throws IOException {
        try (SmbTreeHandleImpl th = ensureTreeConnected()) {
            final SecurityDescriptor desc = querySecurity(th, SecurityInfo.OWNER_SECURITY_INFO);
            final SID ownerUser = desc.getOwnerUserSid();
            if (ownerUser == null) {
                return null;
            }

            String server = this.fileLocator.getServerWithDfs();
            if (resolve) {
                if (this.fileLocator.getDfsPath() == null && this.fileLocator.getPort() != -1) {
                    server = server + ":" + this.fileLocator.getPort();
                }
                try {
                    ownerUser.resolve(server, getContext());
                } catch (final IOException e) {
                    log.warn("Failed to resolve SID " + ownerUser.toString(), e);
                }
            } else {
                ownerUser.initContext(server, getContext());
            }
            return ownerUser;
        }
    }

    @Override
    public SID getOwnerGroup() throws IOException {
        return getOwnerGroup(true);
    }

    @Override
    public SID getOwnerGroup(final boolean resolve) throws IOException {
        try (SmbTreeHandleImpl th = ensureTreeConnected()) {
            final SecurityDescriptor desc = querySecurity(th, SecurityInfo.GROUP_SECURITY_INFO);
            final SID ownerGroup = desc.getOwnerGroupSid();
            if (ownerGroup == null) {
                return null;
            }

            String server = this.fileLocator.getServerWithDfs();
            if (resolve) {
                if (this.fileLocator.getDfsPath() == null && this.fileLocator.getPort() != -1) {
                    server = server + ":" + this.fileLocator.getPort();
                }
                try {
                    ownerGroup.resolve(server, getContext());
                } catch (final IOException e) {
                    log.warn("Failed to resolve SID " + ownerGroup.toString(), e);
                }
            } else {
                ownerGroup.initContext(server, getContext());
            }
            return ownerGroup;
        }
    }

    @Override
    public ACE[] getShareSecurity(final boolean resolveSids) throws IOException {
        try (SmbTreeHandleInternal th = ensureTreeConnected()) {
            String server = this.fileLocator.getServerWithDfs();
            ACE[] aces;
            final MsrpcShareGetInfo rpc = new MsrpcShareGetInfo(server, th.getConnectedShare());
            if (this.fileLocator.getDfsPath() == null && this.fileLocator.getPort() != -1) {
                server = server + ":" + this.fileLocator.getPort();
            }
            try (DcerpcHandle handle = DcerpcHandle.getHandle("ncacn_np:" + server + "[\\PIPE\\srvsvc]", getContext())) {
                handle.sendrecv(rpc);
                if (rpc.retval != 0) {
                    throw new SmbException(rpc.retval, true);
                }
                aces = rpc.getSecurity();
                if (aces != null) {
                    processAces(aces, resolveSids);
                }
            }
            return aces;
        }
    }

}
