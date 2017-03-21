/**
 * © 2017 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 20.03.2017 by mbechler
 */
package jcifs.smb;


import java.net.URL;
import java.net.UnknownHostException;

import jcifs.netbios.UniAddress;


/**
 * @author mbechler
 *
 */
public interface SmbFileLocator {

    /**
     * Returns the last component of the target URL. This will
     * effectively be the name of the file or directory represented by this
     * <code>SmbFile</code> or in the case of URLs that only specify a server
     * or workgroup, the server or workgroup will be returned. The name of
     * the root URL <code>smb://</code> is also <code>smb://</code>. If this
     * <tt>SmbFile</tt> refers to a workgroup, server, share, or directory,
     * the name will include a trailing slash '/' so that composing new
     * <tt>SmbFile</tt>s will maintain the trailing slash requirement.
     *
     * @return The last component of the URL associated with this SMB
     *         resource or <code>smb://</code> if the resource is <code>smb://</code>
     *         itself.
     */

    String getName ();


    /**
     * Everything but the last component of the URL representing this SMB
     * resource is effectivly it's parent. The root URL <code>smb://</code>
     * does not have a parent. In this case <code>smb://</code> is returned.
     *
     * @return The parent directory of this SMB resource or
     *         <code>smb://</code> if the resource refers to the root of the URL
     *         hierarchy which incedentally is also <code>smb://</code>.
     */
    String getParent ();


    /**
     * Returns the full uncanonicalized URL of this SMB resource. An
     * <code>SmbFile</code> constructed with the result of this method will
     * result in an <code>SmbFile</code> that is equal to the original.
     *
     * @return The uncanonicalized full URL of this SMB resource.
     */

    String getPath ();


    /**
     * Retuns the Windows UNC style path with backslashs intead of forward slashes.
     *
     * @return The UNC path.
     */
    String getCanonicalUncPath ();


    /**
     * 
     * @return possibly unresolved UNC path
     */
    String getUncPath ();


    /**
     * Returns the full URL of this SMB resource with '.' and '..' components
     * factored out. An <code>SmbFile</code> constructed with the result of
     * this method will result in an <code>SmbFile</code> that is equal to
     * the original.
     *
     * @return The canonicalized URL of this SMB resource.
     */
    String getCanonicalPath ();


    /**
     * @return The canonicalized UNC path of this SMB resource
     */
    String getCanonicalResourcePath ();


    /**
     * Retrieves the share associated with this SMB resource. In
     * the case of <code>smb://</code>, <code>smb://workgroup/</code>,
     * and <code>smb://server/</code> URLs which do not specify a share,
     * <code>null</code> will be returned.
     *
     * @return The share component or <code>null</code> if there is no share
     */
    String getShare ();


    /**
     * Retrieve the hostname of the server for this SMB resource. If the resources has been resolved by DFS this will
     * return the target name.
     * 
     * @return The server name
     */
    String getServerWithDfs ();


    /**
     * Retrieve the hostname of the server for this SMB resource. If this
     * <code>SmbFile</code> references a workgroup, the name of the workgroup
     * is returned. If this <code>SmbFile</code> refers to the root of this
     * SMB network hierarchy, <code>null</code> is returned.
     * 
     * @return The server or workgroup name or <code>null</code> if this
     *         <code>SmbFile</code> refers to the root <code>smb://</code> resource.
     */
    String getServer ();


    /**
     * If the path of this <code>SmbFile</code> falls within a DFS volume,
     * this method will return the referral path to which it maps. Otherwise
     * <code>null</code> is returned.
     * 
     * @return URL to the DFS volume
     */
    String getDfsPath ();


    /**
     * @return the transport port, if specified
     */
    int getPort ();


    /**
     * @return the original URL
     */
    URL getURL ();


    /**
     * @return resolved server address
     * @throws UnknownHostException
     */
    UniAddress getAddress () throws UnknownHostException;


    /**
     * @return whether to enforce the use of signing on connection to this resource
     */
    boolean shouldForceSigning ();


    /**
     * @return whether this is a IPC connection
     */
    boolean isIPC ();


    /**
     * Returns type of of object this <tt>SmbFile</tt> represents.
     * 
     * @return <tt>TYPE_FILESYSTEM, TYPE_WORKGROUP, TYPE_SERVER,
     * TYPE_NAMED_PIPE</tt>, or <tt>TYPE_SHARE</tt> in which case it may be either <tt>TYPE_SHARE</tt>,
     *         <tt>TYPE_PRINTER</tt> or <tt>TYPE_COMM</tt>.
     * @throws SmbException
     */
    int getType () throws SmbException;


    /**
     * @return whether this is a workgroup reference
     * @throws UnknownHostException
     */
    boolean isWorkgroup () throws UnknownHostException;


    /**
     * 
     * @return whether this is a root resource
     */
    boolean isRoot ();


    /**
     * @param other
     * @return whether the paths share a common root
     * @throws UnknownHostException
     */
    boolean overlaps ( SmbFileLocator other ) throws UnknownHostException;

}