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
package jcifs.internal;

/**
 * Interface for SMB requests that include file system path information.
 * Provides path handling capabilities including UNC path resolution and DFS support
 * for SMB operations that target specific files or directories on remote shares.
 *
 * @author mbechler
 */
public interface RequestWithPath extends CommonServerMessageBlock {

    /**
     * Gets the path to the resource.
     *
     * @return the path to the resource (below share)
     */
    String getPath();

    /**
     * Gets the server name.
     *
     * @return the server name
     */
    String getServer();

    /**
     * Gets the domain name.
     *
     * @return the domain name
     */
    String getDomain();

    /**
     * Gets the full UNC path.
     *
     * @return the full UNC path
     */
    String getFullUNCPath();

    /**
     * Sets the path to the resource.
     *
     * @param path the path to set
     */
    void setPath(String path);

    /**
     * Sets the full UNC path components.
     *
     * @param domain the domain name
     * @param server the server name
     * @param fullPath the full UNC path
     */
    void setFullUNCPath(String domain, String server, String fullPath);

    /**
     * Sets whether to resolve this request path in DFS.
     *
     * @param resolve true to enable DFS resolution
     */
    void setResolveInDfs(boolean resolve);

    /**
     * Checks if this request should be resolved in DFS.
     *
     * @return whether to resolve the request path in DFS
     */
    boolean isResolveInDfs();

}
