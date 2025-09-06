/*
 * © 2025 CodeLibs, Inc.
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
package org.codelibs.jcifs.smb;

import java.util.Arrays;
import java.util.List;

import org.codelibs.jcifs.smb.internal.smb2.lease.DirectoryCacheScope;
import org.codelibs.jcifs.smb.internal.smb2.lease.DirectoryLeaseManager;
import org.codelibs.jcifs.smb.internal.smb2.lease.Smb2LeaseKey;
import org.codelibs.jcifs.smb.internal.smb2.lease.Smb2LeaseState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extension methods for SmbFile to support directory leasing functionality.
 *
 * This utility class provides static methods that enhance SmbFile operations with
 * directory leasing capabilities for improved performance through caching when
 * SMB3 directory leasing is available and enabled.
 */
public class SmbFileDirectoryLeasingExtension {

    /**
     * Private constructor to prevent instantiation of this utility class
     */
    private SmbFileDirectoryLeasingExtension() {
        // Utility class - prevent instantiation
    }

    private static final Logger log = LoggerFactory.getLogger(SmbFileDirectoryLeasingExtension.class);

    /**
     * Enhanced listFiles method that uses directory leasing for caching when available
     *
     * @param smbFile the SmbFile directory to list
     * @return array of SmbFile objects representing the directory contents
     * @throws SmbException if an error occurs
     */
    public static SmbFile[] listFilesWithLeasing(SmbFile smbFile) throws SmbException {
        if (!smbFile.isDirectory()) {
            throw new SmbException("Not a directory: " + smbFile.getPath());
        }

        try (SmbTreeHandleImpl th = smbFile.ensureTreeConnected()) {
            // Check if we can use directory leasing
            DirectoryLeaseManager dirManager = getDirectoryLeaseManager(th);
            if (dirManager != null && smbFile.getContext().getConfig().isUseDirectoryLeasing()) {
                return listFilesWithDirectoryLeasing(smbFile, dirManager);
            } else {
                // Fall back to regular directory listing
                return smbFile.listFiles();
            }
        } catch (CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    /**
     * Enhanced exists method that uses directory leasing for parent directory caching
     *
     * @param smbFile the SmbFile to check existence for
     * @return true if the file exists
     * @throws SmbException if an error occurs
     */
    public static boolean existsWithLeasing(SmbFile smbFile) throws SmbException {
        try (SmbTreeHandleImpl th = smbFile.ensureTreeConnected()) {
            DirectoryLeaseManager dirManager = getDirectoryLeaseManager(th);

            if (dirManager != null && smbFile.getContext().getConfig().isUseDirectoryLeasing()) {
                // Check parent directory cache first
                String parentPath = smbFile.getParent();
                if (parentPath != null) {
                    var parentCache = dirManager.getCacheEntry(parentPath);
                    if (parentCache != null && parentCache.isComplete()) {
                        boolean exists = parentCache.hasChild(smbFile.getName());
                        log.debug("Using cached existence check for: {}", smbFile.getPath());
                        return exists;
                    }
                }
            }

            // Fall back to regular existence check
            return smbFile.exists();
        } catch (CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    /**
     * Request directory lease for the given directory
     *
     * @param smbFile the directory to request lease for
     * @param requestedState requested lease state
     * @param scope cache scope
     * @return lease key or null if not supported
     * @throws SmbException if an error occurs
     */
    public static Smb2LeaseKey requestDirectoryLease(SmbFile smbFile, int requestedState, DirectoryCacheScope scope) throws SmbException {
        if (!smbFile.isDirectory()) {
            throw new SmbException("Directory leasing only supported for directories");
        }

        try (SmbTreeHandleImpl th = smbFile.ensureTreeConnected()) {
            DirectoryLeaseManager dirManager = getDirectoryLeaseManager(th);
            if (dirManager == null) {
                log.debug("Directory leasing not available for: {}", smbFile.getPath());
                return null;
            }

            return dirManager.requestDirectoryLease(smbFile.getPath(), requestedState, scope);
        } catch (CIFSException e) {
            throw SmbException.wrap(e);
        }
    }

    /**
     * List files using directory leasing
     */
    private static SmbFile[] listFilesWithDirectoryLeasing(SmbFile smbFile, DirectoryLeaseManager dirManager) throws SmbException {
        String directoryPath = smbFile.getPath();

        // Check if we can use cached directory listing
        if (dirManager.canCacheDirectoryListing(directoryPath)) {
            List<SmbFile> cachedFiles = dirManager.getCachedDirectoryListing(directoryPath);
            if (cachedFiles != null) {
                log.debug("Using cached directory listing for: {}", directoryPath);
                return cachedFiles.toArray(new SmbFile[0]);
            }
        }

        // Request directory lease if not already present
        DirectoryCacheScope scope = DirectoryCacheScope.valueOf(smbFile.getContext().getConfig().getDirectoryCacheScope());
        Smb2LeaseKey leaseKey = dirManager.requestDirectoryLease(directoryPath,
                Smb2LeaseState.SMB2_LEASE_READ_CACHING | Smb2LeaseState.SMB2_LEASE_HANDLE_CACHING, scope);

        // Perform actual directory enumeration
        SmbFile[] files = smbFile.listFiles();

        // Update cache if we have a directory lease
        if (leaseKey != null) {
            dirManager.updateDirectoryCache(directoryPath, Arrays.asList(files));
        }

        return files;
    }

    /**
     * Get directory lease manager from tree handle
     */
    private static DirectoryLeaseManager getDirectoryLeaseManager(SmbTreeHandleImpl th) {
        try {
            // For now, return null since we need to integrate with the session properly
            // This will be implemented when the session integration is complete
            log.debug("Directory lease manager integration not yet complete");
            return null;
        } catch (Exception e) {
            log.debug("Failed to get directory lease manager", e);
            return null;
        }
    }
}