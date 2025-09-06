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
package org.codelibs.jcifs.smb.util;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import org.codelibs.jcifs.smb.SmbException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Path validation utility to prevent directory traversal and other path-based attacks.
 *
 * Features:
 * - Directory traversal prevention
 * - Path normalization
 * - Blacklist/whitelist support
 * - UNC path validation
 * - Special character filtering
 * - Length validation
 */
public class PathValidator {

    private static final Logger log = LoggerFactory.getLogger(PathValidator.class);

    // Path traversal patterns
    private static final Pattern TRAVERSAL_PATTERN = Pattern.compile("\\.\\.[\\\\/]|[\\\\/]\\.\\.");
    private static final Pattern DOUBLE_DOT_PATTERN = Pattern.compile("\\.\\.");
    private static final Pattern ENCODED_TRAVERSAL = Pattern.compile("%2e%2e|%252e%252e", Pattern.CASE_INSENSITIVE);
    private static final Pattern UNICODE_TRAVERSAL = Pattern.compile("\\\\u002e\\\\u002e|\\\\u002E\\\\u002E", Pattern.CASE_INSENSITIVE);

    // Dangerous characters and sequences
    private static final Pattern NULL_BYTE = Pattern.compile("\\x00|%00");
    private static final Pattern CONTROL_CHARS = Pattern.compile("[\\x00-\\x1F\\x7F]");
    private static final Pattern DANGEROUS_CHARS = Pattern.compile("[<>:\"|?*]");

    // Windows reserved names
    private static final Set<String> WINDOWS_RESERVED = Set.of("CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
            "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9");

    // Configuration
    private final int maxPathLength;
    private final int maxComponentLength;
    private final boolean allowUncPaths;
    private final boolean strictMode;
    private final Set<String> blacklistedPaths;
    private final Set<String> whitelistedPaths;

    /**
     * Create path validator with default settings
     */
    public PathValidator() {
        this(260, 255, true, false);
    }

    /**
     * Create path validator with custom settings
     *
     * @param maxPathLength maximum total path length
     * @param maxComponentLength maximum length for path components
     * @param allowUncPaths whether to allow UNC paths
     * @param strictMode strict validation mode
     */
    public PathValidator(int maxPathLength, int maxComponentLength, boolean allowUncPaths, boolean strictMode) {
        this.maxPathLength = maxPathLength;
        this.maxComponentLength = maxComponentLength;
        this.allowUncPaths = allowUncPaths;
        this.strictMode = strictMode;
        this.blacklistedPaths = new HashSet<>();
        this.whitelistedPaths = new HashSet<>();
    }

    /**
     * Validate and normalize a path
     *
     * @param path the path to validate
     * @return normalized safe path
     * @throws SmbException if path is invalid or dangerous
     */
    public String validatePath(String path) throws SmbException {
        if (path == null || path.isEmpty()) {
            throw new SmbException("Path cannot be null or empty");
        }

        // Check length
        if (path.length() > maxPathLength) {
            throw new SmbException("Path exceeds maximum length: " + path.length() + " > " + maxPathLength);
        }

        // Check for null bytes
        if (NULL_BYTE.matcher(path).find()) {
            log.warn("Path contains null bytes: {}", sanitizeForLog(path));
            throw new SmbException("Path contains null bytes");
        }

        // Check for control characters
        if (strictMode && CONTROL_CHARS.matcher(path).find()) {
            log.warn("Path contains control characters: {}", sanitizeForLog(path));
            throw new SmbException("Path contains control characters");
        }

        // Check for traversal sequences
        if (containsTraversal(path)) {
            log.warn("Path contains directory traversal: {}", sanitizeForLog(path));
            throw new SmbException("Path contains directory traversal sequences");
        }

        // Normalize the path
        String normalized = normalizePath(path);

        // Check against blacklist
        if (isBlacklisted(normalized)) {
            log.warn("Path is blacklisted: {}", sanitizeForLog(normalized));
            throw new SmbException("Path is not allowed");
        }

        // Check against whitelist if configured
        if (!whitelistedPaths.isEmpty() && !isWhitelisted(normalized)) {
            log.warn("Path is not whitelisted: {}", sanitizeForLog(normalized));
            throw new SmbException("Path is not in allowed list");
        }

        // Validate UNC paths
        if (normalized.startsWith("\\\\") || normalized.startsWith("//")) {
            if (!allowUncPaths) {
                throw new SmbException("UNC paths are not allowed");
            }
            validateUncPath(normalized);
        }

        // Check individual components
        validateComponents(normalized);

        return normalized;
    }

    /**
     * Validate an SMB URL
     *
     * @param smbUrl the SMB URL to validate
     * @return normalized safe URL
     * @throws SmbException if URL is invalid
     */
    public String validateSmbUrl(String smbUrl) throws SmbException {
        if (smbUrl == null || smbUrl.isEmpty()) {
            throw new SmbException("SMB URL cannot be null or empty");
        }

        // Check URL format
        if (!smbUrl.toLowerCase().startsWith("smb://")) {
            throw new SmbException("Invalid SMB URL format");
        }

        try {
            URL url = new URL(null, smbUrl, new org.codelibs.jcifs.smb.Handler());

            // Validate host
            String host = url.getHost();
            if (host == null || host.isEmpty()) {
                throw new SmbException("SMB URL missing host");
            }

            // Validate host format
            if (!isValidHost(host)) {
                throw new SmbException("Invalid host in SMB URL");
            }

            // Validate path component
            String path = url.getPath();
            if (path != null && !path.isEmpty()) {
                validatePath(path);
            }

            // Reconstruct normalized URL
            StringBuilder normalized = new StringBuilder("smb://");

            // Add credentials if present
            String userInfo = url.getUserInfo();
            if (userInfo != null && !userInfo.isEmpty()) {
                // Don't log credentials
                normalized.append(userInfo).append("@");
            }

            normalized.append(host.toLowerCase());

            // Add port if non-standard
            int port = url.getPort();
            if (port > 0 && port != 445 && port != 139) {
                normalized.append(":").append(port);
            }

            // Add normalized path
            if (path != null && !path.isEmpty()) {
                normalized.append(normalizePath(path));
            }

            return normalized.toString();

        } catch (MalformedURLException e) {
            throw new SmbException("Invalid SMB URL format: " + e.getMessage());
        }
    }

    /**
     * Check if path contains traversal sequences
     */
    private boolean containsTraversal(String path) {
        // Check various forms of directory traversal
        if (TRAVERSAL_PATTERN.matcher(path).find()) {
            return true;
        }

        // Check encoded traversals
        if (ENCODED_TRAVERSAL.matcher(path).find()) {
            return true;
        }

        // Check Unicode encoded traversals
        if (UNICODE_TRAVERSAL.matcher(path).find()) {
            return true;
        }

        // Check for standalone double dots that could be dangerous
        String[] parts = path.split("[\\\\/]");
        for (String part : parts) {
            if (".".equals(part) || "..".equals(part)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Normalize a path
     */
    private String normalizePath(String path) {
        // Replace forward slashes with backslashes for consistency
        String normalized = path.replace('/', '\\');

        // Remove duplicate slashes
        normalized = normalized.replaceAll("\\\\+", "\\\\");

        // Remove trailing slash unless it's the root
        if (normalized.length() > 1 && normalized.endsWith("\\")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }

        // Handle current directory references
        normalized = normalized.replace("\\.", "");
        normalized = normalized.replace(".\\", "");

        return normalized;
    }

    /**
     * Validate UNC path
     */
    private void validateUncPath(String path) throws SmbException {
        // UNC path should have format: \\server\share[\path]
        if (!path.startsWith("\\\\") && !path.startsWith("//")) {
            throw new SmbException("Invalid UNC path format");
        }

        String[] parts = path.substring(2).split("[\\\\/]");

        if (parts.length < 2) {
            throw new SmbException("UNC path must specify server and share");
        }

        // Validate server name
        String server = parts[0];
        if (!isValidHost(server)) {
            throw new SmbException("Invalid server name in UNC path");
        }

        // Validate share name
        String share = parts[1];
        if (share.isEmpty() || share.endsWith("$") && share.length() == 1) {
            throw new SmbException("Invalid share name in UNC path");
        }
    }

    /**
     * Validate individual path components
     */
    private void validateComponents(String path) throws SmbException {
        String[] components = path.split("[\\\\/]");

        for (String component : components) {
            if (component.isEmpty()) {
                continue; // Skip empty components (from double slashes)
            }

            // Check component length
            if (component.length() > maxComponentLength) {
                throw new SmbException("Path component exceeds maximum length: " + component.length());
            }

            // Check for Windows reserved names
            String upperComponent = component.toUpperCase();
            if (WINDOWS_RESERVED.contains(upperComponent) || upperComponent.matches("^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\\.[^.]+)?$")) {
                throw new SmbException("Path contains Windows reserved name: " + component);
            }

            // Check for dangerous characters in strict mode
            if (strictMode && DANGEROUS_CHARS.matcher(component).find()) {
                throw new SmbException("Path component contains dangerous characters: " + component);
            }

            // Check for trailing spaces or periods (Windows doesn't handle well)
            if (component.endsWith(" ") || component.endsWith(".")) {
                throw new SmbException("Path component has trailing space or period: " + component);
            }
        }
    }

    /**
     * Validate host name
     */
    private boolean isValidHost(String host) {
        if (host == null || host.isEmpty()) {
            return false;
        }

        // Check for valid hostname or IP address
        // Simple validation - can be enhanced
        if (host.length() > 255) {
            return false;
        }

        // Check for invalid characters
        if (host.contains("..") || host.contains("//") || host.contains("\\\\")) {
            return false;
        }

        // Basic hostname/IP validation
        return host.matches("^[a-zA-Z0-9.-]+$");
    }

    /**
     * Add path to blacklist
     *
     * @param path path or pattern to blacklist
     */
    public void addToBlacklist(String path) {
        blacklistedPaths.add(normalizePath(path).toLowerCase());
    }

    /**
     * Add path to whitelist
     *
     * @param path path or pattern to whitelist
     */
    public void addToWhitelist(String path) {
        whitelistedPaths.add(normalizePath(path).toLowerCase());
    }

    /**
     * Check if path is blacklisted
     */
    private boolean isBlacklisted(String path) {
        String lowerPath = path.toLowerCase();
        for (String blacklisted : blacklistedPaths) {
            if (lowerPath.startsWith(blacklisted) || lowerPath.equals(blacklisted)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if path is whitelisted
     */
    private boolean isWhitelisted(String path) {
        if (whitelistedPaths.isEmpty()) {
            return true; // No whitelist means all paths allowed
        }

        String lowerPath = path.toLowerCase();
        for (String whitelisted : whitelistedPaths) {
            if (lowerPath.startsWith(whitelisted) || lowerPath.equals(whitelisted)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Sanitize path for safe logging
     */
    private String sanitizeForLog(String path) {
        if (path == null) {
            return "null";
        }

        // Truncate long paths
        if (path.length() > 100) {
            path = path.substring(0, 100) + "...";
        }

        // Remove control characters for safe logging
        return path.replaceAll("[\\x00-\\x1F\\x7F]", "?");
    }

    /**
     * Get blacklisted paths
     * @return unmodifiable set of blacklisted paths
     */
    public Set<String> getBlacklistedPaths() {
        return Collections.unmodifiableSet(blacklistedPaths);
    }

    /**
     * Get whitelisted paths
     * @return unmodifiable set of whitelisted paths
     */
    public Set<String> getWhitelistedPaths() {
        return Collections.unmodifiableSet(whitelistedPaths);
    }

    /**
     * Clear all blacklisted paths
     */
    public void clearBlacklist() {
        blacklistedPaths.clear();
    }

    /**
     * Clear all whitelisted paths
     */
    public void clearWhitelist() {
        whitelistedPaths.clear();
    }
}
