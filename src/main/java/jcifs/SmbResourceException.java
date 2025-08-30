/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package jcifs;

/**
 * Exception for resource-related SMB errors
 *
 * This exception is thrown when resource issues occur such as:
 * - File handle leaks
 * - Connection pool exhaustion
 * - Memory allocation failures
 * - Quota exceeded
 */
public class SmbResourceException extends SmbException {

    private static final long serialVersionUID = 1L;

    /**
     * Resource type that caused the error
     */
    public enum ResourceType {
        FILE_HANDLE, CONNECTION, MEMORY, DISK_SPACE, QUOTA, LOCK, BUFFER, THREAD_POOL
    }

    private final ResourceType resourceType;
    private final long availableResources;
    private final long requestedResources;

    /**
     * Creates a resource exception
     *
     * @param message the error message
     * @param errorCode the SMB error code
     * @param resourceType the type of resource
     */
    public SmbResourceException(String message, int errorCode, ResourceType resourceType) {
        super(message, errorCode, Severity.TRANSIENT, Category.RESOURCE);
        this.resourceType = resourceType;
        this.availableResources = -1;
        this.requestedResources = -1;
    }

    /**
     * Creates a resource exception with resource details
     *
     * @param message the error message
     * @param errorCode the SMB error code
     * @param resourceType the type of resource
     * @param available available resources
     * @param requested requested resources
     */
    public SmbResourceException(String message, int errorCode, ResourceType resourceType, long available, long requested) {
        super(message, errorCode, Severity.TRANSIENT, Category.RESOURCE);
        this.resourceType = resourceType;
        this.availableResources = available;
        this.requestedResources = requested;

        // Add context
        withContext("resourceType", resourceType);
        withContext("available", available);
        withContext("requested", requested);

        // Add recovery hint
        withRecoveryHint(generateRecoveryHint());
    }

    /**
     * Creates a resource exception with cause
     *
     * @param message the error message
     * @param errorCode the SMB error code
     * @param resourceType the type of resource
     * @param cause the cause exception
     */
    public SmbResourceException(String message, int errorCode, ResourceType resourceType, Throwable cause) {
        super(message, errorCode, Severity.TRANSIENT, Category.RESOURCE, cause);
        this.resourceType = resourceType;
        this.availableResources = -1;
        this.requestedResources = -1;
    }

    /**
     * Gets the resource type
     *
     * @return the resource type
     */
    public ResourceType getResourceType() {
        return resourceType;
    }

    /**
     * Gets available resources
     *
     * @return available resources or -1 if unknown
     */
    public long getAvailableResources() {
        return availableResources;
    }

    /**
     * Gets requested resources
     *
     * @return requested resources or -1 if unknown
     */
    public long getRequestedResources() {
        return requestedResources;
    }

    private String generateRecoveryHint() {
        switch (resourceType) {
        case FILE_HANDLE:
            return "Close unused file handles or increase the file handle limit";
        case CONNECTION:
            return "Close idle connections or increase the connection pool size";
        case MEMORY:
            return "Reduce buffer sizes or increase heap memory";
        case DISK_SPACE:
            return "Free up disk space or use a different location";
        case QUOTA:
            return "Contact administrator to increase quota limits";
        case LOCK:
            return "Release existing locks or wait for them to be released";
        case BUFFER:
            return "Reduce buffer usage or increase buffer pool size";
        case THREAD_POOL:
            return "Reduce concurrent operations or increase thread pool size";
        default:
            return "Check resource availability and retry";
        }
    }

    /**
     * Static factory for file handle exhaustion
     */
    public static SmbResourceException fileHandleExhausted(int errorCode) {
        return new SmbResourceException("File handle limit exceeded", errorCode, ResourceType.FILE_HANDLE);
    }

    /**
     * Static factory for connection pool exhaustion
     */
    public static SmbResourceException connectionPoolExhausted(int errorCode, int poolSize) {
        return new SmbResourceException("Connection pool exhausted", errorCode, ResourceType.CONNECTION, 0, poolSize);
    }

    /**
     * Static factory for quota exceeded
     */
    public static SmbResourceException quotaExceeded(int errorCode, long used, long quota) {
        return new SmbResourceException(String.format("Quota exceeded: %d/%d bytes used", used, quota), errorCode, ResourceType.QUOTA,
                quota - used, 1);
    }
}
