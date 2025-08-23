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
package jcifs.internal.smb2.rdma;

/**
 * Represents a work request for RDMA operations.
 *
 * Work requests are used to track pending RDMA operations
 * and their completion status.
 */
public class RdmaWorkRequest {

    /**
     * Type of RDMA work request
     */
    public enum RequestType {
        SEND, RECEIVE, READ, WRITE
    }

    private final long requestId;
    private final RequestType type;
    private final RdmaMemoryRegion memoryRegion;
    private volatile boolean completed;
    private volatile Exception error;

    /**
     * Create new RDMA work request
     *
     * @param requestId unique request identifier
     * @param type type of request
     * @param memoryRegion associated memory region
     */
    public RdmaWorkRequest(long requestId, RequestType type, RdmaMemoryRegion memoryRegion) {
        this.requestId = requestId;
        this.type = type;
        this.memoryRegion = memoryRegion;
        this.completed = false;
    }

    /**
     * Get request ID
     *
     * @return unique request identifier
     */
    public long getRequestId() {
        return requestId;
    }

    /**
     * Get request type
     *
     * @return type of request
     */
    public RequestType getType() {
        return type;
    }

    /**
     * Get associated memory region
     *
     * @return memory region for this request
     */
    public RdmaMemoryRegion getMemoryRegion() {
        return memoryRegion;
    }

    /**
     * Check if request is completed
     *
     * @return true if completed, false otherwise
     */
    public boolean isCompleted() {
        return completed;
    }

    /**
     * Mark request as completed
     */
    public void markCompleted() {
        this.completed = true;
    }

    /**
     * Mark request as failed with error
     *
     * @param error exception that caused the failure
     */
    public void markFailed(Exception error) {
        this.error = error;
        this.completed = true;
    }

    /**
     * Get error if request failed
     *
     * @return exception if failed, null if successful
     */
    public Exception getError() {
        return error;
    }

    /**
     * Check if request failed
     *
     * @return true if failed, false otherwise
     */
    public boolean hasFailed() {
        return error != null;
    }
}
