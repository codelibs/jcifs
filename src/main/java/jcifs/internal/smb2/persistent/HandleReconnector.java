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
 */
package jcifs.internal.smb2.persistent;

import jcifs.internal.smb2.create.Smb2CreateRequest;
import jcifs.internal.smb2.create.Smb2CreateResponse;
import jcifs.internal.smb2.create.LeaseV1CreateContextRequest;
import jcifs.internal.smb2.create.LeaseV2CreateContextRequest;
import jcifs.internal.smb2.lease.Smb2LeaseState;
import jcifs.smb.SmbException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.io.IOException;

/**
 * Handles automatic reconnection of durable and persistent SMB handles.
 *
 * This class provides retry logic with exponential backoff for handle
 * reconnection after network failures or server issues.
 *
 * @author jcifs team
 */
public class HandleReconnector {

    private static final Logger log = LoggerFactory.getLogger(HandleReconnector.class);

    private final PersistentHandleManager handleManager;
    private final int maxRetries;
    private final long retryDelay;

    /**
     * Create a new handle reconnector
     * @param manager the persistent handle manager
     */
    public HandleReconnector(PersistentHandleManager manager) {
        this(manager, 3, 1000);
    }

    /**
     * Create a new handle reconnector with custom settings
     * @param manager the persistent handle manager
     * @param maxRetries maximum number of retry attempts
     * @param retryDelay base retry delay in milliseconds
     */
    public HandleReconnector(PersistentHandleManager manager, int maxRetries, long retryDelay) {
        this.handleManager = manager;
        this.maxRetries = maxRetries;
        this.retryDelay = retryDelay;
    }

    /**
     * Attempt to reconnect a handle
     * @param path the file path
     * @param cause the original exception that triggered reconnection
     * @return a future that completes with the reconnected handle info or fails
     */
    public CompletableFuture<HandleInfo> reconnectHandle(String path, Exception cause) {
        HandleInfo info = handleManager.getHandleForReconnect(path);

        if (info == null) {
            return CompletableFuture.failedFuture(new IOException("No durable handle available for reconnection: " + path));
        }

        log.debug("Starting reconnection for handle: {} (cause: {})", path, cause.getMessage());
        return attemptReconnect(info, 0, cause);
    }

    /**
     * Attempt to reconnect a specific handle
     * @param handleInfo the handle information
     * @param cause the original exception that triggered reconnection
     * @return a future that completes with the reconnected handle info or fails
     */
    public CompletableFuture<HandleInfo> reconnectHandle(HandleInfo handleInfo, Exception cause) {
        if (handleInfo == null) {
            return CompletableFuture.failedFuture(new IOException("Handle info cannot be null"));
        }

        if (handleInfo.isExpired()) {
            return CompletableFuture.failedFuture(new IOException("Handle has expired and cannot be reconnected: " + handleInfo.getPath()));
        }

        log.debug("Starting reconnection for handle: {} (cause: {})", handleInfo.getPath(), cause.getMessage());
        return attemptReconnect(handleInfo, 0, cause);
    }

    /**
     * Perform a single reconnection attempt
     * @param info the handle information
     * @param attempt the current attempt number (0-based)
     * @param originalCause the original exception that triggered reconnection
     * @return a future that completes with success or failure
     */
    private CompletableFuture<HandleInfo> attemptReconnect(HandleInfo info, int attempt, Exception originalCause) {
        if (attempt >= maxRetries) {
            handleManager.completeReconnect(info.getPath(), false);
            return CompletableFuture.failedFuture(new IOException(
                    "Failed to reconnect after " + maxRetries + " attempts. " + "Original cause: " + originalCause.getMessage(),
                    originalCause));
        }

        return CompletableFuture.supplyAsync(() -> {
            try {
                // Wait before retry (except first attempt)
                if (attempt > 0) {
                    long delay = retryDelay * (1L << attempt); // Exponential backoff
                    Thread.sleep(delay);
                    log.debug("Reconnection attempt {} for {}", attempt + 1, info.getPath());
                }

                // Perform the actual reconnection
                boolean success = performReconnection(info);

                if (success) {
                    handleManager.completeReconnect(info.getPath(), true);
                    log.info("Successfully reconnected handle: {}", info.getPath());
                    return info;
                } else {
                    throw new IOException("Reconnection failed for " + info.getPath());
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Reconnection interrupted", e);
            } catch (Exception e) {
                log.debug("Reconnection attempt {} failed for {}: {}", attempt + 1, info.getPath(), e.getMessage());

                if (attempt + 1 >= maxRetries) {
                    handleManager.completeReconnect(info.getPath(), false);
                    throw new RuntimeException("Final reconnection attempt failed", e);
                }

                // Retry
                try {
                    return attemptReconnect(info, attempt + 1, originalCause).get();
                } catch (Exception retryException) {
                    throw new RuntimeException("Retry failed", retryException);
                }
            }
        });
    }

    /**
     * Perform the actual reconnection logic.
     * This method should be overridden by subclasses to provide the actual
     * SMB reconnection implementation.
     *
     * @param info the handle information
     * @return true if reconnection was successful
     * @throws Exception if reconnection fails
     */
    protected boolean performReconnection(HandleInfo info) throws Exception {
        // This is a template method that should be implemented by the actual
        // SMB file implementation. For now, we'll provide a basic structure.

        log.debug("Performing reconnection for handle: {} (type: {})", info.getPath(), info.getType());

        // Create reconnect context
        DurableHandleReconnect reconnectCtx = new DurableHandleReconnect(info.getFileId());

        // This would typically involve:
        // 1. Creating a new Smb2CreateRequest with reconnect context
        // 2. Adding lease context if needed
        // 3. Sending the request through the appropriate transport
        // 4. Processing the response

        // For now, we'll return false to indicate that the concrete implementation
        // needs to be provided by the calling code
        log.warn("performReconnection called but no concrete implementation available. "
                + "This method should be overridden by the actual SMB implementation.");

        return false;
    }

    /**
     * Create a reconnection request for the given handle
     * @param info the handle information
     * @return the create request configured for reconnection
     */
    protected Smb2CreateRequest createReconnectionRequest(HandleInfo info) {
        // This would need access to the Configuration and proper setup
        // For now, we provide the structure

        // Smb2CreateRequest request = new Smb2CreateRequest(config, info.getPath());
        // request.addCreateContext(new DurableHandleReconnect(info.getFileId()));

        // Add lease context if needed
        // if (info.getLeaseKey() != null) {
        //     request.addLeaseV1Context(info.getLeaseKey(), Smb2LeaseState.SMB2_LEASE_NONE);
        // }

        // return request;

        throw new UnsupportedOperationException("createReconnectionRequest requires Configuration access and should be "
                + "implemented by the concrete SMB file implementation");
    }

    /**
     * Get the maximum number of retry attempts
     * @return the maximum retries
     */
    public int getMaxRetries() {
        return maxRetries;
    }

    /**
     * Get the base retry delay
     * @return the retry delay in milliseconds
     */
    public long getRetryDelay() {
        return retryDelay;
    }
}
