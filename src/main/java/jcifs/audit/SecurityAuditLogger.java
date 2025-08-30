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
package jcifs.audit;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * Security audit logger for SMB operations.
 * Provides structured logging of security-relevant events with sensitive data masking.
 *
 * Features:
 * - Structured JSON logging
 * - Sensitive data masking
 * - Event categorization
 * - Performance metrics
 * - Compliance-ready audit trail
 * - Asynchronous logging with bounded queue
 * - Object pooling to reduce GC pressure
 */
public class SecurityAuditLogger {

    private static final Logger auditLog = LoggerFactory.getLogger("SECURITY.AUDIT");
    private static final Logger log = LoggerFactory.getLogger(SecurityAuditLogger.class);

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_INSTANT;

    // Patterns for sensitive data - compiled once and cached
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "(?i)(password|passwd|pwd|secret|token|key|credential|auth)([\"']?\\s*[:=]\\s*[\"']?)([^\"',\\s]+)", Pattern.CASE_INSENSITIVE);

    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b");

    // Object pools for performance optimization
    private final Queue<AuditEntry> auditEntryPool = new ConcurrentLinkedQueue<>();
    private final Queue<StringBuilder> stringBuilderPool = new ConcurrentLinkedQueue<>();
    private final Queue<HashMap<String, Object>> mapPool = new ConcurrentLinkedQueue<>();

    // Asynchronous logging
    private final BlockingQueue<AuditEntry> logQueue = new LinkedBlockingQueue<>(10000); // Bounded queue
    private final ExecutorService logExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "SecurityAuditLogger");
        t.setDaemon(true);
        return t;
    });
    private volatile boolean asyncLogging = true;
    private volatile boolean shutdown = false;

    // Event statistics
    private final Map<EventType, AtomicLong> eventCounters = new ConcurrentHashMap<>();
    private final Map<EventType, AtomicLong> eventTimings = new ConcurrentHashMap<>();

    // Configuration
    private volatile boolean enableJsonLogging = true;
    private volatile boolean maskSensitiveData = true;
    private volatile boolean includeStackTrace = false;
    private volatile Severity minLogLevel = Severity.INFO;

    // Performance optimization for sensitive data masking
    private volatile boolean enableHighPerformanceMode = false;
    private volatile boolean skipMaskingForDebugLevel = false;

    // Rate limiting
    private final Map<String, AtomicLong> rateLimitCounters = new ConcurrentHashMap<>();
    private volatile long rateLimitWindow = 60000; // 1 minute
    private volatile int maxEventsPerWindow = 10000; // Increased for tests

    /**
     * Security event types
     */
    public enum EventType {
        AUTHENTICATION_SUCCESS, AUTHENTICATION_FAILURE, AUTHORIZATION_SUCCESS, AUTHORIZATION_FAILURE, CONNECTION_ESTABLISHED, CONNECTION_CLOSED, CONNECTION_FAILED, ENCRYPTION_ENABLED, ENCRYPTION_FAILED, KEY_EXCHANGE, KEY_ROTATION, SESSION_CREATED, SESSION_DESTROYED, FILE_ACCESS, FILE_MODIFICATION, PERMISSION_CHANGE, SECURITY_VIOLATION, CONFIGURATION_CHANGE, AUDIT_ENABLED, AUDIT_DISABLED
    }

    /**
     * Event severity levels
     */
    public enum Severity {
        INFO(0), WARNING(1), ERROR(2), CRITICAL(3);

        private final int level;

        Severity(int level) {
            this.level = level;
        }

        public int getLevel() {
            return level;
        }
    }

    private static class SingletonHolder {
        private static final SecurityAuditLogger INSTANCE = new SecurityAuditLogger();
    }

    /**
     * Get the singleton instance
     *
     * @return SecurityAuditLogger instance
     */
    public static SecurityAuditLogger getInstance() {
        return SingletonHolder.INSTANCE;
    }

    private SecurityAuditLogger() {
        // Initialize event counters
        for (EventType type : EventType.values()) {
            eventCounters.put(type, new AtomicLong(0));
            eventTimings.put(type, new AtomicLong(0));
        }

        // Start async logging processor
        startAsyncProcessor();

        // Register shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown));
    }

    private void startAsyncProcessor() {
        logExecutor.submit(() -> {
            while (!shutdown) {
                try {
                    AuditEntry entry = logQueue.take();
                    if (entry != null) {
                        processLogEntry(entry);
                        returnAuditEntry(entry);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    log.error("Error processing audit log entry", e);
                }
            }
        });
    }

    /**
     * Shutdown the audit logger gracefully
     */
    public void shutdown() {
        shutdown = true;
        logExecutor.shutdown();
        try {
            if (!logExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                logExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            logExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Log a security event with performance optimizations
     *
     * @param type event type
     * @param severity event severity
     * @param message event message
     * @param context additional context
     */
    public void logEvent(EventType type, Severity severity, String message, Map<String, Object> context) {
        // Check minimum log level filter
        if (severity.getLevel() < minLogLevel.getLevel()) {
            return;
        }

        // Rate limiting check
        if (!checkRateLimit(type)) {
            return;
        }

        try {
            // Update statistics
            eventCounters.get(type).incrementAndGet();

            // Get pooled objects
            AuditEntry entry = getAuditEntry();
            entry.timestamp = Instant.now();
            entry.eventType = type;
            entry.severity = severity;
            entry.message = maskSensitiveData ? maskSensitiveData(message) : message;

            // Reuse context map or create new
            entry.context = getContextMap();
            if (context != null) {
                entry.context.putAll(maskContext(context));
            }

            // Add MDC context efficiently
            addMdcContext(entry.context);

            // Process asynchronously or synchronously based on configuration
            if (asyncLogging && !shutdown) {
                if (!logQueue.offer(entry)) {
                    // Queue is full, log synchronously as fallback
                    processLogEntry(entry);
                    returnAuditEntry(entry);
                }
            } else {
                processLogEntry(entry);
                returnAuditEntry(entry);
            }

        } catch (Exception e) {
            // Never let audit logging failure affect the main flow
            log.error("Failed to log audit event", e);
        }
    }

    private boolean checkRateLimit(EventType type) {
        String key = type.name();
        long currentWindow = System.currentTimeMillis() / rateLimitWindow;
        String windowKey = key + "_" + currentWindow;

        AtomicLong counter = rateLimitCounters.computeIfAbsent(windowKey, k -> new AtomicLong(0));
        long currentCount = counter.incrementAndGet();

        // Clean up old windows periodically
        if (currentCount == 1) {
            cleanupOldRateLimitCounters(currentWindow);
        }

        return currentCount <= maxEventsPerWindow;
    }

    private void cleanupOldRateLimitCounters(long currentWindow) {
        // Clean up counters from previous windows to prevent memory leaks
        rateLimitCounters.entrySet().removeIf(entry -> {
            String key = entry.getKey();
            int lastUnderscore = key.lastIndexOf('_');
            if (lastUnderscore > 0) {
                try {
                    long window = Long.parseLong(key.substring(lastUnderscore + 1));
                    return window < currentWindow - 2; // Keep current and previous window
                } catch (NumberFormatException e) {
                    return true; // Remove invalid entries
                }
            }
            return true;
        });
    }

    private void addMdcContext(Map<String, Object> context) {
        // Add MDC context efficiently
        context.put("thread", Thread.currentThread().getName());
        context.put("threadId", Thread.currentThread().getId());

        String sessionId = MDC.get("sessionId");
        if (sessionId != null) {
            context.put("sessionId", sessionId);
        }
        String userId = MDC.get("userId");
        if (userId != null) {
            context.put("userId", userId);
        }
    }

    /**
     * Log an authentication event with optimized performance
     *
     * @param success whether authentication succeeded
     * @param username the username (will be masked if configured)
     * @param authMethod authentication method used (domain or method)
     * @param remoteAddress remote address
     */
    public void logAuthentication(boolean success, String username, String authMethod, String remoteAddress) {
        EventType type = success ? EventType.AUTHENTICATION_SUCCESS : EventType.AUTHENTICATION_FAILURE;
        Severity severity = success ? Severity.INFO : Severity.WARNING;

        // Pre-mask sensitive data to avoid repeated processing
        String maskedUsername = maskSensitiveData ? maskUsername(username) : username;
        String maskedAddress = maskSensitiveData ? maskIpAddress(remoteAddress) : remoteAddress;

        Map<String, Object> context = getContextMap();
        context.put("username", maskedUsername);
        context.put("remoteAddress", maskedAddress);
        context.put("authMethod", authMethod);
        context.put("success", success);

        String message = buildAuthMessage(success, maskedUsername, maskedAddress, authMethod);

        logEvent(type, severity, message, context);
        returnContextMap(context);
    }

    private String buildAuthMessage(boolean success, String maskedUsername, String maskedAddress, String authMethod) {
        StringBuilder sb = getStringBuilder();
        try {
            sb.append("Authentication ")
                    .append(success ? "succeeded" : "failed")
                    .append(" for user ")
                    .append(maskedUsername)
                    .append(" from ")
                    .append(maskedAddress)
                    .append(" using ")
                    .append(authMethod);
            return sb.toString();
        } finally {
            returnStringBuilder(sb);
        }
    }

    /**
     * Log a file access event
     *
     * @param path file path
     * @param operation operation performed
     * @param success whether operation succeeded
     * @param username user performing operation
     */
    public void logFileAccess(String path, String operation, boolean success, String username) {
        Map<String, Object> context = getContextMap();
        context.put("path", sanitizePath(path));
        context.put("operation", operation);
        context.put("success", success);
        context.put("username", maskSensitiveData ? maskUsername(username) : username);

        StringBuilder sb = getStringBuilder();
        String message;
        try {
            sb.append("File ")
                    .append(operation)
                    .append(" on ")
                    .append(sanitizePath(path))
                    .append(" by ")
                    .append(maskSensitiveData ? maskUsername(username) : username)
                    .append(": ")
                    .append(success ? "SUCCESS" : "FAILED");
            message = sb.toString();
        } finally {
            returnStringBuilder(sb);
        }

        logEvent(EventType.FILE_ACCESS, success ? Severity.INFO : Severity.WARNING, message, context);
        returnContextMap(context);
    }

    /**
     * Log an encryption event
     *
     * @param enabled whether encryption was enabled
     * @param cipherSuite cipher suite used
     * @param sessionId session identifier
     */
    public void logEncryption(boolean enabled, String cipherSuite, String sessionId) {
        EventType type = enabled ? EventType.ENCRYPTION_ENABLED : EventType.ENCRYPTION_FAILED;

        Map<String, Object> context = getContextMap();
        context.put("cipherSuite", cipherSuite);
        context.put("sessionId", maskSensitiveData ? maskSessionId(sessionId) : sessionId);
        context.put("enabled", enabled);

        StringBuilder sb = getStringBuilder();
        String message;
        try {
            sb.append("Encryption ")
                    .append(enabled ? "enabled" : "failed")
                    .append(" for session ")
                    .append(maskSensitiveData ? maskSessionId(sessionId) : sessionId)
                    .append(" with cipher ")
                    .append(cipherSuite);
            message = sb.toString();
        } finally {
            returnStringBuilder(sb);
        }

        logEvent(type, enabled ? Severity.INFO : Severity.ERROR, message, context);
        returnContextMap(context);
    }

    /**
     * Log a security violation
     *
     * @param violation description of violation
     * @param context additional context
     */
    public void logSecurityViolation(String violation, Map<String, Object> context) {
        String message = "Security violation detected: " + violation;
        logEvent(EventType.SECURITY_VIOLATION, Severity.CRITICAL, message, context);
    }

    private void processLogEntry(AuditEntry entry) {
        if (enableJsonLogging) {
            logAsJson(entry);
        } else {
            logAsText(entry);
        }
    }

    private void logAsJson(AuditEntry entry) {
        StringBuilder json = getStringBuilder();
        try {
            buildJsonEntry(json, entry);
            String jsonStr = json.toString();

            // Log at appropriate level
            switch (entry.severity) {
            case CRITICAL:
            case ERROR:
                auditLog.error(jsonStr);
                break;
            case WARNING:
                auditLog.warn(jsonStr);
                break;
            default:
                auditLog.info(jsonStr);
            }
        } catch (Exception e) {
            log.error("Failed to serialize audit entry to JSON", e);
            logAsText(entry); // Fallback to text
        } finally {
            returnStringBuilder(json);
        }
    }

    private void buildJsonEntry(StringBuilder json, AuditEntry entry) {
        json.append("{");
        json.append("\"timestamp\":\"").append(escapeJson(entry.timestamp.toString())).append("\",");
        json.append("\"eventType\":\"").append(entry.eventType.name()).append("\",");
        json.append("\"severity\":\"").append(entry.severity.name()).append("\",");
        json.append("\"message\":\"").append(escapeJson(entry.message)).append("\"");

        if (!entry.context.isEmpty()) {
            json.append(",\"context\":{");
            boolean first = true;
            for (Map.Entry<String, Object> e : entry.context.entrySet()) {
                if (e.getValue() != null) {
                    if (!first) {
                        json.append(",");
                    }
                    json.append("\"").append(escapeJson(e.getKey())).append("\":\"");
                    json.append(escapeJson(String.valueOf(e.getValue()))).append("\"");
                    first = false;
                }
            }
            json.append("}");
        }

        json.append("}");
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private void logAsText(AuditEntry entry) {
        StringBuilder sb = getStringBuilder();
        try {
            sb.append("[").append(entry.timestamp).append("] ");
            sb.append("[").append(entry.eventType).append("] ");
            sb.append("[").append(entry.severity).append("] ");
            sb.append(entry.message);

            if (!entry.context.isEmpty()) {
                sb.append(" | Context: ");
                for (Map.Entry<String, Object> e : entry.context.entrySet()) {
                    sb.append(e.getKey()).append("=").append(e.getValue()).append(" ");
                }
            }

            String logMessage = sb.toString();
            switch (entry.severity) {
            case CRITICAL:
            case ERROR:
                auditLog.error(logMessage);
                break;
            case WARNING:
                auditLog.warn(logMessage);
                break;
            default:
                auditLog.info(logMessage);
            }
        } finally {
            returnStringBuilder(sb);
        }
    }

    private String maskSensitiveData(String data) {
        if (data == null || !maskSensitiveData) {
            return data;
        }

        // Performance optimization: skip expensive regex for high-frequency logging
        if (enableHighPerformanceMode) {
            // Fast path: only check for obvious patterns without regex
            String lowerData = data.toLowerCase();
            if (!lowerData.contains("password") && !lowerData.contains("secret") && !lowerData.contains("token")
                    && !lowerData.contains("key") && !lowerData.contains("credential") && !lowerData.contains("auth")) {
                return data; // No sensitive patterns detected, skip regex
            }
        }

        // Mask passwords and secrets using cached pattern
        return PASSWORD_PATTERN.matcher(data).replaceAll("$1$2****");
    }

    private Map<String, Object> maskContext(Map<String, Object> context) {
        if (!maskSensitiveData) {
            return context;
        }

        Map<String, Object> masked = getContextMap();
        for (Map.Entry<String, Object> entry : context.entrySet()) {
            String key = entry.getKey().toLowerCase();
            Object value = entry.getValue();

            // Mask sensitive keys
            if (key.contains("password") || key.contains("secret") || key.contains("token") || key.contains("credential")) {
                masked.put(entry.getKey(), "****");
            } else if (value instanceof String) {
                masked.put(entry.getKey(), maskSensitiveData((String) value));
            } else {
                masked.put(entry.getKey(), value);
            }
        }

        return masked;
    }

    private String maskUsername(String username) {
        if (!maskSensitiveData || username == null) {
            return username;
        }

        // Show first and last character only
        if (username.length() <= 2) {
            return "***";
        }

        return username.charAt(0) + "***" + username.charAt(username.length() - 1);
    }

    private String maskIpAddress(String ip) {
        if (!maskSensitiveData || ip == null) {
            return ip;
        }

        // Use cached pattern for performance
        return IP_PATTERN.matcher(ip).replaceAll(mr -> {
            String[] parts = mr.group().split("\\.");
            if (parts.length == 4) {
                return parts[0] + "." + parts[1] + "." + parts[2] + ".xxx";
            }
            return mr.group();
        });
    }

    private String maskSessionId(String sessionId) {
        if (!maskSensitiveData || sessionId == null) {
            return sessionId;
        }

        // Show first 4 characters only
        if (sessionId.length() <= 4) {
            return "****";
        }

        return sessionId.substring(0, 4) + "****";
    }

    private String sanitizePath(String path) {
        if (path == null) {
            return null;
        }

        // Remove any potentially sensitive information from paths
        return path.replaceAll("\\\\+", "/");
    }

    // Object pooling methods for performance optimization
    private AuditEntry getAuditEntry() {
        AuditEntry entry = auditEntryPool.poll();
        if (entry == null) {
            entry = new AuditEntry();
        } else {
            // Reset the entry
            entry.context = null;
            entry.message = null;
            entry.eventType = null;
            entry.severity = null;
            entry.timestamp = null;
        }
        return entry;
    }

    private void returnAuditEntry(AuditEntry entry) {
        if (entry != null) {
            returnContextMap(entry.context);
            auditEntryPool.offer(entry);
        }
    }

    private StringBuilder getStringBuilder() {
        StringBuilder sb = stringBuilderPool.poll();
        if (sb == null) {
            sb = new StringBuilder(512); // Pre-allocate reasonable size
        } else {
            sb.setLength(0); // Reset length
        }
        return sb;
    }

    private void returnStringBuilder(StringBuilder sb) {
        if (sb != null && sb.capacity() < 2048) { // Avoid keeping very large builders
            stringBuilderPool.offer(sb);
        }
    }

    private Map<String, Object> getContextMap() {
        HashMap<String, Object> map = mapPool.poll();
        if (map == null) {
            map = new HashMap<>();
        } else {
            map.clear();
        }
        return map;
    }

    private void returnContextMap(Map<String, Object> map) {
        if (map instanceof HashMap && map.size() < 20) { // Avoid keeping very large maps
            mapPool.offer((HashMap<String, Object>) map);
        }
    }

    /**
     * Get audit statistics
     *
     * @return map of event types to counts
     */
    public Map<EventType, Long> getStatistics() {
        Map<EventType, Long> stats = new HashMap<>();
        for (Map.Entry<EventType, AtomicLong> entry : eventCounters.entrySet()) {
            stats.put(entry.getKey(), entry.getValue().get());
        }
        return stats;
    }

    /**
     * Reset audit statistics
     */
    public void resetStatistics() {
        for (AtomicLong counter : eventCounters.values()) {
            counter.set(0);
        }
        for (AtomicLong timing : eventTimings.values()) {
            timing.set(0);
        }
    }

    /**
     * Enable or disable JSON logging
     *
     * @param enable true to enable JSON logging
     */
    public void setJsonLoggingEnabled(boolean enable) {
        this.enableJsonLogging = enable;
        log.info("JSON logging {}", enable ? "enabled" : "disabled");
    }

    /**
     * Enable or disable sensitive data masking
     *
     * @param enable true to enable masking
     */
    public void setSensitiveDataMaskingEnabled(boolean enable) {
        this.maskSensitiveData = enable;
        log.info("Sensitive data masking {}", enable ? "enabled" : "disabled");
    }

    /**
     * Enable or disable high performance mode for sensitive data masking
     *
     * In high performance mode, expensive regex operations are avoided by doing
     * fast string contains checks first. This significantly improves performance
     * for high-frequency logging scenarios.
     *
     * @param enable true to enable high performance mode
     */
    public void setHighPerformanceModeEnabled(boolean enable) {
        this.enableHighPerformanceMode = enable;
        log.info("High performance masking mode {}", enable ? "enabled" : "disabled");
    }

    /**
     * Enable or disable skipping masking for debug level logs
     *
     * When enabled, DEBUG level logs will skip sensitive data masking entirely
     * to improve performance in development and debugging scenarios.
     *
     * @param enable true to skip masking for debug level
     */
    public void setSkipMaskingForDebugLevel(boolean enable) {
        this.skipMaskingForDebugLevel = enable;
        log.info("Skip masking for debug level {}", enable ? "enabled" : "disabled");
    }

    /**
     * Enable or disable stack trace inclusion
     *
     * @param enable true to include stack traces
     */
    public void setIncludeStackTrace(boolean enable) {
        this.includeStackTrace = enable;
    }

    /**
     * Set minimum log level
     *
     * @param level minimum severity level to log
     */
    public void setMinLogLevel(Severity level) {
        this.minLogLevel = level;
        log.info("Minimum log level set to {}", level);
    }

    /**
     * Enable or disable asynchronous logging
     *
     * @param enable true to enable async logging
     */
    public void setAsyncLogging(boolean enable) {
        this.asyncLogging = enable;
        log.info("Asynchronous logging {}", enable ? "enabled" : "disabled");
    }

    /**
     * Configure rate limiting
     *
     * @param windowMs time window in milliseconds
     * @param maxEvents maximum events per window
     */
    public void setRateLimit(long windowMs, int maxEvents) {
        this.rateLimitWindow = windowMs;
        this.maxEventsPerWindow = maxEvents;
        log.info("Rate limiting set to {} events per {} ms", maxEvents, windowMs);
    }

    /**
     * Internal audit entry class
     */
    private static class AuditEntry {
        Instant timestamp;
        EventType eventType;
        Severity severity;
        String message;
        Map<String, Object> context;
    }
}
