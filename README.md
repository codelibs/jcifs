# JCIFS - Java CIFS/SMB Client Library

[![Java CI with Maven](https://github.com/codelibs/jcifs/actions/workflows/maven.yml/badge.svg)](https://github.com/codelibs/jcifs/actions/workflows/maven.yml)
[![Maven Central](https://img.shields.io/maven-central/v/org.codelibs/jcifs.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22org.codelibs%22%20AND%20a:%22jcifs%22)
[![License: LGPL v2.1](https://img.shields.io/badge/License-LGPL%20v2.1-blue.svg)](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)
[![Java Version](https://img.shields.io/badge/Java-17%2B-green.svg)](https://openjdk.java.net/)

JCIFS is a comprehensive, pure Java implementation of the CIFS/SMB networking protocol suite, providing seamless access to Windows file shares and SMB servers. This library enables Java applications to interact with SMB resources across all major protocol versions while maintaining excellent compatibility with legacy systems.

## 🚀 Key Features

### **Protocol Support**
- **SMB1/CIFS**: Legacy protocol support for older devices and systems
- **SMB2**: Full SMB 2.0.2, 2.1 support with enhanced performance
- **SMB3**: Complete SMB 3.0, 3.0.2, 3.1.1 implementation featuring:
  - **AES-128-CCM encryption** (SMB 3.0/3.0.2)
  - **AES-128-GCM encryption** (SMB 3.1.1)
  - **Pre-Authentication Integrity** (SMB 3.1.1)
  - **AES-CMAC signing** for data integrity
  - **Automatic protocol negotiation**
  - **Transparent encryption** when required by the server, per session or per share (opt-in, see below)

See **[SMB2/SMB3 support status](docs/SMB3_SUPPORT.md)** for what is and is not
implemented, feature by feature. Leases, oplocks, durable handles, multi-channel,
directory leasing, compression, RDMA and the witness protocol are not implemented.

### **Security & Authentication**
- **Multi-method Authentication**: NTLMSSP, Kerberos, SPNEGO
- **Enterprise Security**: Domain authentication with credential renewal
- **Guest & Anonymous Access**: Flexible credential management
- **Per-context Configuration**: No global state, thread-safe operations

### **Performance & Reliability**
- **Large File Support**: Efficient ReadX/WriteX operations for multi-GB files
- **Streaming Operations**: Memory-efficient directory listings and file transfers
- **Connection Pooling**: Intelligent transport management and reuse
- **Buffer Caching**: Optimized memory management for high-throughput scenarios
- **DFS Support**: Distributed File System path resolution

### **Modern Java Integration**
- **Java 17+ Requirement**: Modern language features and performance
- **SLF4J Logging**: Configurable, enterprise-grade logging
- **AutoCloseable Resources**: Proper resource management patterns
- **Jakarta EE Support**: Compatible with modern servlet containers

## 📋 Requirements

- **Java**: 17 or higher (LTS recommended)
- **Dependencies**: SLF4J for logging, Bouncy Castle for cryptography
- **Network**: SMB/CIFS protocol access (typically ports 139/445)

## 📦 Installation

### Maven
```xml
<dependency>
    <groupId>org.codelibs</groupId>
    <artifactId>jcifs</artifactId>
    <version>3.0.0</version>
</dependency>
```

### Gradle
```groovy
implementation 'org.codelibs:jcifs:3.0.0'
```

### Latest Versions
Check [Maven Central](https://repo1.maven.org/maven2/org/codelibs/jcifs/) for the most recent releases.

## 🏃‍♂️ Quick Start

### Basic File Access
```java
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.context.SingletonContext;
import org.codelibs.jcifs.smb.impl.SmbFile;

// Using default context
CIFSContext context = SingletonContext.getInstance();

// Access a file
try (SmbFile file = new SmbFile("smb://server/share/file.txt", context)) {
    if (file.exists()) {
        System.out.println("File size: " + file.length());
        System.out.println("Last modified: " + new Date(file.lastModified()));
    }
}
```

### Reading File Content
```java
try (SmbFile file = new SmbFile("smb://server/share/document.txt", context);
     InputStream is = file.getInputStream();
     BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {

    String line;
    while ((line = reader.readLine()) != null) {
        System.out.println(line);
    }
}
```

### Directory Listing
```java
try (SmbFile dir = new SmbFile("smb://server/share/", context)) {
    for (SmbFile file : dir.listFiles()) {
        System.out.printf("%s %10d %s%n",
            file.isDirectory() ? "[DIR]" : "[FILE]",
            file.length(),
            file.getName());
    }
}
```

## 🔐 Authentication Examples

### Domain Authentication
```java
import org.codelibs.jcifs.smb.context.BaseContext;
import org.codelibs.jcifs.smb.impl.NtlmPasswordAuthenticator;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;

// Create context with domain credentials
Properties props = new Properties();
// Optional: Set SMB protocol preferences
props.setProperty("jcifs.client.minVersion", "SMB202");
props.setProperty("jcifs.client.maxVersion", "SMB311");

CIFSContext baseContext = new BaseContext(new PropertyConfiguration(props));
NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator(
    "DOMAIN",           // Domain name
    "username",         // Username
    "password"          // Password
);

CIFSContext authContext = baseContext.withCredentials(auth);

// Use authenticated context
try (SmbFile file = new SmbFile("smb://server/share/", authContext)) {
    // Authenticated operations...
}
```

### Kerberos Authentication
```java
import org.codelibs.jcifs.smb.impl.JAASAuthenticator;

// Kerberos authentication via JAAS login context (requires proper Kerberos/JAAS setup)
JAASAuthenticator kerbAuth = new JAASAuthenticator("jCIFS");
CIFSContext kerbContext = baseContext.withCredentials(kerbAuth);
```

### Guest Access
```java
// Guest access for servers that allow it
CIFSContext guestContext = baseContext.withGuestCredentials();
```

## 🔧 Advanced Usage

### Large File Operations
```java
// Efficient large file copying
try (SmbFile source = new SmbFile("smb://server/share/largefile.zip", context);
     SmbFile dest = new SmbFile("smb://server/backup/largefile.zip", context);
     InputStream is = source.getInputStream();
     OutputStream os = dest.getOutputStream()) {

    byte[] buffer = new byte[65536]; // 64KB buffer
    int bytesRead;
    while ((bytesRead = is.read(buffer)) != -1) {
        os.write(buffer, 0, bytesRead);
    }
}
```

### File Monitoring
```java
import org.codelibs.jcifs.smb.SmbWatchHandle;

// Monitor directory for changes
try (SmbFile dir = new SmbFile("smb://server/share/monitored/", context);
     SmbWatchHandle watch = dir.watch(
         SmbConstants.FILE_NOTIFY_CHANGE_FILE_NAME |
         SmbConstants.FILE_NOTIFY_CHANGE_SIZE, true)) {

    FileNotifyInformation[] notifications = watch.read();
    for (FileNotifyInformation info : notifications) {
        System.out.println("File changed: " + info.getFileName());
    }
}
```

### Custom Configuration
```java
// Advanced configuration
Properties config = new Properties();
config.setProperty("jcifs.client.minVersion", "SMB300");  // Require SMB3+
config.setProperty("jcifs.client.maxVersion", "SMB311");
config.setProperty("jcifs.client.signingEnforced", "true");  // Require signing
config.setProperty("jcifs.resolveOrder", "LMHOSTS,DNS,WINS,BCAST");

CIFSContext customContext = new BaseContext(new PropertyConfiguration(config));
```

## 🏗️ Architecture Overview

JCIFS follows a layered architecture designed for flexibility and performance:

### Core Components

**Context Layer (`org.codelibs.jcifs.smb.context`)**
- `CIFSContext`: Main entry point encapsulating configuration and credentials
- `BaseContext`: Primary implementation with full feature support
- Context wrappers for credential management and configuration isolation

**Resource Layer (`org.codelibs.jcifs.smb.impl`)**
- `SmbFile`: Primary implementation for files and directories
- `SmbResource`: Interface for all SMB network resources
- Resource locators and handles for connection management

**Protocol Implementation (`org.codelibs.jcifs.smb.internal`)**
- `smb1/`: Legacy SMB1/CIFS protocol support
- `smb2/`: Modern SMB2/SMB3 protocol implementation
- Protocol-specific message handling and transport

**Authentication (`org.codelibs.jcifs.smb.ntlmssp`, `org.codelibs.jcifs.smb.pac`, `org.codelibs.jcifs.smb.spnego`)**
- Multiple authentication mechanisms with automatic negotiation
- Credential management and renewal capabilities
- Enterprise security integration

## 🔨 Development

### Build Requirements
- **Java 17+**: JDK 17 or higher for building
- **Maven 3.6+**: Build system and dependency management

### Building from Source
```bash
# Clone the repository
git clone https://github.com/codelibs/jcifs.git
cd jcifs

# Compile the project
mvn clean compile

# Run tests
mvn test

# Create JAR file
mvn package

# Install to local repository
mvn install
```

### Code Quality
```bash
# Format code according to project standards
mvn formatter:format

# Check license headers
mvn apache-rat:check

# Generate test coverage report
mvn jacoco:report

# Check API compatibility
mvn clirr:check
```

### Testing
The project includes comprehensive test coverage:

```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=SmbFileTest

# Run integration tests
mvn verify

# Generate coverage report (target/site/jacoco/index.html)
mvn jacoco:report
```

#### Integration tests against a real SMB server

`mvn verify` also runs the `*IT` tests in `src/test/java/org/codelibs/jcifs/smb/it`,
which talk to an actual SMB server. Two backends are supported and the same tests
run against both.

**Samba (default, no setup needed).** With Docker available, the harness builds
and starts the container defined in `build_helpers/samba/` and points the tests at
it. Nothing else is required:

```bash
mvn verify
```

That publishes Samba on a mapped port. A DFS referral names a host but no port,
so the DFS tests skip unless the server answers on 445. The harness tries 445
first and falls back, so on a machine already using that port Testcontainers logs
one failed container start before the run continues normally. To run them anyway - on a
machine whose own 445 is taken, for instance - put the server and the test JVM on
the same Docker network:

```bash
./build_helpers/run-it-with-dfs.sh
```

**A real Windows server.** Run `build_helpers/win-setup.ps1` on the Windows
machine to create the shares, symlinks and DFS namespace, then point the tests at
it:

```bash
JCIFS_IT_BACKEND=windows \
JCIFS_IT_HOST=<the Windows computer name> \
JCIFS_IT_USER=testuser1 \
JCIFS_IT_PASSWORD=<the password passed to win-setup.ps1> \
mvn verify
```

This is what the nightly `SMB integration tests (Windows)` workflow does on a
`windows-latest` runner, which is a Windows Server 2025 host.

| Variable | Meaning |
|---|---|
| `JCIFS_IT_BACKEND` | `samba` or `windows`; unset starts the container |
| `JCIFS_IT_HOST`, `JCIFS_IT_PORT` | where the server is; port defaults to 445 |
| `JCIFS_IT_USER`, `JCIFS_IT_PASSWORD`, `JCIFS_IT_DOMAIN` | credentials |
| `JCIFS_IT_SHARE`, `JCIFS_IT_SHARE_ENCRYPTED`, `JCIFS_IT_DFS_ROOT` | share names |
| `JCIFS_IT_REQUIRED` | `true` makes a missing environment a failure instead of a skip |

Before any test runs, a preflight check confirms the server is configured the way
the tests assume - in particular that the encrypted share really does reject a
client that cannot encrypt, and that a pinned dialect is actually honoured.
Without those checks a green run would not mean much.

Some tests skip by design: DFS referrals name a host but no port, so they only
run when the server answers on 445 (a development machine that is already sharing
files will skip them), and tests marked `@RequiresBackend` run on one backend
only.

## ⚡ Performance Considerations

### Connection Management
- **Reuse contexts**: Create one context per configuration, reuse across operations
- **Connection pooling**: JCIFS automatically pools and reuses connections
- **Proper cleanup**: Always use try-with-resources for automatic resource management

### Large File Operations
```java
// Use appropriate buffer sizes for your use case
byte[] buffer = new byte[1024 * 1024]; // 1MB for large files
byte[] buffer = new byte[64 * 1024];   // 64KB for general use

// For very large files, consider streaming
try (InputStream is = smbFile.getInputStream()) {
    // Process in chunks to avoid memory issues
}
```

### Protocol Selection
```java
// For maximum performance on modern servers
props.setProperty("jcifs.client.minVersion", "SMB300");
props.setProperty("jcifs.client.maxVersion", "SMB311");

// For maximum compatibility (default)
props.setProperty("jcifs.client.minVersion", "SMB1");
props.setProperty("jcifs.client.maxVersion", "SMB311");
```

## 🔒 Security Best Practices

### Authentication
- **Use domain authentication** when possible for better security
- **Enable SMB signing** for data integrity: `jcifs.client.signingEnforced=true`
  (`signingPreferred` does **not** enable signing on SMB2/SMB3 — see
  [the support status](docs/SMB3_SUPPORT.md#jcifsclientsigningpreferred-does-not-enable-smb2-signing))
- **Prefer SMB3** for encryption: `jcifs.client.minVersion=SMB300`
- **Rotate credentials** regularly and implement credential renewal

### Network Security
- **Use encrypted connections** when available: set `jcifs.client.encryptionEnabled=true` (default `false`).
  Once enabled, encryption is applied automatically to any session or share the server marks as requiring it.
- **Limit protocol versions** to minimum required for your environment
- **Monitor failed authentication** attempts in logs
- **Use VPN or secure networks** when accessing SMB over public networks

### Configuration Security
```java
// Secure configuration example
Properties secureConfig = new Properties();
secureConfig.setProperty("jcifs.client.minVersion", "SMB300");
secureConfig.setProperty("jcifs.client.signingEnforced", "true");
secureConfig.setProperty("jcifs.client.ipcSigningEnforced", "true");
```

## 🛠️ Troubleshooting

### Common Issues

**Connection Timeouts**
```java
// Increase timeout values
props.setProperty("jcifs.client.soTimeout", "35000");      // 35 seconds
props.setProperty("jcifs.client.connTimeout", "10000");    // 10 seconds
props.setProperty("jcifs.client.responseTimeout", "30000"); // 30 seconds
```

**Authentication Failures**
- Verify domain name, username, and password
- Check if the account has necessary permissions
- Ensure the server allows the authentication method
- For Kerberos, verify proper DNS and time synchronization

**Protocol Negotiation Issues**
```java
// Debug protocol negotiation
// Enable debug logging through your SLF4J backend, e.g.
//   <logger name="org.codelibs.jcifs.smb.internal.smb2" level="DEBUG"/>

// Force specific protocol version if needed
props.setProperty("jcifs.client.minVersion", "SMB202");
props.setProperty("jcifs.client.maxVersion", "SMB202");
```

**Performance Issues**
- Use connection pooling (enabled by default)
- Adjust buffer sizes for your use case
- Consider enabling SMB3 for better performance
- Monitor network latency and bandwidth

### Logging Configuration
JCIFS uses SLF4J for logging. Configure your logging framework accordingly:

```xml
<!-- logback.xml example -->
<configuration>
    <logger name="org.codelibs.jcifs.smb" level="INFO"/>
    <logger name="org.codelibs.jcifs.smb.internal" level="WARN"/>
    <!-- Enable debug for troubleshooting -->
    <logger name="org.codelibs.jcifs.smb.internal.smb2" level="DEBUG"/>
</configuration>
```

## 🔄 Migration Guide

### From JCIFS 2.x to 3.x
- **Java 17+ required**: Update your runtime environment
- **Package changes**: All classes moved to `org.codelibs.jcifs.smb`
- **Property names changed**: the `.smb` segment was dropped from every configuration
  key (see below). Old keys are *silently ignored*, so settings fall back to their
  defaults until you rename them.
- **Enhanced SMB3 support**: New encryption and signing capabilities
- **Improved authentication**: Enhanced credential management

#### Configuration property names

| 2.x | 3.x |
| --- | --- |
| `jcifs.smb.client.<name>` | `jcifs.client.<name>` |
| `jcifs.smb.<name>` (`lmCompatibility`, `maxBuffers`, `allowNTLMFallback`, `useRawNTLM`) | `jcifs.<name>` |
| `jcifs.smb1.smb.client.<name>` (legacy SMB1 stack) | `jcifs.client.<name>` |
| `jcifs.netbios.<name>`, `jcifs.http.<name>`, `jcifs.resolveOrder`, `jcifs.encoding` | unchanged |

`PropertyConfiguration` logs a warning for every property it receives under one of the
old prefixes, naming the key to use instead. The authoritative list of keys and their
defaults is the `Configuration` interface javadoc.

### From Original JCIFS
- **Context-based API**: Replace global configuration with contexts
- **Modern authentication**: Update to new credential classes
- **Resource management**: Use try-with-resources patterns

## 🆚 JCIFS vs jcifs-ng

### Choose JCIFS when:
- Maximum compatibility with legacy SMB devices is required
- SMB3 encryption and security features are needed
- Connecting to diverse SMB implementations
- Using in applications like [Fess](https://github.com/codelibs/fess) that need broad SMB support

### Choose jcifs-ng when:
- Only connecting to modern SMB servers
- SMB3 encryption features are not required
- Working in controlled environments with specific SMB devices

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork the repository** and create a feature branch
2. **Make your changes** with appropriate tests
3. **Follow coding standards**: Use `mvn formatter:format`
4. **Run tests**: Ensure `mvn clean test` passes
5. **Update documentation** if needed
6. **Submit a pull request** with a clear description

### Development Setup
```bash
git clone https://github.com/your-username/jcifs.git
cd jcifs
mvn clean compile
mvn test
```

### Coding Standards
- Follow existing code style and patterns
- Add JavaDoc comments for public APIs
- Include unit tests for new functionality
- Ensure all tests pass before submitting

## 📜 License

JCIFS is licensed under the [GNU Lesser General Public License (LGPL) v2.1](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html).

