JCIFS
[![Java CI with Maven](https://github.com/codelibs/jcifs/actions/workflows/maven.yml/badge.svg)](https://github.com/codelibs/jcifs/actions/workflows/maven.yml)
=====

JCIFS is an Open Source client library that implements the CIFS/SMB networking protocol in 100% Java.
This fork from [jcifs-ng](https://github.com/AgNO3/jcifs-ng) merges backward compatibility with legacy SMB devices while supporting modern SMB2/SMB3 protocols. Key features include SMB2 support, per-context configuration, SLF4J logging, NTLMSSP/Kerberos authentication, and streaming operations.

## Version

[Versions in Maven Repository](https://repo1.maven.org/maven2/org/codelibs/jcifs/)

## Requirements

- Java 17 or higher
- SLF4J for logging
- Bouncy Castle (for SMB3 encryption support)

## Using Maven

```xml
<dependency>
    <groupId>org.codelibs</groupId>
    <artifactId>jcifs</artifactId>
    <version>2.1.39</version>
</dependency>
```



## Features

### Protocol Support
The library supports a full range of SMB protocols with automatic negotiation:

**Supported Protocols:**
- **SMB1/CIFS**: Legacy support via `jcifs.smb1/` package
- **SMB 2.0.2**: Windows Vista+ (0x0202)
- **SMB 2.1**: Windows 7/Server 2008R2 (0x0210)
- **SMB 3.0**: Windows 8/Server 2012 (0x0300) - AES-128-CCM encryption
- **SMB 3.0.2**: Windows 8.1/Server 2012R2 (0x0302) - Enhanced encryption
- **SMB 3.1.1**: Windows 10/Server 2016+ (0x0311) - AES-128-GCM + Pre-Auth Integrity

**Protocol Selection:**
- Default Range: SMB1 to SMB 3.1.1
- Automatic Negotiation: Client offers all supported dialects, server selects highest common version
- Configurable: Min/max versions can be set via configuration properties

### SMB3 Encryption Support
- **SMB2 Transform Header**: Encrypted message wrapping
- **AES-CCM/GCM Support**: Both AES-128-CCM (SMB 3.0/3.0.2) and AES-128-GCM (SMB 3.1.1) cipher suites
- **Encryption Context**: Per-session encryption state management
- **Key Derivation**: SMB3 KDF implementation with dialect-specific parameters
- **Pre-Authentication Integrity**: SMB 3.1.1 PAI for preventing downgrade attacks
- **Automatic Detection**: Encryption automatically enabled when servers require it
- **Secure Key Management**: Proper key derivation and nonce generation

### Core Features
- **Per-context configuration**: No global state, each context encapsulates configuration
- **Authentication**: NTLM, Kerberos, SPNEGO unified subsystem
- **SLF4J Logging**: Comprehensive logging throughout the codebase
- **Resource Management**: AutoCloseable patterns for file handles and connections
- **Thread Safety**: Components support concurrent access
- **DFS Support**: Distributed File System resolution
- **Streaming Operations**: Efficient directory listings and file operations
- **Buffer Caching**: Optimized buffer management
- **DCE/RPC Protocol**: Support for advanced operations

## Quick Start

### Basic Usage

```java
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.context.SingletonContext;
import org.codelibs.jcifs.smb.SmbFile;

// Using default context
CIFSContext context = SingletonContext.getInstance();

// Access a file (encryption is transparent - automatically used if server requires it)
try (SmbFile file = new SmbFile("smb://server/share/file.txt", context)) {
    if (file.exists()) {
        System.out.println("File size: " + file.length());
    }
}
```

### With Authentication

```java
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.context.BaseContext;
import org.codelibs.jcifs.smb.NtlmPasswordAuthenticator;

// Create context with credentials
CIFSContext context = new BaseContext(new org.codelibs.jcifs.smb.config.PropertyConfiguration());
NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("domain", "username", "password");
CIFSContext authContext = context.withCredentials(auth);

// Use authenticated context
try (SmbFile file = new SmbFile("smb://server/share/", authContext)) {
    for (SmbFile f : file.listFiles()) {
        System.out.println(f.getName());
    }
}
```

## Configuration

### Basic Configuration Properties

```properties
# Connection settings
jcifs.smb.client.connTimeout=35000
jcifs.smb.client.soTimeout=180000
jcifs.smb.client.responseTimeout=30000

# Authentication
jcifs.smb.client.domain=WORKGROUP
jcifs.smb.client.username=guest
jcifs.smb.client.password=

# Protocol versions (SMB1 to SMB 3.1.1)
jcifs.smb.client.minVersion=SMB1
jcifs.smb.client.maxVersion=SMB311

# Security
jcifs.smb.client.signingPreferred=false
jcifs.smb.client.signingEnforced=false
jcifs.smb.client.encryptionEnforced=false
jcifs.smb.client.disablePlainTextPasswords=true

# Performance
jcifs.smb.client.useBatching=true
jcifs.smb.client.useUnicode=true
jcifs.smb.client.maxMpxCount=10
```

### Usage with Properties

```java
Properties props = new Properties();
props.setProperty("jcifs.smb.client.domain", "MYDOMAIN");
props.setProperty("jcifs.smb.client.useLeases", "true");

Configuration config = new PropertyConfiguration(props);
CIFSContext context = new BaseContext(config);
```

## Development

### Build Commands
```bash
# Compile the source code
mvn compile

# Build JAR file
mvn package

# Clean and rebuild
mvn clean compile

# Install to local repository
mvn install
```

### Testing
```bash
# Run all tests (JUnit 4 based)
mvn test

# Run specific test class
mvn test -Dtest=SpecificTest

# Alternative test runner
mvn surefire:test
```

### Code Quality
```bash
# Generate code coverage reports
mvn jacoco:report

# License header validation
mvn apache-rat:check

# API compatibility checking
mvn clirr:check
```

### Architecture Overview

The library follows a layered architecture:

- **Context Layer**: `CIFSContext` interface provides the main entry point
- **Resource Layer**: `SmbResource` interface represents SMB network resources  
- **Protocol Layers**: Separate SMB1 (`jcifs.internal.smb1/`) and SMB2/3 (`jcifs.internal.smb2/`) implementations
- **Authentication**: NTLM, Kerberos, SPNEGO unified subsystem
- **Network Layer**: Transport abstraction, NetBIOS name resolution, session management

### Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes with appropriate tests
4. Run `mvn clean test` to ensure all tests pass
5. Submit a pull request

### License

JCIFS is licensed under the GNU Lesser General Public License (LGPL). See the LICENSE file for details.
