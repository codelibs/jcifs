JCIFS
[![Java CI with Maven](https://github.com/codelibs/jcifs/actions/workflows/maven.yml/badge.svg)](https://github.com/codelibs/jcifs/actions/workflows/maven.yml)
=====

JCIFS is an Open Source client library that implements the CIFS/SMB networking protocol in 100% Java.
From version 2.x, this project is forked from [jcifs-ng](https://github.com/AgNO3/jcifs-ng) and existing jcifs code is merged as `smb1`.
Version 3.x introduces SMB3 encryption and enhanced security features, while maintaining backward compatibility with legacy SMB devices.

## Version

[Versions in Maven Repository](https://repo1.maven.org/maven2/org/codelibs/jcifs/)

**Current Version: 3.0.0-SNAPSHOT** - SMB2/SMB3 implementation with advanced capabilities

## Requirements

- Java 17 or higher (upgraded from Java 8)
- SLF4J for logging

## Using Maven

```xml
<dependency>
    <groupId>org.codelibs</groupId>
    <artifactId>jcifs</artifactId>
    <version>2.1.39</version>
</dependency>
```

For the latest version with full SMB3 support:
```xml
<dependency>
    <groupId>org.codelibs</groupId>
    <artifactId>jcifs</artifactId>
    <version>3.0.0</version>
</dependency>
```

## Features

### Protocol Support
 * **SMB1/CIFS**: Legacy protocol support for older devices
 * **SMB2**: Full SMB 2.0.2, 2.1 support
 * **SMB3**: Complete SMB 3.0, 3.0.2, 3.1.1 implementation with:
   - AES-128-CCM encryption (SMB 3.0/3.0.2)
   - AES-128-GCM encryption (SMB 3.1.1)
   - Pre-Authentication Integrity (SMB 3.1.1)
   - Automatic protocol negotiation
   - Transparent encryption when required by server

### SMB3 Features
 * **SMB3 Leases**: Client-side caching with lease support
 * **Persistent Handles**: Network resilience and reconnection
 * **Multi-Channel**: Multiple network connection support  
 * **Directory Leasing**: Directory metadata caching
 * **RDMA Support**: High-performance data transfer (experimental)
 * **Witness Protocol**: Failover notifications (experimental)

### Core Features
 * Per-context configuration (no global state)
 * SLF4J logging framework
 * Unified authentication: NTLMSSP, Kerberos, SPNEGO
 * Large file transfer support (ReadX/WriteX)
 * Streaming operations for directory listings
 * DFS (Distributed File System) support
 * NtTransNotifyChange support for file monitoring
 * Comprehensive test suite with JUnit 4

### Recent Improvements (v3.x)
 * Java 17 minimum requirement
 * Jakarta Servlet namespace migration
 * SMB3 encryption and signing support (AES-CCM/GCM, AES-CMAC)
 * Enhanced protocol negotiation
 * Improved thread safety and resource management

## Quick Start

### Basic Usage

```java
import jcifs.CIFSContext;
import jcifs.context.SingletonContext;
import jcifs.smb.SmbFile;

// Using default context
CIFSContext context = SingletonContext.getInstance();

// Access a file
try (SmbFile file = new SmbFile("smb://server/share/file.txt", context)) {
    if (file.exists()) {
        System.out.println("File size: " + file.length());
    }
}
```

### With Authentication

```java
import jcifs.CIFSContext;
import jcifs.context.BaseContext;
import jcifs.smb.NtlmPasswordAuthenticator;

// Create context with credentials
CIFSContext context = new BaseContext(new jcifs.config.PropertyConfiguration());
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

# Protocol versions
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

### SMB3 Feature Configuration

```properties
# SMB3 Leases
jcifs.smb.client.useLeases=true

# Persistent Handles
jcifs.smb.client.usePersistentHandles=true
jcifs.smb.client.persistentHandleTimeout=120000

# Multi-Channel (experimental)
jcifs.smb.client.useMultiChannel=false
jcifs.smb.client.maxChannels=4

# Directory Leasing (experimental)
jcifs.smb.client.useDirectoryLeasing=false

# RDMA Support (experimental, requires compatible hardware)
jcifs.smb.client.useRDMA=false
jcifs.smb.client.rdmaProvider=disni

# Witness Protocol (experimental)
jcifs.smb.client.useWitness=false
```

### Usage with Properties

```java
Properties props = new Properties();
props.setProperty("jcifs.smb.client.domain", "MYDOMAIN");
props.setProperty("jcifs.smb.client.useLeases", "true");

Configuration config = new PropertyConfiguration(props);
CIFSContext context = new BaseContext(config);
```

## Others

### Choosing Between This JCIFS and jcifs-ng

**Use CodeLibs JCIFS when:**
- You need SMB2/SMB3 support with modern security features
- You require compatibility with both legacy and modern SMB devices
- You need SMB3 encryption and signing support
- Your application (like [Fess](https://github.com/codelibs/fess)) needs to connect to diverse SMB environments

**Use jcifs-ng when:**
- You only need basic SMB2/SMB3 connectivity
- You don't require advanced enterprise features
- You have a controlled environment with specific SMB devices
- Minimal dependency footprint is preferred

### Documentation

Technical documentation for SMB3 features is available in the `docs/smb3-features/` directory.

### Testing

```bash
# Build the project
mvn clean compile

# Run all tests
mvn test

# Run specific test classes
mvn test -Dtest=SmbFileTest
```

### Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes with appropriate tests
4. Run `mvn clean test` to ensure all tests pass
5. Submit a pull request

### License

JCIFS is licensed under the GNU Lesser General Public License (LGPL). See the LICENSE file for details.
