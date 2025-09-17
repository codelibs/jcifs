JCIFS
[![Java CI with Maven](https://github.com/codelibs/jcifs/actions/workflows/maven.yml/badge.svg)](https://github.com/codelibs/jcifs/actions/workflows/maven.yml)
=====

JCIFS is an Open Source client library that implements the CIFS/SMB networking protocol in 100% Java.
From version 2.x, this project is forked from [jcifs-ng](https://github.com/AgNO3/jcifs-ng) and existing jcifs code is merged as `smb1`.
Version 3.x introduces SMB3 encryption and enhanced security features, while maintaining backward compatibility with legacy SMB devices.

## Version

[Versions in Maven Repository](https://repo1.maven.org/maven2/org/codelibs/jcifs/)

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

For the latest version with SMB3 support (coming soon):
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
 * **SMB3**: SMB 3.0, 3.0.2, 3.1.1 security features with:
   - AES-128-CCM encryption (SMB 3.0/3.0.2)
   - AES-128-GCM encryption (SMB 3.1.1)
   - Pre-Authentication Integrity (SMB 3.1.1)
   - Automatic protocol negotiation
   - Transparent encryption when required by server

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
 * SMB3 encryption (AES-CCM/GCM) and signing (AES-CMAC) implementation
 * Enhanced protocol negotiation
 * Improved thread safety
 * Better resource management with AutoCloseable patterns

### Known Limitations
 * SMB3 advanced features not yet implemented:
   - Multi-channel support
   - Persistent handles
   - Directory leasing
   - RDMA transport
 * Uses traditional oplocks instead of SMB3 leases

## Quick Start

### Basic Usage

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
    }
}
```

### With Authentication

```java
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.context.BaseContext;
import org.codelibs.jcifs.smb.impl.NtlmPasswordAuthenticator;

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

## Others

### Choosing Between This JCIFS and jcifs-ng

**Use CodeLibs JCIFS when:**
- You need maximum compatibility with legacy SMB devices
- You require SMB3 encryption and security features (AES-CCM/GCM, AES-CMAC)
- You need to support a wide variety of SMB implementations
- Your application (like [Fess](https://github.com/codelibs/fess)) needs to connect to many different SMB devices

**Use jcifs-ng when:**
- You only need to connect to modern SMB servers
- You don't require SMB3 encryption features
- You have a controlled environment with specific SMB devices

### Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes with appropriate tests
4. Run `mvn clean test` to ensure all tests pass
5. Submit a pull request

### License

JCIFS is licensed under the GNU Lesser General Public License (LGPL). See the LICENSE file for details.
