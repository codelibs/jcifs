# CLAUDE.md - AI Assistant Guide for JCIFS

## Project Overview

JCIFS is a comprehensive, pure Java implementation of the CIFS/SMB networking protocol suite. It provides seamless access to Windows file shares and SMB servers, supporting SMB1, SMB2, and SMB3 protocol versions with features like AES encryption, Kerberos authentication, and DFS resolution.

- **Language**: Java 17+
- **Build System**: Maven
- **License**: LGPL v2.1
- **Package**: `org.codelibs.jcifs`

## Quick Commands

```bash
# Build the project
mvn clean compile

# Run tests
mvn test

# Run specific test
mvn test -Dtest=SmbFileTest

# Package JAR
mvn package

# Install to local repository
mvn install

# Format code (required before commits)
mvn formatter:format

# Check license headers
mvn apache-rat:check

# Generate test coverage report
mvn jacoco:report
```

## Directory Structure

```
jcifs/
├── pom.xml                    # Maven configuration
├── src/
│   ├── main/java/org/codelibs/jcifs/
│   │   ├── smb/               # Main SMB package (public API)
│   │   │   ├── config/        # Configuration implementations
│   │   │   ├── context/       # CIFSContext implementations
│   │   │   ├── impl/          # Core implementations (SmbFile, authenticators, etc.)
│   │   │   ├── internal/      # Protocol internals (NOT public API)
│   │   │   │   ├── smb1/      # SMB1/CIFS protocol
│   │   │   │   ├── smb2/      # SMB2/SMB3 protocol
│   │   │   │   ├── dfs/       # DFS structures
│   │   │   │   ├── dtyp/      # Windows data types
│   │   │   │   └── fscc/      # File system control codes
│   │   │   ├── dcerpc/        # DCE/RPC implementation
│   │   │   ├── netbios/       # NetBIOS name service
│   │   │   ├── ntlmssp/       # NTLM authentication
│   │   │   ├── pac/           # Kerberos PAC structures
│   │   │   ├── spnego/        # SPNEGO authentication
│   │   │   ├── http/          # HTTP integration
│   │   │   └── util/          # Utility classes
│   │   └── smb1/              # Legacy SMB1 implementation (deprecated)
│   └── test/java/             # Test sources (mirrors main structure)
├── docs/                      # Design documentation
│   └── smb3-features/         # SMB3 feature design docs
└── .github/workflows/         # CI configuration
```

## Key Packages and Classes

### Public API (`org.codelibs.jcifs.smb`)

| Class/Interface | Purpose |
|-----------------|---------|
| `CIFSContext` | Main entry point - encapsulates config, credentials, and services |
| `SmbResource` | Interface for SMB files and directories |
| `Configuration` | Configuration interface for all settings |
| `Credentials` | Authentication credentials interface |
| `SmbConstants` | Protocol constants and flags |
| `DialectVersion` | SMB dialect versions (SMB1, SMB202, SMB210, SMB300, SMB302, SMB311) |

### Context Layer (`org.codelibs.jcifs.smb.context`)

| Class | Purpose |
|-------|---------|
| `BaseContext` | Primary context implementation |
| `SingletonContext` | Global shared context (for simple use cases) |
| `CIFSContextWrapper` | Base for context decorators |
| `CIFSContextCredentialWrapper` | Adds credentials to a context |

### Configuration (`org.codelibs.jcifs.smb.config`)

| Class | Purpose |
|-------|---------|
| `PropertyConfiguration` | Configuration from Java Properties |
| `BaseConfiguration` | Base implementation with all defaults |
| `DelegatingConfiguration` | Decorator for configuration overrides |

### Implementation (`org.codelibs.jcifs.smb.impl`)

| Class | Purpose |
|-------|---------|
| `SmbFile` | Main file/directory implementation (~87KB, central class) |
| `SmbTransportImpl` | Network transport layer (~70KB) |
| `SmbSessionImpl` | SMB session management (~51KB) |
| `SmbTreeImpl` | SMB tree connection (~31KB) |
| `NtlmPasswordAuthenticator` | NTLM credential management |
| `Kerb5Authenticator` | Kerberos authentication |
| `DfsImpl` | DFS path resolution |

### Internal Protocol (`org.codelibs.jcifs.smb.internal`)

**DO NOT USE DIRECTLY** - These are internal implementation details.

- `smb1/` - SMB1/CIFS protocol messages
- `smb2/` - SMB2/3 protocol messages
  - `nego/` - Protocol negotiation
  - `session/` - Session setup
  - `tree/` - Tree connect
  - `create/` - File create/open
  - `io/` - Read/write operations
  - `info/` - File information queries
  - `ioctl/` - I/O control operations
  - `lock/` - File locking
  - `notify/` - Change notifications

## Configuration Properties

Key configuration properties (prefix: `jcifs.smb.client.`):

| Property | Default | Description |
|----------|---------|-------------|
| `minVersion` | SMB1 | Minimum SMB protocol version |
| `maxVersion` | SMB311 | Maximum SMB protocol version |
| `soTimeout` | 35000 | Socket timeout (ms) |
| `connTimeout` | 35000 | Connection timeout (ms) |
| `responseTimeout` | 30000 | Response timeout (ms) |
| `signingPreferred` | false | Prefer SMB signing |
| `ipcSigningEnforced` | true | Enforce IPC$ signing |
| `dfs.disabled` | false | Disable DFS resolution |
| `preserveShareCase` | false | Preserve share name case |

## Code Conventions

### Style Guidelines

1. **Formatting**: Use `mvn formatter:format` before committing - this uses the CodeLibs Eclipse formatter
2. **License Headers**: All source files require LGPL headers (checked by apache-rat plugin)
3. **Logging**: Use SLF4J (`org.slf4j.Logger`)
4. **Resources**: Always use try-with-resources for `SmbFile`, streams, and handles

### Naming Conventions

- Interfaces: No prefix (e.g., `CIFSContext`, `SmbResource`)
- Implementations: Often suffixed with `Impl` (e.g., `SmbFileHandleImpl`)
- Internal classes: Placed in `internal` package, not for public use
- Protocol messages: Prefixed with protocol version (`Smb2CreateRequest`, `SmbComOpen`)

### Package Visibility

- `org.codelibs.jcifs.smb` - Public API, stable interfaces
- `org.codelibs.jcifs.smb.impl` - Implementations (use interfaces from parent)
- `org.codelibs.jcifs.smb.internal` - **Private** protocol details, may change without notice
- `org.codelibs.jcifs.smb1` - Legacy SMB1 code (deprecated, maintained for compatibility)

## Testing

### Test Framework

- **JUnit 5** (Jupiter) for unit tests
- **Mockito** for mocking
- **Testcontainers** for integration tests
- **Hamcrest** for assertions

### Test Patterns

```java
// Extend BaseTest for common utilities
@ExtendWith(MockitoExtension.class)
public class MyTest extends BaseTest {

    @Test
    void testSomething() {
        // Test implementation
    }
}
```

### Running Tests

```bash
# All tests
mvn test

# Specific test class
mvn test -Dtest=SmbFileTest

# Tests matching pattern
mvn test -Dtest="*Integration*"

# With coverage
mvn test jacoco:report
# Report at: target/site/jacoco/index.html
```

## Important Design Patterns

### Context-Based Architecture

JCIFS uses a context-based design with no global state:

```java
// Create base context with configuration
Properties props = new Properties();
props.setProperty("jcifs.smb.client.minVersion", "SMB300");
CIFSContext baseContext = new BaseContext(new PropertyConfiguration(props));

// Create authenticated context
NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "user", "pass");
CIFSContext authContext = baseContext.withCredentials(auth);

// Use context for file operations
try (SmbResource file = authContext.get("smb://server/share/file.txt")) {
    // Operations...
}
```

### Resource Management

Always use try-with-resources:

```java
try (SmbResource dir = context.get("smb://server/share/");
     CloseableIterator<SmbResource> iter = dir.children()) {
    while (iter.hasNext()) {
        try (SmbResource child = iter.next()) {
            // Process child
        }
    }
}
```

### Protocol Layering

```
CIFSContext (entry point)
    └── SmbTransportPool (connection management)
        └── SmbTransport (network layer)
            └── SmbSession (authentication)
                └── SmbTree (share connection)
                    └── SmbFile (file operations)
```

## Common Development Tasks

### Adding a New Configuration Property

1. Add method to `Configuration` interface
2. Implement in `BaseConfiguration` with default value
3. Add delegation in `DelegatingConfiguration`
4. Add property parsing in `PropertyConfiguration`
5. Update documentation

### Adding a New SMB2 Command

1. Create request class in `internal/smb2/` (extend `ServerMessageBlock2Request`)
2. Create response class (extend `ServerMessageBlock2Response`)
3. Add command constant to `Smb2Constants`
4. Implement encoding/decoding in request/response classes
5. Add tests for serialization

### Implementing a New Feature

1. Check `docs/smb3-features/` for design documents
2. Start with internal protocol classes
3. Expose through `SmbResource` or `SmbFile` interface
4. Add configuration options if needed
5. Write unit and integration tests

## CI/CD

GitHub Actions workflow (`.github/workflows/maven.yml`):
- Triggers on push/PR to main branch
- Uses JDK 17 (Temurin)
- Runs `mvn -B package`

## Dependencies

### Runtime

- `slf4j-api` - Logging facade
- `bcprov-jdk18on` - Bouncy Castle cryptography (AES-GCM, AES-CCM)
- `jakarta.servlet-api` (optional) - Servlet support

### Test

- `junit-jupiter` - JUnit 5
- `mockito-core` - Mocking
- `testcontainers` - Container-based integration tests
- `hamcrest` - Assertion library

## Known Caveats

1. **SMB1 Code**: The `smb1` package contains legacy code - avoid modifying unless necessary
2. **Internal Package**: Never depend on `internal` package from external code
3. **Thread Safety**: `CIFSContext` and `SmbTransportPool` are thread-safe; `SmbFile` operations are not
4. **DFS Resolution**: DFS paths are automatically resolved; disable with `jcifs.smb.client.dfs.disabled=true`
5. **Large Files**: Use appropriate buffer sizes (64KB-1MB) for large file operations

## Future Development

See `docs/SMB3_IMPLEMENTATION_PLAN.md` for planned features:
- SMB3 Leases (replacing oplocks)
- Persistent/Durable Handles
- Multi-Channel support
- Directory Leasing
- RDMA/SMB Direct
- Witness Protocol

## Useful Resources

- [MS-SMB2 Specification](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- [MS-DTYP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/) - Windows Data Types
- [GitHub Repository](https://github.com/codelibs/jcifs)
