# CLAUDE.md - AI Assistant Guide for JCIFS

## Project Overview

JCIFS is a pure Java implementation of the CIFS/SMB networking protocol suite, providing access to Windows file shares and SMB servers (SMB1/2/3).

- **Language**: Java 17+
- **Build System**: Maven
- **License**: LGPL v2.1
- **Package**: `org.codelibs.jcifs`

## Quick Commands

```bash
mvn clean compile          # Build
mvn test                   # Run tests
mvn test -Dtest=SmbFileTest # Run specific test
mvn package                # Package JAR
mvn formatter:format       # Format code (required before commits)
mvn apache-rat:check       # Check license headers
mvn jacoco:report          # Generate coverage report
```

## Directory Structure

```
src/main/java/org/codelibs/jcifs/
├── smb/                   # Main SMB package (public API)
│   ├── config/            # Configuration implementations
│   ├── context/           # CIFSContext implementations
│   ├── impl/              # Core implementations (SmbFile, authenticators)
│   ├── internal/          # Protocol internals (NOT public API)
│   │   ├── smb1/          # SMB1/CIFS protocol
│   │   └── smb2/          # SMB2/SMB3 protocol
│   ├── dcerpc/            # DCE/RPC implementation
│   ├── netbios/           # NetBIOS name service
│   ├── ntlmssp/           # NTLM authentication
│   ├── pac/               # Kerberos PAC structures
│   └── spnego/            # SPNEGO authentication
└── smb1/                  # Legacy SMB1 (deprecated)
```

## Key Classes

### Public API (`org.codelibs.jcifs.smb`)

| Class/Interface | Purpose |
|-----------------|---------|
| `CIFSContext` | Main entry point - config, credentials, services |
| `SmbResource` | Interface for SMB files and directories |
| `Configuration` | Configuration interface |
| `Credentials` | Authentication credentials interface |

### Implementation (`org.codelibs.jcifs.smb.impl`)

| Class | Purpose |
|-------|---------|
| `SmbFile` | Main file/directory implementation |
| `SmbTransportImpl` | Network transport layer |
| `SmbSessionImpl` | SMB session management |
| `NtlmPasswordAuthenticator` | NTLM credentials |
| `Kerb5Authenticator` | Kerberos authentication |

## Configuration Properties

Prefix: `jcifs.smb.client.`

| Property | Default | Description |
|----------|---------|-------------|
| `minVersion` | SMB1 | Minimum SMB protocol version |
| `maxVersion` | SMB311 | Maximum SMB protocol version |
| `soTimeout` | 35000 | Socket timeout (ms) |
| `connTimeout` | 35000 | Connection timeout (ms) |
| `responseTimeout` | 30000 | Response timeout (ms) |
| `signingPreferred` | false | Prefer SMB signing |
| `dfs.disabled` | false | Disable DFS resolution |

## Code Conventions

1. **Formatting**: Run `mvn formatter:format` before committing
2. **License Headers**: All source files require LGPL headers
3. **Logging**: Use SLF4J (`org.slf4j.Logger`)
4. **Resources**: Always use try-with-resources for `SmbFile`, streams, handles

### Naming Conventions

- Interfaces: No prefix (`CIFSContext`, `SmbResource`)
- Implementations: Suffix with `Impl` (`SmbFileHandleImpl`)
- Protocol messages: Prefix with version (`Smb2CreateRequest`)

### Package Visibility

- `org.codelibs.jcifs.smb` - Public API, stable
- `org.codelibs.jcifs.smb.impl` - Implementations
- `org.codelibs.jcifs.smb.internal` - **Private**, may change without notice
- `org.codelibs.jcifs.smb1` - Legacy, deprecated

## Testing

- **JUnit 5** for unit tests
- **Mockito** for mocking
- **Testcontainers** for integration tests
- Extend `BaseTest` for common utilities

## Design Patterns

### Protocol Layering

```
CIFSContext → SmbTransportPool → SmbTransport → SmbSession → SmbTree → SmbFile
```

### Context-Based Architecture

- No global state
- Create `BaseContext` with `PropertyConfiguration`
- Use `withCredentials()` for authenticated contexts

## Common Development Tasks

### Adding a New Configuration Property

1. Add method to `Configuration` interface
2. Implement in `BaseConfiguration` with default
3. Add delegation in `DelegatingConfiguration`
4. Add parsing in `PropertyConfiguration`

### Adding a New SMB2 Command

1. Create request class in `internal/smb2/` (extend `ServerMessageBlock2Request`)
2. Create response class (extend `ServerMessageBlock2Response`)
3. Add command constant to `Smb2Constants`
4. Implement encoding/decoding
5. Add tests

## Known Caveats

1. **SMB1 Code**: Legacy code in `smb1` package - avoid modifying
2. **Internal Package**: Never depend on `internal` from external code
3. **Thread Safety**: `CIFSContext` is thread-safe; `SmbFile` operations are not
4. **DFS**: Paths auto-resolved; disable with `jcifs.smb.client.dfs.disabled=true`
