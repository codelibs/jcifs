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
│   │   ├── smb2/          # SMB2/SMB3 protocol
│   │   ├── dfs/           # DFS referral internals
│   │   ├── dtyp/          # Windows data types
│   │   ├── fscc/          # File system control codes
│   │   └── util/          # Internal utilities
│   ├── dcerpc/            # DCE/RPC implementation
│   ├── http/              # NTLM HTTP authentication (filter, servlet, URL handler)
│   ├── https/             # HTTPS URL handler
│   ├── netbios/           # NetBIOS name service
│   ├── ntlmssp/           # NTLM authentication
│   ├── pac/               # Kerberos PAC structures
│   └── spnego/            # SPNEGO authentication
└── smb1/                  # Legacy SMB1 (deprecated)
```

## Key Classes

- Entry point: `CIFSContext` (interface) / `BaseContext` (impl) - config, credentials, services
- Files: `SmbResource` (interface) / `SmbFile` (impl)
- Auth: `NtlmPasswordAuthenticator`, `Kerb5Authenticator`
- Config: `Configuration` interface - see `BaseConfiguration` for defaults

## Configuration

Prefix: `jcifs.smb.client.` - see `Configuration` interface for all properties and defaults

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

## Known Caveats

1. **SMB1 Code**: Legacy code in `smb1` package - avoid modifying
2. **Internal Package**: Never depend on `internal` from external code
3. **Thread Safety**: `CIFSContext` is thread-safe; `SmbFile` operations are not
4. **DFS**: Paths auto-resolved; disable with `jcifs.smb.client.dfs.disabled=true`
