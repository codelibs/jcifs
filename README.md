# JCIFS - Java CIFS/SMB Client Library

[![Java CI with Maven](https://github.com/codelibs/jcifs/actions/workflows/maven.yml/badge.svg)](https://github.com/codelibs/jcifs/actions/workflows/maven.yml)
[![Maven Central](https://img.shields.io/maven-central/v/org.codelibs/jcifs.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/org.codelibs/jcifs)
[![License: LGPL v2.1](https://img.shields.io/badge/License-LGPL%20v2.1-blue.svg)](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)
[![Java Version](https://img.shields.io/badge/Java-17%2B-green.svg)](https://openjdk.org/)

JCIFS is a pure Java implementation of the CIFS/SMB client protocol suite. It lets
Java applications access files and directories on Windows file shares, Samba and
other SMB servers, over SMB1 as well as SMB2 and SMB3.

This project continues [jcifs-ng](https://github.com/AgNO3/jcifs-ng), which in turn
is based on the original [jCIFS](https://www.jcifs.org/) library. It is maintained by
[CodeLibs](https://www.codelibs.org/) and used by the
[Fess](https://github.com/codelibs/fess) search server to crawl file shares.

## Features

### Protocol support

- **SMB1/CIFS** for older devices and servers
- **SMB2**: SMB 2.0.2 and 2.1
- **SMB3**: SMB 3.0, 3.0.2 and 3.1.1, including:
  - AES-128-CCM encryption (SMB 3.0/3.0.2)
  - AES-128-GCM, AES-128-CCM, AES-256-GCM and AES-256-CCM encryption (SMB 3.1.1),
    selectable with `jcifs.client.encryptionCiphers`
  - Pre-authentication integrity (SMB 3.1.1)
  - AES-CMAC signing, with AES-GMAC negotiable on SMB 3.1.1 via
    `jcifs.client.signingAlgorithms`
  - Encryption per session or per share when the server requires it (opt-in, see
    [Security](#security))
- Automatic dialect negotiation within a configurable range

See [SMB2/SMB3 support status](docs/SMB3_SUPPORT.md) for what is and is not
implemented, feature by feature. Leases, oplocks, durable handles, multi-channel,
directory leasing, compression, RDMA and the witness protocol are not implemented.

### Authentication

- NTLMSSP, Kerberos and SPNEGO
- Domain, guest and anonymous credentials
- Credential renewal for long-running sessions (`SmbRenewableCredentials`)

### Other

- Configuration and credentials held per context (`CIFSContext`) rather than in
  global state
- Connection pooling and reuse
- DFS referral resolution
- Directory change notification (see [File monitoring](#file-monitoring))
- Logging through SLF4J
- Optional NTLM HTTP authentication filter for Jakarta Servlet containers
  (`org.codelibs.jcifs.smb.http`)

## Requirements

- Java 17 or later
- Runtime dependencies: SLF4J API and Bouncy Castle (`bcprov-jdk18on`)
- Network access to the SMB server (TCP 445, or 139 for NetBIOS)

## Installation

### Maven

```xml
<dependency>
    <groupId>org.codelibs</groupId>
    <artifactId>jcifs</artifactId>
    <version>3.0.4</version>
</dependency>
```

### Gradle

```groovy
implementation 'org.codelibs:jcifs:3.0.4'
```

Released versions are listed on
[Maven Central](https://repo1.maven.org/maven2/org/codelibs/jcifs/).

## Quick Start

### Basic file access

```java
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.context.SingletonContext;
import org.codelibs.jcifs.smb.impl.SmbFile;

// Default context, configured from system properties
CIFSContext context = SingletonContext.getInstance();

try (SmbFile file = new SmbFile("smb://server/share/file.txt", context)) {
    if (file.exists()) {
        System.out.println("File size: " + file.length());
        System.out.println("Last modified: " + new Date(file.lastModified()));
    }
}
```

### Reading file content

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

### Listing a directory

Directory URLs must end with `/`.

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

## Authentication

### Domain (NTLM) authentication

```java
import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.context.BaseContext;
import org.codelibs.jcifs.smb.impl.NtlmPasswordAuthenticator;
import org.codelibs.jcifs.smb.impl.SmbFile;

Properties props = new Properties();
// Optional: restrict the negotiated dialect range
props.setProperty("jcifs.client.minVersion", "SMB202");
props.setProperty("jcifs.client.maxVersion", "SMB311");

CIFSContext baseContext = new BaseContext(new PropertyConfiguration(props));
NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("DOMAIN", "username", "password");
CIFSContext authContext = baseContext.withCredentials(auth);

try (SmbFile file = new SmbFile("smb://server/share/", authContext)) {
    // Authenticated operations
}
```

### Kerberos authentication

```java
import org.codelibs.jcifs.smb.impl.JAASAuthenticator;

// Uses the JAAS login configuration entry named "jCIFS"; requires a working
// Kerberos and JAAS setup (krb5.conf, keytab or ticket cache)
JAASAuthenticator kerberosAuth = new JAASAuthenticator("jCIFS");
CIFSContext kerberosContext = baseContext.withCredentials(kerberosAuth);
```

### Guest and anonymous access

```java
CIFSContext guestContext = baseContext.withGuestCredentials();
CIFSContext anonymousContext = baseContext.withAnonymousCredentials();
```

## Advanced Usage

### Copying files

`SmbFile.copyTo` copies a file or a directory tree between two locations on SMB
servers:

```java
try (SmbFile source = new SmbFile("smb://server/share/largefile.zip", context);
     SmbFile dest = new SmbFile("smb://server/backup/largefile.zip", context)) {
    source.copyTo(dest);
}
```

To copy between SMB and a local file system, use the streams:

```java
try (SmbFile source = new SmbFile("smb://server/share/largefile.zip", context);
     InputStream is = source.getInputStream();
     OutputStream os = Files.newOutputStream(Path.of("largefile.zip"))) {
    is.transferTo(os);
}
```

### File monitoring

`SmbFile.watch(int filter, boolean recursive)` opens a change notification handle
on a directory. The filter is a combination of the `FILE_NOTIFY_CHANGE_*`
constants in `FileNotifyInformation`, and each call to `SmbWatchHandle.watch()`
blocks until the server reports changes:

```java
import java.util.List;

import org.codelibs.jcifs.smb.FileNotifyInformation;
import org.codelibs.jcifs.smb.SmbWatchHandle;
import org.codelibs.jcifs.smb.impl.SmbFile;

try (SmbFile dir = new SmbFile("smb://server/share/monitored/", context);
     SmbWatchHandle handle = dir.watch(
         FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME
             | FileNotifyInformation.FILE_NOTIFY_CHANGE_SIZE, true)) {

    while (true) {
        List<FileNotifyInformation> changes = handle.watch();
        if (changes == null) {
            break; // cancelled with handle.cancel()
        }
        for (FileNotifyInformation info : changes) {
            System.out.println("Changed: " + info.getFileName() + " (action " + info.getAction() + ")");
        }
    }
}
```

Notes:

- `watch()` returns `null` when another thread calls `cancel()` on the handle. The
  handle stays open, and calling `watch()` again resumes monitoring.
- Changes that occur between calls are buffered by the server while the handle is
  open. If they do not fit in the buffer, `watch()` returns an empty list; the
  buffer size is set with `jcifs.client.notify_buf_size`.
- `SmbWatchHandle` implements `Callable<List<FileNotifyInformation>>`, so it can be
  submitted to an `ExecutorService`.

### Custom configuration

```java
Properties config = new Properties();
config.setProperty("jcifs.client.minVersion", "SMB300");     // require SMB 3.0 or later
config.setProperty("jcifs.client.maxVersion", "SMB311");
config.setProperty("jcifs.client.signingEnforced", "true");  // require signing
config.setProperty("jcifs.resolveOrder", "LMHOSTS,DNS,BCAST");

CIFSContext customContext = new BaseContext(new PropertyConfiguration(config));
```

Configuration keys use the `jcifs.client.` prefix, plus `jcifs.netbios.`,
`jcifs.http.` and a few bare `jcifs.` keys. The `Configuration` interface javadoc
lists every setting and its default.

Accepted values for `jcifs.client.minVersion` and `jcifs.client.maxVersion` are
`SMB1`, `SMB202`, `SMB210`, `SMB300`, `SMB302` and `SMB311`. When neither is set,
the range is `SMB1` to `SMB311`.

## Architecture Overview

The layers from context to file are:

```
CIFSContext -> SmbTransportPool -> SmbTransport -> SmbSession -> SmbTree -> SmbFile
```

| Package | Contents |
| --- | --- |
| `org.codelibs.jcifs.smb` | Public API: `CIFSContext`, `SmbResource`, `Configuration`, `SmbWatchHandle`, ... |
| `org.codelibs.jcifs.smb.context` | `BaseContext`, `SingletonContext` and context wrappers |
| `org.codelibs.jcifs.smb.config` | `PropertyConfiguration` and other `Configuration` implementations |
| `org.codelibs.jcifs.smb.impl` | `SmbFile`, streams, authenticators |
| `org.codelibs.jcifs.smb.ntlmssp`, `.spnego`, `.pac` | Authentication mechanisms |
| `org.codelibs.jcifs.smb.dcerpc`, `.netbios` | DCE/RPC and NetBIOS name service |
| `org.codelibs.jcifs.smb.internal` | Protocol implementation (`smb1`, `smb2`, DFS, ...). Not public API and may change without notice |
| `org.codelibs.jcifs.smb1` | Legacy SMB1 stack, deprecated |

## Security

- **Signing.** Set `jcifs.client.signingEnforced=true` to require message signing.
  `jcifs.client.signingPreferred` does not enable signing on SMB2/SMB3; see
  [the support status](docs/SMB3_SUPPORT.md#jcifsclientsigningpreferred-does-not-enable-smb2-signing).
  Signing on IPC connections is enforced by default (`jcifs.client.ipcSigningEnforced`).
- **Encryption.** Set `jcifs.client.encryptionEnabled=true` (default `false`). Once
  enabled, encryption is applied to any session or share the server marks as
  requiring it. Encryption requires SMB 3.0 or later, so combine it with
  `jcifs.client.minVersion=SMB300` if unencrypted fallback is not acceptable.
- **Dialects.** SMB1 is allowed by default. Raise `jcifs.client.minVersion` to
  `SMB202` or higher if your servers do not need it.

```java
Properties secureConfig = new Properties();
secureConfig.setProperty("jcifs.client.minVersion", "SMB300");
secureConfig.setProperty("jcifs.client.signingEnforced", "true");
secureConfig.setProperty("jcifs.client.encryptionEnabled", "true");
```

## Performance

- Create one context per configuration and reuse it; connections are pooled per
  context.
- Close `SmbFile`, streams and handles with try-with-resources so connections and
  file handles are released.

## Troubleshooting

### Timeouts

```java
props.setProperty("jcifs.client.connTimeout", "35000");      // connect, default 35 s
props.setProperty("jcifs.client.soTimeout", "35000");        // idle socket, default 35 s
props.setProperty("jcifs.client.responseTimeout", "30000");  // per request, default 30 s
```

### Authentication failures

- Check the domain name, user name and password.
- Check that the account has permission on the share.
- Check that the server accepts the authentication method in use.
- For Kerberos, check DNS resolution of the server name and clock synchronization.

### Dialect negotiation

To narrow down a negotiation problem, pin a single dialect and enable debug logging
for the SMB2 layer:

```java
props.setProperty("jcifs.client.minVersion", "SMB202");
props.setProperty("jcifs.client.maxVersion", "SMB202");
```

### Logging

JCIFS logs through SLF4J; configure the backend of your choice. For example, with
Logback:

```xml
<configuration>
    <logger name="org.codelibs.jcifs.smb" level="INFO"/>
    <logger name="org.codelibs.jcifs.smb.internal" level="WARN"/>
    <!-- For troubleshooting -->
    <logger name="org.codelibs.jcifs.smb.internal.smb2" level="DEBUG"/>
</configuration>
```

## Migrating from 2.x

- **Java 17 or later** is required.
- **Package names changed.** The root package `jcifs` became
  `org.codelibs.jcifs.smb`, and the implementation classes that were in
  `jcifs.smb` (`SmbFile`, `NtlmPasswordAuthenticator`, ...) are now in
  `org.codelibs.jcifs.smb.impl`. For example, `jcifs.CIFSContext` is now
  `org.codelibs.jcifs.smb.CIFSContext`, and `jcifs.smb.SmbFile` is now
  `org.codelibs.jcifs.smb.impl.SmbFile`.
- **Configuration keys changed.** The `.smb` segment was dropped from every key
  (see below). Old keys are ignored, so settings silently fall back to their
  defaults until they are renamed.

| 2.x | 3.x |
| --- | --- |
| `jcifs.smb.client.<name>` | `jcifs.client.<name>` |
| `jcifs.smb.<name>` (`lmCompatibility`, `maxBuffers`, `allowNTLMFallback`, `useRawNTLM`) | `jcifs.<name>` |
| `jcifs.smb1.smb.client.<name>` (legacy SMB1 stack) | `jcifs.client.<name>` |
| `jcifs.netbios.<name>`, `jcifs.http.<name>`, `jcifs.resolveOrder`, `jcifs.encoding` | unchanged |

`PropertyConfiguration` logs a warning for every property it receives under one of
the old prefixes, naming the key to use instead.

## Building from Source

Building requires JDK 17 or later and Maven 3.6 or later.

```bash
git clone https://github.com/codelibs/jcifs.git
cd jcifs

mvn clean package          # compile, run unit tests and build the JAR
mvn install                # install into the local Maven repository
mvn test -Dtest=SmbFileTest
```

Other useful goals:

```bash
mvn formatter:format       # format sources (required before committing)
mvn apache-rat:check       # check license headers
mvn jacoco:report          # coverage report in target/site/jacoco/index.html
mvn clirr:check            # API compatibility check
```

### Integration tests against a real SMB server

`mvn verify` also runs the `*IT` tests in `src/test/java/org/codelibs/jcifs/smb/it`,
which talk to an actual SMB server. Two backends are supported and the same tests
run against both.

**Samba (default, no setup needed).** With Docker available, the harness builds
and starts the container defined in `build_helpers/samba/` and points the tests at
it:

```bash
mvn verify
```

That publishes Samba on a mapped port. A DFS referral names a host but no port,
so the DFS tests skip unless the server answers on 445. The harness tries 445
first and falls back, so on a machine already using that port Testcontainers logs
one failed container start before the run continues normally. To run the DFS tests
anyway - on a machine whose own 445 is taken, for instance - put the server and the
test JVM on the same Docker network:

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
| `JCIFS_IT_SHARE`, `JCIFS_IT_SHARE_ENCRYPTED`, `JCIFS_IT_DFS_ROOT`, `JCIFS_IT_SHARE_SYMLINKS` | share names |
| `JCIFS_IT_REQUIRED` | `true` makes a missing environment a failure instead of a skip |
| `JCIFS_IT_DIALECT` | pins the whole suite to one SMB2/SMB3 dialect, e.g. `SMB300` |

Before any test runs, a preflight check confirms the server is configured the way
the tests assume - in particular that the encrypted share really does reject a
client that cannot encrypt, and that a pinned dialect is actually honoured.

Some tests skip by design: DFS tests only run when the server answers on 445, and
tests marked `@RequiresBackend` run on one backend only.

#### Choosing a dialect

Left alone, the client and the server negotiate the highest dialect they both
support, which for either backend means SMB 3.1.1. `JCIFS_IT_DIALECT` pins both
ends of the negotiation range and runs the same tests on one dialect:

```bash
JCIFS_IT_DIALECT=SMB300 mvn verify
```

CI does this as a matrix: SMB 3.0 on every pull request and the full range
nightly against Windows, and SMB 2.0.2 through 3.1.1 against Samba. A test of a
feature the pinned dialect cannot reach - encryption below SMB 3.0, say - carries
`@RequiresDialect` and skips rather than failing; the skips are listed in the job
summary.

Individual tests can sweep dialects on their own with `@DialectMatrix` (SMB 2.0.2
through 3.1.1) or `@Smb3Matrix` (SMB 3.0, 3.0.2 and 3.1.1), taking the dialect as
a parameter and building their context with `contextFor(dialect)`.

SMB1 is out of scope for the integration suite, which negotiates SMB2 and above;
SMB1 is covered by the unit tests.

## Contributing

Bug reports and pull requests are welcome on
[GitHub](https://github.com/codelibs/jcifs).

1. Fork the repository and create a topic branch.
2. Make your change with tests.
3. Run `mvn formatter:format` and make sure `mvn clean test` passes.
4. Update this README or the javadoc if behaviour changes.
5. Open a pull request describing the change.

New source files need the LGPL license header, and public APIs should have
javadoc.

## License

JCIFS is licensed under the
[GNU Lesser General Public License, version 2.1](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html).
