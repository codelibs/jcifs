JCIFS
=====

JCIFS is an Open Source client library that implements the CIFS/SMB networking protocol in 100% Java.
From version 2.x, this project is forked from [jcifs-ng](https://github.com/AgNO3/jcifs-ng) and existing jcifs code is merged as `smb1`.

## Version

[Versions in Maven Repository](https://repo1.maven.org/maven2/org/codelibs/jcifs/)

## Using Maven
=======
Latest stable release:

```
<dependency>
    <groupId>org.codelibs</groupId>
    <artifactId>jcifs</artifactId>
    <version>2.1.19</version>
</dependency>
```

## Changes

 * SMB2 (2.02 protocol level) support, some SMB3 support
 * Remove global state
 * Allow per context configuration
 * Logging through SLF4J
 * Drop pre-java 1.7 support
 * Unify authentication subsystem, NTLMSSP/Kerberos support
 * Large ReadX/WriteX support
 * Streaming list operations
 * NtTransNotifyChange support
 * Google patches: various bugfixes, lastAccess support, retrying requests
 * A proper test suite
 * Various fixes

