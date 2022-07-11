JCIFS
[![Java CI with Maven](https://github.com/codelibs/jcifs/actions/workflows/maven.yml/badge.svg)](https://github.com/codelibs/jcifs/actions/workflows/maven.yml)
=====

JCIFS is an Open Source client library that implements the CIFS/SMB networking protocol in 100% Java.
From version 2.x, this project is forked from [jcifs-ng](https://github.com/AgNO3/jcifs-ng) and existing jcifs code is merged as `smb1`.

## Version

[Versions in Maven Repository](https://repo1.maven.org/maven2/org/codelibs/jcifs/)

## Using Maven

```
<dependency>
    <groupId>org.codelibs</groupId>
    <artifactId>jcifs</artifactId>
    <version>2.1.31</version>
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

## Others

### This jcifs or jcifs-ng

jcifs-ng will be a proper choice for many users. 
There are a lot of SMB devices in the world.
Some of them only work with the old jcifs library.
If you want to support many SMB devices, CodeLibs jcifs library will be helpful.
For example, since [Fess](https://github.com/codelibs/fess) needs to support many SMB devices, it uses this library.
However, if you have only a specific SMB device, you should use jcifs-ng library.
