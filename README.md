JCIFS
=====

JCIFS is an Open Source client library that implements the CIFS/SMB networking protocol in 100% Java.
From version 2.x, this project is forked from [jcifs-ng](https://github.com/AgNO3/jcifs-ng).

## Version

[Versions in Maven Repository](http://central.maven.org/maven2/org/codelibs/jcifs/)

## Using Maven

Put the following block into pom.xml if using Maven:

    <dependency>
        <groupId>org.codelibs</groupId>
        <artifactId>jcifs</artifactId>
        <version>2.x.y</version>
    </dependency>

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

### Building from sources

Run the following to install the newest master version into your local `~/.m2/repository`:

```bash
mvn -C clean install -DskipTests -Dmaven.javadoc.skip=true -Dgpg.skip=true
```

