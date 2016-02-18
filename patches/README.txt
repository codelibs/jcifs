These patches are not supported. They are provided here only for your
conveinience. If you port a patch to a newer version of jCIFS please
resubmit it to the mailing list.

GetOwnerSid.patch

This patch adds methods to SmbFile to retrieve the owner SID of the file.

backup-domain-controllers-1.2.13.patch

This patch allows multiple comma separated domain controllers to be
specified using the jcifs.http.domainController property. If one is not
'active' another will be tried.

Eventlog.patch

This patch adds the necessary MSRPCs to remotely read an event log.

Print.patch

This minor patch and example program demonstrates how to emit
PostScript rendered from an AWT/Swing Graphics context and send it
directly to a shared printer. Note that currently you also need to set
jcifs.smb.client.useNTSmbs = false (as otherwise the server spits back
an invalid parameter error). If users determine that this feature works
reliably with a wide variety of printers we will incorporate it into
the distribution (and fix the useNTSmbs goof).

DnsSrv.patch

This patch adds JNDI _ldap._tcp.dc._msdcs.<domain> lookups so that the
NtlmHttpFilter can use load balancing without jcifs.netbios.wins.

urlfix.patch

This patch fixes a bug in URL handling that caused the credentials within
URLs to be unescaped twice causing an authentication error.

Specifically if using a URL like smb://user:p%25ss@server/path/to/file
where the password should be 'p%ss' it gets unescaped but child SmbFiles
derived from this URL will unsuccessfully try to unescape p%ss again.

Note: Applications should not use credentials in URLs. Use the
NtlmPasswordAuthentication class instead.

LargeReadWrite.patch:

This patch adds two SMBs that supposedly improves read and write
performance considerably. Unfortunately it's not crystal clear
that all implementation properly support the commands. Note that
in addition to this patch an '& 0xFFFF' needs to be added in
SmbTransport.java:doRecv:~437 to appear as:

  int size = Encdec.dec_uint16be( BUF, 2 ) & 0xFFFF;

although this change has been made in 1.2.7.
