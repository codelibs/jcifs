#!/bin/sh
#
# Creates the fixture layout that the jcifs integration tests expect and then
# runs smbd in the foreground. The layout mirrors build_helpers/win-setup.ps1 so
# that the same tests can run against either backend.
set -eu

PASSWORD="${SMB_TEST_PASSWORD:-Public-Fixture-Not-A-Secret-1!}"
DFS_TARGET_HOST="${SMB_DFS_TARGET_HOST:-localhost}"

for share in share share-encrypted dfs public users testuser1private testuser2private symlinks; do
    mkdir -p "/srv/${share}"
    chmod 0777 "/srv/${share}"
done

# Deliberately outside every share, so a symlink pointing here crosses the
# share boundary.
mkdir -p /srv/outside
chmod 0777 /srv/outside

mkdir -p /var/log/samba /var/lib/samba/private

for user in testuser1 testuser2; do
    adduser -D -H -s /sbin/nologin "${user}"
    printf '%s\n%s\n' "${PASSWORD}" "${PASSWORD}" | smbpasswd -a -s "${user}"
    smbpasswd -e "${user}"
done

# ---------------------------------------------------------------- fixtures --
printf 'target file contents\n' > /srv/share/target.txt
mkdir -p /srv/share/subdir
printf 'inside subdir\n' > /srv/share/subdir/inside.txt
printf 'outside the share\n' > /srv/outside/outside.txt
chmod -R 0777 /srv/share /srv/outside

# Symlinks: inside the share, to a directory, broken, outside the share, relative.
ln -sfn target.txt                /srv/share/link-to-file
ln -sfn subdir                    /srv/share/link-to-dir
ln -sfn missing.txt               /srv/share/link-broken
ln -sfn /srv/outside/outside.txt  /srv/share/link-outside
ln -sfn ./target.txt              /srv/share/link-relative

# Files the connecting account is granted less than the share is. The share
# itself is writable by both accounts, so anything that reports access from the
# share alone reports the same answer for all three of these - only the access
# the server computes for the file itself tells them apart. Created after the
# blanket chmod above so it does not undo them, and owned by root, which is the
# account none of the tests authenticate as.
mkdir -p /srv/share/access
printf 'readable contents\n'  > /srv/share/access/readable.txt
printf 'read-only contents\n' > /srv/share/access/readonly.txt
printf 'secret contents\n'    > /srv/share/access/noaccess.txt
chmod 0777 /srv/share/access
chmod 0666 /srv/share/access/readable.txt
# Readable by everyone, writable only by root.
chmod 0444 /srv/share/access/readonly.txt
# Unreadable by anyone but root. The directory stays searchable, so the account
# can still stat the file: that is what keeps it reporting that it exists while
# its contents stay unreachable.
chmod 0600 /srv/share/access/noaccess.txt

# The same shapes again in the share that reports links rather than resolving
# them. Every in-share target is relative, which is the only form a client can
# resolve: an absolute target names a path in the server's own namespace.
# link-outside keeps an absolute one on purpose - that is the case a resolver
# has to refuse rather than follow.
printf 'target file contents\n' > /srv/symlinks/target.txt
mkdir -p /srv/symlinks/subdir
printf 'inside subdir\n' > /srv/symlinks/subdir/inside.txt
chmod -R 0777 /srv/symlinks

ln -sfn target.txt                /srv/symlinks/link-to-file
ln -sfn subdir                    /srv/symlinks/link-to-dir
ln -sfn missing.txt               /srv/symlinks/link-broken
ln -sfn /srv/outside/outside.txt  /srv/symlinks/link-outside

# DFS links. "link" and "link-extra" share a prefix on purpose: unbounded
# prefix matching has been a recurring defect class in the DFS referral code.
ln -sfn "msdfs:${DFS_TARGET_HOST}\\share"                              /srv/dfs/link
ln -sfn "msdfs:${DFS_TARGET_HOST}\\users"                              /srv/dfs/link-extra
ln -sfn "msdfs:${DFS_TARGET_HOST}\\missing,${DFS_TARGET_HOST}\\share"  /srv/dfs/multi
ln -sfn "msdfs:${DFS_TARGET_HOST}\\missing"                            /srv/dfs/broken

testparm --suppress-prompt >/dev/null

exec smbd --foreground --no-process-group --debug-stdout
