#!/bin/sh
#
# Creates the fixture layout that the jcifs integration tests expect and then
# runs smbd in the foreground. The layout mirrors build_helpers/win-setup.ps1 so
# that the same tests can run against either backend.
set -eu

PASSWORD="${SMB_TEST_PASSWORD:-Public-Fixture-Not-A-Secret-1!}"
DFS_TARGET_HOST="${SMB_DFS_TARGET_HOST:-localhost}"

for share in share share-encrypted dfs public users testuser1private testuser2private; do
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

# DFS links. "link" and "link-extra" share a prefix on purpose: unbounded
# prefix matching has been a recurring defect class in the DFS referral code.
ln -sfn "msdfs:${DFS_TARGET_HOST}\\share"                              /srv/dfs/link
ln -sfn "msdfs:${DFS_TARGET_HOST}\\users"                              /srv/dfs/link-extra
ln -sfn "msdfs:${DFS_TARGET_HOST}\\missing,${DFS_TARGET_HOST}\\share"  /srv/dfs/multi
ln -sfn "msdfs:${DFS_TARGET_HOST}\\missing"                            /srv/dfs/broken

testparm --suppress-prompt >/dev/null

exec smbd --foreground --no-process-group --debug-stdout
