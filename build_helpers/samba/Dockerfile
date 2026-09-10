# Samba backend for the jcifs SMB integration tests.
#
# Pinned to an Alpine release rather than a floating tag so the Samba version
# only moves when this file moves. Multi-arch, so the same image builds on the
# amd64 CI runners and on arm64 development machines.
FROM alpine:3.22

RUN apk add --no-cache samba-server samba-client samba-common-tools

COPY smb.conf /etc/samba/smb.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 445

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
