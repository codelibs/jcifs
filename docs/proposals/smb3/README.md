# SMB3 Advanced Feature Proposals

Everything in this directory is a **proposal**. None of it is implemented, and
nothing here describes code that exists in the jcifs source tree.

For what jcifs actually supports today, see
[SMB3_SUPPORT.md](../../SMB3_SUPPORT.md). That document is the authoritative
one; this directory is kept for design reference only.

These documents were written before the features were attempted, and they show
package layouts, class listings, and configuration properties as if the code
existed. Each one now carries a status banner recording what — if anything — is
actually present for that feature. In most cases it is a protocol constant that
nothing references.

## Contents

| Document | Feature | Present in the source tree |
| --- | --- | --- |
| [SMB3_IMPLEMENTATION_PLAN.md](SMB3_IMPLEMENTATION_PLAN.md) | Overall phasing for all six | — |
| [01-smb3-lease-design.md](01-smb3-lease-design.md) | SMB3 leases | Unused constants; inert create context framework |
| [02-persistent-handles-design.md](02-persistent-handles-design.md) | Durable / persistent handles | Unused capability constant |
| [03-multi-channel-design.md](03-multi-channel-design.md) | Multi-channel | Unused constants; an uncalled session-binding setter |
| [04-directory-leasing-design.md](04-directory-leasing-design.md) | Directory leasing | Unused capability constant |
| [05-rdma-smb-direct-design.md](05-rdma-smb-direct-design.md) | RDMA (SMB Direct) | Unused read-channel constants |
| [06-witness-protocol-design.md](06-witness-protocol-design.md) | Witness protocol | Nothing |

## Before implementing any of these

Read the status banner in the document first, then verify the current state of
the code rather than trusting the design text. The proposals have not been
revised since they were written and are not kept in step with the source tree.
