# Agent Evidence Verifier

Made as a clean-room implementation based on the draft specifications during the hackathon at IETF 127.

Licensed under the [Apache License, Version 2.0](LICENSE).

## Specifications used

- Evidence Request: [draft-mih-agent-evidence-request-02](https://datatracker.ietf.org/doc/draft-mih-agent-evidence-request/02/)
- Checkpointed Local Log (the checkpoints and consistency proofs the history card is built on): [draft-mih-scitt-checkpointed-local-log-02](https://datatracker.ietf.org/doc/draft-mih-scitt-checkpointed-local-log/02/)
- Evidence Layer (architecture and context): [draft-mih-agent-evidence-layer-00](https://datatracker.ietf.org/doc/draft-mih-agent-evidence-layer/00/)
- Evidence Bundle: [draft-mih-zhang-agent-disclosure-bundle-02](https://datatracker.ietf.org/doc/draft-mih-zhang-agent-disclosure-bundle/02/)
- Agent Action Capsule: [draft-mih-scitt-agent-action-capsule-05](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/05/)

## Dependencies used

- [clap](https://crates.io/crates/clap) for command line argument parsing.
