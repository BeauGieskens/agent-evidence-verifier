# Agent Evidence Verifier

Made as a clean-room implementation based on the draft specifications during the hackathon at IETF 127.

Licensed under the [Apache License, Version 2.0](LICENSE).

## Specifications used

- Evidence Request: [draft-mih-agent-evidence-request-02](https://datatracker.ietf.org/doc/draft-mih-agent-evidence-request/02/)
- Checkpointed Local Log: [draft-mih-scitt-checkpointed-local-log-02](https://datatracker.ietf.org/doc/draft-mih-scitt-checkpointed-local-log/02/)
  - COSE Receipts for MMRs [draft-bryce-cose-receipts-mmr-profile-03](https://datatracker.ietf.org/doc/draft-bryce-cose-receipts-mmr-profile/03/)
- Evidence Layer: [draft-mih-agent-evidence-layer-00](https://datatracker.ietf.org/doc/draft-mih-agent-evidence-layer/00/)
- Evidence Bundle: [draft-mih-zhang-agent-disclosure-bundle-02](https://datatracker.ietf.org/doc/draft-mih-zhang-agent-disclosure-bundle/02/)
- Agent Action Capsule: [draft-mih-scitt-agent-action-capsule-05](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/05/)

## Gaps identified

- Evidence Request:
  - §3.1: "range (a, b)" (in table 2)
    - I inferred from elsewhere in the document that (a, b) represents a tuple.
  - §3.7: "Human-readable detail MAY accompany the reason token"
    - It is not clear to me at what layer this detail should or should not be included in a hypothetical response.
    - I would like to think it would be reasonable to allow an optional string field as part of the response, but I don't know if that messes with the signature or digest requirements on the requester's side.
  - §5: "For a given responder, the same subject under the same coverage anchor MUST yield a byte-identical evidence artifact, regardless of the requester's identity, the transport binding used, or any other property of the request."
    - Does that mean infinite retention??
      - §9 later seems to clarify that it doesn't have to mean infinite retention, but only if the responder knows upfront when it will stop giving that guarantee.
      - Introducing a shorter retention policy later on is a breaking change for the responder and violates the requirement for deterministic responses.
      - I recommend either making it a requirement to define a reasonable retention policy up front, or loosening the requirement for responses to be deterministic by warning that retention policy can change after a given response is received.
  - Digests do not have a defined format in this document, which makes a generalized implementation difficult, in comparison to most other field values where a more concrete type can be guess more easily.
    - I could use any of `Vec<u8>`, a byte-string (which isn't portable across JSON/CBOR), a hex string, or a base64 string for the digest. There are probably other possibilities too.
      - For my implementation I went with a lowercase hex string because that's what the Evidence Layer spec prescribes.
    - A particular form of digest is also not prescribed, which I assume is intentional. Because digests are supposed to be stable identifiers, it would be nice to have a stable algorithm for generating them.
    - Because the digest is hard-linked to the bytes of the response, the response is forced into a single format. As of now, I can only use JSON forms of the Evidence Layer records or Agent Action Capsules; CBOR or any other format would lead to different digests.
- Checkpointed Local Log:
  - §4.2: the format doesn't exactly match the COSE receipts MMR profile since `hash` isn't specified anywhere.
    - I had to check against the MMR profile document to guess what the intent was.

### Minor suggestions

These are just some minor grammar errors or usability issues which did not affect the implementation, but made it more difficult to parse the documents in the first reading:

- Evidence Layer:
  - §4: "typed links" could link to §5.
- Evidence Request:
  - §3.3: "by a registered token" points to IANA considerations but the first table there is for request refusal reasons. If the tables had their order switched that would have been less confusing.
    - §3.7: "Two consequences for implementers." This is not a complete sentence.
      - If I was to include a principal reference within the request itself can I do that? I can't tell if an extension is required for that to be allowed or if it's fine for someone to do that
    - 4.2: "Human-readable detail MAY accompany the reason token; the token, not the prose, is the machine-readable answer." — what would be the mechanism for providing that?
- Checkpointed Local Log:
  - §4.3, step 8: "Otherwise `consistency_proof` is present and is a `consistency-proof`; its `tree-size-1` equals `prev_size` and its `tree-size-2` equals `log_size`; and applying the verification steps of the MMR profile for a Receipt of consistency — `consistent_roots` from `prev_size` and the accumulator in `prev_commitment`, followed by the `right-peaks` — yields an accumulator whose encoding equals `commitment`."
    - It would be nice to have one more direct links to the MMR profile which describes the relevant verification steps.

## Dependencies used

See Cargo.toml for the up-to-date list of dependencies.
