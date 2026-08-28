# Provider-neutral execution sidecar v1

The execution sidecar separates four authorities: the unchanged pipeline v1
defines what is validated; execution requirements declare portable needs; an
adapter descriptor declares how an executor can satisfy them; normalized
evidence records what actually happened. Delivery remains a separate contract
and every v1 adapter explicitly has `delivery_authority: none`.

`execution-requirements-v1` uses stable command IDs, argument arrays, and
repository-relative working directories. Adapters may not add, omit, rewrite,
or reorder those commands. Raw shell strings, shell wrappers, absolute paths,
traversal, home expansion, backslash paths, and symlink escapes are rejected.
The caller must supply an independently pinned requirements SHA-256 and the
literal reviewed contract bytes. The local reference runner verifies both,
the runner implementation digest, the pipeline template/profile identity, the
complete command and artifact declarations, exact clean Git SHA, capabilities,
and paths before starting work. It uses `shell=False`, terminates complete
process groups on timeout or active cancellation, and verifies declared
artifact SHA-256 digests.

Evidence is canonical JSON: UTF-8, sorted keys, compact separators, one final
newline. Timestamps are explicit caller inputs, making repeated rendering and
hashing deterministic for identical inputs. Evidence contains stable IDs,
hashes, capability names, and conclusions only; stdout, stderr, environment
dumps, credentials, endpoints, machine names, and private topology are never
included.

The Local adapter is executable only through `local-reference-v1` and currently
advertises the validated Darwin process-group implementation. Cloud Build and
Jenkins/hybrid descriptors are marked `synthetic-only`: the local runner
returns `unsupported` without starting a process. They install nothing,
connect to nothing, and grant no delivery authority. Unsupported, deprecated,
incomplete, cancelled, timed-out, superseded, failed, and partial results are
non-success. The runner does not claim to enforce network isolation; its
supported network class is therefore only `public`.

Adapters declare exact command ordering, fail-fast propagation, process-group
timeout/cancellation, and no-process supersession semantics. Successful
evidence must include the complete ordered successful command list, complete
artifact list and digests, and the exact executor platform and capability set.

Run the standard-library suite with:

```text
python3 -m unittest discover -s tests -p 'test_*.py'
```
