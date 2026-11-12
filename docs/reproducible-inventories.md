# Reproducible inventories

Scan one checkout twice and you get two inventories that record the same content but
differ in when, and in which run, they were collected. This page lists exactly what
differs, describes the content digest that leaves it out, and shows how
`SOURCE_DATE_EPOCH` makes the files themselves byte-identical.

- [What differs between two collections](#what-differs-between-two-collections)
- [The content digest](#the-content-digest)
- [Byte-identical files with `SOURCE_DATE_EPOCH`](#byte-identical-files-with-source_date_epoch)
- [Example](#example)
- [Limits](#limits)

## What differs between two collections

An inventory records paths relative to the scanned directory, so where a checkout lies
does not enter it. Two scans of the same checkout, with the same tool and settings,
differ only in fields that record the collection event:

| Field | What a scan writes |
|---|---|
| `metadata.serial_number` | A random `urn:uuid:` URN (a version 4 UUID) |
| `metadata.timestamp` | The time the scan started |
| `metadata.completeness.timestamp` | The same time |
| `components[].claims.<name>.observed_at` | The same time, in each claim a collector attached |

`import-shadowscan` writes the first two; its records carry no collection times.

Every digest of a whole document therefore changes from run to run: the SHA-256 of the
file's bytes, and the canonical digest that a signed runtime snapshot binds
(`runtime digest --kind bom`). The exports carry the same values: CycloneDX
`serialNumber` and `metadata.timestamp`, SPDX `created` and a document identifier
derived from the whole native document, and SARIF `endTimeUtc`.

## The content digest

`nexus-symbiote digest` prints the content digest as `content_digest`, and its profile,
`nexus-symbiote/inventory-content/v1`, as `content_profile`; see the
[CLI reference](cli-reference.md#digest). It is the SHA-256 of the RFC 8785 canonical
JSON of the native document as parsed from the file, with these fields left out:

- `metadata.serial_number`, when it is null or a `urn:uuid:` URN in lower-case
  hexadecimal;
- `metadata.timestamp`, `metadata.completeness.timestamp` and the `observed_at` of each
  component claim, when null or an RFC 3339 timestamp of the form
  `YYYY-MM-DDThh:mm:ss`, with up to nine digits of fractional seconds, and `Z` or a
  `+hh:mm` or `-hh:mm` offset.

A field is left out only at that location, only when the object that holds it is a
JSON object, and only when its value has that shape. Everything else is content:

- a key with one of these names anywhere else, such as in `properties`, in a dependency
  edge or in a deployment profile, so that a change cannot hide behind a field that is
  merely named like a collection event;
- any other value at these locations, such as a timestamp without a time of day;
- the order of every list, `components` and `dependencies` included;
- the tool version, the governing policy and its relaxations, and the whole coverage
  record.

The document must be a JSON object with a `metadata` object and a `components` list.
The digest covers the document as it is in the file: reading an inventory into the
model and writing it again can fill in defaults and rewrite timestamps, which makes a
different document. A change to what is left out is a new profile version; the
known-answer vectors in `tests/vectors/inventory-content-v1.json` pin this one.

Equal content digests establish that two documents record the same content, field for
field, apart from when and in which run each was collected. They do not establish who
produced either file, that either is genuine or complete, or that what they record is
safe: a forged inventory that copies a genuine one's content has the same content
digest. Compare content digests of inventories that came from sources you trust, and
use the SHA-256 of the file to name an exact file.

## Byte-identical files with `SOURCE_DATE_EPOCH`

Set `SOURCE_DATE_EPOCH`, the variable that reproducible builds use, to a whole number
of seconds since 1970-01-01T00:00:00Z: 1 to 12 ASCII digits, at most 253402300799
(9999-12-31T23:59:59Z). Then `scan`, `baseline`, which runs `scan`, and
`import-shadowscan`:

- record that instant, instead of the clock, in every field of the table above;
- once collection has finished, set `metadata.serial_number` to `urn:uuid:` followed
  by the version 5 UUID of the content digest in the namespace
  `ccaa2a43-8ba9-58e6-8f22-f8793a2039d5`, which the standard exports already use.

The serial number is not content, so anyone who holds the native JSON file can
recompute it from that file, and it names the content: two inventories of the same
content have the same serial number, whatever instant each records. CycloneDX and SPDX
exports carry the same serial number, but it cannot be recomputed from an export, which
embeds a sorted copy of the native document (see [limits](#limits)). It is a name, not a
digest: compare content digests to compare content.

The same inputs then give byte-identical native JSON, CycloneDX and SPDX files, and
`vex` gives identical documents for them. SARIF records file locations relative to the
working directory when the scanned directory lies below it, and relative to the scanned
directory otherwise. Two SARIF files are therefore identical when the scanned directory
lies at the same path below the working directory in both scans, or below it in
neither: a scan run from inside the scanned directory, as CI and the pre-commit hooks
do, and a scan of a directory elsewhere record the same locations.

Any other value, such as an empty, signed, fractional or hexadecimal number, one with
spaces, one of more than 12 digits or one after the year 9999, is a usage error (exit
status 2) before anything is collected, and the message does not repeat it. Without
the variable nothing changes: a scan records the clock and a random serial number.

No gate and no other command reads the variable:

- Gates keep using the clock. An expired suppression stays expired whatever instant
  the inventory records: `SOURCE_DATE_EPOCH` is often a commit time, which whoever
  makes the commit can choose.
- `discover-mcp --record` and `verify-live --record` record when they observed the
  server.

The release workflow exports the variable, set to the commit time, for its whole build
job. The `project.cdx.json` it publishes as release evidence therefore records the
commit time, not the time of its scan, and a serial number derived from its content;
see [releasing](releasing.md#what-the-pipeline-guarantees).

With the variable set, an inventory whose content digest cannot be computed, because
it holds a value outside the I-JSON range, such as a lone surrogate, or nests too
deeply, is not written: `scan` exits 1 rather than write a serial number that does not
name its content. Without the variable, such an inventory cannot be exported either,
or is written in a form that the other commands refuse.

## Example

From the repository root, without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` in the
environment:

```console
$ demo="$PWD/examples/demo-agent"
$ cd "$(mktemp -d)"
$ export SOURCE_DATE_EPOCH=1767225600
$ cp -R "$demo" first && mkdir -p ci/work && cp -R "$demo" ci/work/second
$ nexus-symbiote scan first -o first.json 2>/dev/null
$ nexus-symbiote scan ci/work/second -o second.json 2>/dev/null
$ cmp first.json second.json && echo identical
identical
$ nexus-symbiote digest first.json
file_sha256: sha256:36a53ae4f4cc8fa9263a767288418d6d4d5aca849b4a71d2ab48d863d54fd1c7
canonical_digest: sha256:c0e584e39a8f160ae335a09c77593493de085958e52b882a3c4cd125732affc7
content_digest: sha256:70565ff758239dcaacd4c27eea8c10a3756ee135b35bccb0306ebeaa6a5f86a0
content_profile: nexus-symbiote/inventory-content/v1
spec_version: 1.1.0
components: 11
```

Without the variable, a new scan writes a different file with the same content digest:

```console
$ unset SOURCE_DATE_EPOCH
$ nexus-symbiote scan "$demo" -o now.json 2>/dev/null
$ cmp -s first.json now.json || echo different
different
$ nexus-symbiote digest now.json --json-output | grep content_digest
  "content_digest": "sha256:70565ff758239dcaacd4c27eea8c10a3756ee135b35bccb0306ebeaa6a5f86a0",
```

These are the digests of this tree's scan of the demo; a release that records anything
differently prints others. `tests/test_reproducible_inventory.py` checks this page
against the current tree.

## Limits

- **Content can change for reasons other than the checkout.** The tool version is
  content, and another release can record more or differently. So are the governing
  policy (`policy_source`, `policy_weakened`, the exclusions), the collectors selected
  with `--scanner`, the [collection limits](collection-limits.md), which decide what is
  a gap, and `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, which keys the settings bindings (see
  [source binding](verification-source-binding.md)). Take the inventories you compare
  the same way; see
  [take both snapshots the same way](drift-gate.md#take-both-snapshots-the-same-way).
- **List order is content.** CycloneDX and SPDX exports embed the native document with
  its components and dependencies sorted, so a native document recovered from an
  export has another content digest than the native file, although it records the same
  inventory. Compare native files with native files. For the same reason, an export's
  serial number names the content of the native file, not of the sorted copy the export
  embeds.
- **SARIF locations depend on the working directory**, as described above.
- **A readable inventory can lack a digest.** A document without a `metadata` object or
  a `components` list has no content digest. A runtime snapshot binds a document only
  when its compact JSON, with every character outside ASCII escaped and each number
  counted as 24 bytes, is at most 16 MiB, it holds at most 1,000,000 values and no value
  is nested more than 64 levels deep; any other document has no canonical digest. A
  native inventory may be up to 16 MiB as written, so one with much text outside ASCII,
  or many numbers, can lack a canonical digest at a fraction of that size. `digest`
  prints `unavailable` for a missing digest and every other value as usual, and exits 1.
- **File names are input.** An inventory records names as the operating system lists
  them, so a checkout whose names differ between machines, for example after Unicode
  normalization, records different paths. The byte-identical results on this page were
  checked with copies of a checkout on one file system.
- **A digest is not a signature.** No digest on this page says who wrote a file.
