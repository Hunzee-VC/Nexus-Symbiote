# Registry collector

The `registry` collector records the AI-related packages and container images a project declares in its root manifests. It reads files only: it runs no package manager, builds no image and fetches nothing. A record is a declaration with unknown trust, not proof of what is installed.

It inventories only the packages and images in the [AI package catalog](#ai-package-catalog) below. Every other dependency, including a malicious package outside the catalog or a look-alike name such as `langchian`, produces no component and no finding: the collector does not detect typosquats and is not a full software bill of materials. "registry (no AI-related dependencies found)" means that no declaration matched the catalog, not that the project has no dependencies. The catalog changes between releases, so a scan with a newer release can inventory packages an older baseline left out.

## What it reads

All paths are relative to the scan root, and the inventory records them that way, so the same tree gives the same inventory wherever it is checked out.

| Ecosystem | Files and fields |
| --- | --- |
| npm | `package.json`: `peerDependencies`, `dependencies`, `optionalDependencies` and `devDependencies`, in that order of precedence, as npm reads them; a name declared differently in more than one section is recorded with every spec. Resolution evidence from one lockfile: `npm-shrinkwrap.json` when it exists, which npm installs from instead of `package-lock.json`, and otherwise `package-lock.json` (lockfile versions 2 and 3), `pnpm-lock.yaml` or `yarn.lock` (v1 and Berry). With the lockfiles of more than one package manager no evidence is bound; see [lockfile evidence](npm-lockfile-evidence.md) |
| PyPI | Root `requirements*.txt` files, read by pip 26.3's rules. `pyproject.toml`: `[project]` dependencies and optional dependencies, `[dependency-groups]` (PEP 735), `[build-system]` requires, `[tool.uv]` dev-dependencies, `[tool.pdm.dev-dependencies]`, and Poetry's `dependencies`, `dev-dependencies` and `group.*.dependencies` tables translated to PEP 508. Resolution evidence from `uv.lock` or `poetry.lock`, unless both exist |
| Containers | `Dockerfile`, `Dockerfile.agent` and `Containerfile`, read as BuildKit reads them. The Compose files Compose reads by default: `compose.yaml`, `compose.yml`, `docker-compose.yml` and `docker-compose.yaml`, and the override files it merges, `compose.override.yml`, `compose.override.yaml`, `docker-compose.override.yml` and `docker-compose.override.yaml`. Each is parsed as YAML: the `image` of every service, with YAML merge keys and aliases followed, the `FROM` lines of a `build.dockerfile_inline`, and the `model` of every top-level model, which Docker Model Runner pulls (recorded with `artifact_type` `model`, whatever its name). A value is read as written only when it is untagged or tagged `!!str` or with Compose's `!override`; `!reset` and null hold no value. A root `.env` is read only for the name `COMPOSE_FILE`; nothing in it is recorded |

A name is matched in its normal form, as PEP 503 normalises a PyPI name, so `llama.index.core`, `LLAMA_INDEX_CORE` and `llama-index-core` are one package with one component. An npm dependency declared as an alias, `"app-utils": "npm:@anthropic-ai/sdk@0.30.1"`, is classified and recorded by the package it installs, with the alias in the `npm_alias` property; a lockfile record whose `name` is an AI package also brings the dependency into the inventory. The same image named in several files is one component whose `source_paths` property lists them all.

## Coverage gaps

These make the collector partial, so `scan`, `validate` and `risk` fail by default. Gaps never name the value that caused them, which can hold a credential.

| Gap | Cause |
| --- | --- |
| `package.json: dependency override not translated` | `overrides` (npm), `resolutions` (yarn) or `pnpm.overrides` names an inventoried package, or installs an AI package as an alias |
| `package.json: workspaces not followed` | `workspaces` lists member packages, whose manifests are not read |
| `package.json: git, URL or path dependency not classified` | A dependency outside the catalog by name, or a package that `overrides`, `resolutions` or `pnpm.overrides` replaces, comes from git, a URL or a path, and no lockfile record names the package it holds |
| `pnpm-workspace.yaml: workspace settings not read` | A `pnpm-workspace.yaml` exists: pnpm reads workspace packages, overrides and version catalogs from it |
| `multiple npm lockfiles present (<files>); resolution is ambiguous` | More than one of `npm-shrinkwrap.json` or `package-lock.json`, `pnpm-lock.yaml` and `yarn.lock` exists, so no lockfile evidence is bound. `npm-shrinkwrap.json` beside `package-lock.json` is not ambiguous: npm installs from it |
| `<npm lockfile>: aliased package identity is unresolved` | A lockfile record names a different package than `package.json` declares, or a pnpm or Yarn lockfile resolves an `npm:` alias, which only `npm-shrinkwrap.json` and `package-lock.json` records resolve |
| `<npm lockfile>: local link resolution is unverified`, `local or non-registry resolution is unverified`, `multiple package resolutions for <package> are ambiguous` | A lockfile resolves a package from a link, a workspace, a directory, git or another non-registry source, or a pnpm or Yarn lockfile resolves it to more than one version |
| `multiple Python lockfiles present (uv.lock and poetry.lock); resolution is ambiguous`, `<Python lockfile>: non-registry package source is unverified`, `multiple package resolutions for <package> are ambiguous` | Both Python lockfiles exist, or the lockfile resolves a package from a local, git or URL source, or more than once |
| `pyproject.toml: uv source not translated` | `[tool.uv.sources]` replaces an inventoried package with a git, URL, path, workspace or index source |
| `pyproject.toml: uv override or constraint not followed` | `override-dependencies` or `constraint-dependencies` names an inventoried package |
| `pyproject.toml: PDM override not followed` | `[tool.pdm.resolution.overrides]` names an inventoried package |
| `pyproject.toml: uv workspace members not followed` | `[tool.uv.workspace]` lists members, whose manifests uv installs from |
| `Pipfile: dependencies not read` | A `Pipfile` exists; pipenv installs what it declares |
| `.env: COMPOSE_FILE not followed` | The root `.env` contains `COMPOSE_FILE`, in any letter case: Compose reads the files a `COMPOSE_FILE` setting lists instead of the default ones, and takes them from the environment when the name has no value. Compose's dotenv parser reads statements, not lines (it skips any Unicode space before a name and before `=`, and a statement can follow a closing quote on the same line), so any mention counts, including one in a comment or a value |
| `<compose file>: include not followed`, `extends not followed`, `build context not followed` | Compose reads another file, or builds from a Dockerfile the collector does not read: a context or `dockerfile` other than the project root and a root `Dockerfile`, `Dockerfile.agent` or `Containerfile`, including an absolute path such as `/`, one with a backslash and one longer than 4,096 characters. Also a build that names contexts, in `additional_contexts` or in the `contexts` of `x-bake`, which `docker buildx bake` reads from the same file: BuildKit uses a named context in place of the image that a `FROM` line of that name pulls |
| `<compose file>: image substitution not resolved` | An image contains `$`; Compose fills it in from the environment |
| `<compose file>: image not parsed`, `build not followed`, `tagged image value not resolved` | An empty, null or `!reset` `dockerfile_inline`, or an `image`, `model`, `build` or `dockerfile_inline` value that is not text: a YAML tag other than `!!str`, `!override` and `!reset`, such as `!!binary`, which Compose decodes from base64, `!!null` on a value, or a scalar YAML reads as another type, such as a number |
| `<compose file>: dockerfile_inline <Dockerfile gap>` | An inline Dockerfile has one of the Dockerfile gaps the README lists |
| `<compose file>: YAML merge key cycle not followed` | A mapping merges itself |
| `<file>: image reference not parsed` | An image that matches the catalog is not a valid image reference |

The requirements-file and Dockerfile gaps are listed in the [README](../README.md#registry-gaps-in-requirements-files-and-dockerfiles). A file that cannot be read or parsed, such as invalid TOML, JSON or YAML, a Compose file with a repeated key, a key tagged `!!binary` or with a tag outside YAML's own `tag:yaml.org,2002:` types, or a non-mapping service, or a requirement that packaging cannot parse, is a collection failure, which fails the collector.

## Findings

| Category | Severity | Raised when |
| --- | --- | --- |
| `version_pinning` | medium | A package has no exact pin: no `==` pin in any PyPI declaration, a PyPI range or bare name that the reported pin does not satisfy, under any marker or group, or an npm range or tag that no consistent `npm-shrinkwrap.json` or `package-lock.json` record with a strong integrity value resolves (a pnpm or Yarn record binds the version and leaves the finding, and so does a `uv.lock` or `poetry.lock` record for a PyPI range). Also two PyPI declarations that cannot both hold |
| `version_pinning` | low | Every PyPI pin has an environment marker, such as `; sys_platform == "linux"` |
| `nonregistry_source` | high or medium | A package comes from a URL, VCS or path instead of a registry; high for a VCS reference without a full commit, or a plain `http://` URL |
| `package_alias` | low | An npm dependency installs a package under another name |
| `missing_lockfile_integrity` | medium | An `npm-shrinkwrap.json` or `package-lock.json` record has no integrity value. An integrity value with only SHA-1, in any npm, pnpm or Yarn lockfile, is a collection failure |
| `lockfile_resolution_mismatch` | high | An npm, pnpm or Yarn record's tarball URL names another package or version than the record |
| `registry_origin` | low | An `npm-shrinkwrap.json` or `package-lock.json` record resolves from a registry other than `registry.npmjs.org` and `registry.yarnpkg.com` |
| `lockfile_unread` | low | `Pipfile.lock` or `pdm.lock` (PyPI), or `bun.lock` or `bun.lockb` (npm) exists: the package manager resolves the package from a file the collector does not read. Coverage stays complete, because the declarations are read |
| `version_pinning`, `mutable_image_tag` | high, medium | An image has no digest Docker pulls, which is `sha256`, `sha384` or `sha512` in lower-case hex of that algorithm's length: high without a tag or with `latest`, medium with another tag |

The rating of a PyPI package follows from all of its declarations, in every file, whichever is read first. The first exact pin without a marker is the version reported, and it resolves every range it satisfies, in any root file, under any marker or group, as a compiled `requirements.txt` resolves the ranges of `pyproject.toml`. A range it does not satisfy is a `version_pinning` finding that names its files, declarations under the same markers and group that cannot both hold are a conflict, and a URL declaration anywhere is a finding. The collector cannot tell which file is installed, so a pin in a file that never is, such as `requirements-docs.txt`, also resolves a range in `requirements.txt`; the `declarations` property lists every declaration with its file.

## Identities

| Field | PyPI | npm | Images |
| --- | --- | --- | --- |
| `bom_ref` | `registry:pypi/<normal name>` | `registry:npm/<name in package.json>` | `registry:docker/<reference as written>` |
| `name` | PEP 503 normal name | The package npm installs: the alias target for an alias | The reference as written |
| `package_url` | `pkg:pypi/...` only when every exact pin names the same version, every other declaration admits it, and nothing is a URL, untranslated or in conflict; or the version a `uv.lock` or `poetry.lock` record resolves, unless a declaration of the package is a URL | `pkg:npm/...` from a consistent npm, pnpm or Yarn lockfile record, with `repository_url` when it resolves from another registry, or from an exact spec without a record | `pkg:oci/...` with `repository_url` and `tag` when the reference has a digest Docker pulls |
| `registry_uri` | `https://pypi.org`; the URL origin when every declaration is a URL with that origin; none when declarations mix a URL with others, or a uv, PDM or Poetry source or override replaces the package; the index origin a `uv.lock` or `poetry.lock` record names | The lockfile record's origin | `https://docker.io`, or `https://` and the registry host |
| `registry_type` | `pypi` | `npm` | `docker-hub` for Docker Hub, `oci` for another registry, none for a reference kept as written because of a substitution or quotes |

PyPI components record their hash pins as `requirement_hashes`, so a changed or removed `--hash` value is drift. Components a lockfile resolves keep the digest of the whole lockfile in `lockfile_sha256`: it is the only drift signal for the transitive dependencies the collector does not inventory. Images record their normalised repository, such as `docker.io/library/ollama`, as `image_repository`.

## Limits

| Input | Limit | Beyond it |
| --- | --- | --- |
| Root `requirements*.txt` files | 4 MiB of text together | Collection failure |
| Option text with a quote or backslash, on one requirement line | 16 KiB | `option line not parsed` gap |
| `pyproject.toml` | 256 KiB | Collection failure |
| A dotted key or table name in `pyproject.toml`, `uv.lock` or `poetry.lock` | 16 dots, quoted parts included | Collection failure |
| `uv.lock` or `poetry.lock` | 10,000 packages | Collection failure |
| `pnpm-lock.yaml` | 1,000,000 YAML tokens, and no anchors, aliases or tags | Collection failure |
| `yarn.lock` | 100,000 lines | Collection failure |
| A Compose file | 20,000 YAML tokens and 100,000 merge-key steps | Collection failure |
| A Compose build `context` or `dockerfile` | 4,096 characters, Linux's `PATH_MAX` | `build context not followed` gap, even for a path that names the project root |
| npm `overrides`, `resolutions` and `pnpm.overrides` together | 10,000 entries, nested 32 deep | `dependency override not translated` gap, also for every inventoried npm package |
| An image reference | 520 characters, docker/distribution's limit | `image reference not parsed` gap when it matches the catalog |

## AI package catalog

One catalog serves PyPI and npm. A name is compared in its normal form, in which runs of -, _ and . are one hyphen and letters are lower case, as PEP 503 normalises a PyPI name; an npm scope is kept. A name matches when it is listed, when its npm scope is listed, or when the part after any scope starts with a listed prefix or has a listed word among its hyphen-separated words. A prefix without a trailing hyphen also matches longer names. A name listed for one registry also matches in the other, so an unrelated package of that name there is inventoried too.

### Packages

- Names: `@aws-sdk/client-bedrock-agent-runtime`, `@aws-sdk/client-bedrock-runtime`, `@browserbasehq/stagehand`, `@google-cloud/aiplatform`, `@google-cloud/vertexai`, `@google/adk`, `@google/genai`, `@google/generative-ai`, `accelerate`, `ag2`, `agno`, `ai`, `ai21`, `bitsandbytes`, `browser-use`, `camel-ai`, `ctransformers`, `deepspeed`, `dspy`, `e2b`, `farm-haystack`, `fireworks-ai`, `flash-attn`, `flax`, `gguf`, `griptape`, `groq`, `groq-sdk`, `haystack-ai`, `instructor`, `jax`, `jaxlib`, `js-tiktoken`, `lancedb`, `letta`, `mastra`, `mcp`, `mem0ai`, `mlx`, `node-llama-cpp`, `onnx`, `optimum`, `paddlepaddle`, `pyautogen`, `pymilvus`, `redisvl`, `replicate`, `sentencepiece`, `together`, `trl`, `vertexai`, `voyageai`, `xformers`
- npm scopes, every package of which matches: `@a2a-js`, `@ai-sdk`, `@anthropic-ai`, `@huggingface`, `@lancedb`, `@langchain`, `@llamaindex`, `@mastra`, `@mistralai`, `@mlc-ai`, `@modelcontextprotocol`, `@openai`, `@pinecone-database`, `@qdrant`, `@smithery`, `@tensorflow`, `@tensorflow-models`, `@xenova`, `@zilliz`
- Prefixes: `a2a-sdk`, `agno-`, `anthropic`, `autogen`, `chromadb`, `claude-agent-sdk`, `claude-code-sdk`, `cohere`, `crewai`, `diffusers`, `dspy-`, `e2b-`, `faiss`, `fastmcp`, `google-adk`, `google-cloud-aiplatform`, `google-genai`, `google-generativeai`, `guardrails`, `huggingface`, `keras`, `langchain`, `langgraph`, `langsmith`, `letta-`, `litellm`, `llama-cpp`, `llama-index`, `llamaindex`, `mcp-`, `mistralai`, `mlx-`, `nemo-guardrails`, `nemoguardrails`, `ollama`, `onnxruntime`, `openai`, `peft`, `pgvector`, `pinecone`, `pydantic-ai`, `qdrant`, `rebuff`, `safetensors`, `semantic-kernel`, `sentence-transformers`, `smolagents`, `strands-agents`, `tensorflow`, `tiktoken`, `tokenizers`, `torch`, `transformers`, `vllm`, `weaviate`
- Words: `llm`, `mcp`

### Container images

An image is inventoried when its reference, in lower case, contains one of `chroma`, `huggingface`, `litellm`, `llama`, `lmdeploy`, `localai`, `milvus`, `model`, `ollama`, `onnxruntime`, `pgvector`, `pytorch`, `qdrant`, `sglang`, `tensorflow`, `text-embeddings-inference`, `text-generation-inference`, `tgi`, `triton`, `vllm` or `weaviate`, or has `mcp` or `tei` as one of its parts, such as Docker's MCP catalog images under mcp/. These are substrings: an unrelated image whose name contains one of them is inventoried too.

## Not read

These declare or change what is installed but are not read, and leave no gap. Review changes to them by other means.

- Manifests outside the project root: workspace members (a gap when `workspaces`, a `pnpm-workspace.yaml` or `[tool.uv.workspace]` lists them), other `package.json` files, `requirements*.txt` files in subdirectories and pip-tools `*.in` files.
- `setup.py`, `setup.cfg` and dependencies declared dynamic in `pyproject.toml`; conda `environment.yml`; `[tool.hatch.envs]` environments.
- Index and registry choices: `--index-url`, `--extra-index-url`, `--find-links` and `--trusted-host` in requirements files, `[[tool.uv.index]]`, Poetry and PDM sources, and `.npmrc`. Packages from another index are recorded as PyPI packages unless a uv or Poetry source names them or a `uv.lock` or `poetry.lock` record gives their index.
- `bundleDependencies`, which npm installs from `dependencies` anyway.
- Kubernetes manifests, Helm charts and `.devcontainer` configuration.
- Compose provider services (`provider:`), including `type: model`; Compose files that `COMPOSE_FILE` selects when it is set in the environment Compose runs in rather than in `.env`, or that `-f` or `--env-file` select.
- `docker buildx bake` files, such as `docker-bake.hcl` and `docker-bake.json`; in a Compose file, bake's `x-bake` field is read only for its `contexts`.
