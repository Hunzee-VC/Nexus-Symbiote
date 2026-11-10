# Registry collector

The `registry` collector records the AI-related packages and container images a project declares in its root manifests. It reads files only: it runs no package manager, builds no image and fetches nothing. A record is a declaration with unknown trust, not proof of what is installed.

It inventories only the packages and images in the [AI package catalog](#ai-package-catalog) below. Every other dependency, including a malicious package outside the catalog or a look-alike name such as `langchian`, produces no component and no finding: the collector does not detect typosquats and is not a full software bill of materials. "registry (no AI-related dependencies found)" means that no declaration matched the catalog, not that the project has no dependencies. The catalog changes between releases, so a scan with a newer release can inventory packages an older baseline left out.

## What it reads

All paths are relative to the scan root, and the inventory records them that way, so the same tree gives the same inventory wherever it is checked out.

| Ecosystem | Files and fields |
| --- | --- |
| npm | `package.json`: `peerDependencies`, `dependencies`, `optionalDependencies` and `devDependencies`, in that order of precedence, as npm reads them; a name declared differently in more than one section is recorded with every spec. Resolution evidence from `npm-shrinkwrap.json` when it exists, which npm installs from instead of `package-lock.json`, and otherwise from `package-lock.json` (lockfile versions 2 and 3); see [npm lockfile evidence](npm-lockfile-evidence.md) |
| PyPI | Root `requirements*.txt` files, read by pip 26.3's rules. `pyproject.toml`: `[project]` dependencies and optional dependencies, `[dependency-groups]` (PEP 735), `[build-system]` requires, `[tool.uv]` dev-dependencies, `[tool.pdm.dev-dependencies]`, and Poetry's `dependencies`, `dev-dependencies` and `group.*.dependencies` tables translated to PEP 508 |
| Containers | `Dockerfile`, `Dockerfile.agent` and `Containerfile`, read as BuildKit reads them. The Compose files Compose reads by default: `compose.yaml`, `compose.yml`, `docker-compose.yml` and `docker-compose.yaml`, and the override files it merges, `compose.override.yml`, `compose.override.yaml`, `docker-compose.override.yml` and `docker-compose.override.yaml`. Each is parsed as YAML: the `image` of every service, with YAML merge keys and aliases followed, the `FROM` lines of a `build.dockerfile_inline`, and the `model` of every top-level model, which Docker Model Runner pulls (recorded with `artifact_type` `model`, whatever its name) |

A PyPI name is matched in its PEP 503 normal form, so `llama.index.core`, `LLAMA_INDEX_CORE` and `llama-index-core` are one package with one component. An npm dependency declared as an alias, `"app-utils": "npm:@anthropic-ai/sdk@0.30.1"`, is classified and recorded by the package it installs, with the alias in the `npm_alias` property; a lockfile record whose `name` is an AI package also brings the dependency into the inventory. The same image named in several files is one component whose `source_paths` property lists them all.

## Coverage gaps

These make the collector partial, so `scan`, `validate` and `risk` fail by default. Gaps never name the value that caused them, which can hold a credential.

| Gap | Cause |
| --- | --- |
| `package.json: dependency override not translated` | `overrides` (npm), `resolutions` (yarn) or `pnpm.overrides` names an inventoried package, or installs an AI package as an alias |
| `package.json: workspaces not followed` | `workspaces` lists member packages, whose manifests are not read |
| `package.json: git, URL or path dependency not classified` | A dependency outside the catalog by name comes from git, a URL or a path, and no lockfile record names the package it holds |
| `package-lock.json: aliased package identity is unresolved` | A lockfile record names a different package than `package.json` declares |
| `pyproject.toml: uv source not translated` | `[tool.uv.sources]` replaces an inventoried package with a git, URL, path, workspace or index source |
| `pyproject.toml: uv override or constraint not followed` | `override-dependencies` or `constraint-dependencies` names an inventoried package |
| `pyproject.toml: PDM override not followed` | `[tool.pdm.resolution.overrides]` names an inventoried package |
| `Pipfile: dependencies not read` | A `Pipfile` exists; pipenv installs what it declares |
| `<compose file>: include not followed`, `extends not followed`, `build context not followed` | Compose reads another file, or builds from a Dockerfile the collector does not read |
| `<compose file>: image substitution not resolved` | An image contains `$`; Compose fills it in from the environment |
| `<compose file>: image not parsed`, `build not followed`, `tagged image value not resolved` | An `image`, `model` or `build` value that is not text, or has a YAML tag other than Compose's `!reset` and `!override` |
| `<compose file>: dockerfile_inline <Dockerfile gap>` | An inline Dockerfile has one of the Dockerfile gaps the README lists |
| `<compose file>: YAML merge key cycle not followed` | A mapping merges itself |
| `<file>: image reference not parsed` | An image that matches the catalog is not a valid image reference |

The requirements-file and Dockerfile gaps are listed in the [README](../README.md#what-it-inventories). A file that cannot be read or parsed, such as invalid TOML, JSON or YAML, a Compose file with a repeated key or a non-mapping service, or a requirement that packaging cannot parse, is a collection failure, which fails the collector.

## Findings

| Category | Severity | Raised when |
| --- | --- | --- |
| `version_pinning` | medium | A package has no exact pin: no `==` pin in any PyPI declaration, or an npm range or tag that no consistent lockfile record with a strong integrity value resolves. Also two PyPI declarations that cannot both hold |
| `version_pinning` | low | Every PyPI pin has an environment marker, such as `; sys_platform == "linux"` |
| `nonregistry_source` | high or medium | A package comes from a URL, VCS or path instead of a registry; high for a VCS reference without a full commit, or a plain `http://` URL |
| `package_alias` | low | An npm dependency installs a package under another name |
| `missing_lockfile_integrity`, `weak_lockfile_integrity` | medium | A lockfile record has no integrity value, or only SHA-1 |
| `lockfile_resolution_mismatch` | high | A lockfile record's tarball URL names another package or version than the record |
| `registry_origin` | low | A lockfile record resolves from a registry other than `registry.npmjs.org` |
| `lockfile_unread` | low | `uv.lock`, `poetry.lock`, `Pipfile.lock` or `pdm.lock` (PyPI), or `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` or `bun.lockb` (npm) exists: the package manager resolves the package from a file the collector does not read. Coverage stays complete, because the declarations are read |
| `version_pinning`, `mutable_image_tag` | high, medium | An image has no digest: high without a tag or with `latest`, medium with another tag |

The rating of a PyPI package follows from all of its declarations, in every file, whichever is read first: an exact pin without a marker in any file leaves no `version_pinning` finding, declarations under the same markers and group that cannot both hold are a conflict, and a URL declaration anywhere is a finding.

## Identities

| Field | PyPI | npm | Images |
| --- | --- | --- | --- |
| `bom_ref` | `registry:pypi/<normal name>` | `registry:npm/<name in package.json>` | `registry:docker/<reference as written>` |
| `name` | PEP 503 normal name | The package npm installs: the alias target for an alias | The reference as written |
| `package_url` | `pkg:pypi/...` only when every exact pin names the same version, nothing is a URL, untranslated or in conflict | `pkg:npm/...` from a consistent lockfile record, with `repository_url` when it resolves from another registry, or from an exact spec without a record | `pkg:oci/...` with `repository_url` and `tag` when the reference has a digest |
| `registry_uri` | `https://pypi.org`; the URL origin when every declaration is a URL with that origin; none when declarations mix a URL with others, or a uv, PDM or Poetry source or override replaces the package | The lockfile record's origin | `https://docker.io`, or `https://` and the registry host |
| `registry_type` | `pypi` | `npm` | `docker-hub` for Docker Hub, `oci` for another registry, none for a reference kept as written because of a substitution or quotes |

PyPI components record their hash pins as `requirement_hashes`, so a changed or removed `--hash` value is drift. npm components keep the digest of the whole lockfile in `lockfile_sha256`: it is the only drift signal for the transitive dependencies the collector does not inventory. Images record their normalised repository, such as `docker.io/library/ollama`, as `image_repository`.

## Limits

| Input | Limit | Beyond it |
| --- | --- | --- |
| Root `requirements*.txt` files | 4 MiB of text together | Collection failure |
| Option text with a quote or backslash, on one requirement line | 16 KiB | `option line not parsed` gap |
| `pyproject.toml` | 256 KiB | Collection failure |
| A dotted key or table name in `pyproject.toml` | 16 dots | Collection failure |
| A Compose file | 20,000 YAML tokens and 100,000 merge-key steps | Collection failure |

## AI package catalog

PyPI names are compared in their PEP 503 normal form, in which runs of -, _ and . are one hyphen and letters are lower case. npm names are compared in lower case; prefixes and words apply to the part after a scope, whose words are separated by -, _ or . . A name matches when it is listed, starts with a listed prefix or contains a listed word. A prefix without a trailing hyphen also matches longer names.

### PyPI

- Names: `accelerate`, `ag2`, `agno`, `ai21`, `bitsandbytes`, `browser-use`, `camel-ai`, `ctransformers`, `deepspeed`, `dspy`, `e2b`, `farm-haystack`, `fireworks-ai`, `flash-attn`, `flax`, `gguf`, `griptape`, `groq`, `haystack-ai`, `instructor`, `jax`, `jaxlib`, `lancedb`, `letta`, `mcp`, `mem0ai`, `mlx`, `onnx`, `optimum`, `paddlepaddle`, `pyautogen`, `pymilvus`, `redisvl`, `replicate`, `sentencepiece`, `together`, `trl`, `vertexai`, `voyageai`, `xformers`
- Prefixes: `a2a-sdk`, `agno-`, `anthropic`, `autogen`, `chromadb`, `claude-agent-sdk`, `claude-code-sdk`, `cohere`, `crewai`, `diffusers`, `dspy-`, `e2b-`, `faiss`, `fastmcp`, `google-adk`, `google-cloud-aiplatform`, `google-genai`, `google-generativeai`, `guardrails`, `huggingface`, `keras`, `langchain`, `langgraph`, `langsmith`, `letta-`, `litellm`, `llama-cpp`, `llama-index`, `llamaindex`, `mcp-`, `mistralai`, `mlx-`, `nemo-guardrails`, `nemoguardrails`, `ollama`, `onnxruntime`, `openai`, `peft`, `pgvector`, `pinecone`, `pydantic-ai`, `qdrant`, `rebuff`, `safetensors`, `semantic-kernel`, `sentence-transformers`, `smolagents`, `strands-agents`, `tensorflow`, `tiktoken`, `tokenizers`, `torch`, `transformers`, `vllm`, `weaviate`
- Words: `llm`, `mcp`

### npm

- Scopes, every package of which matches: `@ai-sdk`, `@anthropic-ai`, `@huggingface`, `@lancedb`, `@langchain`, `@llamaindex`, `@mastra`, `@mistralai`, `@mlc-ai`, `@modelcontextprotocol`, `@openai`, `@pinecone-database`, `@qdrant`, `@smithery`, `@tensorflow`, `@tensorflow-models`, `@xenova`, `@zilliz`
- Names: `@aws-sdk/client-bedrock-agent-runtime`, `@aws-sdk/client-bedrock-runtime`, `@browserbasehq/stagehand`, `@google-cloud/aiplatform`, `@google-cloud/vertexai`, `@google/adk`, `@google/genai`, `@google/generative-ai`, `ai`, `fastmcp`, `groq-sdk`, `js-tiktoken`, `node-llama-cpp`, `replicate`, `tiktoken`
- Prefixes: `anthropic`, `autogen`, `chromadb`, `cohere`, `crewai`, `faiss`, `guardrails`, `langchain`, `langgraph`, `litellm`, `llama-index`, `llama_index`, `llamaindex`, `mcp-`, `mcp_`, `nemo-guardrails`, `nemo_guardrails`, `ollama`, `onnxruntime`, `openai`, `pgvector`, `pinecone`, `qdrant`, `rebuff`, `safetensors`, `tensorflow`, `tokenizers`, `torch`, `transformers`, `weaviate`
- Words: `llm`, `mcp`

### Container images

An image is inventoried when its reference, in lower case, contains one of `chroma`, `huggingface`, `litellm`, `llama`, `lmdeploy`, `localai`, `milvus`, `model`, `ollama`, `onnxruntime`, `pgvector`, `pytorch`, `qdrant`, `sglang`, `tensorflow`, `text-embeddings-inference`, `text-generation-inference`, `tgi`, `triton`, `vllm` or `weaviate`, or has `mcp` or `tei` as one of its parts, such as Docker's MCP catalog images under mcp/. These are substrings: an unrelated image whose name contains one of them is inventoried too.

## Not read

These declare or change what is installed but are not read, and leave no gap. Review changes to them by other means.

- Manifests outside the project root: workspace members (a gap when `workspaces` lists them), other `package.json` files, `requirements*.txt` files in subdirectories and pip-tools `*.in` files.
- `setup.py`, `setup.cfg` and dependencies declared dynamic in `pyproject.toml`; conda `environment.yml`; `[tool.hatch.envs]` environments.
- Index and registry choices: `--index-url`, `--extra-index-url`, `--find-links` and `--trusted-host` in requirements files, `[[tool.uv.index]]`, Poetry and PDM sources, and `.npmrc`. Packages from another index are recorded as PyPI packages unless a uv or Poetry source names them.
- `bundleDependencies`, which npm installs from `dependencies` anyway.
- Kubernetes manifests, Helm charts and `.devcontainer` configuration.
