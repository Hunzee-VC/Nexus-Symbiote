"""Discovery cases for the AI platform: packages, images, cloud AI resources and endpoints."""

from __future__ import annotations

import base64

from .artifacts import digest_bytes, hex64
from .build import ML_MODEL, as_json, case, decoy, edge, ex, has, loc, purl, text, typ, ver
from .model import Case, Expect


def _package(expect_id: str, token: str, version: str, package_url: str) -> Expect:
    return ex(expect_id, "platform", "ai-package", token, attrs=[ver(version), purl(package_url)])


def python_packages() -> Case:
    pins = [
        ("openai", "1.51.2"),
        ("anthropic", "0.39.0"),
        ("langchain", "0.3.7"),
        ("transformers", "4.46.2"),
        ("torch", "2.5.1"),
        ("chromadb", "0.5.18"),
    ]
    lines = [f"{name}=={version}" for name, version in pins] + ["# decoy-llm-sdk==9.9.9"]
    return case(
        "p01-python-packages",
        "Pinned Python AI packages",
        {"requirements.txt": ("\n".join(lines) + "\n").encode()},
        [
            _package(f"p01.{name}", name, version, f"pkg:pypi/{name}@{version}")
            for name, version in pins
        ],
        decoys=[
            decoy(
                "p01.comment",
                "decoy-llm-sdk",
                "p01.openai",
                "a commented-out requirement is not installed",
            )
        ],
        surface="requirements.txt",
        sources=("PURL", "CycloneDX", "Syft", "cdxgen", "agent-bom", "AIsbom"),
    )


def javascript_packages() -> Case:
    pins = [
        ("@anthropic-ai/sdk", "0.32.1"),
        ("openai", "4.71.1"),
        ("@modelcontextprotocol/sdk", "1.0.3"),
        ("@langchain/core", "0.3.18"),
    ]
    dependencies = dict(pins)
    packages: dict[str, object] = {
        "": {"name": "storefront-assistant", "version": "1.0.0", "dependencies": dependencies}
    }
    for name, version in pins:
        tarball = name.rsplit("/", 1)[-1]
        integrity = base64.b64encode(digest_bytes(f"p02:{name}", 64)).decode()
        packages[f"node_modules/{name}"] = {
            "version": version,
            "resolved": f"https://registry.npmjs.org/{name}/-/{tarball}-{version}.tgz",
            "integrity": f"sha512-{integrity}",
        }
    manifest = {
        "name": "storefront-assistant",
        "version": "1.0.0",
        "private": True,
        "dependencies": dependencies,
    }
    lock = {
        "name": "storefront-assistant",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": packages,
    }
    return case(
        "p02-javascript-packages",
        "JavaScript AI packages with a lockfile",
        {"package.json": as_json(manifest), "package-lock.json": as_json(lock)},
        [
            _package(
                "p02.anthropic", "@anthropic-ai/sdk", "0.32.1", "pkg:npm/%40anthropic-ai/sdk@0.32.1"
            ),
            _package("p02.openai", "openai", "4.71.1", "pkg:npm/openai@4.71.1"),
            _package(
                "p02.mcp",
                "@modelcontextprotocol/sdk",
                "1.0.3",
                "pkg:npm/%40modelcontextprotocol/sdk@1.0.3",
            ),
            _package(
                "p02.langchain", "@langchain/core", "0.3.18", "pkg:npm/%40langchain/core@0.3.18"
            ),
        ],
        surface="package.json with package-lock.json",
        sources=("PURL", "CycloneDX", "Syft", "cdxgen", "agent-bom"),
    )


def polyglot_packages() -> Case:
    go_mod = text(
        """
        module example.com/acme/assistant

        go 1.23

        require (
        \tgithub.com/sashabaranov/go-openai v1.35.6
        \tgithub.com/tmc/langchaingo v0.1.12
        )
        """
    )
    pom = text(
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <modelVersion>4.0.0</modelVersion>
          <groupId>example.acme</groupId>
          <artifactId>assistant-service</artifactId>
          <version>1.0.0</version>
          <dependencies>
            <dependency>
              <groupId>dev.langchain4j</groupId>
              <artifactId>langchain4j</artifactId>
              <version>0.36.2</version>
            </dependency>
            <dependency>
              <groupId>com.openai</groupId>
              <artifactId>openai-java</artifactId>
              <version>0.8.0</version>
            </dependency>
          </dependencies>
        </project>
        """
    )
    cargo = text(
        """
        [package]
        name = "assistant-cli"
        version = "0.1.0"
        edition = "2021"

        [dependencies]
        async-openai = "=0.26.0"
        """
    )
    cargo_lock = text(
        f"""
        version = 3

        [[package]]
        name = "assistant-cli"
        version = "0.1.0"
        dependencies = [
         "async-openai",
        ]

        [[package]]
        name = "async-openai"
        version = "0.26.0"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        checksum = "{hex64("p03:async-openai")}"
        """
    )
    gemfile_lock = text(
        """
        GEM
          remote: https://rubygems.org/
          specs:
            ruby-openai (7.3.1)

        PLATFORMS
          ruby

        DEPENDENCIES
          ruby-openai (= 7.3.1)

        BUNDLED WITH
           2.5.22
        """
    )
    return case(
        "p03-polyglot-packages",
        "AI SDKs in Go, Java, Rust and Ruby manifests",
        {
            "go.mod": go_mod,
            "pom.xml": pom,
            "Cargo.toml": cargo,
            "Cargo.lock": cargo_lock,
            "Gemfile": text('source "https://rubygems.org"\n\ngem "ruby-openai", "7.3.1"'),
            "Gemfile.lock": gemfile_lock,
        },
        [
            _package(
                "p03.go-openai",
                "go-openai",
                "v1.35.6",
                "pkg:golang/github.com/sashabaranov/go-openai@v1.35.6",
            ),
            _package(
                "p03.langchaingo",
                "langchaingo",
                "v0.1.12",
                "pkg:golang/github.com/tmc/langchaingo@v0.1.12",
            ),
            _package(
                "p03.langchain4j",
                "langchain4j",
                "0.36.2",
                "pkg:maven/dev.langchain4j/langchain4j@0.36.2",
            ),
            _package(
                "p03.openai-java", "openai-java", "0.8.0", "pkg:maven/com.openai/openai-java@0.8.0"
            ),
            _package("p03.async-openai", "async-openai", "0.26.0", "pkg:cargo/async-openai@0.26.0"),
            _package("p03.ruby-openai", "ruby-openai", "7.3.1", "pkg:gem/ruby-openai@7.3.1"),
        ],
        surface="go.mod, pom.xml, Cargo and Bundler manifests",
        sources=("PURL", "CycloneDX", "Syft", "cdxgen", "Cisco", "Trusera"),
    )


def container_images() -> Case:
    compose = text(
        """
        services:
          ollama:
            image: ollama/ollama:0.4.2
            volumes:
              - ollama:/root/.ollama
          qdrant:
            image: qdrant/qdrant:v1.12.4
          tgi:
            image: ghcr.io/huggingface/text-generation-inference:2.4.0
            command: --model-id HuggingFaceH4/zephyr-7b-beta
        volumes:
          ollama: {}
        """
    )
    dockerfile = text(
        """
        FROM pytorch/pytorch:2.5.1-cuda12.4-cudnn9-runtime
        COPY . /app
        CMD ["python", "/app/serve.py"]
        """
    )
    return case(
        "p04-container-images",
        "AI runtime images in Compose and a Dockerfile",
        {"docker-compose.yml": compose, "Dockerfile": dockerfile},
        [
            ex(
                "p04.ollama",
                "platform",
                "container-image",
                "ollama/ollama",
                attrs=[ver("0.4.2"), loc("docker-compose.yml")],
            ),
            ex(
                "p04.qdrant",
                "platform",
                "container-image",
                "qdrant/qdrant",
                attrs=[ver("v1.12.4"), loc("docker-compose.yml")],
            ),
            ex(
                "p04.tgi",
                "platform",
                "container-image",
                "text-generation-inference",
                attrs=[ver("2.4.0"), loc("docker-compose.yml")],
            ),
            ex(
                "p04.pytorch",
                "platform",
                "container-image",
                "pytorch/pytorch",
                attrs=[ver("2.5.1-cuda12.4-cudnn9-runtime"), loc("Dockerfile")],
            ),
            ex("p04.zephyr", "model", "served-model", "zephyr-7b-beta", attrs=[typ(ML_MODEL)]),
        ],
        edges=[edge("p04.tgi", "p04.zephyr", "serves")],
        surface="Compose services and Dockerfile base images",
        sources=("Docker", "Trusera", "agent-bom", "Cisco", "cdxgen"),
    )


def cloud_ai_resources() -> Case:
    terraform = text(
        """
        resource "aws_bedrockagent_agent" "claims_agent" {
          agent_name              = "claims-intake-agent"
          agent_resource_role_arn = aws_iam_role.agent.arn
          foundation_model        = "anthropic.claude-3-5-sonnet-20241022-v2:0"
          instruction             = "Collect the claim details and open a case."
        }

        resource "azurerm_cognitive_deployment" "chat" {
          name                 = "gpt4o-prod"
          cognitive_account_id = azurerm_cognitive_account.openai.id

          model {
            format  = "OpenAI"
            name    = "gpt-4o"
            version = "2024-08-06"
          }

          sku {
            name = "GlobalStandard"
          }
        }
        """
    )
    embed = text(
        """
        import json

        import boto3

        runtime = boto3.client("bedrock-runtime")


        def embed(passage: str) -> list[float]:
            response = runtime.invoke_model(
                modelId="amazon.titan-embed-text-v2:0",
                body=json.dumps({"inputText": passage}),
            )
            return json.loads(response["body"].read())["embedding"]
        """
    )
    return case(
        "p05-cloud-ai-resources",
        "Managed AI resources in Terraform and a cloud SDK call",
        {"infra/main.tf": terraform, "src/embed.py": embed},
        [
            ex(
                "p05.agent",
                "platform",
                "cloud-agent",
                "claims-intake-agent",
                "claims_agent",
                attrs=[loc("infra/main.tf")],
            ),
            ex(
                "p05.bedrock-model",
                "model",
                "cloud-model",
                "anthropic.claude-3-5-sonnet-20241022-v2:0",
                attrs=[typ(ML_MODEL)],
            ),
            ex(
                "p05.azure",
                "platform",
                "cloud-model-deployment",
                "gpt4o-prod",
                attrs=[has("model version", "2024-08-06"), loc("infra/main.tf")],
            ),
            ex(
                "p05.titan",
                "model",
                "cloud-model",
                "amazon.titan-embed-text-v2:0",
                attrs=[typ(ML_MODEL), loc("src/embed.py")],
            ),
        ],
        edges=[edge("p05.agent", "p05.bedrock-model", "uses")],
        surface="Terraform AI resources and Bedrock runtime calls",
        sources=("Terraform", "Trusera", "Cisco", "agent-bom"),
    )


def endpoints_and_gateway() -> Case:
    env = text(
        """
        OPENAI_BASE_URL=https://llm-gateway.acme.example/v1
        OPENAI_API_KEY=
        OLLAMA_HOST=http://ollama.internal:11434
        LANGFUSE_HOST=https://langfuse.acme.example
        LANGFUSE_PUBLIC_KEY=
        """
    )
    litellm = text(
        """
        model_list:
          - model_name: router-fast
            litellm_params:
              model: azure/gpt-4o-mini
              api_base: https://acme-openai.openai.azure.com
              api_version: "2024-10-21"
          - model_name: router-deep
            litellm_params:
              model: anthropic/claude-3-7-sonnet-20250219
        """
    )
    return case(
        "p06-endpoints-gateway",
        "Model endpoints in an environment template and a gateway configuration",
        {".env.example": env, "litellm_config.yaml": litellm},
        [
            ex(
                "p06.gateway",
                "platform",
                "llm-endpoint",
                "llm-gateway.acme.example",
                attrs=[loc(".env.example")],
            ),
            ex(
                "p06.ollama",
                "platform",
                "llm-endpoint",
                "ollama.internal",
                attrs=[loc(".env.example")],
            ),
            ex(
                "p06.langfuse", "platform", "observability", "langfuse", attrs=[loc(".env.example")]
            ),
            ex(
                "p06.route",
                "platform",
                "model-route",
                "router-fast",
                attrs=[has("target model", "gpt-4o-mini"), loc("litellm_config.yaml")],
            ),
            ex(
                "p06.deep",
                "model",
                "api-model",
                "claude-3-7-sonnet-20250219",
                attrs=[typ(ML_MODEL), loc("litellm_config.yaml")],
            ),
        ],
        surface="environment templates and an LLM gateway configuration",
        sources=("LiteLLM", "Trusera", "Cisco"),
    )


def cases() -> list[Case]:
    return [
        python_packages(),
        javascript_packages(),
        polyglot_packages(),
        container_images(),
        cloud_ai_resources(),
        endpoints_and_gateway(),
    ]
