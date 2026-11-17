"""Discovery cases for models: weight files, registry references, API models and serving."""

from __future__ import annotations

from .artifacts import digest_bytes, gguf, hex40, onnx, pickle_benign, safetensors, torch_archive
from .build import (
    DATA,
    ML_MODEL,
    as_json,
    case,
    decoy,
    edge,
    ex,
    has,
    lic,
    loc,
    purl,
    sha,
    text,
    typ,
    ver,
)
from .model import Case

CHAT_TEMPLATE = (
    "{% for message in messages %}<|{{ message.role }}|>\n{{ message.content }}<|end|>\n"
    "{% endfor %}<|assistant|>\n"
)


def gguf_local() -> Case:
    path = "models/phi-3-mini-4k-instruct-q4.gguf"
    weights = gguf(
        [
            ("general.architecture", "phi3"),
            ("general.name", "Phi-3 Mini 4K Instruct"),
            ("general.license", "mit"),
            ("general.file_type", 15),
            ("general.quantization_version", 2),
            ("phi3.context_length", 4096),
            ("tokenizer.chat_template", CHAT_TEMPLATE),
        ],
        "m01",
    )
    return case(
        "m01-gguf-local",
        "Quantized GGUF weights in the repository",
        {
            path: weights,
            "README.md": text(
                """
                # Local assistant

                Runs the quantized model in `models/` with llama.cpp.
                """
            ),
        },
        [
            ex(
                "m01.gguf",
                "model",
                "model-file",
                "phi-3-mini-4k-instruct-q4",
                attrs=[
                    typ(ML_MODEL),
                    sha(path),
                    loc(path),
                    has("architecture", "phi3"),
                    lic("MIT"),
                ],
            )
        ],
        surface="GGUF weight file with header metadata",
        sources=("GGUF", "AIsbom", "Syft", "Trusera", "cdxgen", "agent-bom"),
    )


def safetensors_with_card() -> Case:
    root = "models/sentiment-distil-v2"
    weights = safetensors(
        [
            ("classifier.weight", "F32", (3, 4), digest_bytes("m02:w", 48)),
            ("classifier.bias", "F32", (3,), digest_bytes("m02:b", 12)),
        ],
        {"format": "pt"},
    )
    card = text(
        """
        ---
        license: apache-2.0
        base_model: distilbert/distilbert-base-uncased
        datasets:
        - stanfordnlp/sst2
        pipeline_tag: text-classification
        library_name: transformers
        language:
        - en
        ---

        # sentiment-distil-v2

        Three-class sentiment classifier fine-tuned for support tickets.
        """
    )
    config = {
        "_name_or_path": "acme-ml/sentiment-distil-v2",
        "architectures": ["DistilBertForSequenceClassification"],
        "model_type": "distilbert",
        "num_labels": 3,
        "transformers_version": "4.46.2",
    }
    return case(
        "m02-safetensors-card",
        "SafeTensors weights with a configuration and a model card",
        {
            f"{root}/model.safetensors": weights,
            f"{root}/config.json": as_json(config),
            f"{root}/README.md": card,
            f"{root}/tokenizer_config.json": as_json(
                {"do_lower_case": True, "model_max_length": 512}
            ),
        },
        [
            ex(
                "m02.weights",
                "model",
                "model-file",
                "sentiment-distil-v2",
                attrs=[
                    typ(ML_MODEL),
                    sha(f"{root}/model.safetensors"),
                    loc(root),
                    lic("Apache-2.0"),
                    has("task", "text-classification"),
                    has("architecture", "distilbert"),
                ],
            ),
            ex("m02.base", "model", "base-model-reference", "distilbert-base-uncased"),
            ex("m02.dataset", "data", "training-dataset-reference", "sst2", attrs=[typ(DATA)]),
        ],
        edges=[
            edge("m02.weights", "m02.base", "derived from"),
            edge("m02.weights", "m02.dataset", "trained on"),
        ],
        surface="SafeTensors weights, config.json and a model card with base model and datasets",
        sources=("SafeTensors", "Hugging Face model card", "CycloneDX ML-BOM", "AIsbom", "Syft"),
    )


def onnx_local() -> Case:
    path = "models/intent-router.onnx"
    return case(
        "m03-onnx-local",
        "ONNX model in the repository",
        {path: onnx("bench-exporter", "intent_router")},
        [
            ex(
                "m03.onnx",
                "model",
                "model-file",
                "intent-router",
                attrs=[typ(ML_MODEL), sha(path), loc(path)],
            )
        ],
        surface="ONNX model file",
        sources=("ONNX", "AIsbom", "Trusera", "agent-bom"),
    )


def torch_checkpoint() -> Case:
    path = "checkpoints/reranker-epoch3.pt"
    return case(
        "m04-torch-checkpoint",
        "PyTorch checkpoint archive holding only data",
        {path: torch_archive("reranker-epoch3", pickle_benign("m04"))},
        [
            ex(
                "m04.checkpoint",
                "model",
                "model-file",
                "reranker-epoch3",
                attrs=[typ(ML_MODEL), sha(path), loc(path)],
            )
        ],
        surface="PyTorch zip checkpoint (pickle inside)",
        sources=("PyTorch", "AIsbom", "Trusera", "agent-bom"),
    )


def hub_references() -> Case:
    minilm = hex40("m05:minilm")
    finbert = hex40("m05:finbert")
    source = text(
        f"""
        from sentence_transformers import SentenceTransformer
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        # evaluated decoy-org/decoy-rerank-9b last quarter and rejected it
        EMBEDDER = SentenceTransformer(
            "sentence-transformers/all-MiniLM-L6-v2",
            revision="{minilm}",
        )

        CLASSIFIER_ID = "ProsusAI/finbert"
        CLASSIFIER_REVISION = "{finbert}"
        tokenizer = AutoTokenizer.from_pretrained(CLASSIFIER_ID, revision=CLASSIFIER_REVISION)
        classifier = AutoModelForSequenceClassification.from_pretrained(
            CLASSIFIER_ID, revision=CLASSIFIER_REVISION
        )
        """
    )
    return case(
        "m05-hub-references",
        "Hugging Face models loaded by pinned revision in Python",
        {"src/embed.py": source},
        [
            ex(
                "m05.minilm",
                "model",
                "hub-model-reference",
                "all-MiniLM-L6-v2",
                attrs=[
                    typ(ML_MODEL),
                    ver(minilm),
                    purl(f"pkg:huggingface/sentence-transformers/all-MiniLM-L6-v2@{minilm}"),
                    loc("src/embed.py"),
                ],
            ),
            ex(
                "m05.finbert",
                "model",
                "hub-model-reference",
                "finbert",
                attrs=[
                    typ(ML_MODEL),
                    ver(finbert),
                    purl(f"pkg:huggingface/ProsusAI/finbert@{finbert}"),
                    loc("src/embed.py"),
                ],
            ),
        ],
        decoys=[
            decoy(
                "m05.comment",
                "decoy-rerank-9b",
                "m05.minilm",
                "a model named only in a comment is not loaded",
            )
        ],
        surface="from_pretrained calls with a literal and with a constant identifier",
        sources=("Hugging Face Hub", "PURL huggingface type", "cdxgen", "Cisco", "Trusera"),
    )


def api_models() -> Case:
    python = text(
        """
        import logging

        import anthropic
        from openai import OpenAI

        logger = logging.getLogger(__name__)
        openai_client = OpenAI()
        claude = anthropic.Anthropic()


        def draft(prompt: str) -> str:
            response = openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
            )
            return response.choices[0].message.content or ""


        def review(draft_text: str) -> str:
            message = claude.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1024,
                messages=[{"role": "user", "content": draft_text}],
            )
            return message.content[0].text


        logger.info("migrated away from decoy-legacy-model-v0")
        """
    )
    typescript = text(
        """
        import { GoogleGenerativeAI } from "@google/generative-ai";

        const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY ?? "");
        export const summarizer = genAI.getGenerativeModel({ model: "gemini-1.5-pro" });
        """
    )
    config = text(
        """
        fallback:
          provider: mistral
          model: mistral-large-latest
          temperature: 0.2
        """
    )
    return case(
        "m06-api-models",
        "Hosted models selected in Python, TypeScript and YAML",
        {"src/assistant.py": python, "web/summarize.ts": typescript, "config/llm.yaml": config},
        [
            ex(
                "m06.gpt",
                "model",
                "api-model",
                "gpt-4o-mini",
                attrs=[typ(ML_MODEL), loc("src/assistant.py")],
            ),
            ex(
                "m06.claude",
                "model",
                "api-model",
                "claude-3-5-sonnet-20241022",
                attrs=[typ(ML_MODEL), loc("src/assistant.py")],
            ),
            ex(
                "m06.gemini",
                "model",
                "api-model",
                "gemini-1.5-pro",
                attrs=[typ(ML_MODEL), loc("web/summarize.ts")],
            ),
            ex(
                "m06.mistral",
                "model",
                "api-model",
                "mistral-large-latest",
                attrs=[typ(ML_MODEL), loc("config/llm.yaml")],
            ),
        ],
        decoys=[
            decoy(
                "m06.log",
                "decoy-legacy-model-v0",
                "m06.gpt",
                "a model named in a log message is not called",
            )
        ],
        surface="model identifiers passed to provider SDKs and set in configuration",
        sources=("Trusera", "Cisco", "cdxgen", "agent-bom"),
    )


def ollama_modelfile() -> Case:
    modelfile = text(
        '''
        FROM llama3.1:8b-instruct-q4_K_M
        PARAMETER temperature 0.3
        PARAMETER num_ctx 8192
        SYSTEM """You answer questions about shipping policy. Cite the policy section."""
        '''
    )
    return case(
        "m07-ollama-modelfile",
        "Ollama Modelfile deriving a local model",
        {
            "Modelfile": modelfile,
            "scripts/create.sh": text("#!/bin/sh\nollama create shipping-helper -f Modelfile"),
        },
        [
            ex(
                "m07.base",
                "model",
                "base-model-reference",
                "llama3.1",
                attrs=[typ(ML_MODEL), has("tag", "8b-instruct-q4_K_M"), loc("Modelfile")],
            )
        ],
        surface="Ollama Modelfile",
        sources=("Ollama", "cdxgen", "Trusera"),
    )


def lora_adapter() -> Case:
    root = "adapters/support-lora"
    config = {
        "base_model_name_or_path": "meta-llama/Llama-3.1-8B-Instruct",
        "peft_type": "LORA",
        "task_type": "CAUSAL_LM",
        "r": 16,
        "lora_alpha": 32,
        "target_modules": ["q_proj", "v_proj"],
    }
    weights = safetensors(
        [("base_model.model.q_proj.lora_A.weight", "F32", (2, 4), digest_bytes("m08", 32))],
        {"format": "pt"},
    )
    return case(
        "m08-lora-adapter",
        "LoRA adapter with a declared base model",
        {
            f"{root}/adapter_config.json": as_json(config),
            f"{root}/adapter_model.safetensors": weights,
        },
        [
            ex(
                "m08.adapter",
                "model",
                "adapter",
                "support-lora",
                attrs=[typ(ML_MODEL), sha(f"{root}/adapter_model.safetensors"), loc(root)],
            ),
            ex("m08.base", "model", "base-model-reference", "Llama-3.1-8B-Instruct"),
        ],
        edges=[edge("m08.adapter", "m08.base", "adapts")],
        surface="PEFT adapter directory",
        sources=("PEFT", "CycloneDX ML-BOM", "AIsbom"),
    )


def served_model() -> Case:
    revision = hex40("m09:mistral")
    manifest = text(
        f"""
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: chat-backend
        spec:
          replicas: 1
          selector:
            matchLabels:
              app: chat-backend
          template:
            metadata:
              labels:
                app: chat-backend
            spec:
              containers:
                - name: vllm
                  image: vllm/vllm-openai:v0.6.3
                  args:
                    - --model
                    - mistralai/Mistral-7B-Instruct-v0.3
                    - --revision
                    - {revision}
                    - --max-model-len
                    - "8192"
                  resources:
                    limits:
                      nvidia.com/gpu: 1
        """
    )
    return case(
        "m09-served-model",
        "Model served by an inference image in a Kubernetes manifest",
        {"deploy/vllm.yaml": manifest},
        [
            ex(
                "m09.model",
                "model",
                "served-model",
                "Mistral-7B-Instruct-v0.3",
                attrs=[typ(ML_MODEL), ver(revision), loc("deploy/vllm.yaml")],
            ),
            ex(
                "m09.image",
                "platform",
                "inference-image",
                "vllm-openai",
                attrs=[ver("v0.6.3"), loc("deploy/vllm.yaml")],
            ),
        ],
        edges=[edge("m09.image", "m09.model", "serves")],
        surface="Kubernetes manifest for a model server",
        sources=("Kubernetes", "Trusera", "Cisco", "agent-bom", "k8s-aibom"),
    )


def notebook_model() -> Case:
    revision = hex40("m10:bart")
    notebook = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# Summarization evaluation\n"]},
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "from transformers import pipeline\n",
                    "\n",
                    "summarizer = pipeline(\n",
                    '    "summarization",\n',
                    '    model="facebook/bart-large-cnn",\n',
                    f'    revision="{revision}",\n',
                    ")\n",
                ],
            },
        ],
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    return case(
        "m10-notebook-model",
        "Model loaded in a Jupyter notebook",
        {"notebooks/summarize-eval.ipynb": as_json(notebook)},
        [
            ex(
                "m10.bart",
                "model",
                "hub-model-reference",
                "bart-large-cnn",
                attrs=[typ(ML_MODEL), ver(revision), loc("notebooks/summarize-eval.ipynb")],
            )
        ],
        surface="Jupyter notebook code cell",
        sources=("Jupyter", "Trusera", "Cisco"),
    )


def cases() -> list[Case]:
    return [
        gguf_local(),
        safetensors_with_card(),
        onnx_local(),
        torch_checkpoint(),
        hub_references(),
        api_models(),
        ollama_modelfile(),
        lora_adapter(),
        served_model(),
        notebook_model(),
    ]
