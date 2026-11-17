"""Discovery cases for data: datasets, dataset cards, pointers, retrieval stores and training files."""

from __future__ import annotations

import hashlib

from .artifacts import faiss_flat_index, hex40, hex64, pickle_benign
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
    sha,
    text,
    typ,
    ver,
)
from .model import Case


def hub_datasets() -> Case:
    imdb = hex40("d01:imdb")
    squad = hex40("d01:squad")
    source = text(
        f'''
        """Unlike decoy-corp/decoy-dataset-xl, this loader streams from disk."""

        from datasets import load_dataset

        train = load_dataset("stanfordnlp/imdb", split="train", revision="{imdb}")
        validation = load_dataset(
            "rajpurkar/squad_v2",
            split="validation",
            revision="{squad}",
        )
        '''
    )
    return case(
        "d01-hub-datasets",
        "Hugging Face datasets loaded by pinned revision",
        {"src/train.py": source},
        [
            ex(
                "d01.imdb",
                "data",
                "hub-dataset-reference",
                "stanfordnlp/imdb",
                attrs=[typ(DATA), ver(imdb), loc("src/train.py")],
            ),
            ex(
                "d01.squad",
                "data",
                "hub-dataset-reference",
                "squad_v2",
                attrs=[typ(DATA), ver(squad), loc("src/train.py")],
            ),
        ],
        decoys=[
            decoy(
                "d01.docstring",
                "decoy-dataset-xl",
                "d01.imdb",
                "a dataset named only in a docstring is not loaded",
            )
        ],
        surface="load_dataset calls",
        sources=("Hugging Face Datasets", "CycloneDX ML-BOM", "Cisco", "agent-bom"),
    )


def local_dataset_card() -> Case:
    root = "data/support-tickets"
    rows = text(
        """
        {"id": 1, "text": "My parcel arrived damaged.", "label": "damage"}
        {"id": 2, "text": "Where is my refund?", "label": "refund"}
        {"id": 3, "text": "The courier never came.", "label": "delivery"}
        """
    )
    card = text(
        """
        ---
        license: cc-by-4.0
        pretty_name: Support Tickets v3
        task_categories:
        - text-classification
        language:
        - en
        size_categories:
        - n<1K
        ---

        # Support Tickets v3

        Anonymized support tickets labelled by issue type.
        """
    )
    info = {
        "dataset_name": "support-tickets",
        "description": "Anonymized support tickets labelled by issue type.",
        "license": "cc-by-4.0",
        "features": {
            "id": {"dtype": "int64", "_type": "Value"},
            "text": {"dtype": "string", "_type": "Value"},
            "label": {"dtype": "string", "_type": "Value"},
        },
        "splits": {"train": {"name": "train", "num_examples": 3}},
        "version": {"version_str": "3.0.0", "major": 3, "minor": 0, "patch": 0},
    }
    return case(
        "d02-local-dataset-card",
        "Dataset files in the repository with a dataset card",
        {
            f"{root}/train.jsonl": rows,
            f"{root}/README.md": card,
            f"{root}/dataset_info.json": as_json(info),
        },
        [
            ex(
                "d02.dataset",
                "data",
                "dataset",
                "support-tickets",
                attrs=[
                    typ(DATA),
                    sha(f"{root}/train.jsonl"),
                    loc(root),
                    lic("CC-BY-4.0"),
                    ver("3.0.0"),
                ],
            )
        ],
        surface="dataset directory with README front matter and dataset_info.json",
        sources=("Hugging Face dataset card", "CycloneDX ML-BOM", "agent-bom", "Cisco"),
    )


def dvc_pointer() -> Case:
    md5 = hex64("d03:corpus")[:32]
    pointer = text(
        f"""
        outs:
        - md5: {md5}
          size: 48213377
          hash: md5
          path: corpus.parquet
        """
    )
    config = text(
        """
        [core]
            remote = warehouse
        ['remote "warehouse"']
            url = s3://acme-ml-data/dvcstore
        """
    )
    return case(
        "d03-dvc-pointer",
        "Dataset tracked by a DVC pointer and a remote",
        {"data/corpus.parquet.dvc": pointer, ".dvc/config": config, ".dvcignore": b""},
        [
            ex(
                "d03.dataset",
                "data",
                "versioned-dataset",
                "corpus.parquet",
                attrs=[typ(DATA), has("content hash", md5), loc("data/corpus.parquet.dvc")],
            ),
            ex("d03.remote", "data", "data-store", "acme-ml-data", attrs=[loc(".dvc/config")]),
        ],
        edges=[edge("d03.dataset", "d03.remote", "stored in")],
        surface="DVC pointer file and remote configuration",
        sources=("DVC", "Cisco"),
    )


def retrieval_pipeline() -> Case:
    config = text(
        """
        vector_store:
          provider: qdrant
          url: http://qdrant.internal:6333
          collection: kb-articles-v4
        embedding:
          provider: huggingface
          model: BAAI/bge-small-en-v1.5
        sources:
          - docs/kb
        chunking:
          size: 800
          overlap: 120
        """
    )
    ingest = text(
        """
        from langchain_community.document_loaders import DirectoryLoader
        from langchain_huggingface import HuggingFaceEmbeddings
        from langchain_qdrant import QdrantVectorStore
        from qdrant_client import QdrantClient

        client = QdrantClient(url="http://qdrant.internal:6333")
        embeddings = HuggingFaceEmbeddings(model_name="BAAI/bge-small-en-v1.5")
        store = QdrantVectorStore(
            client=client,
            collection_name="kb-articles-v4",
            embedding=embeddings,
        )
        documents = DirectoryLoader("docs/kb", glob="**/*.md").load()
        store.add_documents(documents)
        """
    )
    return case(
        "d04-retrieval-pipeline",
        "Retrieval pipeline: corpus, embedding model and vector store",
        {
            "rag/config.yaml": config,
            "rag/ingest.py": ingest,
            "docs/kb/returns.md": text("# Returns\n\nItems can be returned within 30 days."),
            "docs/kb/shipping.md": text("# Shipping\n\nOrders ship within two working days."),
        },
        [
            ex(
                "d04.store",
                "data",
                "vector-store",
                "qdrant",
                attrs=[has("collection", "kb-articles-v4"), has("endpoint", "qdrant.internal")],
            ),
            ex(
                "d04.embedding",
                "model",
                "embedding-model",
                "bge-small-en-v1.5",
                attrs=[typ(ML_MODEL)],
            ),
            ex("d04.corpus", "data", "knowledge-source", "docs/kb", attrs=[typ(DATA)]),
        ],
        edges=[
            edge("d04.store", "d04.embedding", "embedded with"),
            edge("d04.store", "d04.corpus", "indexes"),
        ],
        surface="retrieval configuration and ingestion code",
        sources=("LangChain", "Cisco", "agent-bom", "Trusera"),
    )


def vector_index_files() -> Case:
    root = "index/product-search"
    loader = text(
        """
        from langchain_community.vectorstores import FAISS
        from langchain_openai import OpenAIEmbeddings

        index = FAISS.load_local(
            "index/product-search",
            OpenAIEmbeddings(model="text-embedding-3-small"),
            allow_dangerous_deserialization=True,
        )
        """
    )
    return case(
        "d05-vector-index-files",
        "Committed FAISS index with its pickled document store",
        {
            f"{root}/index.faiss": faiss_flat_index(8, "d05"),
            f"{root}/index.pkl": pickle_benign("d05"),
            "search.py": loader,
        },
        [
            ex(
                "d05.index",
                "data",
                "vector-index",
                "product-search",
                attrs=[sha(f"{root}/index.faiss"), loc(root)],
            ),
            ex(
                "d05.embedding",
                "model",
                "embedding-model",
                "text-embedding-3-small",
                attrs=[typ(ML_MODEL), loc("search.py")],
            ),
        ],
        edges=[edge("d05.index", "d05.embedding", "embedded with")],
        surface="vector index files",
        sources=("FAISS", "Cisco"),
    )


def fine_tuning_data() -> Case:
    rows = text(
        """
        {"messages": [{"role": "user", "content": "I want my money back."}, {"role": "assistant", "content": "I can help with that refund."}]}
        {"messages": [{"role": "user", "content": "This is the third time I ask."}, {"role": "assistant", "content": "I am sorry for the delay. Here is the status."}]}
        """
    )
    launch = text(
        """
        from openai import OpenAI

        client = OpenAI()
        with open("finetune/train.jsonl", "rb") as handle:
            upload = client.files.create(file=handle, purpose="fine-tune")
        job = client.fine_tuning.jobs.create(
            training_file=upload.id,
            model="gpt-4o-mini-2024-07-18",
            suffix="refund-tone",
        )
        """
    )
    return case(
        "d06-fine-tuning-data",
        "Fine-tuning job with its training file",
        {"finetune/train.jsonl": rows, "finetune/launch.py": launch},
        [
            ex(
                "d06.train",
                "data",
                "training-file",
                "finetune/train.jsonl",
                attrs=[typ(DATA), sha("finetune/train.jsonl")],
            ),
            ex(
                "d06.base",
                "model",
                "base-model-reference",
                "gpt-4o-mini-2024-07-18",
                attrs=[typ(ML_MODEL), loc("finetune/launch.py")],
            ),
        ],
        edges=[edge("d06.base", "d06.train", "fine-tuned on")],
        surface="fine-tuning job creation with a local training file",
        sources=("OpenAI fine-tuning API", "CycloneDX ML-BOM", "Cisco"),
    )


def croissant_dataset() -> Case:
    root = "datasets/retail-returns-eval"
    rows = text(
        """
        order_id,reason,refunded
        9001,damaged,true
        9002,late,false
        """
    )
    metadata = {
        "@context": {
            "@vocab": "https://schema.org/",
            "cr": "http://mlcommons.org/croissant/",
            "sc": "https://schema.org/",
        },
        "@type": "sc:Dataset",
        "conformsTo": "http://mlcommons.org/croissant/1.0",
        "name": "retail-returns-eval",
        "description": "Evaluation set of retail return decisions.",
        "license": "https://creativecommons.org/licenses/by-sa/4.0/",
        "version": "1.2.0",
        "url": "https://data.acme.example/retail-returns-eval",
        "distribution": [
            {
                "@type": "cr:FileObject",
                "@id": "returns.csv",
                "name": "returns.csv",
                "contentUrl": "returns.csv",
                "encodingFormat": "text/csv",
                "sha256": hashlib.sha256(rows).hexdigest(),
            }
        ],
    }
    return case(
        "d07-croissant-dataset",
        "Evaluation dataset described by Croissant metadata",
        {f"{root}/returns.csv": rows, f"{root}/croissant.json": as_json(metadata)},
        [
            ex(
                "d07.dataset",
                "data",
                "dataset",
                "retail-returns-eval",
                attrs=[
                    typ(DATA),
                    ver("1.2.0"),
                    sha(f"{root}/returns.csv"),
                    has("license", "by-sa"),
                ],
            )
        ],
        surface="Croissant dataset metadata",
        sources=("MLCommons Croissant", "CycloneDX ML-BOM"),
    )


def cases() -> list[Case]:
    return [
        hub_datasets(),
        local_dataset_card(),
        dvc_pointer(),
        retrieval_pipeline(),
        vector_index_files(),
        fine_tuning_data(),
        croissant_dataset(),
    ]
