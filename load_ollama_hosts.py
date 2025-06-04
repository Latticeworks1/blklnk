"""
load_ollama_hosts

Utility for loading the Ollama hosts index Parquet dataset from Hugging Face.

Functions:
    load_ollama_hosts(verbose: bool = False) -> pd.DataFrame
"""

import pandas as pd
import logging


_PARQUET_URL = (
    "https://huggingface.co/datasets/latterworks/ollama-hosts-index/resolve/main/data/train-00000-of-00001.parquet"
)


def load_ollama_hosts(verbose: bool = False) -> pd.DataFrame:
    """
    Loads the Ollama hosts index dataset from Hugging Face into a pandas DataFrame.

    Args:
        verbose (bool): If True, prints preview and schema information.

    Returns:
        pd.DataFrame: Parsed dataset as a DataFrame.

    Raises:
        RuntimeError: If the file cannot be retrieved or parsed.
    """
    try:
        df = pd.read_parquet(_PARQUET_URL)
        if verbose:
            _print_debug_info(df)
        return df
    except Exception as e:
        raise RuntimeError(f"Failed to load Ollama hosts dataset: {e}") from e


def _print_debug_info(df: pd.DataFrame):
    """
    Outputs dataset preview and schema metadata.

    Args:
        df (pd.DataFrame): The dataset to inspect.
    """
    logging.basicConfig(level=logging.INFO)
    logging.info("Dataset loaded successfully.")
    logging.info("Preview:\n%s", df.head().to_string())
    logging.info("Schema:\n%s", df.dtypes.to_string())
    logging.info("Total rows: %d", len(df))
