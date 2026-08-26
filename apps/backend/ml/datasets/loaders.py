import os
import sys
from typing import Tuple, List, Optional
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

# Ensure backend root is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from ml.datasets.preprocessing import extract_numeric_features

DATASETS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../../datasets")
)


def load_cicids2017(
    benign_only: bool = False,
    csv_filename: str = "CICIDS2017_sample.csv",
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Loads CICIDS2017 flow features from CSV.
    If benign_only is True, filters only 'BENIGN' records.
    Returns: (X, y, feature_names)
    """
    file_path = os.path.join(DATASETS_DIR, "CICIDS2017", csv_filename)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"CICIDS2017 dataset not found at {file_path}")

    df = pd.read_csv(file_path)

    # Standardize column name for Label
    label_col = "Label"
    if label_col not in df.columns:
        for col in df.columns:
            if col.strip().lower() == "label":
                label_col = col
                break

    if benign_only:
        df = df[df[label_col].astype(str).str.upper() == "BENIGN"]

    return extract_numeric_features(df, label_col=label_col)


def load_nsl_kdd(
    benign_only: bool = False,
    split: str = "train",
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Loads NSL-KDD dataset.
    split: 'train' (KDDTrain+.csv) or 'test' (KDDTest+.csv)
    """
    filename = "KDDTrain+.csv" if split == "train" else "KDDTest+.csv"
    file_path = os.path.join(DATASETS_DIR, "NSL-KDD", filename)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"NSL-KDD dataset not found at {file_path}")

    df = pd.read_csv(file_path, header=None)
    label_col = 41
    if benign_only:
        df = df[df[label_col].astype(str).str.lower() == "normal"]

    if 42 in df.columns:
        df = df.drop(columns=[42])

    return extract_numeric_features(df, label_col=label_col)


def train_test_split_stratified(
    X: np.ndarray,
    y: np.ndarray,
    test_size: float = 0.2,
    random_state: int = 42,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """
    Performs stratified train/test split so rare attack categories are preserved.
    """
    unique_classes, counts = np.unique(y, return_counts=True)
    if len(unique_classes) <= 1 or np.min(counts) < 2:
        return train_test_split(
            X, y, test_size=test_size, random_state=random_state, shuffle=True
        )

    return train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
        shuffle=True,
    )
