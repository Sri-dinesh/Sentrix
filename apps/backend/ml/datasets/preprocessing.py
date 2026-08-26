import os
import joblib
import numpy as np
import pandas as pd
from typing import List, Tuple, Optional
from sklearn.preprocessing import StandardScaler

# Path where default fitted scaler will be stored
DEFAULT_SCALER_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../models/scaler.joblib")
)


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans DataFrame by replacing infinity with NaN, dropping null rows,
    and stripping whitespace from column names.
    """
    cleaned = df.copy()
    # Strip whitespace from column names if strings
    cleaned.columns = [
        col.strip() if isinstance(col, str) else col for col in cleaned.columns
    ]

    # Replace positive and negative infinity with NaN
    cleaned.replace([np.inf, -np.inf], np.nan, inplace=True)
    # Fill remaining NaNs with column medians or drop
    cleaned.dropna(inplace=True)
    return cleaned


def extract_numeric_features(
    df: pd.DataFrame,
    label_col: str = "Label",
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Extracts ordered numeric feature columns and string labels from DataFrame.
    Returns: (X_numeric, y_labels, feature_names)
    """
    cleaned = clean_dataframe(df)

    if label_col in cleaned.columns:
        y = cleaned[label_col].astype(str).values
        feature_df = cleaned.drop(columns=[label_col])
    else:
        # If label is last column
        y = cleaned.iloc[:, -1].astype(str).values
        feature_df = cleaned.iloc[:, :-1]

    # Select only numeric columns (convert object/categorical where applicable)
    numeric_df = feature_df.select_dtypes(include=[np.number])
    feature_names = list(numeric_df.columns)
    X = numeric_df.values.astype(np.float32)

    return X, y, feature_names


def fit_and_save_scaler(
    X: np.ndarray,
    scaler_path: str = DEFAULT_SCALER_PATH,
) -> StandardScaler:
    """
    Fits a StandardScaler on input features and saves it to disk via joblib.
    """
    os.makedirs(os.path.dirname(scaler_path), exist_ok=True)
    scaler = StandardScaler()
    scaler.fit(X)
    joblib.dump(scaler, scaler_path)
    return scaler


def load_scaler(scaler_path: str = DEFAULT_SCALER_PATH) -> StandardScaler:
    """
    Loads a fitted StandardScaler from disk.
    """
    if not os.path.exists(scaler_path):
        raise FileNotFoundError(f"Fitted scaler not found at: {scaler_path}")
    return joblib.load(scaler_path)


def transform_features(
    X: np.ndarray,
    scaler: StandardScaler,
    clip_range: Tuple[float, float] = (-10.0, 10.0),
) -> np.ndarray:
    """
    Standardizes feature vector and clips extreme out-of-distribution values
    to protect downstream neural networks and tree models.
    """
    X_scaled = scaler.transform(X)
    if clip_range:
        X_scaled = np.clip(X_scaled, clip_range[0], clip_range[1])
    return X_scaled
