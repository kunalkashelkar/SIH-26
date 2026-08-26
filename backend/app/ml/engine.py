from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

from app.schemas.ml import MLPredictionInput, MLPredictionResponse

logger = logging.getLogger(__name__)

# Default location for the Phase 14 final model artifacts
MODEL_DIR = Path(__file__).parent.parent.parent / "final_model"


class MLEngine:
    """
    Singleton ML Inference Engine for XGBoost Vulnerability Classification.
    Loads Phase 14 preprocessor.pkl and xgboost_vulnerability_model.json once on startup.
    """
    _instance: Optional["MLEngine"] = None

    def __init__(self, model_dir: Optional[Path] = None):
        self.model_dir = model_dir or MODEL_DIR
        self.model: Optional[xgb.XGBClassifier] = None
        self.preprocessor: Any = None
        self.metadata: Dict[str, Any] = {}
        self.raw_feature_names: list[str] = []
        self.processed_feature_names: list[str] = []
        self._is_loaded = False
        self._load_artifacts()

    @classmethod
    def get_instance(cls) -> "MLEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_artifacts(self) -> None:
        try:
            model_path = self.model_dir / "xgboost_vulnerability_model.json"
            preprocessor_path = self.model_dir / "preprocessor.pkl"
            metadata_path = self.model_dir / "model_metadata.json"
            raw_names_path = self.model_dir / "raw_feature_names.json"
            processed_names_path = self.model_dir / "processed_feature_names.json"

            if not model_path.exists() or not preprocessor_path.exists():
                logger.warning(f"ML artifacts not found in {self.model_dir}. MLEngine initialized in standby.")
                return

            # 1. Load Preprocessor via joblib
            self.preprocessor = joblib.load(preprocessor_path)
            logger.info(f"Loaded ML preprocessor from {preprocessor_path}")

            # 2. Load XGBoost Classifier
            self.model = xgb.XGBClassifier()
            self.model.load_model(str(model_path))
            logger.info(f"Loaded XGBoost model from {model_path}")

            # 3. Load Metadata & Feature Names
            if metadata_path.exists():
                with open(metadata_path, "r") as f:
                    self.metadata = json.load(f)

            if raw_names_path.exists():
                with open(raw_names_path, "r") as f:
                    self.raw_feature_names = json.load(f)

            if processed_names_path.exists():
                with open(processed_names_path, "r") as f:
                    self.processed_feature_names = json.load(f)

            self._is_loaded = True
            logger.info("MLEngine successfully initialized with 19 raw -> 27 processed feature transformation.")
        except Exception as e:
            logger.error(f"Failed to load ML artifacts from {self.model_dir}: {e}", exc_info=True)
            self._is_loaded = False

    @property
    def is_ready(self) -> bool:
        return self._is_loaded and self.model is not None and self.preprocessor is not None

    def predict(self, feature_dict: Dict[str, Any]) -> MLPredictionResponse:
        """
        Takes a dictionary of the 19 raw features, transforms them to 27 features via preprocessor,
        and returns prediction and probabilities.
        """
        if not self.is_ready:
            raise RuntimeError("MLEngine is not initialized with model artifacts.")

        # Ensure all 19 raw features are present in DataFrame
        df_raw = pd.DataFrame([feature_dict])

        # Preprocess: 19 raw -> 27 processed
        try:
            X_processed = self.preprocessor.transform(df_raw)
        except Exception as e:
            logger.error(f"Preprocessing error: {e}")
            raise ValueError(f"Failed to preprocess features: {e}")

        if X_processed.shape[1] != 27:
            raise ValueError(
                f"Preprocessor output dimension mismatch: expected 27 features, got {X_processed.shape[1]}"
            )

        # Predict
        try:
            pred = int(self.model.predict(X_processed)[0])
            proba = self.model.predict_proba(X_processed)[0]
            not_vuln_prob = float(proba[0])
            vuln_prob = float(proba[1])
        except Exception as e:
            logger.error(f"XGBoost inference error: {e}")
            raise RuntimeError(f"Model inference failed: {e}")

        label = "Vulnerable" if pred == 1 else "Not Vulnerable"

        return MLPredictionResponse(
            prediction=pred,
            label=label,
            vulnerable_probability=round(vuln_prob, 4),
            not_vulnerable_probability=round(not_vuln_prob, 4),
            model_name=self.metadata.get("model_file", "xgboost_vulnerability_model.json"),
            model_type=self.metadata.get("model_type", "XGBoost"),
            raw_feature_count=19,
            processed_feature_count=27
        )
