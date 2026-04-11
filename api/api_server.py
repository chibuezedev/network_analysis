import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

import numpy as np
import tensorflow as tf
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

MODEL_PATH = "../outputs/production_model.h5"
PREPROCESSOR_PATH = "../outputs/preprocessors/preprocessor.pkl"
METADATA_PATH = "../outputs/model_metadata.json"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Network IDS API",
    description="Real-time Network Intrusion Detection System using Deep Learning",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class NetworkTraffic(BaseModel):
    """Network traffic feature vector"""

    features: List[float] = Field(
        ..., description="Network flow features (80+ features from CICFlowMeter)"
    )

    class Config:
        schema_extra = {"example": {"features": [0.5] * 80}}


class PredictionResponse(BaseModel):
    """Prediction response model"""

    success: bool
    prediction: str
    prediction_id: int
    confidence: float
    all_probabilities: Dict[str, float]
    action: str
    timestamp: str
    processing_time_ms: float


class BatchNetworkTraffic(BaseModel):
    """Batch prediction request"""

    traffic_batch: List[List[float]] = Field(
        ..., description="List of network flow feature vectors"
    )


class BatchPredictionResponse(BaseModel):
    """Batch prediction response"""

    success: bool
    predictions: List[Dict]
    total_samples: int
    processing_time_ms: float
    timestamp: str


class ModelStatus(BaseModel):
    """Model status response"""

    status: str
    model_loaded: bool
    model_name: str
    num_classes: int
    class_names: List[str]
    input_features: int
    model_metrics: Optional[Dict]


class IDSModelServer:
    """Model server for IDS inference"""

    def __init__(self, model_path: str, preprocessor_path: str, metadata_path: str):
        """
        Initialize model server

        Args:
            model_path: Path to trained model (.h5)
            preprocessor_path: Path to preprocessor (.pkl)
            metadata_path: Path to metadata (.json)
        """
        self.model = None
        self.preprocessor = None
        self.metadata = None
        self.class_names = []
        self.model_name = "Unknown"

        self._load_model(model_path)
        self._load_preprocessor(preprocessor_path)
        self._load_metadata(metadata_path)

        logger.info("✓ Model server initialized successfully")

    def _load_model(self, model_path: str):
        """Load trained Keras model"""
        try:
            self.model = tf.keras.models.load_model(model_path)
            logger.info(f"✓ Model loaded from {model_path}")
        except Exception as e:
            logger.error(f"✗ Failed to load model: {str(e)}")
            raise

    def _load_preprocessor(self, preprocessor_path: str):
        """Load preprocessor"""
        try:
            from preprocessors.preprocessor import AdvancedPreprocessor

            self.preprocessor = AdvancedPreprocessor.load(preprocessor_path)
            logger.info(f"✓ Preprocessor loaded from {preprocessor_path}")
        except Exception as e:
            logger.error(f"✗ Failed to load preprocessor: {str(e)}")
            raise

    def _load_metadata(self, metadata_path: str):
        """Load model metadata"""
        try:
            with open(metadata_path, "r") as f:
                self.metadata = json.load(f)
            self.class_names = self.metadata.get("class_names", [])
            self.model_name = self.metadata.get("model_name", "Unknown")
            logger.info(f"✓ Metadata loaded: {self.model_name}")
        except Exception as e:
            logger.warning(f"⚠ Failed to load metadata: {str(e)}")
            self.class_names = [
                "Benign",
                "Analysis",
                "Backdoor",
                "DoS",
                "Exploits",
                "Fuzzers",
                "Generic",
                "Reconnaissance",
                "Shellcode",
                "Worms",
            ]

    def preprocess_features(self, features: np.ndarray) -> np.ndarray:
        """
        Preprocess raw features

        Args:
            features: Raw feature array

        Returns:
            Preprocessed features
        """
        features = np.nan_to_num(features, nan=0.0, posinf=1e10, neginf=-1e10)

        features_processed = self.preprocessor.transform(features)

        return features_processed

    def predict(self, features: np.ndarray) -> Dict:
        """
        Make prediction on network traffic

        Args:
            features: Preprocessed feature array

        Returns:
            Prediction dictionary
        """
        start_time = datetime.now()

        if len(self.model.input_shape) == 3:
            features = features.reshape(features.shape[0], features.shape[1], 1)

        probabilities = self.model.predict(features, verbose=0)

        prediction_id = int(np.argmax(probabilities[0]))
        confidence = float(probabilities[0][prediction_id])
        prediction_name = self.class_names[prediction_id]

        action = "ALLOW" if prediction_id == 0 else "BLOCK"

        all_probs = {
            self.class_names[i]: float(probabilities[0][i])
            for i in range(len(self.class_names))
        }

        processing_time = (datetime.now() - start_time).total_seconds() * 1000

        return {
            "prediction": prediction_name,
            "prediction_id": prediction_id,
            "confidence": confidence,
            "all_probabilities": all_probs,
            "action": action,
            "processing_time_ms": processing_time,
        }

    def predict_batch(self, features_batch: np.ndarray) -> List[Dict]:
        """
        Batch prediction

        Args:
            features_batch: Batch of preprocessed features

        Returns:
            List of predictions
        """
        start_time = datetime.now()

        if len(self.model.input_shape) == 3:
            features_batch = features_batch.reshape(
                features_batch.shape[0], features_batch.shape[1], 1
            )

        probabilities = self.model.predict(features_batch, verbose=0)

        predictions = []
        for i, probs in enumerate(probabilities):
            prediction_id = int(np.argmax(probs))
            confidence = float(probs[prediction_id])
            prediction_name = self.class_names[prediction_id]
            action = "ALLOW" if prediction_id == 0 else "BLOCK"

            predictions.append(
                {
                    "sample_id": i,
                    "prediction": prediction_name,
                    "prediction_id": prediction_id,
                    "confidence": confidence,
                    "action": action,
                    "all_probabilities": {
                        self.class_names[j]: float(probs[j])
                        for j in range(len(self.class_names))
                    },
                }
            )

        processing_time = (datetime.now() - start_time).total_seconds() * 1000

        for pred in predictions:
            pred["processing_time_ms"] = processing_time / len(predictions)

        return predictions

    def get_status(self) -> Dict:
        """Get model status"""
        return {
            "status": "active",
            "model_loaded": self.model is not None,
            "model_name": self.model_name,
            "num_classes": len(self.class_names),
            "class_names": self.class_names,
            "input_features": self.model.input_shape[1] if self.model else 0,
            "model_metrics": self.metadata.get("metrics", {}) if self.metadata else {},
        }


try:
    model_server = IDSModelServer(MODEL_PATH, PREPROCESSOR_PATH, METADATA_PATH)
    logger.info("✓ Model server initialized")
except Exception as e:
    logger.error(f"✗ Failed to initialize model server: {str(e)}")
    model_server = None


@app.get("/", tags=["Health"])
async def root():
    """Root endpoint"""
    return {
        "message": "Network IDS API",
        "version": "1.0.0",
        "status": "active",
        "endpoints": {
            "health": "/health",
            "status": "/status",
            "predict": "/predict",
            "predict_batch": "/predict/batch",
        },
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    if model_server is None:
        raise HTTPException(status_code=503, detail="Model server not initialized")

    return {
        "status": "healthy",
        "model_loaded": model_server.model is not None,
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/status", response_model=ModelStatus, tags=["Model"])
async def get_model_status():
    """Get detailed model status"""
    if model_server is None:
        raise HTTPException(status_code=503, detail="Model server not initialized")

    return model_server.get_status()


@app.post("/predict", response_model=PredictionResponse, tags=["Prediction"])
async def predict_traffic(traffic: NetworkTraffic):
    """
    Predict network traffic classification

    Real-time classification of network flow into benign or attack categories.
    """
    if model_server is None:
        raise HTTPException(status_code=503, detail="Model server not initialized")

    try:
        features = np.array([traffic.features])

        features_processed = model_server.preprocess_features(features)
        result = model_server.predict(features_processed)

        response = PredictionResponse(
            success=True,
            prediction=result["prediction"],
            prediction_id=result["prediction_id"],
            confidence=result["confidence"],
            all_probabilities=result["all_probabilities"],
            action=result["action"],
            timestamp=datetime.now().isoformat(),
            processing_time_ms=result["processing_time_ms"],
        )

        return response

    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")


@app.post("/predict/batch", response_model=BatchPredictionResponse, tags=["Prediction"])
async def predict_batch(batch_data: BatchNetworkTraffic):
    """
    Batch prediction for multiple network flows

    Efficient batch processing for high-throughput scenarios.
    """
    if model_server is None:
        raise HTTPException(status_code=503, detail="Model server not initialized")

    try:
        start_time = datetime.now()

        features_batch = np.array(batch_data.traffic_batch)

        features_processed = model_server.preprocess_features(features_batch)

        predictions = model_server.predict_batch(features_processed)

        total_time = (datetime.now() - start_time).total_seconds() * 1000

        response = BatchPredictionResponse(
            success=True,
            predictions=predictions,
            total_samples=len(predictions),
            processing_time_ms=total_time,
            timestamp=datetime.now().isoformat(),
        )

        return response

    except Exception as e:
        logger.error(f"Batch prediction error: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Batch prediction failed: {str(e)}"
        )


@app.get("/classes", tags=["Model"])
async def get_classes():
    """Get all attack classes"""
    if model_server is None:
        raise HTTPException(status_code=503, detail="Model server not initialized")

    return {
        "classes": model_server.class_names,
        "num_classes": len(model_server.class_names),
        "description": {
            "Benign": "Normal network traffic",
            "Analysis": "Traffic analysis attacks",
            "Backdoor": "Backdoor access attempts",
            "DoS": "Denial of Service attacks",
            "Exploits": "Vulnerability exploitation",
            "Fuzzers": "Fuzzing attacks",
            "Generic": "Generic cryptographic attacks",
            "Reconnaissance": "Network reconnaissance",
            "Shellcode": "Shellcode injection",
            "Worms": "Worm propagation",
        },
    }


@app.post("/debug-predict")
async def debug_predict(traffic: NetworkTraffic):
    features_arr = np.array([traffic.features])
    features_processed = model_server.preprocess_features(features_arr)
    result = model_server.predict(features_processed)
    return {
        "raw_input": traffic.features[:10],
        "processed_sample": features_processed[0][:10].tolist(),
        "result": result,
    }


@app.get("/inject-attack")
def inject_attack_get(
    attack: str = "dos", src_ip: str = "172.20.10.5", mac: str = "unknown"
):
    features = _craft_features(attack)
    result = _classify(features)
    prediction = result.get("prediction", "Unknown")
    confidence = result.get("confidence", 0.0)

    if prediction != "Benign" and confidence >= 0.20:
        try:
            import requests as req

            req.post(
                "http://127.0.0.1:8001",
                json={
                    "src_ip": src_ip,
                    "mac": mac,
                    "prediction": prediction,
                    "confidence": confidence,
                },
                timeout=2,
            )
        except Exception as e:
            print(f"Webhook failed: {e}")

    return {"prediction": prediction, "confidence": confidence, "src_ip": src_ip}


def _classify(features):
    import numpy as np

    features_arr = np.array(features).reshape(1, -1)
    features_processed = model_server.preprocess_features(features_arr)
    result = model_server.predict(features_processed)
    return {"prediction": result["prediction"], "confidence": result["confidence"]}


def _craft_features(attack: str) -> list:
    f = [0.0] * 76

    if attack == "dos":
        f[0] = 0.01  # very short duration (normalized)
        f[1] = 0.95  # fwd_packets — max
        f[2] = 0.01  # bwd_packets — near zero
        f[3] = 0.95  # fwd_bytes — max
        f[4] = 0.01  # bwd_bytes — near zero
        f[5] = 0.90  # fwd pkt max
        f[6] = 0.80  # fwd pkt min
        f[7] = 0.85  # fwd pkt mean
        f[13] = 0.99  # bytes/sec — extreme
        f[14] = 0.99  # pkts/sec — extreme
        f[25] = 0.90  # FIN flags
        f[29] = 0.90  # ACK flags
        f[41] = 0.99  # fwd pkt rate
        f[42] = 0.01  # bwd pkt rate

    elif attack == "recon":
        f[0] = 0.50
        f[1] = 0.99
        f[2] = 0.0
        f[3] = 0.30
        f[4] = 0.0
        f[5] = 0.05
        f[6] = 0.05
        f[7] = 0.05
        f[14] = 0.80
        f[26] = 0.99  # SYN flags
        f[41] = 0.80

    elif attack == "fuzzer":
        f[0] = 0.30
        f[1] = 0.60
        f[2] = 0.20
        f[3] = 0.90
        f[4] = 0.10
        f[5] = 0.99
        f[6] = 0.01
        f[7] = 0.70
        f[8] = 0.95  # high std — irregular sizes
        f[13] = 0.75
        f[47] = 0.99  # variance — max

    elif attack == "backdoor":
        f[0] = 0.90  # long duration
        f[1] = 0.20
        f[2] = 0.20
        f[3] = 0.15
        f[4] = 0.15
        f[15] = 0.85  # IAT mean — high (slow beaconing)
        f[16] = 0.05  # IAT std — low (regular)
        f[20] = 0.85
        f[64] = 0.85
        f[68] = 0.85

    elif attack == "shellcode":
        f[0] = 0.10
        f[1] = 0.30
        f[2] = 0.10
        f[3] = 0.40
        f[4] = 0.10
        f[5] = 0.50
        f[7] = 0.40
        f[13] = 0.60
        f[26] = 0.70  # SYN
        f[28] = 0.80  # RST — abnormal
        f[62] = 0.99  # max window

    elif attack == "generic":
        f[0] = 0.25
        f[1] = 0.65
        f[2] = 0.25
        f[3] = 0.55
        f[4] = 0.30
        f[13] = 0.60
        f[14] = 0.45
        f[47] = 0.75

    return f


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": str(exc),
            "timestamp": datetime.now().isoformat(),
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api_server:app", host="0.0.0.0", port=8000, reload=False, log_level="info"
    )
