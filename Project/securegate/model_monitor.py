"""
Model Monitoring and Drift Detection System

This module provides comprehensive monitoring for the transformer classifier,
including performance tracking, drift detection, and automated alerts.
"""

import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import statistics
import numpy as np

from .observability import METRICS
from .transformer_classifier import TransformerPromptClassifier


@dataclass
class PredictionRecord:
    """Single prediction record for monitoring"""
    timestamp: float
    prompt: str
    predicted_label: str
    predicted_score: float
    actual_label: Optional[int] = None
    confidence: float = 0.0
    inference_time_ms: float = 0.0
    model_version: str = ""
    attack_type: Optional[str] = None


@dataclass
class PerformanceMetrics:
    """Current performance metrics"""
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    avg_inference_time: float = 0.0
    total_predictions: int = 0
    correct_predictions: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_positives: int = 0
    true_negatives: int = 0


@dataclass
class DriftMetrics:
    """Drift detection metrics"""
    score_distribution_change: float = 0.0
    prediction_confidence_change: float = 0.0
    inference_time_change: float = 0.0
    feature_distribution_change: float = 0.0
    drift_detected: bool = False
    drift_severity: str = "none"


class ModelMonitor:
    """Comprehensive model monitoring system"""
    
    def __init__(self, storage_path: str = "monitoring/model_data.json"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.predictions: List[PredictionRecord] = []
        self.baseline_metrics: Optional[PerformanceMetrics] = None
        self.current_metrics: PerformanceMetrics = PerformanceMetrics()
        self.drift_metrics: DriftMetrics = DriftMetrics()
        
        # Monitoring thresholds
        self.drift_threshold_score_dist = 0.15  # 15% change in score distribution
        self.drift_threshold_confidence = 0.10  # 10% change in confidence
        self.drift_threshold_inference_time = 0.20  # 20% change in inference time
        self.performance_window_hours = 24  # 24-hour sliding window
        
        self.load_data()
    
    def record_prediction(
        self,
        prompt: str,
        predicted_label: str,
        predicted_score: float,
        inference_time_ms: float,
        actual_label: Optional[int] = None,
        confidence: float = 0.0,
        attack_type: Optional[str] = None,
        model_version: str = "latest"
    ) -> None:
        """Record a prediction for monitoring"""
        
        record = PredictionRecord(
            timestamp=time.time(),
            prompt=prompt,
            predicted_label=predicted_label,
            predicted_score=predicted_score,
            actual_label=actual_label,
            confidence=confidence,
            inference_time_ms=inference_time_ms,
            model_version=model_version,
            attack_type=attack_type
        )
        
        self.predictions.append(record)
        self.update_metrics()
        self.save_data()
        
        # Check for drift after every 100 predictions
        if len(self.predictions) % 100 == 0:
            self.check_drift()
    
    def update_metrics(self) -> None:
        """Update performance metrics based on recent predictions"""
        recent_predictions = self.get_recent_predictions()
        
        if not recent_predictions:
            return
        
        # Calculate basic metrics
        self.current_metrics.total_predictions = len(recent_predictions)
        self.current_metrics.avg_inference_time = statistics.mean([
            p.inference_time_ms for p in recent_predictions
        ])
        
        # Calculate accuracy metrics (only if we have actual labels)
        labeled_predictions = [p for p in recent_predictions if p.actual_label is not None]
        if labeled_predictions:
            self.calculate_classification_metrics(labeled_predictions)
        
        # Update global metrics
        METRICS.inc("monitor.predictions_recorded")
        METRICS.inc("monitor.avg_inference_time", int(self.current_metrics.avg_inference_time))
    
    def calculate_classification_metrics(self, labeled_predictions: List[PredictionRecord]) -> None:
        """Calculate classification performance metrics"""
        tp = fp = fn = tn = 0
        
        for pred in labeled_predictions:
            predicted_malicious = pred.predicted_score >= 0.5
            actual_malicious = pred.actual_label == 1
            
            if predicted_malicious and actual_malicious:
                tp += 1
            elif predicted_malicious and not actual_malicious:
                fp += 1
            elif not predicted_malicious and actual_malicious:
                fn += 1
            else:
                tn += 1
        
        self.current_metrics.true_positives = tp
        self.current_metrics.false_positives = fp
        self.current_metrics.false_negatives = fn
        self.current_metrics.true_negatives = tn
        self.current_metrics.correct_predictions = tp + tn
        
        # Calculate derived metrics
        total = tp + fp + fn + tn
        if total > 0:
            self.current_metrics.accuracy = (tp + tn) / total
        
        if (tp + fp) > 0:
            self.current_metrics.precision = tp / (tp + fp)
        
        if (tp + fn) > 0:
            self.current_metrics.recall = tp / (tp + fn)
        
        if (self.current_metrics.precision + self.current_metrics.recall) > 0:
            self.current_metrics.f1_score = (
                2 * self.current_metrics.precision * self.current_metrics.recall /
                (self.current_metrics.precision + self.current_metrics.recall)
            )
    
    def check_drift(self) -> None:
        """Check for model drift and update drift metrics"""
        if not self.baseline_metrics or len(self.predictions) < 200:
            return
        
        recent_predictions = self.get_recent_predictions()
        baseline_predictions = self.get_baseline_predictions()
        
        if len(recent_predictions) < 50 or len(baseline_predictions) < 50:
            return
        
        # Check score distribution drift
        recent_scores = [p.predicted_score for p in recent_predictions]
        baseline_scores = [p.predicted_score for p in baseline_predictions]
        
        score_drift = self.calculate_distribution_drift(recent_scores, baseline_scores)
        
        # Check confidence drift
        recent_confidence = [p.confidence for p in recent_predictions if p.confidence > 0]
        baseline_confidence = [p.confidence for p in baseline_predictions if p.confidence > 0]
        
        confidence_drift = self.calculate_distribution_drift(recent_confidence, baseline_confidence)
        
        # Check inference time drift
        recent_times = [p.inference_time_ms for p in recent_predictions]
        baseline_times = [p.inference_time_ms for p in baseline_predictions]
        
        time_drift = self.calculate_distribution_drift(recent_times, baseline_times)
        
        # Update drift metrics
        self.drift_metrics.score_distribution_change = score_drift
        self.drift_metrics.prediction_confidence_change = confidence_drift
        self.drift_metrics.inference_time_change = time_drift
        
        # Determine if drift is detected
        drift_detected = (
            score_drift > self.drift_threshold_score_dist or
            confidence_drift > self.drift_threshold_confidence or
            time_drift > self.drift_threshold_inference_time
        )
        
        self.drift_metrics.drift_detected = drift_detected
        
        if drift_detected:
            self.drift_metrics.drift_severity = self.assess_drift_severity(
                score_drift, confidence_drift, time_drift
            )
            self.alert_drift()
        
        METRICS.inc("monitor.drift_checks")
        if drift_detected:
            METRICS.inc("monitor.drift_detected")
    
    def calculate_distribution_drift(self, recent: List[float], baseline: List[float]) -> float:
        """Calculate KL divergence between two distributions"""
        if not recent or not baseline:
            return 0.0
        
        # Create histograms
        bins = np.linspace(0, 1, 11)  # 10 bins from 0 to 1
        recent_hist, _ = np.histogram(recent, bins=bins, density=True)
        baseline_hist, _ = np.histogram(baseline, bins=bins, density=True)
        
        # Add small epsilon to avoid division by zero
        epsilon = 1e-10
        recent_hist = recent_hist + epsilon
        baseline_hist = baseline_hist + epsilon
        
        # Calculate KL divergence
        kl_div = np.sum(recent_hist * np.log(recent_hist / baseline_hist))
        return float(kl_div)
    
    def assess_drift_severity(self, score_drift: float, confidence_drift: float, time_drift: float) -> str:
        """Assess the severity of detected drift"""
        max_drift = max(score_drift, confidence_drift, time_drift)
        
        if max_drift > 0.5:
            return "critical"
        elif max_drift > 0.3:
            return "high"
        elif max_drift > 0.2:
            return "medium"
        elif max_drift > 0.1:
            return "low"
        else:
            return "minimal"
    
    def alert_drift(self) -> None:
        """Send alert when drift is detected"""
        logger = logging.getLogger(__name__)
        
        alert_msg = (
            f"🚨 MODEL DRIFT DETECTED\n"
            f"Severity: {self.drift_metrics.drift_severity}\n"
            f"Score Distribution Change: {self.drift_metrics.score_distribution_change:.3f}\n"
            f"Confidence Change: {self.drift_metrics.prediction_confidence_change:.3f}\n"
            f"Inference Time Change: {self.drift_metrics.inference_time_change:.3f}\n"
            f"Current Performance: Accuracy={self.current_metrics.accuracy:.3f}, "
            f"F1={self.current_metrics.f1_score:.3f}\n"
            f"Recommendation: Consider model retraining"
        )
        
        logger.warning(alert_msg)
        
        # Save alert to separate file
        alert_path = self.storage_path.parent / "drift_alerts.jsonl"
        with open(alert_path, "a") as f:
            alert_record = {
                "timestamp": datetime.now().isoformat(),
                "severity": self.drift_metrics.drift_severity,
                "metrics": asdict(self.drift_metrics),
                "performance": asdict(self.current_metrics)
            }
            f.write(json.dumps(alert_record) + "\n")
    
    def get_recent_predictions(self, hours: Optional[int] = None) -> List[PredictionRecord]:
        """Get predictions from recent time window"""
        if hours is None:
            hours = self.performance_window_hours
        
        cutoff_time = time.time() - (hours * 3600)
        return [p for p in self.predictions if p.timestamp >= cutoff_time]
    
    def get_baseline_predictions(self) -> List[PredictionRecord]:
        """Get baseline predictions for drift comparison"""
        if not self.baseline_metrics:
            return []
        
        # Use first 1000 predictions as baseline
        return self.predictions[:1000]
    
    def set_baseline(self) -> None:
        """Set current metrics as baseline for drift detection"""
        self.baseline_metrics = PerformanceMetrics(
            accuracy=self.current_metrics.accuracy,
            precision=self.current_metrics.precision,
            recall=self.current_metrics.recall,
            f1_score=self.current_metrics.f1_score,
            avg_inference_time=self.current_metrics.avg_inference_time,
            total_predictions=self.current_metrics.total_predictions,
            correct_predictions=self.current_metrics.correct_predictions,
            false_positives=self.current_metrics.false_positives,
            false_negatives=self.current_metrics.false_negatives,
            true_positives=self.current_metrics.true_positives,
            true_negatives=self.current_metrics.true_negatives
        )
        
        logger = logging.getLogger(__name__)
        logger.info(f"📊 Baseline metrics set: {asdict(self.baseline_metrics)}")
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary"""
        return {
            "current_metrics": asdict(self.current_metrics),
            "baseline_metrics": asdict(self.baseline_metrics) if self.baseline_metrics else None,
            "drift_metrics": asdict(self.drift_metrics),
            "total_predictions": len(self.predictions),
            "monitoring_window_hours": self.performance_window_hours,
            "last_updated": datetime.now().isoformat()
        }
    
    def get_attack_type_performance(self) -> Dict[str, Dict[str, float]]:
        """Get performance breakdown by attack type"""
        recent_predictions = self.get_recent_predictions()
        labeled_predictions = [p for p in recent_predictions if p.actual_label is not None]
        
        attack_performance = {}
        
        # Group by attack type
        attack_groups = {}
        for pred in labeled_predictions:
            attack_type = pred.attack_type or "unknown"
            if attack_type not in attack_groups:
                attack_groups[attack_type] = []
            attack_groups[attack_type].append(pred)
        
        # Calculate metrics for each attack type
        for attack_type, preds in attack_groups.items():
            if not preds:
                continue
            
            tp = fp = fn = tn = 0
            for pred in preds:
                predicted_malicious = pred.predicted_score >= 0.5
                actual_malicious = pred.actual_label == 1
                
                if predicted_malicious and actual_malicious:
                    tp += 1
                elif predicted_malicious and not actual_malicious:
                    fp += 1
                elif not predicted_malicious and actual_malicious:
                    fn += 1
                else:
                    tn += 1
            
            total = tp + fp + fn + tn
            accuracy = (tp + tn) / total if total > 0 else 0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
            
            attack_performance[attack_type] = {
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "total_samples": len(preds)
            }
        
        return attack_performance
    
    def save_data(self) -> None:
        """Save monitoring data to file"""
        data = {
            "predictions": [asdict(p) for p in self.predictions[-1000:]],  # Keep last 1000
            "current_metrics": asdict(self.current_metrics),
            "baseline_metrics": asdict(self.baseline_metrics) if self.baseline_metrics else None,
            "drift_metrics": asdict(self.drift_metrics),
            "last_updated": datetime.now().isoformat()
        }
        
        with open(self.storage_path, "w") as f:
            json.dump(data, f, indent=2)
    
    def load_data(self) -> None:
        """Load monitoring data from file"""
        if not self.storage_path.exists():
            return
        
        try:
            with open(self.storage_path, "r") as f:
                data = json.load(f)
            
            # Load predictions
            if "predictions" in data:
                self.predictions = [
                    PredictionRecord(**p) for p in data["predictions"]
                ]
            
            # Load metrics
            if "current_metrics" in data:
                self.current_metrics = PerformanceMetrics(**data["current_metrics"])
            
            if "baseline_metrics" in data and data["baseline_metrics"]:
                self.baseline_metrics = PerformanceMetrics(**data["baseline_metrics"])
            
            if "drift_metrics" in data:
                self.drift_metrics = DriftMetrics(**data["drift_metrics"])
                
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to load monitoring data: {e}")


# Global monitor instance
_model_monitor: Optional[ModelMonitor] = None


def get_model_monitor() -> ModelMonitor:
    """Get or create global model monitor instance"""
    global _model_monitor
    if _model_monitor is None:
        _model_monitor = ModelMonitor()
    return _model_monitor


def monitor_prediction(
    prompt: str,
    predicted_score: float,
    inference_time_ms: float,
    actual_label: Optional[int] = None,
    confidence: float = 0.0,
    attack_type: Optional[str] = None
) -> None:
    """Convenience function to record a prediction"""
    monitor = get_model_monitor()
    
    predicted_label = "LABEL_1" if predicted_score >= 0.5 else "LABEL_0"
    
    monitor.record_prediction(
        prompt=prompt,
        predicted_label=predicted_label,
        predicted_score=predicted_score,
        actual_label=actual_label,
        confidence=confidence,
        inference_time_ms=inference_time_ms,
        attack_type=attack_type
    )
