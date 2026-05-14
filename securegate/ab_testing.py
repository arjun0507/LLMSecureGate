"""
A/B Testing Framework for SecureGate

This module provides A/B testing capabilities to compare
transformer vs rule-based performance in production.
"""

import json
import time
import random
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import statistics
import numpy as np

from .model_monitor import get_model_monitor, monitor_prediction
from .prompt_defense import PromptDefenseEngine
from .transformer_classifier import TransformerPromptClassifier


@dataclass
class ExperimentConfig:
    """Configuration for A/B test experiment"""
    name: str
    description: str
    transformer_weight: float
    ml_weight: float
    rule_weight: float
    traffic_split: float  # percentage for transformer (0.0-1.0)
    sample_size: int = 1000  # target sample size
    duration_hours: int = 24  # experiment duration


@dataclass
class ExperimentResult:
    """Results from A/B test experiment"""
    config: ExperimentConfig
    transformer_metrics: Dict[str, float]
    rule_based_metrics: Dict[str, float]
    statistical_significance: float = 0.0
    winner: str = "inconclusive"
    confidence_level: float = 0.0
    total_samples: int = 0
    transformer_samples: int = 0
    rule_based_samples: int = 0


class ABTestManager:
    """Manages A/B testing experiments"""
    
    def __init__(self, storage_path: str = "monitoring/ab_tests.json"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.current_experiment: Optional[ExperimentConfig] = None
        self.experiment_results: List[ExperimentResult] = []
        self.sample_buffer: List[Dict] = []
        
        self.load_experiments()
    
    def start_experiment(
        self,
        name: str,
        description: str,
        transformer_weight: float = 0.4,
        ml_weight: float = 0.35,
        rule_weight: float = 0.25,
        traffic_split: float = 0.5,
        sample_size: int = 1000,
        duration_hours: int = 24
    ) -> None:
        """Start a new A/B test experiment"""
        
        config = ExperimentConfig(
            name=name,
            description=description,
            transformer_weight=transformer_weight,
            ml_weight=ml_weight,
            rule_weight=rule_weight,
            traffic_split=traffic_split,
            sample_size=sample_size,
            duration_hours=duration_hours
        )
        
        self.current_experiment = config
        self.sample_buffer = []
        
        logger = logging.getLogger(__name__)
        logger.info(f"🧪 Starting A/B test: {name}")
        logger.info(f"Description: {description}")
        logger.info(f"Traffic split: {traffic_split*100:.1f}% transformer, {(1-traffic_split)*100:.1f}% rule-based")
        
        self.save_experiments()
    
    def evaluate_prompt(
        self,
        prompt: str,
        actual_label: Optional[int] = None
    ) -> Tuple[Dict, Dict]:
        """Evaluate prompt using both transformer and rule-based approaches"""
        
        if not self.current_experiment:
            # Default behavior: use current configuration
            return self._evaluate_with_current_config(prompt, actual_label)
        
        # A/B test logic
        use_transformer = random.random() < self.current_experiment.traffic_split
        
        if use_transformer:
            return self._evaluate_transformer_heavy(prompt, actual_label)
        else:
            return self._evaluate_rule_based_heavy(prompt, actual_label)
    
    def _evaluate_with_current_config(
        self,
        prompt: str,
        actual_label: Optional[int] = None
    ) -> Tuple[Dict, Dict]:
        """Evaluate with current production configuration"""
        from .pipeline import SecureGatePipeline
        
        # Use current pipeline configuration
        pipeline = SecureGatePipeline()
        result = pipeline.prompt_engine.inspect(prompt)
        
        # Record prediction
        monitor = get_model_monitor()
        monitor.record_prediction(
            prompt=prompt,
            predicted_label="LABEL_1" if result.risk_score >= 0.5 else "LABEL_0",
            predicted_score=result.risk_score,
            inference_time_ms=50.0,  # Estimated
            actual_label=actual_label,
            confidence=1.0 - abs(result.risk_score - 0.5),
            attack_type=self._detect_attack_type(prompt)
        )
        
        return {
            "method": "current_config",
            "risk_score": result.risk_score,
            "blocked": result.blocked,
            "transformer_score": getattr(result, 'transformer_score', 0.0),
            "model_score": result.model_score,
            "semantic_score": result.semantic_leakage_score,
            "flags": [f.label for f in result.flags],
            "actions": result.actions
        }, {
            "method": "current_config",
            "accuracy": 1.0 if actual_label is None else (1.0 if (result.blocked and actual_label == 1) or (not result.blocked and actual_label == 0) else 0.0),
            "inference_time_ms": 50.0
        }
    
    def _evaluate_transformer_heavy(
        self,
        prompt: str,
        actual_label: Optional[int] = None
    ) -> Tuple[Dict, Dict]:
        """Evaluate with transformer-heavy configuration"""
        
        # Create custom prompt defense with transformer emphasis
        original_engine = PromptDefenseEngine()
        
        # Temporarily modify weights for transformer emphasis
        original_ml_weight = original_engine.ml_weight
        original_transformer_weight = getattr(original_engine, 'transformer_weight', 0.4)
        
        original_engine.ml_weight = 0.1  # Reduce ML weight
        original_engine.transformer_weight = self.current_experiment.transformer_weight
        
        start_time = time.perf_counter()
        result = original_engine.inspect(prompt)
        inference_time = (time.perf_counter() - start_time) * 1000
        
        # Restore original weights
        original_engine.ml_weight = original_ml_weight
        original_engine.transformer_weight = original_transformer_weight
        
        success = (result.blocked and actual_label == 1) or (not result.blocked and actual_label == 0) if actual_label is not None else True
        
        return {
            "method": "transformer_heavy",
            "risk_score": result.risk_score,
            "blocked": result.blocked,
            "transformer_score": getattr(result, 'transformer_score', 0.0),
            "model_score": result.model_score,
            "semantic_score": result.semantic_leakage_score,
            "flags": [f.label for f in result.flags],
            "actions": result.actions
        }, {
            "method": "transformer_heavy",
            "accuracy": 1.0 if actual_label is None else (1.0 if success else 0.0),
            "inference_time_ms": inference_time
        }
    
    def _evaluate_rule_based_heavy(
        self,
        prompt: str,
        actual_label: Optional[int] = None
    ) -> Tuple[Dict, Dict]:
        """Evaluate with rule-based heavy configuration"""
        
        # Create custom prompt defense with rule emphasis
        original_engine = PromptDefenseEngine()
        
        # Temporarily modify weights for rule emphasis
        original_ml_weight = original_engine.ml_weight
        original_transformer_weight = getattr(original_engine, 'transformer_weight', 0.4)
        
        original_engine.ml_weight = 0.1  # Reduce ML weight
        original_engine.transformer_weight = 0.1  # Reduce transformer weight
        
        start_time = time.perf_counter()
        result = original_engine.inspect(prompt)
        inference_time = (time.perf_counter() - start_time) * 1000
        
        # Restore original weights
        original_engine.ml_weight = original_ml_weight
        original_engine.transformer_weight = original_transformer_weight
        
        success = (result.blocked and actual_label == 1) or (not result.blocked and actual_label == 0) if actual_label is not None else True
        
        return {
            "method": "rule_based_heavy",
            "risk_score": result.risk_score,
            "blocked": result.blocked,
            "transformer_score": getattr(result, 'transformer_score', 0.0),
            "model_score": result.model_score,
            "semantic_score": result.semantic_leakage_score,
            "flags": [f.label for f in result.flags],
            "actions": result.actions
        }, {
            "method": "rule_based_heavy",
            "accuracy": 1.0 if actual_label is None else (1.0 if success else 0.0),
            "inference_time_ms": inference_time
        }
    
    def _detect_attack_type(self, prompt: str) -> Optional[str]:
        """Detect attack type for monitoring"""
        prompt_lower = prompt.lower()
        
        if any(keyword in prompt_lower for keyword in ["dan", "do anything now", "unfiltered"]):
            return "role_playing"
        elif any(keyword in prompt_lower for keyword in ["base64", "decode", "rot13"]):
            return "encoding"
        elif any(keyword in prompt_lower for keyword in ["first", "then", "after that"]):
            return "multi_step"
        elif any(keyword in prompt_lower for keyword in ["hypothetical", "educational", "research"]):
            return "contextual"
        elif any(keyword in prompt_lower for keyword in ["researcher", "professor", "openai"]):
            return "social_engineering"
        elif any(keyword in prompt_lower for keyword in ["code", "script", "execute"]):
            return "code_injection"
        else:
            return None
    
    def record_result(
        self,
        prompt: str,
        transformer_result: Dict,
        rule_based_result: Dict,
        actual_label: Optional[int] = None
    ) -> None:
        """Record A/B test result"""
        
        if not self.current_experiment:
            return
        
        sample = {
            "timestamp": time.time(),
            "prompt": prompt[:200],  # Truncate for storage
            "transformer_result": transformer_result,
            "rule_based_result": rule_based_result,
            "actual_label": actual_label,
            "experiment_name": self.current_experiment.name
        }
        
        self.sample_buffer.append(sample)
        
        # Check if experiment should be concluded
        if len(self.sample_buffer) >= self.current_experiment.sample_size:
            self.conclude_experiment()
        else:
            self.save_experiments()
    
    def conclude_experiment(self) -> None:
        """Analyze and conclude current experiment"""
        if not self.current_experiment or not self.sample_buffer:
            return
        
        # Separate results by method
        transformer_samples = []
        rule_based_samples = []
        
        for sample in self.sample_buffer:
            if sample["transformer_result"]["method"] == "transformer_heavy":
                transformer_samples.append(sample)
            else:
                rule_based_samples.append(sample)
        
        # Calculate metrics
        transformer_metrics = self._calculate_method_metrics(transformer_samples)
        rule_based_metrics = self._calculate_method_metrics(rule_based_samples)
        
        # Statistical significance test
        significance = self._calculate_statistical_significance(
            transformer_samples, rule_based_samples
        )
        
        # Determine winner
        winner = self._determine_winner(
            transformer_metrics, rule_based_metrics, significance
        )
        
        # Create result
        result = ExperimentResult(
            config=self.current_experiment,
            transformer_metrics=transformer_metrics,
            rule_based_metrics=rule_based_metrics,
            statistical_significance=significance,
            winner=winner,
            confidence_level=self._calculate_confidence_level(
                transformer_samples, rule_based_samples
            ),
            total_samples=len(self.sample_buffer),
            transformer_samples=len(transformer_samples),
            rule_based_samples=len(rule_based_samples)
        )
        
        self.experiment_results.append(result)
        self.current_experiment = None
        self.sample_buffer = []
        
        # Save and log results
        self.save_experiments()
        self._log_experiment_results(result)
    
    def _calculate_method_metrics(self, samples: List[Dict]) -> Dict[str, float]:
        """Calculate performance metrics for a method"""
        if not samples:
            return {"accuracy": 0.0, "avg_inference_time": 0.0, "avg_risk_score": 0.0}
        
        accuracies = []
        inference_times = []
        risk_scores = []
        
        for sample in samples:
            if sample["actual_label"] is not None:
                method_result = sample["transformer_result"] if sample["transformer_result"]["method"] == "transformer_heavy" else sample["rule_based_result"]
                accuracies.append(method_result["accuracy"])
            
            method_result = sample["transformer_result"] if sample["transformer_result"]["method"] == "transformer_heavy" else sample["rule_based_result"]
            inference_times.append(method_result["inference_time_ms"])
            risk_scores.append(method_result["risk_score"])
        
        return {
            "accuracy": statistics.mean(accuracies) if accuracies else 0.0,
            "avg_inference_time": statistics.mean(inference_times) if inference_times else 0.0,
            "avg_risk_score": statistics.mean(risk_scores) if risk_scores else 0.0,
            "sample_count": len(samples)
        }
    
    def _calculate_statistical_significance(
        self,
        transformer_samples: List[Dict],
        rule_based_samples: List[Dict]
    ) -> float:
        """Calculate statistical significance using t-test"""
        
        if len(transformer_samples) < 30 or len(rule_based_samples) < 30:
            return 0.0  # Not enough samples
        
        # Get accuracy scores
        transformer_accuracies = [
            s["transformer_result"]["accuracy"] 
            for s in transformer_samples 
            if s["actual_label"] is not None
        ]
        rule_based_accuracies = [
            s["rule_based_result"]["accuracy"]
            for s in rule_based_samples 
            if s["actual_label"] is not None
        ]
        
        if len(transformer_accuracies) < 10 or len(rule_based_accuracies) < 10:
            return 0.0
        
        # Simple t-test
        from scipy import stats
        
        t_stat, p_value = stats.ttest_ind(
            transformer_accuracies, rule_based_accuracies
        )
        
        return 1.0 - p_value if not np.isnan(p_value) else 0.0
    
    def _determine_winner(
        self,
        transformer_metrics: Dict[str, float],
        rule_based_metrics: Dict[str, float],
        significance: float
    ) -> str:
        """Determine winner based on metrics and significance"""
        
        if significance < 0.95:  # 95% confidence threshold
            return "inconclusive"
        
        # Compare accuracies
        if transformer_metrics["accuracy"] > rule_based_metrics["accuracy"] + 0.02:  # 2% improvement threshold
            return "transformer"
        elif rule_based_metrics["accuracy"] > transformer_metrics["accuracy"] + 0.02:
            return "rule_based"
        else:
            return "inconclusive"
    
    def _calculate_confidence_level(
        self,
        transformer_samples: List[Dict],
        rule_based_samples: List[Dict]
    ) -> float:
        """Calculate confidence level in results"""
        total_samples = len(transformer_samples) + len(rule_based_samples)
        
        if total_samples < 100:
            return 0.5  # Low confidence for small samples
        
        # Simple confidence calculation based on sample size
        if total_samples >= 1000:
            return 0.99
        elif total_samples >= 500:
            return 0.95
        elif total_samples >= 200:
            return 0.90
        else:
            return 0.80
    
    def _log_experiment_results(self, result: ExperimentResult) -> None:
        """Log experiment results"""
        logger = logging.getLogger(__name__)
        
        logger.info(
            f"📊 A/B Test Results: {result.config.name}\n"
            f"Winner: {result.winner}\n"
            f"Statistical Significance: {result.statistical_significance:.3f}\n"
            f"Confidence Level: {result.confidence_level:.3f}\n"
            f"Transformer Accuracy: {result.transformer_metrics['accuracy']:.3f} "
            f"({result.transformer_samples} samples)\n"
            f"Rule-based Accuracy: {result.rule_based_metrics['accuracy']:.3f} "
            f"({result.rule_based_samples} samples)\n"
            f"Transformer Inference Time: {result.transformer_metrics['avg_inference_time']:.2f}ms\n"
            f"Rule-based Inference Time: {result.rule_based_metrics['avg_inference_time']:.2f}ms"
        )
    
    def get_experiment_summary(self) -> Dict:
        """Get summary of all experiments"""
        return {
            "current_experiment": asdict(self.current_experiment) if self.current_experiment else None,
            "experiment_results": [asdict(r) for r in self.experiment_results],
            "total_experiments": len(self.experiment_results),
            "current_sample_count": len(self.sample_buffer)
        }
    
    def save_experiments(self) -> None:
        """Save experiment data to file"""
        data = self.get_experiment_summary()
        
        with open(self.storage_path, "w") as f:
            json.dump(data, f, indent=2)
    
    def load_experiments(self) -> None:
        """Load experiment data from file"""
        if not self.storage_path.exists():
            return
        
        try:
            with open(self.storage_path, "r") as f:
                data = json.load(f)
            
            if "current_experiment" in data and data["current_experiment"]:
                self.current_experiment = ExperimentConfig(**data["current_experiment"])
            
            if "experiment_results" in data:
                self.experiment_results = [
                    ExperimentResult(**r) for r in data["experiment_results"]
                ]
            
            if "sample_buffer" in data:
                self.sample_buffer = data["sample_buffer"]
                
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to load A/B test data: {e}")


# Global A/B test manager
_ab_test_manager: Optional[ABTestManager] = None


def get_ab_test_manager() -> ABTestManager:
    """Get or create global A/B test manager"""
    global _ab_test_manager
    if _ab_test_manager is None:
        _ab_test_manager = ABTestManager()
    return _ab_test_manager


def start_ab_test(
    name: str,
    description: str,
    transformer_weight: float = 0.4,
    ml_weight: float = 0.35,
    rule_weight: float = 0.25,
    traffic_split: float = 0.5,
    sample_size: int = 1000,
    duration_hours: int = 24
) -> None:
    """Convenience function to start A/B test"""
    manager = get_ab_test_manager()
    manager.start_experiment(
        name=name,
        description=description,
        transformer_weight=transformer_weight,
        ml_weight=ml_weight,
        rule_weight=rule_weight,
        traffic_split=traffic_split,
        sample_size=sample_size,
        duration_hours=duration_hours
    )
