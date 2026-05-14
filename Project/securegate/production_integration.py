"""
Production Integration System

This module integrates monitoring, A/B testing, and edge optimization
into the main SecureGate pipeline for production deployment.
"""

import os
import logging
from typing import Dict, Optional, Tuple, Any
import time

from .model_monitor import get_model_monitor, monitor_prediction
from .ab_testing import get_ab_test_manager, start_ab_test
from .edge_optimizer import get_edge_optimizer, optimize_model_for_edge
from .observability import METRICS


class ProductionSecureGatePipeline:
    """Production-ready SecureGate pipeline with advanced features"""
    
    def __init__(self):
        # Initialize components
        self.model_monitor = get_model_monitor()
        self.ab_test_manager = get_ab_test_manager()
        self.edge_optimizer = None
        
        # Production settings
        self.monitoring_enabled = self._env_bool("SECUREGATE_MONITORING_ENABLED", True)
        self.ab_testing_enabled = self._env_bool("SECUREGATE_AB_TESTING_ENABLED", False)
        self.edge_optimization_enabled = self._env_bool("SECUREGATE_EDGE_OPTIMIZATION_ENABLED", False)
        
        # Initialize edge optimizer if enabled
        if self.edge_optimization_enabled:
            model_path = os.getenv("SECUREGATE_TRANSFORMER_MODEL_PATH", "models/prompt_classifier")
            optimization_level = os.getenv("SECUREGATE_EDGE_OPTIMIZATION_LEVEL", "balanced")
            self.edge_optimizer = optimize_model_for_edge(model_path, optimization_level)
        
        # Start A/B test if configured
        if self.ab_testing_enabled:
            self._start_configured_ab_test()
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("Production SecureGate pipeline initialized")
        
        # Set baseline metrics after warmup
        if self.monitoring_enabled:
            self._schedule_baseline_setting()
    
    def _env_bool(self, name: str, default: bool) -> bool:
        """Get boolean environment variable"""
        raw = os.getenv(name)
        if raw is None:
            return default
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    
    def _start_configured_ab_test(self) -> None:
        """Start A/B test from environment configuration"""
        test_name = os.getenv("SECUREGATE_AB_TEST_NAME", "")
        if not test_name:
            return
        
        description = os.getenv("SECUREGATE_AB_TEST_DESCRIPTION", "Production A/B test")
        transformer_weight = float(os.getenv("SECUREGATE_AB_TRANSFORMER_WEIGHT", "0.4"))
        ml_weight = float(os.getenv("SECUREGATE_AB_ML_WEIGHT", "0.35"))
        rule_weight = float(os.getenv("SECUREGATE_AB_RULE_WEIGHT", "0.25"))
        traffic_split = float(os.getenv("SECUREGATE_AB_TRAFFIC_SPLIT", "0.5"))
        sample_size = int(os.getenv("SECUREGATE_AB_SAMPLE_SIZE", "1000"))
        duration_hours = int(os.getenv("SECUREGATE_AB_DURATION_HOURS", "24"))
        
        start_ab_test(
            name=test_name,
            description=description,
            transformer_weight=transformer_weight,
            ml_weight=ml_weight,
            rule_weight=rule_weight,
            traffic_split=traffic_split,
            sample_size=sample_size,
            duration_hours=duration_hours
        )
    
    def _schedule_baseline_setting(self) -> None:
        """Schedule baseline metrics setting after warmup period"""
        import threading
        
        def set_baseline():
            time.sleep(300)  # 5 minutes warmup
            self.model_monitor.set_baseline()
            self.logger.info("📊 Production baseline metrics set")
        
        # Run in background thread
        baseline_thread = threading.Thread(target=set_baseline, daemon=True)
        baseline_thread.start()
    
    def evaluate_prompt_with_monitoring(
        self,
        prompt: str,
        actual_label: Optional[int] = None
    ) -> Tuple[Dict[str, Any], float]:
        """Evaluate prompt with full monitoring and A/B testing"""
        
        start_time = time.perf_counter()
        
        # A/B test evaluation if enabled
        if self.ab_testing_enabled and self.ab_test_manager.current_experiment:
            transformer_result, rule_based_result = self.ab_test_manager.evaluate_prompt(prompt, actual_label)
            
            # Use the appropriate result based on test
            if transformer_result["method"] == "transformer_heavy":
                evaluation_result = transformer_result
            else:
                evaluation_result = rule_based_result
            
            inference_time = time.perf_counter() - start_time
            
            # Record both predictions for monitoring
            monitor_prediction(
                prompt=prompt,
                predicted_score=evaluation_result["risk_score"],
                inference_time_ms=inference_time * 1000,
                actual_label=actual_label,
                confidence=1.0 - abs(evaluation_result["risk_score"] - 0.5),
                attack_type=self._detect_attack_type(prompt)
            )
            
            return evaluation_result, inference_time
        
        # Edge-optimized evaluation if enabled
        elif self.edge_optimization_enabled and self.edge_optimizer:
            scores, inference_time = self.edge_optimizer.predict(prompt, use_cache=True)
            
            # Convert to expected format
            evaluation_result = {
                "method": "edge_optimized",
                "risk_score": scores.get("LABEL_1", 0.0),
                "blocked": scores.get("LABEL_1", 0.0) >= 0.5,
                "transformer_score": scores.get("LABEL_1", 0.0),
                "model_score": 0.0,  # Not used in edge mode
                "semantic_score": 0.0,  # Not used in edge mode
                "flags": [],
                "actions": ["edge_optimized"]
            }
            
            # Record for monitoring
            monitor_prediction(
                prompt=prompt,
                predicted_score=evaluation_result["risk_score"],
                inference_time_ms=inference_time,
                actual_label=actual_label,
                confidence=1.0 - abs(evaluation_result["risk_score"] - 0.5),
                attack_type=self._detect_attack_type(prompt)
            )
            
            return evaluation_result, inference_time
        
        # Standard evaluation with monitoring
        else:
            from .prompt_defense import PromptDefenseEngine
            
            engine = PromptDefenseEngine()
            result = engine.inspect(prompt)
            
            inference_time = time.perf_counter() - start_time
            
            # Record for monitoring
            if self.monitoring_enabled:
                monitor_prediction(
                    prompt=prompt,
                    predicted_score=result.risk_score,
                    inference_time_ms=inference_time * 1000,
                    actual_label=actual_label,
                    confidence=1.0 - abs(result.risk_score - 0.5),
                    attack_type=self._detect_attack_type(prompt)
                )
            
            return {
                "method": "standard",
                "risk_score": result.risk_score,
                "blocked": result.blocked,
                "transformer_score": getattr(result, 'transformer_score', 0.0),
                "model_score": result.model_score,
                "semantic_score": result.semantic_leakage_score,
                "flags": [f.label for f in result.flags],
                "actions": result.actions
            }, inference_time
    
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
    
    def get_production_metrics(self) -> Dict[str, Any]:
        """Get comprehensive production metrics"""
        metrics = {
            "monitoring": {
                "enabled": self.monitoring_enabled,
                "performance": self.model_monitor.get_performance_summary() if self.monitoring_enabled else None
            },
            "ab_testing": {
                "enabled": self.ab_testing_enabled,
                "current_experiment": self.ab_test_manager.get_experiment_summary() if self.ab_testing_enabled else None
            },
            "edge_optimization": {
                "enabled": self.edge_optimization_enabled,
                "optimization_report": self.edge_optimizer.get_optimization_report() if self.edge_optimization_enabled else None
            },
            "global_metrics": METRICS.snapshot()
        }
        
        return metrics
    
    def export_production_config(self, export_path: str) -> None:
        """Export production configuration and metrics"""
        import json
        from pathlib import Path
        
        config = {
            "timestamp": time.time(),
            "configuration": {
                "monitoring_enabled": self.monitoring_enabled,
                "ab_testing_enabled": self.ab_testing_enabled,
                "edge_optimization_enabled": self.edge_optimization_enabled
            },
            "metrics": self.get_production_metrics()
        }
        
        export_path = Path(export_path)
        export_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(export_path, "w") as f:
            json.dump(config, f, indent=2)
        
        self.logger.info(f"Production configuration exported to {export_path}")
    
    def run_health_checks(self) -> Dict[str, bool]:
        """Run comprehensive health checks"""
        health_status = {
            "monitoring_system": self._check_monitoring_health(),
            "ab_testing_system": self._check_ab_testing_health(),
            "edge_optimizer": self._check_edge_optimizer_health(),
            "model_performance": self._check_model_performance_health(),
            "memory_usage": self._check_memory_health(),
            "inference_speed": self._check_inference_speed_health()
        }
        
        overall_health = all(health_status.values())
        health_status["overall"] = overall_health
        
        if overall_health:
            self.logger.info("✅ All production systems healthy")
        else:
            self.logger.warning(f"⚠️ Health issues detected: {health_status}")
        
        return health_status
    
    def _check_monitoring_health(self) -> bool:
        """Check monitoring system health"""
        if not self.monitoring_enabled:
            return True  # Not enabled, so not unhealthy
        
        try:
            metrics = self.model_monitor.get_performance_summary()
            return metrics is not None
        except Exception:
            return False
    
    def _check_ab_testing_health(self) -> bool:
        """Check A/B testing system health"""
        if not self.ab_testing_enabled:
            return True  # Not enabled, so not unhealthy
        
        try:
            summary = self.ab_test_manager.get_experiment_summary()
            return summary is not None
        except Exception:
            return False
    
    def _check_edge_optimizer_health(self) -> bool:
        """Check edge optimizer health"""
        if not self.edge_optimization_enabled:
            return True  # Not enabled, so not unhealthy
        
        try:
            # If optimization is enabled but optimizer failed to load, mark as unhealthy
            if self.edge_optimizer is None:
                return False
            report = self.edge_optimizer.get_optimization_report()
            return report.get("error") is None
        except Exception:
            return False
    
    def _check_model_performance_health(self) -> bool:
        """Check model performance health"""
        try:
            metrics = self.model_monitor.get_performance_summary()
            if not metrics or not metrics.get("current_metrics"):
                return True  # No data yet, assume healthy
            
            current = metrics["current_metrics"]
            # Only check if we have actual performance data
            total_predictions = current.get("total_predictions", 0)
            if total_predictions < 10:
                return True  # Not enough data, assume healthy
            
            # For initial deployment, be more lenient
            accuracy = current.get("accuracy", 0)
            inference_time = current.get("avg_inference_time", 1000)
            
            # Acceptable performance thresholds
            accuracy_ok = accuracy >= 0.6  # More lenient for initial deployment
            speed_ok = inference_time <= 500  # More lenient for initial deployment
            
            return accuracy_ok and speed_ok
        except Exception:
            return False
    
    def _check_memory_health(self) -> bool:
        """Check memory usage health"""
        try:
            import psutil
            memory_percent = psutil.virtual_memory().percent
            return memory_percent < 85  # Less than 85% memory usage
        except ImportError:
            return True  # psutil not available, assume healthy
        except Exception:
            return False
    
    def _check_inference_speed_health(self) -> bool:
        """Check inference speed health"""
        try:
            metrics = self.model_monitor.get_performance_summary()
            if not metrics or not metrics.get("current_metrics"):
                return True  # No data yet
            
            avg_time = metrics["current_metrics"].get("avg_inference_time", 1000)
            return avg_time < 150  # Less than 150ms average
        except Exception:
            return False


# Global production pipeline instance
_production_pipeline: Optional[ProductionSecureGatePipeline] = None


def get_production_pipeline() -> ProductionSecureGatePipeline:
    """Get or create global production pipeline instance"""
    global _production_pipeline
    if _production_pipeline is None:
        _production_pipeline = ProductionSecureGatePipeline()
    return _production_pipeline


def get_production_health() -> Dict[str, bool]:
    """Get production system health status"""
    pipeline = get_production_pipeline()
    return pipeline.run_health_checks()


def export_production_metrics(export_path: str) -> None:
    """Export production metrics to file"""
    pipeline = get_production_pipeline()
    pipeline.export_production_config(export_path)
