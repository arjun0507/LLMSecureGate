"""
Edge Deployment Optimization System

This module provides optimization for transformer models in edge environments,
including model quantization, caching, and resource management.
"""

import os
import logging
import time
import gc
from typing import Dict, Optional, Tuple, Any
from pathlib import Path
import torch
import numpy as np

try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    from optimum.onnxruntime import ORTModelForSequenceClassification
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

from .observability import METRICS


class EdgeOptimizer:
    """Optimizes transformer models for edge deployment"""
    
    def __init__(self, model_path: str, optimization_level: str = "balanced"):
        self.model_path = Path(model_path)
        self.optimization_level = optimization_level  # "speed", "memory", "balanced"
        
        self.original_model = None
        self.optimized_model = None
        self.tokenizer = None
        self.cache = {}
        self.max_cache_size = 1000
        
        # Optimization thresholds
        self.memory_threshold_mb = 512  # Target memory usage
        self.inference_threshold_ms = 100  # Target inference time
        
        self.logger = logging.getLogger(__name__)
        
        if TRANSFORMERS_AVAILABLE:
            self._load_and_optimize()
    
    def _load_and_optimize(self) -> None:
        """Load and optimize model based on level"""
        try:
            # Load original model
            self.tokenizer = AutoTokenizer.from_pretrained(str(self.model_path))
            self.original_model = AutoModelForSequenceClassification.from_pretrained(str(self.model_path))
            
            self.logger.info(f"Loaded original model: {self._get_model_info(self.original_model)}")
            
            # Apply optimizations based on level
            if self.optimization_level == "speed":
                self._optimize_for_speed()
            elif self.optimization_level == "memory":
                self._optimize_for_memory()
            else:  # balanced
                self._optimize_balanced()
            
            self.logger.info(f"Applied {self.optimization_level} optimization")
            
        except Exception as e:
            self.logger.error(f"Failed to optimize model: {e}")
            self.optimized_model = self.original_model
    
    def _optimize_for_speed(self) -> None:
        """Optimize model for maximum inference speed"""
        # Use half precision for faster inference
        self.original_model = self.original_model.half()
        
        # Optimize for inference
        self.original_model.eval()
        
        # Enable attention optimization
        if hasattr(self.original_model.config, 'use_cache'):
            self.original_model.config.use_cache = True
        
        # Disable gradient computation
        for param in self.original_model.parameters():
            param.requires_grad = False
        
        # Use TorchScript if available
        try:
            self.optimized_model = torch.jit.script(self.original_model)
            self.logger.info("Applied TorchScript optimization")
        except Exception as e:
            self.logger.warning(f"TorchScript optimization failed: {e}")
            self.optimized_model = self.original_model
    
    def _optimize_for_memory(self) -> None:
        """Optimize model for minimal memory usage"""
        # Use quantization to reduce memory
        try:
            # Dynamic quantization (8-bit)
            self.optimized_model = torch.quantization.quantize_dynamic(
                self.original_model, {torch.nn.Linear}
            )
            self.logger.info("Applied dynamic quantization (8-bit)")
        except Exception as e:
            self.logger.warning(f"Dynamic quantization failed: {e}")
            # Fall back to half precision
            self.optimized_model = self.original_model.half()
            self.logger.info("Applied half precision optimization")
        
        # Reduce cache size
        if hasattr(self.optimized_model.config, 'use_cache'):
            self.optimized_model.config.use_cache = False
        
        # Clear unnecessary cache
        torch.cuda.empty_cache() if torch.cuda.is_available() else None
    
    def _optimize_balanced(self) -> None:
        """Apply balanced optimization (speed + memory)"""
        # Use half precision
        self.optimized_model = self.original_model.half()
        
        # Enable selective optimizations
        if hasattr(self.optimized_model.config, 'use_cache'):
            self.optimized_model.config.use_cache = True
        
        # Disable gradients
        for param in self.optimized_model.parameters():
            param.requires_grad = False
        
        # Apply model-specific optimizations
        self._apply_model_specific_optimizations()
    
    def _apply_model_specific_optimizations(self) -> None:
        """Apply model-specific optimizations"""
        model_type = type(self.optimized_model).__name__
        
        if "DistilBert" in model_type:
            # DistilBERT specific optimizations
            if hasattr(self.optimized_model, 'distilbert'):
                self.optimized_model.distilbert.dropout = 0.0  # Disable dropout for inference
        
        elif "Bert" in model_type:
            # BERT specific optimizations
            if hasattr(self.optimized_model, 'bert'):
                self.optimized_model.bert.dropout = 0.0
        
        # General optimizations
        self.optimized_model.eval()
    
    def predict(self, text: str, use_cache: bool = True) -> Tuple[Dict[str, float], float]:
        """Make optimized prediction with caching"""
        if not self.optimized_model or not self.tokenizer:
            raise RuntimeError("Model not properly loaded")
        
        start_time = time.perf_counter()
        
        # Check cache first
        cache_key = self._get_cache_key(text)
        if use_cache and cache_key in self.cache:
            cached_result = self.cache[cache_key]
            inference_time = (time.perf_counter() - start_time) * 1000
            
            METRICS.inc("edge.cache_hit")
            return cached_result, inference_time
        
        METRICS.inc("edge.cache_miss")
        
        # Prepare input
        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=512
        )
        
        # Move to appropriate device
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        inputs = {k: v.to(device) for k, v in inputs.items()}
        self.optimized_model = self.optimized_model.to(device)
        
        # Inference
        with torch.no_grad():
            outputs = self.optimized_model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=-1)
        
        # Extract results
        scores = {}
        if probabilities.shape[-1] == 2:
            scores["LABEL_0"] = float(probabilities[0][0])
            scores["LABEL_1"] = float(probabilities[0][1])
        else:
            # Handle multi-class case
            for i, prob in enumerate(probabilities[0]):
                scores[f"LABEL_{i}"] = float(prob)
        
        malicious_score = scores.get("LABEL_1", 0.0)
        
        # Update cache
        if use_cache:
            self._update_cache(cache_key, scores)
        
        inference_time = (time.perf_counter() - start_time) * 1000
        
        # Record metrics
        METRICS.inc("edge.predictions")
        METRICS.inc("edge.inference_time_ms", int(inference_time))
        
        # Memory management
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        
        # Garbage collection
        if len(self.cache) > self.max_cache_size * 1.5:
            self._cleanup_cache()
        
        return scores, inference_time
    
    def _get_cache_key(self, text: str) -> str:
        """Generate cache key for text"""
        # Simple hash-based key
        import hashlib
        return hashlib.md5(text.encode()).hexdigest()[:16]
    
    def _update_cache(self, key: str, result: Dict[str, float]) -> None:
        """Update prediction cache"""
        if len(self.cache) >= self.max_cache_size:
            # Remove oldest entries
            oldest_keys = list(self.cache.keys())[:len(self.cache) // 4]
            for old_key in oldest_keys:
                del self.cache[old_key]
        
        self.cache[key] = result
    
    def _cleanup_cache(self) -> None:
        """Clean up cache to free memory"""
        # Keep only most recent entries
        if len(self.cache) > self.max_cache_size:
            sorted_items = sorted(
                self.cache.items(),
                key=lambda x: x[1]  # Sort by some metric (simplified)
            )
            self.cache = dict(sorted_items[-self.max_cache_size:])
        
        # Force garbage collection
        gc.collect()
        METRICS.inc("edge.cache_cleanup")
    
    def _get_model_info(self, model) -> Dict[str, Any]:
        """Get model information for logging"""
        total_params = sum(p.numel() for p in model.parameters())
        trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
        
        return {
            "model_type": type(model).__name__,
            "total_parameters": total_params,
            "trainable_parameters": trainable_params,
            "device": str(next(model.parameters()).device) if total_params > 0 else "unknown",
            "dtype": str(next(model.parameters()).dtype) if total_params > 0 else "unknown"
        }
    
    def get_optimization_report(self) -> Dict[str, Any]:
        """Get comprehensive optimization report"""
        if not self.optimized_model:
            return {"error": "Model not loaded"}
        
        # Memory usage
        if torch.cuda.is_available():
            memory_allocated = torch.cuda.memory_allocated() / 1024 / 1024  # MB
            memory_reserved = torch.cuda.memory_reserved() / 1024 / 1024  # MB
        else:
            memory_allocated = 0
            memory_reserved = 0
        
        # Performance metrics
        cache_hit_rate = (
            METRICS.get("edge.cache_hit", 0) / 
            max(1, METRICS.get("edge.cache_hit", 0) + METRICS.get("edge.cache_miss", 0))
        )
        
        avg_inference_time = (
            METRICS.get("edge.inference_time_ms", 0) / 
            max(1, METRICS.get("edge.predictions", 0))
        )
        
        return {
            "optimization_level": self.optimization_level,
            "model_info": self._get_model_info(self.optimized_model),
            "memory_usage_mb": {
                "allocated": memory_allocated,
                "reserved": memory_reserved
            },
            "performance": {
                "cache_hit_rate": cache_hit_rate,
                "avg_inference_time_ms": avg_inference_time,
                "total_predictions": METRICS.get("edge.predictions", 0),
                "cache_size": len(self.cache)
            },
            "thresholds_met": {
                "memory_threshold_met": memory_allocated <= self.memory_threshold_mb,
                "inference_threshold_met": avg_inference_time <= self.inference_threshold_ms
            }
        }
    
    def benchmark_model(self, test_prompts: list, num_runs: int = 10) -> Dict[str, float]:
        """Benchmark model performance"""
        if not self.optimized_model:
            raise RuntimeError("Model not loaded")
        
        results = {
            "avg_inference_time": 0.0,
            "min_inference_time": float('inf'),
            "max_inference_time": 0.0,
            "memory_usage_mb": 0.0,
            "throughput_qps": 0.0
        }
        
        # Warm up
        for _ in range(3):
            self.predict(test_prompts[0], use_cache=False)
        
        # Benchmark
        inference_times = []
        start_memory = 0
        
        if torch.cuda.is_available():
            torch.cuda.reset_peak_memory_stats()
            start_memory = torch.cuda.max_memory_allocated() / 1024 / 1024
        
        for prompt in test_prompts * num_runs:
            _, inference_time = self.predict(prompt, use_cache=False)
            inference_times.append(inference_time)
        
        if torch.cuda.is_available():
            peak_memory = torch.cuda.max_memory_allocated() / 1024 / 1024
            results["memory_usage_mb"] = peak_memory - start_memory
        
        # Calculate metrics
        results["avg_inference_time"] = np.mean(inference_times)
        results["min_inference_time"] = np.min(inference_times)
        results["max_inference_time"] = np.max(inference_times)
        results["throughput_qps"] = len(test_prompts) * num_runs / sum(inference_times) * 1000
        
        self.logger.info(f"Benchmark results: {results}")
        return results
    
    def export_optimized_model(self, export_path: str) -> None:
        """Export optimized model for deployment"""
        if not self.optimized_model:
            raise RuntimeError("No optimized model to export")
        
        export_path = Path(export_path)
        export_path.mkdir(parents=True, exist_ok=True)
        
        # Save model and tokenizer
        self.tokenizer.save_pretrained(str(export_path))
        self.optimized_model.save_pretrained(str(export_path))
        
        # Save optimization metadata
        metadata = {
            "optimization_level": self.optimization_level,
            "optimization_timestamp": time.time(),
            "model_info": self._get_model_info(self.optimized_model),
            "performance_benchmark": self.benchmark_model(["test prompt 1", "test prompt 2"], 5)
        }
        
        import json
        with open(export_path / "optimization_metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"Optimized model exported to {export_path}")


# Global optimizer instance
_edge_optimizer: Optional[EdgeOptimizer] = None


def get_edge_optimizer(
    model_path: str,
    optimization_level: str = "balanced"
) -> EdgeOptimizer:
    """Get or create global edge optimizer instance"""
    global _edge_optimizer
    if _edge_optimizer is None:
        _edge_optimizer = EdgeOptimizer(model_path, optimization_level)
    return _edge_optimizer


def optimize_model_for_edge(
    model_path: str,
    optimization_level: str = "balanced",
    export_path: Optional[str] = None
) -> EdgeOptimizer:
    """Optimize model for edge deployment"""
    optimizer = EdgeOptimizer(model_path, optimization_level)
    
    if export_path:
        optimizer.export_optimized_model(export_path)
    
    return optimizer
