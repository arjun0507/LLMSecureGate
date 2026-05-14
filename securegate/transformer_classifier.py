"""
Transformer-based Prompt Injection Classifier

This module implements a transformer-based ML classifier for detecting
prompt injection attempts using fine-tuned language models.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import numpy as np

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import Dataset, DataLoader
    from transformers import (
        AutoTokenizer,
        AutoModelForSequenceClassification,
        Trainer,
        TrainingArguments,
        pipeline
    )
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    # Fallback Dataset class to prevent NameError when torch is not available
    class Dataset:
        pass

from .config import load_policy
from .observability import METRICS

logger = logging.getLogger(__name__)


class PromptInjectionDataset(Dataset):
    """Dataset for prompt injection classification"""
    
    def __init__(self, texts: List[str], labels: List[int], tokenizer, max_length: int = 512):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length
    
    def __len__(self):
        return len(self.texts)
    
    def __getitem__(self, idx):
        text = str(self.texts[idx])
        label = self.labels[idx]
        
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )
        
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }


class TransformerPromptClassifier:
    """Transformer-based prompt injection classifier"""
    
    def __init__(self, model_path: Optional[str] = None):
        self.enabled = self._env_bool("SECUREGATE_TRANSFORMER_ENABLED", False)
        self.model_name = os.getenv("SECUREGATE_TRANSFORMER_MODEL", "distilbert-base-uncased")
        self.model_path = model_path or os.getenv("SECUREGATE_TRANSFORMER_MODEL_PATH", "models/prompt_classifier")
        self.threshold = self._env_float("SECUREGATE_TRANSFORMER_THRESHOLD", 0.5)
        self.max_length = self._env_int("SECUREGATE_TRANSFORMER_MAX_LENGTH", 512)
        
        self.model = None
        self.tokenizer = None
        self.pipeline = None
        
        if self.enabled and TRANSFORMERS_AVAILABLE:
            self._load_model()
        elif self.enabled and not TRANSFORMERS_AVAILABLE:
            logger.warning("Transformer classifier enabled but transformers library not available")
    
    def _load_model(self):
        """Load the transformer model and tokenizer"""
        try:
            # Try to load fine-tuned model first
            if Path(self.model_path).exists():
                logger.info(f"Loading fine-tuned model from {self.model_path}")
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
                self.model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
            else:
                logger.info(f"Using pre-trained model: {self.model_name}")
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                self.model = AutoModelForSequenceClassification.from_pretrained(
                    self.model_name, 
                    num_labels=2  # Binary classification: malicious vs benign
                )
            
            # Create inference pipeline
            self.pipeline = pipeline(
                "text-classification",
                model=self.model,
                tokenizer=self.tokenizer,
                device=0 if torch.cuda.is_available() else -1,
                return_all_scores=True
            )
            
            logger.info("Transformer classifier loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load transformer model: {e}")
            self.enabled = False
    
    def predict(self, text: str) -> Tuple[float, Dict[str, float]]:
        """
        Predict if the given text is a prompt injection attempt
        
        Args:
            text: Input text to classify
            
        Returns:
            Tuple of (risk_score, detailed_scores)
        """
        if not self.enabled or not self.pipeline:
            return 0.0, {}
        
        try:
            results = self.pipeline(text)
            
            # Extract scores
            scores = {result['label']: result['score'] for result in results}
            
            # Get malicious score (LABEL_1 is typically the positive class)
            malicious_score = scores.get('LABEL_1', 0.0)
            
            # Log for metrics
            METRICS.inc("transformer.inferences")
            if malicious_score >= self.threshold:
                METRICS.inc("transformer.malicious_detected")
            
            return round(malicious_score, 3), scores
            
        except Exception as e:
            logger.error(f"Transformer inference failed: {e}")
            METRICS.inc("transformer.errors")
            return 0.0, {}
    
    def train(self, train_data_path: str, eval_data_path: Optional[str] = None):
        """
        Train the transformer model on prompt injection data
        
        Args:
            train_data_path: Path to training CSV file
            eval_data_path: Path to evaluation CSV file (optional)
        """
        if not TRANSFORMERS_AVAILABLE:
            raise ImportError("transformers library is required for training")
        
        # Load training data
        train_texts, train_labels = self._load_data_from_csv(train_data_path)
        
        # Prepare datasets
        train_dataset = PromptInjectionDataset(
            train_texts, train_labels, self.tokenizer, self.max_length
        )
        
        eval_dataset = None
        if eval_data_path and Path(eval_data_path).exists():
            eval_texts, eval_labels = self._load_data_from_csv(eval_data_path)
            eval_dataset = PromptInjectionDataset(
                eval_texts, eval_labels, self.tokenizer, self.max_length
            )
        
        # Training arguments
        training_args = TrainingArguments(
            output_dir=self.model_path,
            num_train_epochs=3,
            per_device_train_batch_size=8,
            per_device_eval_batch_size=8,
            warmup_steps=100,
            weight_decay=0.01,
            logging_dir=f"{self.model_path}/logs",
            logging_steps=10,
            eval_strategy="epoch" if eval_dataset else "no",
            save_strategy="epoch",
            load_best_model_at_end=True if eval_dataset else False,
        )
        
        # Create trainer
        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=eval_dataset,
        )
        
        # Train the model
        logger.info("Starting transformer model training...")
        trainer.train()
        
        # Save the model
        trainer.save_model(self.model_path)
        self.tokenizer.save_pretrained(self.model_path)
        
        logger.info(f"Model training completed and saved to {self.model_path}")
        
        # Update pipeline with new model
        self.pipeline = pipeline(
            "text-classification",
            model=self.model,
            tokenizer=self.tokenizer,
            device=0 if torch.cuda.is_available() else -1,
            return_all_scores=True
        )
    
    def _load_data_from_csv(self, csv_path: str) -> Tuple[List[str], List[int]]:
        """Load training data from CSV file"""
        import pandas as pd
        
        df = pd.read_csv(csv_path)
        
        # Handle different column names
        text_col = 'text' if 'text' in df.columns else 'prompt'
        label_col = 'label' if 'label' in df.columns else 'malicious'
        
        texts = df[text_col].astype(str).tolist()
        labels = df[label_col].astype(int).tolist()
        
        return texts, labels
    
    @staticmethod
    def _env_bool(name: str, default: bool) -> bool:
        raw = os.getenv(name)
        if raw is None:
            return default
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    
    @staticmethod
    def _env_float(name: str, default: float) -> float:
        raw = os.getenv(name)
        if not raw:
            return default
        try:
            return float(raw)
        except ValueError:
            return default
    
    @staticmethod
    def _env_int(name: str, default: int) -> int:
        raw = os.getenv(name)
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            return default


# Training script for the transformer classifier
def train_transformer_classifier():
    """Utility function to train the transformer classifier"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Train transformer prompt injection classifier")
    parser.add_argument("--train-data", required=True, help="Path to training CSV file")
    parser.add_argument("--eval-data", help="Path to evaluation CSV file")
    parser.add_argument("--model-name", default="distilbert-base-uncased", help="Base model name")
    parser.add_argument("--output-dir", default="models/prompt_classifier", help="Output directory")
    
    args = parser.parse_args()
    
    # Initialize classifier
    classifier = TransformerPromptClassifier()
    
    # Override model name and output path
    classifier.model_name = args.model_name
    classifier.model_path = args.output_dir
    
    # Load fresh model and tokenizer
    classifier.tokenizer = AutoTokenizer.from_pretrained(args.model_name)
    classifier.model = AutoModelForSequenceClassification.from_pretrained(
        args.model_name, 
        num_labels=2
    )
    
    # Train the model
    classifier.train(args.train_data, args.eval_data)


if __name__ == "__main__":
    train_transformer_classifier()
