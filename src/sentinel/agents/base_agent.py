"""
src/sentinel/agents/base_agent.py

Base class for Red and Blue agents.
UPDATED: Uses Groq (Fast & High Rate Limits).
"""

import os
import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from openai import OpenAI  # <--- Using OpenAI client for Groq
from tenacity import retry, stop_after_attempt, wait_exponential

from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger(__name__)


@dataclass
class AgentResponse:
    content: str
    confidence: float
    reasoning: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class BaseLLMAgent(ABC):
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.llm_config = config.get('llm', {})
        self.provider = self.llm_config.get('provider', 'groq') # Default to groq
        
        # --- GROQ SETUP ---
        if self.provider == 'groq':
            api_key = os.getenv('GROQ_API_KEY')
            if not api_key:
                raise ValueError("GROQ_API_KEY not found in .env")
            
            # Groq uses the OpenAI client format
            self.client = OpenAI(
                base_url="https://api.groq.com/openai/v1",
                api_key=api_key
            )
            # Use Llama 3.3 70B (Fast & Smart)
            self.model_name = self.llm_config.get('model', 'llama-3.3-70b-versatile')
        # ------------------
        
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")
        
        self.temperature = self.llm_config.get('temperature', 0.7)
        self.max_tokens = self.llm_config.get('max_tokens', 2000)
        self.agent_config = self._get_agent_config()
        self.action_history: List[Dict[str, Any]] = []
        
        logger.info(f"Initialized {self.__class__.__name__} with {self.provider}/{self.model_name}")
    
    @abstractmethod
    def _get_agent_config(self) -> Dict[str, Any]:
        pass
    
    # Retry logic is still good, but Groq is usually stable
    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=2, max=10))
    def _call_llm(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        # Tiny sleep just to be safe, but Groq is fast!
        time.sleep(1) 

        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
            return response.choices[0].message.content
                
        except Exception as e:
            logger.error(f"LLM API call failed: {e}")
            raise

    def add_to_history(self, action: Dict[str, Any]) -> None:
        self.action_history.append(action)
        if len(self.action_history) > 100:
            self.action_history = self.action_history[-100:]
    
    def get_recent_history(self, n: int = 10) -> List[Dict[str, Any]]:
        return self.action_history[-n:]
    
    def clear_history(self) -> None:
        self.action_history = []

    @abstractmethod
    def act(self, observation: Dict[str, Any]) -> AgentResponse:
        pass
    
    def update_policy(self, reward: float, info: Dict[str, Any]) -> None:
        logger.info(f"{self.__class__.__name__} received reward: {reward}")
        self.add_to_history({'reward': reward, 'info': info})


class RewardCalculator:
    @staticmethod
    def calculate_red_reward(attack_success, is_novel, caught_by_static, **kwargs):
        reward = 0.0
        if attack_success: reward += 10.0
        if is_novel: reward += 5.0
        if caught_by_static: reward -= 5.0
        if attack_success and is_novel and not caught_by_static: reward += 3.0
        return reward
    
    @staticmethod
    def calculate_blue_reward(patch_blocks_attack, tests_pass, no_new_vulnerabilities, red_bypassed, functionality_broken, **kwargs):
        reward = 0.0
        if patch_blocks_attack: reward += 15.0
        if tests_pass: reward += 5.0
        if no_new_vulnerabilities: reward += 3.0
        if red_bypassed: reward -= 10.0
        if functionality_broken: reward -= 5.0
        return reward