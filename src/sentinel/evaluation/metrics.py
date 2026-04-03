"""
src/sentinel/evaluation/metrics.py

Metrics tracking for agent evaluation.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
import json
import logging

logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityMetrics:
    total_attacks: int = 0
    successful_attacks: int = 0
    total_patches: int = 0
    successful_patches: int = 0
    static_analysis_evasions: int = 0
    
    @property
    def attack_success_rate(self) -> float:
        return self.successful_attacks / max(self.total_attacks, 1)
        
    @property
    def patch_success_rate(self) -> float:
        return self.successful_patches / max(self.total_patches, 1)


class MetricsTracker:
    def __init__(self):
        self.vuln_metrics: Dict[str, VulnerabilityMetrics] = {}
        self.overall_metrics = VulnerabilityMetrics()
        
    def record_attack(self, vuln_type: str, success: bool, evaded_static: bool):
        if vuln_type not in self.vuln_metrics:
            self.vuln_metrics[vuln_type] = VulnerabilityMetrics()
            
        self.vuln_metrics[vuln_type].total_attacks += 1
        self.overall_metrics.total_attacks += 1
        
        if success:
            self.vuln_metrics[vuln_type].successful_attacks += 1
            self.overall_metrics.successful_attacks += 1
            
        if evaded_static:
            self.vuln_metrics[vuln_type].static_analysis_evasions += 1
            self.overall_metrics.static_analysis_evasions += 1

    def record_patch(self, vuln_type: str, success: bool):
        if vuln_type not in self.vuln_metrics:
            self.vuln_metrics[vuln_type] = VulnerabilityMetrics()
            
        self.vuln_metrics[vuln_type].total_patches += 1
        self.overall_metrics.total_patches += 1
        
        if success:
            self.vuln_metrics[vuln_type].successful_patches += 1
            self.overall_metrics.successful_patches += 1
            
    def get_summary(self) -> Dict[str, Any]:
        result = {
            "overall": {
                "attack_success_rate": self.overall_metrics.attack_success_rate,
                "patch_success_rate": self.overall_metrics.patch_success_rate,
                "static_evasions": self.overall_metrics.static_analysis_evasions
            },
            "by_vulnerability": {}
        }
        for vt, m in self.vuln_metrics.items():
            result["by_vulnerability"][vt] = {
                "attack_success_rate": m.attack_success_rate,
                "patch_success_rate": m.patch_success_rate,
                "total_attacks": m.total_attacks,
                "total_patches": m.total_patches
            }
        return result
