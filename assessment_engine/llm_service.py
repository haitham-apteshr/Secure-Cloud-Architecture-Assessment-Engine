"""
LLM Service using Groq (Fast cloud models)
"""
import os
import groq
import json
import re
from typing import Dict, List, Optional
from .prompts import (
    SYSTEM_CONTEXT,
    DISCOVERY_PROMPT,
    PILLAR_DEEP_DIVE_PROMPT,
    TRADEOFF_RESOLUTION_PROMPT,
    ANSWER_ANALYZER_PROMPT,
    DAST_SUMMARY_PROMPT,
    DAST_CONTEXT_CLARIFICATION_PROMPT,
    DAST_REMEDIATION_PLAN_PROMPT,
    RECOMMENDATION_GENERATOR_PROMPT,
    EXECUTIVE_SUMMARY_PROMPT
)

SYSTEM_CONTEXT = """
You are an expert DevSecOps Architect and Security Analyst. 
Your goal is to help users assess their workloads against the Well-Architected Framework (WAF) and analyze security vulnerabilities from DAST scans.
Provide clear, actionable, and context-aware responses. 
When analyzing vulnerabilities, focus on risk, impact, and concrete remediation steps.
"""

class LLMService:
    def __init__(self, model="llama3.2"):
        """
        Initialize LLM service with Ollama
        Default model: llama3.2 (3B params, fast and good quality)
        Alternative: mistral, llama3.1, phi3
        """
        self.model = model
        self.client = groq.Groq(api_key=os.getenv("GROQ_API_KEY", ""))
        print(f"Initializing LLM Service with Groq model: {self.model}")
    
    def generate_question(self, phase: str, pillar: str, workload_type: str, previous_context: str) -> str:
        """Generate the next assessment question based on the current phase."""
        if phase == "discovery":
            prompt = DISCOVERY_PROMPT.format(
                workload_type=workload_type,
                previous_context=previous_context
            )
        elif phase == "tradeoffs":
            prompt = TRADEOFF_RESOLUTION_PROMPT.format(
                workload_type=workload_type,
                previous_context=previous_context
            )
        else:
            prompt = PILLAR_DEEP_DIVE_PROMPT.format(
                pillar=pillar,
                workload_type=workload_type,
                previous_context=previous_context
            )
        return self._chat(SYSTEM_CONTEXT, prompt)

    def summarize_dast_findings(self, findings: List[Dict], context: Dict) -> str:
        """
        Generate conversational summary of DAST findings.
        Expects findings to be a list of dicts (serialized UnifiedVulnerability).
        """
        critical_count = sum(1 for f in findings if f.get('severity') == 'critical')
        high_count = sum(1 for f in findings if f.get('severity') == 'high')
        medium_count = sum(1 for f in findings if f.get('severity') == 'medium')
        low_count = sum(1 for f in findings if f.get('severity') == 'low')
        
        # Get top 3 findings for context
        top_findings = ""
        sorted_findings = sorted(findings, key=lambda x: x.get('remediation_tracking', {}).get('priority_score', 0), reverse=True)[:3]
        for i, f in enumerate(sorted_findings, 1):
            top_findings += f"{i}. {f.get('title')} (Severity: {f.get('severity')})\n"
            
        prompt = DAST_SUMMARY_PROMPT.format(
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            top_findings=top_findings,
            workload_type=context.get('workload_type', 'Unknown'),
            environment=context.get('environment', 'Unknown')
        )
        
        return self._chat(SYSTEM_CONTEXT, prompt)

    def get_dast_clarifications(self, findings: List[Dict], context: Dict) -> str:
        """
        Generate clarifying questions for DAST findings to improve prioritization.
        """
        # Create a snippet of findings
        findings_snippet = ""
        for f in findings[:5]:
            findings_snippet += f"- {f.get('title')} ({f.get('severity')})\n"
            
        prompt = DAST_CONTEXT_CLARIFICATION_PROMPT.format(
            asset_criticality=context.get('asset_criticality', 'Medium'),
            internet_facing=context.get('internet_facing', 'Unknown'),
            data_sensitivity=context.get('data_sensitivity', 'Unknown'),
            waf_present=context.get('waf_present', 'Unknown'),
            findings_snippet=findings_snippet
        )
        
        return self._chat(SYSTEM_CONTEXT, prompt)

    def generate_remediation_guidance(self, vulnerability: Dict, tech_stack: str = "Generic") -> str:
        """
        Generate detailed remediation plan for a specific vulnerability.
        """
        tech_details = vulnerability.get('technical_details', {})
        
        prompt = DAST_REMEDIATION_PLAN_PROMPT.format(
            title=vulnerability.get('title'),
            description=vulnerability.get('description'),
            technical_details=f"Endpoint: {tech_details.get('endpoint')}, Method: {tech_details.get('http_method')}, Payload: {tech_details.get('payload')}",
            tech_stack=tech_stack
        )
        
        return self._chat(SYSTEM_CONTEXT, prompt)
    
    def dast_chat(self, query: str, context: str, history: List[Dict]) -> str:
        """
        Conversational assistant for DAST/CSPM findings.
        """
        hist_str = "\n".join([f"{m['role']}: {m['content']}" for m in history[-5:]])
        
        system_prompt = (
            f"{SYSTEM_CONTEXT}\n"
            "You are now acting as a 'Intelligent Pentesting Assistant'.\n"
            "Use the provided Vulnerability Context to answer the user's question.\n"
            "Be conversational, tactical, and help the pentester secure the cloud environment.\n"
            "Vulnerability Context:\n"
            f"{context}\n"
        )
        
        user_prompt = f"Previous Conversation:\n{hist_str}\n\nUser Question: {query}"
        
        return self._chat(system_prompt, user_prompt)
    
    def answer_with_context(self, query: str, context: str) -> str:
        """Answer a user question based strictly on the provided RAG context."""
        system_prompt = (
            "You are a helpful AI assistant. Answer the user's question based strictly on the provided context. "
            "If the answer is not contained in the context, say 'I cannot answer this based on the provided documents.' "
            "Do not use outside knowledge."
        )
        user_prompt = f"Context:\n{context}\n\nQuestion:\n{query}"
        
        return self._chat(system_prompt, user_prompt)
        
    def _chat(self, system_prompt: str, user_prompt: str) -> str:
        """Internal method to call Groq"""
        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.2
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"LLM Error: {e}")
            return f"Error: Could not generate response. Error: {e}"
    
    def generate_pillar_analysis(self, pillar: str, score: float, maturity_level: str, evidence: str) -> str:
        """Generate structured technical analysis for a specific pillar."""
        from .prompts import PILLAR_DEEP_ANALYSIS_PROMPT
        prompt = PILLAR_DEEP_ANALYSIS_PROMPT.format(
            pillar=pillar,
            score=round(score, 1),
            maturity_level=maturity_level,
            evidence=evidence
        )
        return self._chat(SYSTEM_CONTEXT, prompt)

    def analyze_answer(self, question: str, answer: str) -> Dict:
        """Analyze user answer and extract structured data using the 7-point technical prompt."""
        from .prompts import ANSWER_ANALYZER_PROMPT
        prompt = ANSWER_ANALYZER_PROMPT.format(
            question=question,
            answer=answer
        )
        response = self._chat(SYSTEM_CONTEXT, prompt)
        
        # Extract JSON from response
        try:
            # Try to find JSON block in the response (e.g., ```json\n{...}\n```)
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', response, re.DOTALL)
            if not json_match:
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                
            if json_match:
                extracted_data = json.loads(json_match.group(1) if len(json_match.groups()) > 0 else json_match.group())
                
                # Format to merge extracted JSON + conversational response
                return {
                    "evidence_summary": response, # The full 7-point analysis
                    "confidence": extracted_data.get("confidence", "low"),
                    "maturity_signal": extracted_data.get("maturity_signal", 3),
                    "key_points": extracted_data.get("key_points", []),
                    "risk_level": extracted_data.get("risk_level", "medium"),
                    "gaps_identified": extracted_data.get("gaps_identified", []),
                    "aws_services_mentioned": extracted_data.get("aws_services_mentioned", []),
                    "compliance_frameworks": extracted_data.get("compliance_frameworks", []),
                    "needs_followup": False
                }
        except:
            pass

        # Fallback
        return {
            "evidence_summary": response,
            "confidence": "medium",
            "maturity_signal": 3,
            "key_points": [],
            "risk_level": "medium",
            "gaps_identified": [],
            "aws_services_mentioned": [],
            "compliance_frameworks": [],
            "needs_followup": False
        }

    def generate_recommendations(self, workload_profile: Dict, pillar_scores: List[Dict], gaps: List[str]) -> List[Dict]:
        """Generate actionable recommendations based on the remediated roadmap prompt."""
        from .prompts import RECOMMENDATION_GENERATOR_PROMPT
        prompt = RECOMMENDATION_GENERATOR_PROMPT.format(
            workload_profile=json.dumps(workload_profile, indent=2),
            pillar_scores=json.dumps(pillar_scores, indent=2),
            gaps="\n".join(gaps) if gaps else "None identified"
        )
        response = self._chat(SYSTEM_CONTEXT, prompt)
        
        try:
            # Look for JSON array
            json_match = re.search(r'\[\s*\{.*\}\s*\]', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass
        return []

    def generate_executive_summary(self, workload_type: str, avg_score: float, 
                                   pillar_scores: List[Dict], top_gaps: List[str]) -> str:
        """Generate a 3-paragraph executive summary."""
        from .prompts import EXECUTIVE_SUMMARY_PROMPT
        prompt = EXECUTIVE_SUMMARY_PROMPT.format(
            workload_type=workload_type,
            avg_score=round(avg_score, 1),
            pillar_scores="\n".join([f"- {p['pillar']}: {p['score']}/5" for p in pillar_scores]),
            top_gaps="\n".join([f"- {g}" for g in top_gaps[:5]])
        )
        return self._chat(SYSTEM_CONTEXT, prompt)
