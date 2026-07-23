"""Base de conocimiento estructurada sobre las CVEs monitoreadas."""

from .loader import CveDefinition, KnowledgeBase, load_knowledge_base

__all__ = ["CveDefinition", "KnowledgeBase", "load_knowledge_base"]
