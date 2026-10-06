import os
from langchain_openai import ChatOpenAI

# Overridable without code changes; defaults match the original deployment.
DEFAULT_MODEL = "gpt-5.6-luna"
DEFAULT_BASE_URL = "https://tag-news-resource.services.ai.azure.com/openai/v1"


def make_llm(api_key: str = None) -> ChatOpenAI:
    """Builds the chat model. The key is passed directly, never written to os.environ."""
    return ChatOpenAI(
        model=os.environ.get("DFIR_LLM_MODEL", DEFAULT_MODEL),
        temperature=0,
        api_key=api_key or os.environ.get("OPENAI_API_KEY"),
        base_url=os.environ.get("DFIR_LLM_BASE_URL", DEFAULT_BASE_URL),
    )
