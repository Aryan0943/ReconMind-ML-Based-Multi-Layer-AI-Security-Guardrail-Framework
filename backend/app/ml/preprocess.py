import re
import unicodedata
from typing import List, Union
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer

# Key security indicator tokens that must never be stripped or normalized away
SECURITY_PRESERVED_TOKENS = {
    "ignore", "previous", "instructions", "system", "prompt", "override", 
    "bypass", "disregard", "dan", "jailbreak", "developer", "unrestricted",
    "secret", "reveal", "print", "admin", "root", "leak", "eval"
}

def clean_security_text(text: Union[str, float, None]) -> str:
    """
    Cleans and normalizes text while preserving crucial attack signatures and punctuation.
    - Handles NaN/None/non-string types safely
    - Normalizes Unicode (NFKC)
    - Normalizes excessive whitespace
    - Preserves case-insensitive security tokens and structural punctuation (e.g. delimiters, brackets)
    """
    if text is None or (isinstance(text, float) and np.isnan(text)):
        return ""
    
    if not isinstance(text, str):
        text = str(text)
        
    # Unicode normalization
    text = unicodedata.normalize("NFKC", text)
    
    # Standardize newlines and tabs
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\t", " ")
    
    # Collapse excessive spaces while preserving line breaks
    text = re.sub(r"[ ]{2,}", " ", text)
    text = text.strip()
    
    return text

class SecurityTextPreprocessor(BaseEstimator, TransformerMixin):
    """
    Scikit-learn compatible transformer for text cleaning.
    Ensures safe, reproducible preprocessing in ML pipelines.
    """
    def __init__(self):
        pass

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        if isinstance(X, (list, tuple, np.ndarray)):
            return [clean_security_text(t) for t in X]
        elif hasattr(X, "apply"):
            return X.apply(clean_security_text).tolist()
        else:
            return [clean_security_text(X)]

def create_security_tfidf(
    ngram_range=(1, 2),
    max_features=50000,
    min_df=2,
    sublinear_tf=True
) -> TfidfVectorizer:
    """
    Factory for standard TF-IDF vectorizer tuned for adversarial and security text detection.
    """
    return TfidfVectorizer(
        ngram_range=ngram_range,
        max_features=max_features,
        min_df=min_df,
        sublinear_tf=sublinear_tf,
        strip_accents="unicode",
        lowercase=True,
        token_pattern=r"(?u)\b\w+\b|[\[\]<>{}]"
    )
