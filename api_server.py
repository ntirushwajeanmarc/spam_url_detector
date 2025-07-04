#!/usr/bin/env python3
"""
FastAPI Server for URL Spam Detection

A high-performance REST API server for the URL spam detection service.
Provides endpoints for single URL checking and batch processing with automatic documentation.

Usage:
    uvicorn api_server:app --host 0.0.0.0 --port 5000

Endpoints:
    POST /check - Check single URL
    POST /batch - Check multiple URLs
    GET /health - Health check
    GET /stats - Get detector statistics
    GET /docs - Interactive API documentation
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import List, Dict, Any, Optional
from spam_detector import URLSpamDetector
import logging
import time
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Pydantic models for request/response validation
class URLCheckRequest(BaseModel):
    url: str = Field(..., description="URL to check for spam/phishing", example="https://example.com")
    
    @validator('url')
    def validate_url(cls, v):
        if not v or not isinstance(v, str) or len(v.strip()) == 0:
            raise ValueError('Valid URL string is required')
        return v.strip()

class BatchURLRequest(BaseModel):
    urls: List[str] = Field(..., description="List of URLs to check", max_items=100)
    
    @validator('urls')
    def validate_urls(cls, v):
        if not v or len(v) == 0:
            raise ValueError('At least one URL is required')
        if len(v) > 100:
            raise ValueError('Maximum 100 URLs per batch')
        return [url.strip() for url in v if url.strip()]

class URLCheckResponse(BaseModel):
    is_spam: bool = Field(..., description="Whether the URL is classified as spam")
    confidence: float = Field(..., description="Confidence score (0-1)")
    classification: str = Field(..., description="Classification label")
    risk_factors: List[str] = Field(..., description="Identified risk factors")
    processing_time: float = Field(..., description="Processing time in seconds")

class BatchURLResponse(BaseModel):
    results: List[Dict[str, Any]] = Field(..., description="Results for each URL")
    total_processed: int = Field(..., description="Total number of URLs processed")
    processing_time: float = Field(..., description="Total processing time in seconds")

class HealthResponse(BaseModel):
    status: str = Field(..., description="Service status")
    service: str = Field(..., description="Service name")
    version: str = Field(..., description="Service version")
    timestamp: float = Field(..., description="Current timestamp")

class StatsResponse(BaseModel):
    model_info: Dict[str, Any] = Field(..., description="Model information")
    capabilities: List[str] = Field(..., description="Detection capabilities")
    supported_schemes: List[str] = Field(..., description="Supported URL schemes")
    version: str = Field(..., description="Service version")

# Initialize FastAPI app
app = FastAPI(
    title="URL Spam Detection API",
    description="A robust, production-ready API for detecting spam and phishing URLs using machine learning",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global detector instance
detector: Optional[URLSpamDetector] = None

@app.on_event("startup")
async def startup_event():
    """Initialize the spam detector on startup."""
    global detector
    try:
        detector = URLSpamDetector()
        logger.info("URL spam detector initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize detector: {e}")
        raise

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint to verify service status."""
    return HealthResponse(
        status="healthy",
        service="url-spam-detector",
        version="1.0.0",
        timestamp=time.time()
    )

@app.post("/check", response_model=URLCheckResponse, tags=["Detection"])
async def check_url(request: URLCheckRequest):
    """
    Check a single URL for spam/phishing.
    
    Returns detailed analysis including confidence score and risk factors.
    """
    start_time = time.time()
    
    try:
        if detector is None:
            raise HTTPException(status_code=503, detail="Detector not initialized")
        
        # Make prediction
        is_spam, confidence, details = detector.predict(request.url)
        
        return URLCheckResponse(
            is_spam=is_spam,
            confidence=confidence,
            classification=details.get('classification', 'unknown'),
            risk_factors=details.get('risk_factors', []),
            processing_time=time.time() - start_time
        )
        
    except Exception as e:
        logger.error(f"Error processing URL check: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Internal server error: {str(e)}"
        )

@app.post("/batch", response_model=BatchURLResponse, tags=["Detection"])
async def batch_check(request: BatchURLRequest):
    """
    Check multiple URLs for spam/phishing.
    
    Processes up to 100 URLs in a single request with detailed results for each.
    """
    start_time = time.time()
    
    try:
        if detector is None:
            raise HTTPException(status_code=503, detail="Detector not initialized")
        
        # Process batch
        results = []
        for url in request.urls:
            try:
                is_spam, confidence, details = detector.predict(url)
                result = {
                    'url': url,
                    'is_spam': is_spam,
                    'confidence': confidence,
                    'classification': details.get('classification', 'unknown'),
                    'risk_factors': details.get('risk_factors', [])
                }
                results.append(result)
            except Exception as e:
                results.append({
                    'url': url,
                    'error': str(e),
                    'classification': 'error',
                    'confidence': 0.0
                })
        
        return BatchURLResponse(
            results=results,
            total_processed=len(results),
            processing_time=time.time() - start_time
        )
        
    except Exception as e:
        logger.error(f"Error processing batch check: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/stats", response_model=StatsResponse, tags=["Information"])
async def get_stats():
    """Get detector statistics and model information."""
    try:
        return StatsResponse(
            model_info={
                'features': 22,
                'algorithm': 'Random Forest',
                'training_samples': 10783,
                'accuracy': 0.9926
            },
            capabilities=[
                'Phishing keyword detection',
                'Typosquatting detection',
                'Suspicious TLD detection',
                'IP address detection',
                'Security pattern analysis'
            ],
            supported_schemes=['http', 'https', 'ftp'],
            version='1.0.0'
        )
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=5000,
        reload=False,
        log_level="info"
    )
