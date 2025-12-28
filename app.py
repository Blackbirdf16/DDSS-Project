from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import uuid
import secrets

# Initialize FastAPI
app = FastAPI(
    title="FairRide API",
    description="Secure Ride Price Comparison Platform",
    version="1.0.0"
)

# CORS for mobile app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# === In-Memory Storage (for testing) ===
users_db: dict[str, dict[str, str]] = {
    "test":  {"password": "test123", "user_id": "user_001", "email": "test@example.com"},
    "demo": {"password": "demo123", "user_id": "user_002", "email": "demo@example.com"}
}
sessions = {}
trips_db = {}

# === Request/Response Models ===

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None

class LoginResponse(BaseModel):
    session_token: str
    user_id:  str
    username: str

class TripRequest(BaseModel):
    origin:  str
    destination: str

class TripResponse(BaseModel):
    trip_id: str
    origin: str
    destination:  str
    created_at: str

class PriceQuote(BaseModel):
    provider: str
    price: float
    currency: str = "USD"
    eta_minutes: int

class PriceComparisonResponse(BaseModel):
    trip_id: str
    quotes: List[PriceQuote]
    best_price: Optional[PriceQuote]

# === Auth Dependency ===

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    user_data = sessions.get(token)
    
    if not user_data: 
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session"
        )
    
    return user_data

# === Helper Functions ===

def simulate_provider_prices(origin: str, destination: str):
    """Simulate getting prices from multiple providers"""
    import random
    base_price = random.uniform(15, 50)
    
    providers = [
        {"provider": "Uber", "multiplier": 1.0, "eta_range": (5, 10)},
        {"provider": "Lyft", "multiplier":  0.95, "eta_range": (6, 12)},
        {"provider": "Bolt", "multiplier": 0.85, "eta_range": (7, 15)},
        {"provider": "FreeNow", "multiplier": 0.90, "eta_range": (5, 11)}
    ]
    
    quotes = []
    for p in providers:
        price = round(base_price * p["multiplier"], 2)
        eta = random.randint(*p["eta_range"])
        quotes.append({
            "provider": p["provider"],
            "price": price,
            "currency": "USD",
            "eta_minutes": eta
        })
    
    return quotes

# === Endpoints ===

@app.get("/")
async def root():
    return {
        "service": "FairRide API",
        "status": "running",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "health": "/health",
            "register": "/api/auth/register",
            "login":  "/api/auth/login",
            "create_trip": "/api/trips",
            "get_prices": "/api/trips/{trip_id}/prices"
        }
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "users_count": len(users_db),
        "active_sessions": len(sessions),
        "trips_count": len(trips_db)
    }

@app.post("/api/auth/register")
async def register(request: RegisterRequest):
    """Register new user"""
    if request.username in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    user_id = f"user_{uuid.uuid4().hex[:8]}"
    users_db[request.username] = {
        "password": request.password,
        "user_id":  user_id,
        "email": request.email or "",
        "created_at": datetime.utcnow().isoformat()
    }
    
    return {
        "success": True,
        "user_id": user_id,
        "username": request.username,
        "message": "User registered successfully"
    }

@app.post("/api/auth/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """Login and get session token"""
    user = users_db.get(request.username)
    
    if not user or user["password"] != request.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Create session
    session_token = secrets.token_urlsafe(32)
    sessions[session_token] = {
        "user_id": user["user_id"],
        "username": request.username,
        "created_at": datetime.utcnow().isoformat()
    }
    
    return LoginResponse(
        session_token=session_token,
        user_id=user["user_id"],
        username=request.username
    )

@app.post("/api/auth/logout")
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Logout and invalidate session"""
    token = credentials.credentials
    if token in sessions:
        del sessions[token]
    
    return {"success": True, "message": "Logged out successfully"}

@app. get("/api/auth/me")
async def get_current_user_info(user_data: dict = Depends(get_current_user)):
    """Get current user information"""
    return {
        "user_id": user_data["user_id"],
        "username": user_data["username"]
    }

@app.post("/api/trips", response_model=TripResponse)
async def create_trip(
    trip: TripRequest,
    user_data: dict = Depends(get_current_user)
):
    """Create new trip request"""
    trip_id = f"trip_{uuid.uuid4().hex[:12]}"
    trip_data = {
        "trip_id": trip_id,
        "user_id": user_data["user_id"],
        "origin":  trip.origin,
        "destination": trip.destination,
        "created_at": datetime.utcnow().isoformat(),
        "status": "pending"
    }
    
    trips_db[trip_id] = trip_data
    
    return TripResponse(
        trip_id=trip_data["trip_id"],
        origin=trip_data["origin"],
        destination=trip_data["destination"],
        created_at=trip_data["created_at"]
    )

@app.get("/api/trips/{trip_id}/prices", response_model=PriceComparisonResponse)
async def get_prices(
    trip_id: str,
    user_data: dict = Depends(get_current_user)
):
    """Get real-time prices and best option"""
    trip = trips_db.get(trip_id)
    
    if not trip:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Trip not found"
        )
    
    if trip["user_id"] != user_data["user_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Get simulated prices
    prices = simulate_provider_prices(trip["origin"], trip["destination"])
    
    # Format quotes
    quotes = [
        PriceQuote(
            provider=p["provider"],
            price=p["price"],
            currency=p["currency"],
            eta_minutes=p["eta_minutes"]
        )
        for p in prices
    ]
    
    # Find best price
    best = min(prices, key=lambda x: x["price"])
    best_quote = PriceQuote(
        provider=best["provider"],
        price=best["price"],
        currency=best["currency"],
        eta_minutes=best["eta_minutes"]
    )
    
    return PriceComparisonResponse(
        trip_id=trip_id,
        quotes=quotes,
        best_price=best_quote
    )

@app.get("/api/trips/user/history")
async def get_trip_history(user_data: dict = Depends(get_current_user)):
    """Get user's trip history"""
    user_trips = [
        trip for trip in trips_db.values()
        if trip["user_id"] == user_data["user_id"]
    ]
    
    return {
        "user_id": user_data["user_id"],
        "trips": user_trips,
        "count": len(user_trips)
    }

if __name__ == "__main__": 
    import uvicorn
    print("🚀 Starting FairRide API Server...")
    print("📱 Ready for Android app connection!")
    print("📚 API Docs: http://localhost:8000/docs")
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)