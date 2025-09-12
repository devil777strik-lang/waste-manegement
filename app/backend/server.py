from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
from jose import JWTError, jwt
import httpx
from emergentintegrations.llm.chat import LlmChat, UserMessage

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# JWT Configuration
JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "waste-warriors-secret-key-2024")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_TIME = timedelta(hours=24)

# Emergent Auth URLs
EMERGENT_AUTH_URL = "https://auth.emergentagent.com"
EMERGENT_SESSION_URL = "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data"

# LLM Configuration
EMERGENT_LLM_KEY = os.environ.get('EMERGENT_LLM_KEY')

# Security
security = HTTPBearer(auto_error=False)

# Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    name: str
    picture: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Product(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    price: float
    image: str
    category: str = "waste-management"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ProductCreate(BaseModel):
    name: str
    description: str
    price: float
    image: str
    category: str = "waste-management"

class SellListing(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    title: str
    description: str
    category: str
    image: str
    price: Optional[float] = None
    ai_suggested_price: Optional[float] = None
    ai_classification: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SellListingCreate(BaseModel):
    title: str
    description: str
    category: str
    image: str
    price: Optional[float] = None

class Complaint(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    message: str
    category: str
    status: str = "pending"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ComplaintCreate(BaseModel):
    message: str
    category: str

class AuthSession(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    session_token: str
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SessionData(BaseModel):
    session_id: str

# Helper Functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + JWT_EXPIRATION_TIME
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    # Check session token from cookie first
    session_token = request.cookies.get("session_token")
    
    if session_token:
        # Validate session token from database
        session = await db.auth_sessions.find_one({"session_token": session_token})
        if session and session["expires_at"] > datetime.now(timezone.utc):
            user = await db.users.find_one({"id": session["user_id"]})
            if user:
                return User(**user)
    
    # Fallback to Authorization header
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    user = await db.users.find_one({"id": user_id})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    return User(**user)

async def classify_waste_with_ai(title: str, description: str) -> str:
    """Use AI to classify waste items"""
    try:
        chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=f"waste-classification-{uuid.uuid4()}",
            system_message="You are an expert in waste management and recycling. Classify items into categories: 'recyclable', 'biodegradable', 'hazardous', 'electronic', 'furniture', 'clothing', 'books', 'toys', or 'other'. Respond with only the category name."
        ).with_model("openai", "gpt-4o-mini")
        
        user_message = UserMessage(
            text=f"Classify this item: Title: {title}, Description: {description}"
        )
        
        response = await chat.send_message(user_message)
        return response.strip().lower()
    except Exception as e:
        logging.error(f"AI classification error: {e}")
        return "other"

async def suggest_price_with_ai(title: str, description: str, category: str) -> float:
    """Use AI to suggest pricing for items"""
    try:
        chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=f"price-suggestion-{uuid.uuid4()}",
            system_message="You are an expert in pricing second-hand items. Based on the title, description, and category, suggest a fair market price in USD. Consider condition, demand, and typical market values. Respond with only a number (no currency symbols)."
        ).with_model("openai", "gpt-4o-mini")
        
        user_message = UserMessage(
            text=f"Suggest a price for: Title: {title}, Description: {description}, Category: {category}"
        )
        
        response = await chat.send_message(user_message)
        try:
            price = float(response.strip().replace('$', '').replace(',', ''))
            return max(1.0, min(price, 10000.0))  # Between $1 and $10,000
        except ValueError:
            return 25.0  # Default price
    except Exception as e:
        logging.error(f"AI pricing error: {e}")
        return 25.0

# Authentication Routes
@api_router.post("/auth/session")
async def process_session(session_data: SessionData, response: Response):
    """Process Emergent Auth session ID"""
    try:
        headers = {"X-Session-ID": session_data.session_id}
        async with httpx.AsyncClient() as client:
            resp = await client.get(EMERGENT_SESSION_URL, headers=headers, timeout=30.0)
            if resp.status_code != 200:
                raise HTTPException(status_code=400, detail="Invalid session ID")
            
            auth_data = resp.json()
            
            # Check if user exists
            existing_user = await db.users.find_one({"email": auth_data["email"]})
            
            if not existing_user:
                # Create new user
                user_data = {
                    "id": str(uuid.uuid4()),
                    "email": auth_data["email"],
                    "name": auth_data["name"],
                    "picture": auth_data.get("picture"),
                    "created_at": datetime.now(timezone.utc)
                }
                await db.users.insert_one(user_data)
                user = User(**user_data)
            else:
                user = User(**existing_user)
            
            # Create session
            session_token = auth_data["session_token"]
            expires_at = datetime.now(timezone.utc) + timedelta(days=7)
            
            session_doc = {
                "id": str(uuid.uuid4()),
                "user_id": user.id,
                "session_token": session_token,
                "expires_at": expires_at,
                "created_at": datetime.now(timezone.utc)
            }
            await db.auth_sessions.insert_one(session_doc)
            
            # Set secure cookie
            response.set_cookie(
                key="session_token",
                value=session_token,
                httponly=True,
                secure=True,
                samesite="none",
                max_age=7 * 24 * 60 * 60,  # 7 days
                path="/"
            )
            
            return {"user": user, "message": "Authentication successful"}
            
    except Exception as e:
        logging.error(f"Session processing error: {e}")
        raise HTTPException(status_code=400, detail="Session processing failed")

@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    """Register new user with email/password"""
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(user_data.password)
    
    user_doc = {
        "id": str(uuid.uuid4()),
        "email": user_data.email,
        "name": user_data.name,
        "password_hash": hashed_password,
        "created_at": datetime.now(timezone.utc)
    }
    
    await db.users.insert_one(user_doc)
    user = User(**{k: v for k, v in user_doc.items() if k != "password_hash"})
    
    access_token = create_access_token(data={"sub": user.id})
    
    return {"access_token": access_token, "token_type": "bearer", "user": user}

@api_router.post("/auth/login")
async def login(login_data: UserLogin):
    """Login with email/password"""
    user_doc = await db.users.find_one({"email": login_data.email})
    
    if not user_doc or not verify_password(login_data.password, user_doc.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    user = User(**{k: v for k, v in user_doc.items() if k != "password_hash"})
    access_token = create_access_token(data={"sub": user.id})
    
    return {"access_token": access_token, "token_type": "bearer", "user": user}

@api_router.post("/auth/logout")
async def logout(response: Response, current_user: User = Depends(get_current_user)):
    """Logout and clear session"""
    # Clear session from database
    await db.auth_sessions.delete_many({"user_id": current_user.id})
    
    # Clear cookie
    response.delete_cookie(key="session_token", path="/")
    
    return {"message": "Logged out successfully"}

@api_router.get("/auth/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return current_user

# Product Routes
@api_router.get("/products", response_model=List[Product])
async def get_products():
    """Get all products"""
    products = await db.products.find().to_list(1000)
    return [Product(**product) for product in products]

@api_router.post("/products", response_model=Product)
async def create_product(product_data: ProductCreate, current_user: User = Depends(get_current_user)):
    """Create new product (admin only for now)"""
    product_doc = product_data.dict()
    product_doc["id"] = str(uuid.uuid4())
    product_doc["created_at"] = datetime.now(timezone.utc)
    
    await db.products.insert_one(product_doc)
    return Product(**product_doc)

# Sell/Community Marketplace Routes
@api_router.get("/listings", response_model=List[SellListing])
async def get_listings():
    """Get all community listings"""
    listings = await db.sell_listings.find().sort("created_at", -1).to_list(1000)
    return [SellListing(**listing) for listing in listings]

@api_router.post("/listings", response_model=SellListing)
async def create_listing(listing_data: SellListingCreate, current_user: User = Depends(get_current_user)):
    """Create new sell listing with AI features"""
    # Get AI classification and price suggestion
    ai_classification = await classify_waste_with_ai(listing_data.title, listing_data.description)
    ai_suggested_price = await suggest_price_with_ai(
        listing_data.title, 
        listing_data.description, 
        listing_data.category
    )
    
    listing_doc = listing_data.dict()
    listing_doc["id"] = str(uuid.uuid4())
    listing_doc["user_id"] = current_user.id
    listing_doc["ai_classification"] = ai_classification
    listing_doc["ai_suggested_price"] = ai_suggested_price
    listing_doc["created_at"] = datetime.now(timezone.utc)
    
    await db.sell_listings.insert_one(listing_doc)
    return SellListing(**listing_doc)

@api_router.get("/listings/my", response_model=List[SellListing])
async def get_my_listings(current_user: User = Depends(get_current_user)):
    """Get current user's listings"""
    listings = await db.sell_listings.find({"user_id": current_user.id}).sort("created_at", -1).to_list(1000)
    return [SellListing(**listing) for listing in listings]

# Complaint Routes
@api_router.post("/complaints", response_model=Complaint)
async def create_complaint(complaint_data: ComplaintCreate, current_user: User = Depends(get_current_user)):
    """Submit complaint or feedback"""
    complaint_doc = complaint_data.dict()
    complaint_doc["id"] = str(uuid.uuid4())
    complaint_doc["user_id"] = current_user.id
    complaint_doc["status"] = "pending"
    complaint_doc["created_at"] = datetime.now(timezone.utc)
    
    await db.complaints.insert_one(complaint_doc)
    return Complaint(**complaint_doc)

@api_router.get("/complaints/my", response_model=List[Complaint])
async def get_my_complaints(current_user: User = Depends(get_current_user)):
    """Get current user's complaints"""
    complaints = await db.complaints.find({"user_id": current_user.id}).sort("created_at", -1).to_list(1000)
    return [Complaint(**complaint) for complaint in complaints]

# AI Features Routes
@api_router.post("/ai/classify")
async def classify_item(title: str, description: str, current_user: User = Depends(get_current_user)):
    """Get AI classification for an item"""
    classification = await classify_waste_with_ai(title, description)
    return {"classification": classification}

@api_router.post("/ai/price-suggest")
async def suggest_price(title: str, description: str, category: str, current_user: User = Depends(get_current_user)):
    """Get AI price suggestion for an item"""
    price = await suggest_price_with_ai(title, description, category)
    return {"suggested_price": price}

# Initialize sample products
@api_router.post("/init/products")
async def initialize_products():
    """Initialize sample products"""
    sample_products = [
        {
            "id": str(uuid.uuid4()),
            "name": "Smart Waste Bin Set",
            "description": "Color-coded waste bins for efficient waste sorting - Recyclable, Biodegradable, Hazardous",
            "price": 89.99,
            "image": "https://images.unsplash.com/photo-1611284446314-60a58ac0deb9?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2NzV8MHwxfHNlYXJjaHwxfHx3YXN0ZSUyMG1hbmFnZW1lbnR8ZW58MHx8fHwxNzU3NjkzMjYxfDA&ixlib=rb-4.1.0&q=85",
            "category": "waste-management",
            "created_at": datetime.now(timezone.utc)
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Compost Starter Kit",
            "description": "Complete organic waste composting system for home use",
            "price": 45.99,
            "image": "https://images.unsplash.com/photo-1542601906990-b4d3fb778b09?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NDk1Nzd8MHwxfHNlYXJjaHwyfHxzdXN0YWluYWJpbGl0eXxlbnwwfHx8fDE3NTc2OTMyNjZ8MA&ixlib=rb-4.1.0&q=85",
            "category": "composting",
            "created_at": datetime.now(timezone.utc)
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Recycling Collection Bags",
            "description": "Durable collection bags for different waste categories",
            "price": 24.99,
            "image": "https://images.unsplash.com/photo-1582408921715-18e7806365c1?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2NzV8MHwxfHNlYXJjaHw0fHx3YXN0ZSUyMG1hbmFnZW1lbnR8ZW58MHx8fHwxNzU3NjkzMjYxfDA&ixlib=rb-4.1.0&q=85",
            "category": "recycling",
            "created_at": datetime.now(timezone.utc)
        }
    ]
    
    # Clear existing products and insert new ones
    await db.products.delete_many({})
    await db.products.insert_many(sample_products)
    
    return {"message": "Sample products initialized", "count": len(sample_products)}

# Basic status check
@api_router.get("/")
async def root():
    return {"message": "Waste Warriors API is running", "version": "1.0.0"}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()