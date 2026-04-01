"""
Database layer — MySQL (PyMySQL) via SQLAlchemy.
Connection string is read from the DATABASE_URL environment variable.
Default: XAMPP local MySQL with root user and no password.
"""
from sqlalchemy import create_engine, Column, String, Float, DateTime, Text, JSON, Integer
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.dialects.mysql import LONGTEXT
import os
import datetime
from dotenv import load_dotenv

load_dotenv()  # Load .env file if present

# ── Connection ──────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "mysql+pymysql://root:@localhost/CloudSecurityApp"
)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,        # Reconnect on stale connections
    pool_recycle=3600,         # Recycle connections every hour
    echo=False,                # Set True for SQL debug output
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── ORM Models ───────────────────────────────────────────────────────────────

class VulnerabilityDB(Base):
    """Mirrors the `vulnerabilities` MySQL table."""
    __tablename__ = "vulnerabilities"

    id             = Column(String(36),  primary_key=True, index=True)
    title          = Column(String(512), index=True, nullable=False)
    severity       = Column(String(32),  index=True, nullable=False, default="info")
    priority_score = Column(Float,       index=True, nullable=False, default=0.0)
    status         = Column(String(64),  nullable=False, default="new")
    scanner_source = Column(String(64),  nullable=False, default="unknown")
    environment    = Column(String(128), nullable=True, default="unknown")
    full_data      = Column(JSON,        nullable=False)
    created_at     = Column(DateTime,    nullable=False, default=datetime.datetime.utcnow)
    updated_at     = Column(DateTime,    nullable=False, default=datetime.datetime.utcnow,
                            onupdate=datetime.datetime.utcnow)


class AssessmentSessionDB(Base):
    """Mirrors the `assessment_sessions` MySQL table."""
    __tablename__ = "assessment_sessions"

    id                   = Column(String(36),  primary_key=True)
    started_at           = Column(DateTime,    nullable=False, default=datetime.datetime.utcnow)
    completed_at         = Column(DateTime,    nullable=True)
    workload_type        = Column(String(256), nullable=True)
    average_score        = Column(Float,       nullable=True)
    pillar_scores        = Column(JSON,        nullable=True)
    recommendations      = Column(JSON,        nullable=True)
    executive_summary    = Column(Text,        nullable=True)
    qa_log               = Column(JSON,        nullable=True)
    conversation_history = Column(JSON,        nullable=True)


class ApiKeyDB(Base):
    """Mirrors the `api_keys` MySQL table."""
    __tablename__ = "api_keys"

    id             = Column(Integer,     primary_key=True, autoincrement=True)
    key_hash       = Column(String(128), unique=True, nullable=False, index=True)
    label          = Column(String(128), nullable=False)
    is_active      = Column(Integer,     nullable=False, default=1)
    created_at     = Column(DateTime,    nullable=False, default=datetime.datetime.utcnow)
    last_used_at   = Column(DateTime,    nullable=True)
    requests_count = Column(Integer,     nullable=False, default=0)


# ── Helpers ───────────────────────────────────────────────────────────────────

def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)
    
    # Auto-seed default dev key
    import hashlib
    db = SessionLocal()
    try:
        key_str = "dev-test-key-antigravity"
        key_hash = hashlib.sha256(key_str.encode()).hexdigest()
        if not db.query(ApiKeyDB).filter(ApiKeyDB.key_hash == key_hash).first():
            new_key = ApiKeyDB(key_hash=key_hash, label="Default Dev Key", is_active=1)
            db.add(new_key)
            db.commit()
    except Exception as e:
        print(f"Error seeding DB: {e}")
    finally:
        db.close()


def get_db():
    """FastAPI dependency: yields a DB session and closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
