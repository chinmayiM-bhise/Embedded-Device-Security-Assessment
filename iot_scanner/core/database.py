from sqlalchemy import Column, String, DateTime, JSON, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

Base = declarative_base()

class ScanResult(Base):
    __tablename__ = 'scans'
    id = Column(String, primary_key=True)
    filename = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String)
    results = Column(JSON)

# Create engine and tables
engine = create_engine('sqlite:///iot_scanner.db')
Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)

def save_scan(scan_id, filename, results, status="Completed"):
    session = Session()
    try:
        scan = ScanResult(id=scan_id, filename=filename, results=results, status=status)
        session.merge(scan)
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def get_all_scans():
    session = Session()
    try:
        scans = session.query(ScanResult).order_by(ScanResult.timestamp.desc()).all()
        return scans
    finally:
        session.close()

def get_scan(scan_id):
    session = Session()
    try:
        return session.query(ScanResult).filter(ScanResult.id == scan_id).first()
    finally:
        session.close()

