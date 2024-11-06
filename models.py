from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    password = Column(String)  # 哈希后的密码


class Client(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100))
  # 定义 relationship
    locations = relationship("Location", back_populates="client")

class Location(Base):
    __tablename__ = "locations"
    id = Column(Integer, primary_key=True, index=True)
    address = Column(String(255))
    client_id = Column(Integer, ForeignKey("clients.id"))
 # 定义 relationship
    client = relationship("Client", back_populates="locations")


class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100))
    identifier1 = Column(String(100))
    identifier2 = Column(String(100))

class Photo(Base):
    __tablename__ = "photos"
    id = Column(Integer, primary_key=True, index=True)
    file_path = Column(String(255))
    result = Column(String(255))
    task_id = Column(Integer, ForeignKey("tasks.id"))


class PhotoUpload(Base):
    __tablename__ = "photo_uploads"

    id = Column(Integer, primary_key=True, index=True)
    file_path = Column(String(2048), nullable=False)  # 存储文件路径
    file_result_path = Column(String(2048), nullable=True)  # 存储可选文件路径
    customerId = Column(Integer, nullable=False)
    locationId = Column(Integer, nullable=False)
    detectLabels = Column(String(1024), nullable=False)
    taskId = Column(Integer, nullable=False)
    saveTime = Column(String(100), nullable=False)
    ownerName = Column(String(255), nullable=True)
    userName = Column(String(255), nullable=False, default="user")
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), onupdate=datetime.utcnow)
