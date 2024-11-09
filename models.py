from sqlalchemy import Column, Integer, String, ForeignKey, DateTime,Boolean
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    password = Column(String)  # 哈希后的密码
    name = Column(String(100))  # 用户真实姓名
    # SUPERADMIN (超級管理) | WEB(平台) | TEST (測試用) | MOBILE (手機用)
    mode = Column(String(20),default="TEST")   # 用户模式
    enable = Column(Boolean, default=True)  # 启用状态
    comment = Column(String(255))  # 备注

class Client(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100))
    enabled = Column(Boolean, default=True)  # 新增字段，默认值为 True
  # 定义 relationship
    locations = relationship("Location", back_populates="client")

class Location(Base):
    __tablename__ = "locations"
    id = Column(Integer, primary_key=True, index=True)
    address = Column(String(255))
    enabled = Column(Boolean, default=True)  # 新增字段，默认值为 True
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



class VersionManagement(Base):
    __tablename__ = 'version_management'

    id = Column(Integer, primary_key=True, index=True)
    version_name = Column(String(100), index=True)
    file_path = Column(String(1024))
    upload_date = Column(DateTime, default=datetime.utcnow)
    uploaded_by = Column(String(100))

    def __repr__(self):
        return f"<VersionManagement(version_name={self.version_name}, uploaded_by={self.uploaded_by})>"

class VersionMapping(Base):
    __tablename__ = 'version_mapping'

    id = Column(Integer, primary_key=True, index=True)
    version_name = Column(String(100), index=True)
    user_name = Column(String(100))
    update_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<VersionMapping(version_name={self.version_name}, user_name={self.user_name})>"