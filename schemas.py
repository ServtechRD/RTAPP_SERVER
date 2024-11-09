from pydantic import BaseModel
from typing import Any,List, Optional
from datetime import datetime




class UserCreate(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class ClientBase(BaseModel):
    name: str
    enabled: Optional[bool] = True


class ClientUpdate(BaseModel):
    name: Optional[str] = None  # 假设仅更新客户的名称字段
    enabled: Optional[bool] = True
    # 添加更多字段（如地址或其他客户信息）

class LocationBase(BaseModel):
    address: str
    client_id: int
    enabled: Optional[bool] = True  # 默认值为 True

class LocationUpdate(BaseModel):
    address: Optional[str] = None
    client_id: Optional[int] = None
    enabled: Optional[bool] = None

# Location 的 Pydantic 模型
class LocationResponse(BaseModel):
    id: int
    address: str
    enabled: bool

    class Config:
        orm_mode = True

# Client 的 Pydantic 模型
class ClientResponse(BaseModel):
    id: int
    name: str
    enabled: bool
    locations: List[LocationResponse] = []  # 包含 LocationResponse 列表

    class Config:
        orm_mode = True


class TaskBase(BaseModel):
    name: str
    identifier1: str
    identifier2: str

class PhotoBase(BaseModel):
    file_path: str
    result: str
    task_id: int

# Pydantic 模型
class PhotoUploadResponse(BaseModel):
    id: int
    file_path: str
    file_result_path: Optional[str]
    customerId: int
    locationId: int
    detectLabels: str
    taskId: int
    saveTime: str
    ownerName: Optional[str]
    userName: str
    created_at: datetime
    updated_at: Optional[datetime]


class JSendResponse(BaseModel):
    status: str
    data: Optional[Any] = None
    message: Optional[str] = None

    class Config:
        orm_mode = True