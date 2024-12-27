from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Query, status, Request
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import FileResponse, JSONResponse
from datetime import datetime
from sqlalchemy import and_, distinct
from sqlalchemy.orm import Session, joinedload
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from auth import create_access_token, authenticate_user, get_password_hash, SECRET_KEY, ALGORITHM
from database import SessionLocal, engine
from models import Base, User, Client, Location, Task, Photo, PhotoUpload, VersionManagement, VersionMapping
from schemas import Token, UserCreate, ClientBase, LocationBase, TaskBase, PhotoBase, PhotoUploadResponse, \
    ClientResponse, JSendResponse, ClientUpdate, LocationUpdate, VersionMappingResponse, VersionManagementResponse, \
    UserUpdate
from auth import get_password_hash
from pydantic import BaseModel
from typing import Any, List, Optional
from jose import JWTError, jwt

import shutil

import logging
from logging.handlers import TimedRotatingFileHandler

import re
import os
import uuid
import json
import glob
import zipfile

# 创建日志目录
log_dir = "../logs"
os.makedirs(log_dir, exist_ok=True)

# 获取当前日期
# current_date = datetime.now()

# 格式化为 yyyyMMdd
# formatted_date = current_date.strftime("%Y%m%d")

# 设置日志文件路径
# log_file_path = os.path.join(log_dir, f"dev_{formatted_date}.txt")

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        TimedRotatingFileHandler(
            filename=os.path.join(log_dir, "app.txt"),  # 基础日志文件名
            when="midnight",  # 每天生成一个新日志文件
            interval=1,
            backupCount=30,  # 保留最近30天的日志
            encoding="utf-8",
            utc=True
        )
    ],
)

# 获取 logger
logger = logging.getLogger(__name__)

app = FastAPI()

# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 根据需要配置来源
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 设定静态文件目录 (即React build后的目录)
# app.mount("/static", StaticFiles(directory="build/static"), name="static")


Base.metadata.create_all(bind=engine)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Dependency to get the session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        print("JWT DECODE")
        # 解码 JWT
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # 查询数据库，获取用户信息
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception

    print(f"user is {user.username} mode = {user.mode}")

    return user


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    logger.error(f"HTTP Exception: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error(f"Validation Error: {exc.errors()}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unexpected Exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


@app.middleware("http")
async def log_requests(request: Request, call_next):
    # 记录请求信息
    request_time = datetime.utcnow()

    # 定义需要跳过日志记录的路径
    excluded_paths = ["/token", "/weblogin/", "/user_mode/"]

    # 如果路径在排除列表中，则跳过日志记录
    if request.url.path in excluded_paths:
        return await call_next(request)

        # 尝试解析请求体
    try:
        if request.method in ["POST", "PUT", "PATCH"]:  # 针对需要处理请求体的 HTTP 方法
            request_body = await request.json()
            # 只记录文字或数字的字段
            filtered_body = {key: value for key, value in request_body.items() if isinstance(value, (str, int, float))}
        else:
            filtered_body = {}
    except Exception:
        # 如果不是 JSON 格式，尝试解析 Form 数据
        try:
            form_data = await request.form()
            filtered_body = {key: value for key, value in form_data.items() if isinstance(value, (str, int, float))}
        except Exception:
            filtered_body = {}

    # 记录请求日志
    logger.info(
        f"Request: method={request.method}, url={request.url}, body={filtered_body}"
    )

    # 调用下一个处理程序
    response = await call_next(request)

    # 记录响应信息
    # response_body = b""
    # async for chunk in response.body_iterator:
    #    response_body += chunk
    logger.info(
        f"Response: status_code={response.status_code}"
    )

    # 返回响应
    return response


@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    # 检查用户名是否已经存在
    user = db.query(User).filter(User.username == username).first()
    if user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # 对密码进行哈希处理
    hashed_password = get_password_hash(password)
    new_user = User(username=username, password=hashed_password)

    # 保存新用户到数据库
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created successfully", "username": new_user.username}


@app.post("/token", response_model=Token)
async def login_for_access_token(db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/weblogin/")
def check_user_role(current_user: User = Depends(get_current_user)):
    # 检查用户的角色
    if current_user.mode not in ["SUPERADMIN", "WEB", "VIEW"]:
        raise HTTPException(status_code=400, detail=f"未授權Web登入 mode{current_user.mode}")

    # 返回成功信息
    return {"message": "User is authorized", "user_mode": current_user.mode}


@app.get("/users_mode/", response_model=List[str])
def get_available_user_types(current_user: User = Depends(get_current_user)):
    # 检查用户的角色，并返回相应的可用用户类型
    if current_user.mode == "SUPERADMIN":
        return ["WEB", "TEST", "MOBILE"]
    elif current_user.mode == "WEB":
        return ["WEB", "VIEW"]
    else:
        raise HTTPException(status_code=403, detail="Unauthorized to retrieve user types")


@app.post("/users/", response_model=UserCreate)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, password=hashed_password, mode=user.mode, name=user.name, enable=True)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.put("/users/{user_id}")
def update_user(user_id: int, user_update: UserUpdate, current_user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    # 仅允许 SUPER ADMIN 和 WEB 用户进行此操作
    if current_user.mode not in ["SUPERADMIN", "WEB"]:
        raise HTTPException(status_code=403, detail="Unauthorized to update user")

    # 查询指定的用户
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 更新密码（如果提供了新的密码）
    if user_update.password:
        user.password = get_password_hash(user_update.password)

    if user_update.name:
        user.name = user_update.name

    # 更新启用状态（如果提供了新的启用状态）
    if user_update.enable is not None:
        user.enable = user_update.enable

    # 提交更改
    db.commit()
    db.refresh(user)
    return {"message": "User updated successfully",
            "user": {"id": user.id, "username": user.username, "enable": user.enable}}


@app.get("/users/all/")
def get_all_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user_mode = current_user.mode

    if user_mode == "SUPERADMIN":
        users = db.query(User).all()
    elif user_mode == "WEB":
        users = db.query(User).filter(User.mode.in_(["WEB", "VIEW", "MOBILE"])).all()
    else:
        raise HTTPException(status_code=403, detail="Insufficient permissions to view all users")

    return {
        "users": [
            {"id": user.id, "username": user.username, "mode": user.mode, "name": user.name, "enable": user.enable} for
            user in users]}


@app.get("/users/mobile/")
def get_mobile_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user_mode = current_user.mode

    if user_mode == "SUPERADMIN":
        users = db.query(User).filter(User.mode.in_(["TEST", "MOBILE"])).all()
    elif user_mode == "WEB":
        users = db.query(User).filter(User.mode == "MOBILE").all()
    else:
        raise HTTPException(status_code=403, detail="Insufficient permissions to view mobile users")

    return {
        "users": [{"id": user.id, "username": user.username, "mode": user.mode, "name": user.name} for user in users]}


# CRUD for Clients
@app.post("/clients/")
def create_client(client: ClientBase, db: Session = Depends(get_db)):
    db_client = Client(name=client.name)
    db.add(db_client)
    db.commit()
    db.refresh(db_client)
    return db_client


@app.get("/clients/")
def get_clients(db: Session = Depends(get_db)):
    return db.query(Client).all()


@app.put("/clients/{client_id}")
def update_client(client_id: int, client: ClientUpdate, db: Session = Depends(get_db)):
    # 查询客户是否存在
    db_client = db.query(Client).filter(Client.id == client_id).first()
    if not db_client:
        raise HTTPException(status_code=404, detail="Client not found")

    # 更新客户信息
    if client.name is not None:
        db_client.name = client.name

    db_client.enabled = client.enabled

    # 可以根据需要添加更多字段的更新逻辑

    # 提交更改
    db.commit()
    db.refresh(db_client)
    return {"message": "Client updated successfully", "client": db_client}


# CRUD for Locations
@app.post("/locations/")
def create_location(location: LocationBase, db: Session = Depends(get_db)):
    db_location = Location(address=location.address, client_id=location.client_id)
    db.add(db_location)
    db.commit()
    db.refresh(db_location)
    return db_location


@app.get("/locations/")
def get_locations(db: Session = Depends(get_db)):
    return db.query(Location).all()


@app.put("/locations/{location_id}")
def update_location(location_id: int, location: LocationUpdate, db: Session = Depends(get_db)):
    # 查找指定的 Location 记录
    db_location = db.query(Location).filter(Location.id == location_id).first()
    if not db_location:
        raise HTTPException(status_code=404, detail="Location not found")

    # 更新字段
    if location.address is not None:
        db_location.address = location.address
    if location.client_id is not None:
        db_location.client_id = location.client_id
    if location.enabled is not None:
        db_location.enabled = location.enabled

    # 提交更改
    db.commit()
    db.refresh(db_location)
    return {"message": "Location updated successfully", "location": db_location}


@app.get("/clients_with_locations/", response_model=List[ClientResponse])
async def get_clients_with_locations(all: bool = Query(False), db: Session = Depends(get_db)):
    # 如果 all 参数为 True，则不进行过滤
    if all:
        clients = db.query(Client).options(joinedload(Client.locations)).all()
    else:
        # 仅查询 enabled = True 的客户和位置
        clients = (
            db.query(Client)
            .filter(Client.enabled == True)  # 过滤 enabled 为 True 的客户
            .options(joinedload(Client.locations.and_(Location.enabled == True)))  # 过滤 enabled 为 True 的位置
            .all()
        )

    return clients


# CRUD for Tasks
@app.post("/tasks/")
def create_task(task: TaskBase, db: Session = Depends(get_db)):
    db_task = Task(name=task.name, identifier1=task.identifier1, identifier2=task.identifier2)
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task


@app.get("/tasks/")
def get_tasks(db: Session = Depends(get_db)):
    return db.query(Task).all()


@app.get("/models/last")
async def get_version(user_name: str):
    # 指定 JSON 文件路径
    file_path = "../Models/last.json"

    # 检查文件是否存在
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    # 读取 JSON 文件
    try:
        with open(file_path, "r") as file:
            data = json.load(file)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Error reading JSON file")

    # 查找版本号
    if user_name in data:
        return {"version": data[user_name]}
    elif "all" in data:
        return {"version": data["all"]}
    else:
        raise HTTPException(status_code=404, detail="Version not found")

    # 1. 下载 train.tflite 文件


@app.get("/models/labels", response_model=list)
async def get_model_labels(version: str):
    # 搜索 train.tflite 文件路径
    search_path = f"../Models/{version}/**/train.pbtxt"
    files = glob.glob(search_path, recursive=True)
    # 检查是否找到文件
    if not files:
        raise HTTPException(status_code=404, detail="train.pbtxt file not found")

    try:
        # 读取文件内容
        # 获取找到的文件路径
        file_path = files[0]
        with open(file_path, "r") as file:
            content = file.read()

        # 使用正则表达式提取 `name` 字段
        labels = re.findall(r"name:\s*'(.*?)'", content)
        return labels

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file: {str(e)}")


@app.get("/models/file")
async def download_tfile(version: str):
    # 搜索 train.tflite 文件路径
    search_path = f"../Models/{version}/**/train.tflite"
    files = glob.glob(search_path, recursive=True)

    # 检查是否找到文件
    if not files:
        raise HTTPException(status_code=404, detail="train.tflite file not found")

    # 获取找到的文件路径
    file_path = files[0]

    # 返回文件作为下载
    return FileResponse(path=file_path, media_type="application/octet-stream", filename="train.tflite")


# 2. 获取 action.json 内容
@app.get("/models/action")
async def get_action(version: str):
    # 搜索 action.json 文件路径
    search_path = f"../Models/{version}/**/action.json"
    files = glob.glob(search_path, recursive=True)

    # 检查是否找到文件
    if not files:
        raise HTTPException(status_code=404, detail="action.json file not found")

    # 获取找到的文件路径
    file_path = files[0]

    # 读取 JSON 文件内容并返回
    try:
        with open(file_path, "r") as file:
            data = json.load(file)
        return JSONResponse(content=data)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Error reading JSON file")


# Photo Upload
# 创建保存路径的函数
def create_upload_path(cid, lid, sn):
    # 获取当前时间并格式化为 yyyy/MM/dd
    now = datetime.now()
    dir_path = "/home/Upload/NA"
    if (len(sn) > 0):
        dir_path = now.strftime(f"/home/Upload/{sn}/%Y/%m/%d")
    else:
        dir_path = now.strftime(f"/home/Upload/{cid}/{lid}/%Y/%m/%d")
    print("create path = " + dir_path)
    # 如果目录不存在，则创建
    os.makedirs(dir_path, exist_ok=True)
    return dir_path


# 生成带有日期和 UUID 的文件名
def generate_file_name(extension: str, unique_id):
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d%H%M")  # 生成年月日時分
    # unique_id = uuid.uuid4()  # 生成唯一的 UUID
    return f"{timestamp}_{unique_id}.{extension}"


# 上传文件处理
@app.post("/photos/")
async def upload_photo(
        file: UploadFile = File(...),
        file_result: UploadFile = File(None),
        customerId: str = Form(...),
        locationId: str = Form(...),
        detectLabels: str = Form(...),
        taskId: str = Form(...),
        saveTime: str = Form(...),
        ownerName=Form(None),
        userName=Form("user"),
        serialNumber=Form(""),
        db: Session = Depends(get_db)
):
    logger.info(f"start to create upload_path :{serialNumber}")

    # 创建保存文件的目录
    upload_dir = create_upload_path(customerId, locationId, serialNumber)

    # task_id = 1
    unique_id = uuid.uuid4()  # 生成唯一的 UUID

    print(unique_id)

    if (ownerName is None):
        ownerName = userName

    # return "success"

    logger.info(f"start to save image :{file.filename} ")
    # 保存图片文件
    file_path_extension = file.filename.split(".")[-1]  # 获取文件扩展名
    file_name = generate_file_name(file_path_extension, unique_id)  # 生成新的文件名
    file_path_location = os.path.join(upload_dir, file_name)  # 完整的文件路径
    print(file_path_location)
    with open(file_path_location, "wb") as f:
        print("start to write raw image")
        f.write(await file.read())  # 保存文件

    if (file_result is not None):
        file_result_path_location = file_path_location + "_result.png"
        print(file_result_path_location)

        with open(file_result_path_location, "wb") as f:
            print("start to write result image")
            f.write(await file_result.read())  # 保存文件

    logger.info("start to save txt ")
    # 保存任意文件 (result)
    result_extension = "txt"
    result_file_name = generate_file_name(result_extension, unique_id)
    result_file_location = os.path.join(upload_dir, result_file_name)
    print(result_file_location)
    with open(result_file_location, "w") as f:
        f.write(taskId + "\n")
        f.write(detectLabels + "\n")
        f.write(saveTime + "\n")
        f.write(userName + "\n")
        f.write(ownerName + "\n")

    # 如果未輸入, 表示是舊版本
    sn = serialNumber
    if len(sn) == 0:
        sn = "0000000"

    ownerType = 0
    # 有非數字
    if not ownerName.isdigit():
        ownerType = 1

    logger.info("start to save database ")
    # 将文件名保存到数据库
    new_photo = PhotoUpload(
        file_path=file_path_location,  # 只保存文件名
        file_result_path=file_result_path_location,
        serialNumber=sn,
        customerId=int(customerId),
        locationId=int(locationId),
        detectLabels=detectLabels,
        taskId=int(taskId),
        saveTime=saveTime,
        ownerName=ownerName,
        userName=userName,
        ownerType=ownerType,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    db.add(new_photo)
    db.commit()
    db.refresh(new_photo)

    print("finish")
    logger.info("photo save finish ")

    # 返回文件名而不是文件内容
    return {"message": "File uploaded successfully", "photo": {
        "file_path": file_name,
        "result": result_file_name
    }}


# 综合查询 API
@app.get("/photos/query/", response_model=List[PhotoUploadResponse])
async def query_photos(
        start_time: str,
        end_time: str,
        serialNumber: Optional[str] = None,
        customerId: Optional[str] = None,
        ownerName: Optional[str] = None,
        db: Session = Depends(get_db)
):
    # 构建基本的时间范围过滤条件
    filters = [
        PhotoUpload.saveTime >= start_time,
        PhotoUpload.saveTime <= end_time
    ]

    # 如果指定了 customerId，则添加到过滤条件中
    if customerId:
        filters.append(PhotoUpload.customerId == customerId)

    # 如果指定了 ownerName，则添加到过滤条件中
    if ownerName:
        filters.append(PhotoUpload.ownerName == ownerName)

    if serialNumber:
        filters.append(PhotoUpload.serialNumber == serialNumber)

    # 应用所有过滤条件
    photos = db.query(PhotoUpload).filter(and_(*filters)).all()

    if not photos:
        raise HTTPException(status_code=404, detail="No photos found for the specified criteria.")

    return photos


@app.get("/photos/download_zip/")
async def download_photos_as_zip(
        start_time: str,
        end_time: str,
        serialNumber: Optional[str] = None,
        customerId: Optional[str] = None,
        ownerName: Optional[str] = None,
        db: Session = Depends(get_db)
):
    # 构建时间过滤条件
    filters = [
        PhotoUpload.saveTime >= start_time,
        PhotoUpload.saveTime <= end_time
    ]
    if serialNumber:
        filters.append(PhotoUpload.serialNumber == serialNumber)
    if customerId:
        filters.append(PhotoUpload.customerId == customerId)
    if ownerName:
        filters.append(PhotoUpload.ownerName == ownerName)

    # 查询数据库
    photos = db.query(PhotoUpload).filter(and_(*filters)).all()
    if not photos:
        raise HTTPException(status_code=404, detail="No photos found for the specified criteria.")

    # 定义目标目录
    temp_dir = "../Download/Temp"
    os.makedirs(temp_dir, exist_ok=True)

    # 清空目标目录
    for file in os.listdir(temp_dir):
        file_path = os.path.join(temp_dir, file)
        if os.path.isfile(file_path):
            os.remove(file_path)

    # 处理文件
    for photo in photos:
        # 复制 file_path
        if photo.file_path and os.path.exists(photo.file_path):
            target_file_path = os.path.join(temp_dir, f"{photo.id}.png")
            shutil.copy(photo.file_path, target_file_path)

        # 复制 file_result_path
        if photo.file_result_path and os.path.exists(photo.file_result_path):
            target_result_path = os.path.join(temp_dir, f"{photo.id}_result.png")
            shutil.copy(photo.file_result_path, target_result_path)

    # 压缩目录为 zip
    zip_file_path = "../Download/photos.zip"
    with zipfile.ZipFile(zip_file_path, "w") as zipf:
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, temp_dir)  # 相对路径
                zipf.write(file_path, arcname=arcname)

    # 返回 zip 文件
    return FileResponse(zip_file_path, media_type="application/zip", filename="photos.zip")


@app.get("/unique_owners/", response_model=List[str])
def get_unique_owners(db: Session = Depends(get_db)):
    # 查询不重复的 ownerName
    unique_owners = db.query(distinct(PhotoUpload.ownerName)).filter(PhotoUpload.ownerName != None).all()
    # 提取查询结果中的 ownerName 值
    owner_names = [owner[0] for owner in unique_owners]

    if not owner_names:
        raise HTTPException(status_code=404, detail="No unique owner names found")

    return owner_names


@app.get("/unique_serials/", response_model=List[str])
def get_unique_serials(db: Session = Depends(get_db)):
    # 查询不重复的 serialnumber
    uniquire_record = db.query(distinct(PhotoUpload.serialNumber)).filter(PhotoUpload.serialNumber != None).all()
    # 提取查询结果中的 serialnumber 值
    serial_numbers = [sn[0] for sn in uniquire_record]

    if not serial_numbers:
        raise HTTPException(status_code=404, detail="No unique serial number found")

    return serial_numbers


# 创建 JSend 响应
def jsend_response(status: str, data: Optional[Any] = None, message: Optional[str] = None) -> JSendResponse:
    return JSendResponse(status=status, data=data, message=message)


@app.put("/update_version/")
async def upload_version(
        versionName: str = Form(...),
        showModel: bool = Form(...),
        showScore: bool = Form(...),
        threshold: float = Form(...),
        usernameList: str = Form(...),
        labelNames: str = Form(...),
        labelShows: str = Form(...),
        labelChecks: str = Form(...),
        db: Session = Depends(get_db)
):
    try:
        model_dir = f"../Models/{versionName}"

        # 3. 写入 action.json 文件
        action_data = {
            "showModel": showModel,
            "showScore": showScore,
            "modelThreshold": threshold,
            "labelNames": labelNames,
            "labelShows": labelShows,
            "labelChecks": labelChecks,
        }
        action_file_path = os.path.join(model_dir, "action.json")
        with open(action_file_path, "w") as action_file:
            json.dump(action_data, action_file)

        # 4. 读取 last.json 文件并更新
        last_file_path = "../Models/last.json"
        try:
            with open(last_file_path, "r") as last_file:
                last_data = json.load(last_file)
        except FileNotFoundError:
            last_data = {}

        # 将 usernameList 分隔并更新 last.json
        usernames = usernameList.split("|")
        passMap = {}
        for username in usernames:
            if (username in last_data.keys()):
                if (last_data[username] == versionName):
                    passMap[username] = True
            last_data[username] = versionName

        # 更新 last.json 文件
        with open(last_file_path, "w") as last_file:
            json.dump(last_data, last_file)

        # 记录版本映射信息
        for username in usernames:
            # 跳過已經加入過的
            if (username in passMap.keys()):
                continue
            version_mapping = VersionMapping(
                version_name=versionName,
                user_name=username
            )
            db.add(version_mapping)

        db.commit()

        # 成功响应
        return jsend_response(status="success", data={"version_name": versionName},
                              message="Version update successfully!")

    except Exception as e:
        # 错误响应
        return jsend_response(status="error", message=str(e))


@app.post("/upload_version2/")
async def upload_version2(
        versionName: str = Form(...),
        zipFile: UploadFile = File(...),
        db: Session = Depends(get_db)
):
    try:
        # 1. 创建目录 ../Models/versionName
        model_dir = f"../Models/{versionName}"
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)

        # 2. 解压 zipFile 到 ../Models/versionName 目录
        zip_file_path = f"../Models/{versionName}/{zipFile.filename}"
        with open(zip_file_path, "wb") as f:
            f.write(await zipFile.read())

        # 解压 zip 文件
        try:
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                zip_ref.extractall(model_dir)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error extracting zip file: {str(e)}")

        # 5. 记录 versionManagement 和 versionMapping 数据
        # 记录版本管理信息
        version_management = VersionManagement(
            version_name=versionName,
            file_path=model_dir,
            uploaded_by="System",  # 可以替换为实际上传用户
        )
        db.add(version_management)
        db.commit()

        # 成功响应
        return jsend_response(status="success", data={"version_name": versionName},
                              message="Version uploaded and processed successfully!")

    except Exception as e:
        # 错误响应
        return jsend_response(status="error", message=str(e))


@app.post("/upload_version/")
async def upload_version(
        versionName: str = Form(...),
        zipFile: UploadFile = File(...),
        showModel: bool = Form(...),
        showScore: bool = Form(...),
        threshold: float = Form(...),
        usernameList: str = Form(...),
        db: Session = Depends(get_db)
):
    try:
        # 1. 创建目录 ../Models/versionName
        model_dir = f"../Models/{versionName}"
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)

        # 2. 解压 zipFile 到 ../Models/versionName 目录
        zip_file_path = f"../Models/{versionName}/{zipFile.filename}"
        with open(zip_file_path, "wb") as f:
            f.write(await zipFile.read())

        # 解压 zip 文件
        try:
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                zip_ref.extractall(model_dir)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error extracting zip file: {str(e)}")

        # 3. 写入 action.json 文件
        action_data = {
            "showModel": showModel,
            "showScore": showScore,
            "modelThreshold": threshold
        }
        action_file_path = os.path.join(model_dir, "action.json")
        with open(action_file_path, "w") as action_file:
            json.dump(action_data, action_file)

        # 4. 读取 last.json 文件并更新
        last_file_path = "../Models/last.json"
        try:
            with open(last_file_path, "r") as last_file:
                last_data = json.load(last_file)
        except FileNotFoundError:
            last_data = {}

        # 将 usernameList 分隔并更新 last.json
        usernames = usernameList.split("|")
        for username in usernames:
            last_data[username] = versionName

        # 更新 last.json 文件
        with open(last_file_path, "w") as last_file:
            json.dump(last_data, last_file)

        # 5. 记录 versionManagement 和 versionMapping 数据
        # 记录版本管理信息
        version_management = VersionManagement(
            version_name=versionName,
            file_path=model_dir,
            uploaded_by="System",  # 可以替换为实际上传用户
        )
        db.add(version_management)
        db.commit()

        # 记录版本映射信息
        for username in usernames:
            version_mapping = VersionMapping(
                version_name=versionName,
                user_name=username
            )
            db.add(version_mapping)

        db.commit()

        # 成功响应
        return jsend_response(status="success", data={"version_name": versionName},
                              message="Version uploaded and processed successfully!")

    except Exception as e:
        # 错误响应
        return jsend_response(status="error", message=str(e))


# API：处理版本上传
@app.post("/upload_version2/action")
async def upload_version(
        versionName: str = Form(...),
        showModel: bool = Form(...),
        showScore: bool = Form(...),
        threshold: float = Form(...),

        labelThreshold: str = Form(...),
        labelNames: str = Form(...),
        labelShows: str = Form(...),
        labelChecks: str = Form(...),
        taskAlias: str = Form(...),

        labelTaskNames: str = Form(...),

        usernameList: str = Form(...),
        db: Session = Depends(get_db)
):
    try:
        # 1. 创建目录 ../Models/versionName
        model_dir = f"../Models/{versionName}"
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)

        labelThresholdDict = json.loads(labelThreshold)
        taskAliasDict = json.loads(taskAlias)

        # 将字符串解析为字典
        labelNameDict = {
            pair.split("@")[0]: pair.split("@")[1]
            for pair in labelNames.split("|")
        }

        labelTaskDict = {
            pair.split("@")[0]: pair.split("@")[1]
            for pair in labelTaskNames.split("|")
        }

        labelChecksDict = {
            pair.split("@")[0]: pair.split("@")[1]
            for pair in labelChecks.split("|")
        }

        taskInfos = []
        task0 = []
        task0.append({"taskName": "安全帽", "taskLabels": [], "checkLabels": []})
        task0.append({"taskName": "安全帶(掛勾)", "taskLabels": [], "checkLabels": []})
        task1 = []
        task1.append({"taskName": "安全帽", "taskLabels": [], "checkLabels": []})
        task1.append({"taskName": "安全帶", "taskLabels": [], "checkLabels": []})

        taskInfos.append(task0)
        taskInfos.append(task1)

        for label in labelTaskDict.keys():
            taskName = labelTaskDict[label]
            for taskGroup in taskInfos:
                for taskItems in taskGroup:
                    if (taskItems["taskName"] == taskName):
                        lblthreshold = threshold
                        if label in labelThresholdDict.keys():
                            lblthreshold = labelThresholdDict[label]

                        labelItem = {"label": label, "name": labelNameDict[label], "labelThreshold": lblthreshold}
                        taskItems["taskLabels"].append(labelItem)

                        if label in labelChecksDict.keys():
                            taskItems["checkLabels"].append(label)

        # 3. 写入 action.json 文件
        action_data = {
            "showModel": showModel,
            "showScore": showScore,
            "modelThreshold": threshold,
            "labelThreshold": labelThresholdDict,
            "labelNames": labelNames,
            "labelShows": labelShows,
            "labelChecks": labelChecks,
            "taskAlias": taskAliasDict,
            "taskInfos": taskInfos,

        }
        action_file_path = os.path.join(model_dir, "action.json")
        with open(action_file_path, "w") as action_file:
            json.dump(action_data, action_file)

        # 4. 读取 last.json 文件并更新
        last_file_path = "../Models/last.json"
        try:
            with open(last_file_path, "r") as last_file:
                last_data = json.load(last_file)
        except FileNotFoundError:
            last_data = {}

        # 将 usernameList 分隔并更新 last.json
        usernames = usernameList.split("|")
        for username in usernames:
            last_data[username] = versionName

        # 更新 last.json 文件
        with open(last_file_path, "w") as last_file:
            json.dump(last_data, last_file)

        # 5. 记录 versionManagement 和 versionMapping 数据
        # 记录版本管理信息
        version_management = VersionManagement(
            version_name=versionName,
            file_path=model_dir,
            uploaded_by="System",  # 可以替换为实际上传用户
        )
        db.add(version_management)
        db.commit()

        # 记录版本映射信息
        for username in usernames:
            version_mapping = VersionMapping(
                version_name=versionName,
                user_name=username
            )
            db.add(version_mapping)

        db.commit()

        # 成功响应
        return jsend_response(status="success", data={"version_name": versionName},
                              message="Version uploaded and processed successfully!")

    except Exception as e:
        # 错误响应
        return jsend_response(status="error", message=str(e))


@app.get("/versions/", response_model=List[VersionManagementResponse])
def get_all_versions(db: Session = Depends(get_db)):
    versions = db.query(VersionManagement).order_by(VersionManagement.upload_date.desc()).all()
    return versions


@app.get("/versions/mapping/{user_name}", response_model=List[VersionMappingResponse])
def get_user_version_mappings(user_name: str, db: Session = Depends(get_db)):
    mappings = db.query(VersionMapping).filter(VersionMapping.user_name == user_name).order_by(
        VersionMapping.update_date.desc()).all()
    if not mappings:
        raise HTTPException(status_code=404, detail="No version mappings found for this user")
    return mappings


@app.get("/photo/")
def get_photo(file_path: str, db: Session = Depends(get_db)):
    # 从数据库中查询照片记录，以确保文件路径有效
    photo = db.query(PhotoUpload).filter(PhotoUpload.file_path == file_path).first()
    if not photo:
        raise HTTPException(status_code=404, detail="Photo not found")

    # 检查文件是否存在
    if not os.path.exists(photo.file_path):
        raise HTTPException(status_code=404, detail="File not found")

    # 返回文件内容，供前端展示或下载
    return FileResponse(path=photo.file_path, media_type="image/jpeg", filename=os.path.basename(photo.file_path))


@app.get("/photos/download/{photo_id}")
def download_photo(photo_id: int, result: bool = Query(False), db: Session = Depends(get_db)):
    # 根据 photo_id 查询数据库，获取文件路径
    photo = db.query(PhotoUpload).filter(PhotoUpload.id == photo_id).first()
    if not photo:
        raise HTTPException(status_code=404, detail="Photo not found")

    # 根据 result 参数决定返回的文件路径
    file_path = photo.file_result_path if result else photo.file_path

    # 检查文件是否存在
    if not file_path or not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    # 返回文件以供下载
    return FileResponse(path=file_path, media_type="image/jpeg", filename=os.path.basename(file_path))


@app.get("/photos/show/{photo_id}")
def download_photo(photo_id: int, result: bool = Query(False), db: Session = Depends(get_db)):
    # 根据 photo_id 查询数据库，获取文件路径
    photo = db.query(PhotoUpload).filter(PhotoUpload.id == photo_id).first()
    if not photo:
        raise HTTPException(status_code=404, detail="Photo not found")

    # 根据 result 参数决定返回的文件路径
    file_path = photo.file_result_path if result else photo.file_path

    # 检查文件是否存在
    if not file_path or not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    # 自动判断媒体类型
    media_type = "image/jpeg" if file_path.endswith(".jpg") or file_path.endswith(".jpeg") else "image/png"

    # 返回文件以供展示，不设置 filename 以避免下载提示
    return FileResponse(path=file_path, media_type=media_type)
