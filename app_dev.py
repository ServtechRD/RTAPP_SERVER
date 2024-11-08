from fastapi import FastAPI, Depends, HTTPException,UploadFile,File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from datetime import datetime
from sqlalchemy import and_
from sqlalchemy.orm import Session,joinedload
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from auth import create_access_token, authenticate_user, get_password_hash
from database import SessionLocal, engine
from models import Base, User, Client, Location, Task, Photo, PhotoUpload
from schemas import Token, UserCreate, ClientBase, LocationBase, TaskBase, PhotoBase, PhotoUploadResponse, \
    ClientResponse, JSendResponse
from auth import get_password_hash
from pydantic import BaseModel
from typing import Any,List,Optional
import os
import uuid
import json
import glob
import zipfile



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
#app.mount("/static", StaticFiles(directory="build/static"), name="static")


Base.metadata.create_all(bind=engine)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependency to get the session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# 用户注册的 Pydantic 模型
class UserCreate(BaseModel):
    username: str
    password: str


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

@app.post("/users/", response_model=UserCreate)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

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



@app.get("/clients_with_locations/", response_model=List[ClientResponse])
async def get_clients_with_locations(db: Session = Depends(get_db)):
    # 使用 joinedload 进行预加载，减少查询次数
    clients = db.query(Client).options(joinedload(Client.locations)).all()
    
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
def create_upload_path(cid,lid):
    # 获取当前时间并格式化为 yyyy/MM/dd
    now = datetime.now()
    dir_path = now.strftime(f"../Upload/{cid}/{lid}/%Y/%m/%d")
    print("create path = "+dir_path)
    # 如果目录不存在，则创建
    os.makedirs(dir_path, exist_ok=True)
    return dir_path

# 生成带有日期和 UUID 的文件名
def generate_file_name(extension: str,unique_id):
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d%H%M")  # 生成年月日時分
    #unique_id = uuid.uuid4()  # 生成唯一的 UUID
    return f"{timestamp}_{unique_id}.{extension}"

# 上传文件处理
@app.post("/photos/")
async def upload_photo(
    file: UploadFile = File(...), 
    file_result: UploadFile = File(None),
    customerId:str = Form(...),
    locationId:str = Form(...),
    detectLabels:str = Form(...),
    taskId: str = Form(...),
    saveTime:str = Form(...),
    ownerName = Form(None),
    userName = Form("user"),
    db: Session = Depends(get_db)
):
    # 创建保存文件的目录
    upload_dir = create_upload_path(customerId,locationId)

    #task_id = 1
    unique_id = uuid.uuid4()  # 生成唯一的 UUID

    print(unique_id)

    if(ownerName is None):
      ownerName = userName


    #return "success"

    # 保存图片文件
    file_path_extension = file.filename.split(".")[-1]  # 获取文件扩展名
    file_name = generate_file_name(file_path_extension,unique_id)  # 生成新的文件名
    file_path_location = os.path.join(upload_dir, file_name)  # 完整的文件路径
    print(file_path_location)
    with open(file_path_location, "wb") as f:
       print("start to write raw image")
       f.write(await file.read())  # 保存文件


    if(file_result is not  None):
       file_result_path_location = file_path_location+"_result.png"
       print(file_result_path_location)
     
       with open(file_result_path_location, "wb") as f:
          print("start to write result image")
          f.write(await file_result.read())  # 保存文件
 


    # 保存任意文件 (result)
    result_extension = "txt"
    result_file_name = generate_file_name(result_extension,unique_id)
    result_file_location = os.path.join(upload_dir, result_file_name)
    print(result_file_location)
    with open(result_file_location, "w") as f:
        f.write(taskId+"\n")
        f.write(detectLabels+"\n")
        f.write(saveTime+"\n")
        f.write(userName+"\n")
        f.write(ownerName+"\n")

    # 将文件名保存到数据库
    new_photo = PhotoUpload(
        file_path=file_path_location,  # 只保存文件名
        file_result_path=file_result_path_location,
        customerId=int(customerId),
        locationId=int(locationId),
        detectLabels=detectLabels,
        taskId=int(taskId),
        saveTime=saveTime,
        ownerName=ownerName,
        userName=userName,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    db.add(new_photo)
    db.commit()
    db.refresh(new_photo)

    print("finish")

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
    
    # 应用所有过滤条件
    photos = db.query(PhotoUpload).filter(and_(*filters)).all()
    
    if not photos:
        raise HTTPException(status_code=404, detail="No photos found for the specified criteria.")
    
    return photos


# 创建 JSend 响应
def jsend_response(status: str, data: Optional[Any] = None, message: Optional[str] = None) -> JSendResponse:
    return JSendResponse(status=status, data=data, message=message)


# API：处理版本上传
@app.post("/upload_version/")
async def upload_version(
    versionName: str,
    zipFile: UploadFile = File(...),
    showModel: bool = True,
    showScore: bool = False,
    threshold: float = 0.5,
    usernameList: str = "",
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
            "threshold": threshold
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
        version_management = models.VersionManagement(
            version_name=versionName,
            file_path=model_dir,
            uploaded_by="System",  # 可以替换为实际上传用户
        )
        db.add(version_management)
        db.commit()

        # 记录版本映射信息
        for username in usernames:
            version_mapping = models.VersionMapping(
                version_name=versionName,
                user_name=username
            )
            db.add(version_mapping)

        db.commit()

        # 成功响应
        return jsend_response(status="success", data={"version_name": versionName}, message="Version uploaded and processed successfully!")

    except Exception as e:
        # 错误响应
        return jsend_response(status="error", message=str(e))