from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "mysql://root:pass@localhost/RTAAPP"

# 建立引擎，加入連線池設定
engine = create_engine(
    DATABASE_URL,
    pool_size=5,              # 連線池大小
    max_overflow=10,          # 超過連線池大小時，最多允許的額外連線數
    pool_timeout=30,          # 等待連線的超時時間
    pool_recycle=3600,        # 連線回收時間（秒），防止連線過期
    pool_pre_ping=True,       # 在使用連線前檢查連線是否有效
    connect_args={
        'connect_timeout': 10,
        'read_timeout': 30,
        'write_timeout': 30,
        'charset': 'utf8mb4'
    }
)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
metadata = MetaData()
