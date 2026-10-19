import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
import app as rm
from fastapi.staticfiles import StaticFiles

_dir = os.path.dirname(os.path.abspath(__file__))
# 把前端 index.html 与 /api 同域托管，避免跨域问题
rm.app.mount("/", StaticFiles(directory=_dir, html=True))

import uvicorn
if __name__ == "__main__":
    cfg = config.load_config()
    # 该 wrapper 负责把界面与 API 一同暴露给浏览器，故监听 0.0.0.0；
    # 端口沿用 config.json（默认 5006），便于不同部署环境错开端口。
    uvicorn.run(rm.app, host="0.0.0.0", port=cfg.get("port", 5006), log_level="info")
