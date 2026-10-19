FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg && rm -rf /var/lib/apt/lists/*
RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple --no-cache-dir fastapi uvicorn python-multipart
COPY . .
EXPOSE 5007
CMD ["python", "run_server.py"]
