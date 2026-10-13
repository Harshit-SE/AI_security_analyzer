FROM python:3.11-slim

WORKDIR /app

# Install system dependencies needed for compiling numpy/faiss if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV RAG_HOST=0.0.0.0
ENV RAG_PORT=5001
ENV OLLAMA_BASE_URL=http://ollama:11434
ENV OLLAMA_MODEL=phi3

EXPOSE 5001

CMD ["python", "rag_service.py", "server"]
