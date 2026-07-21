FROM python:3.12-slim

WORKDIR /app

# Install the application dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy in the source code
COPY backend/ ./
EXPOSE 8000

# Create user and set permissions before switching
# -m creates the user's home directory at home/app/ with correct ownership
# chown -R app:app /app changes ownership of app directory (where code lives) to the app user (recursive, applies to
# everything inside /app too)
# create the cache and user directories and set ownership before switching users
RUN mkdir -p /app/.cache/huggingface && \
    useradd -m app && \
    chown -R app:app /app

USER app

# Tell HuggingFace to cache models inside /app where the user has permission
ENV HF_HOME=/app/.cache/huggingface

CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

