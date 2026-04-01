# Stage 1: Build the React Application
FROM node:18-alpine AS frontend-builder
WORKDIR /app/ui

# Copy package.json and install dependencies
COPY ui/package.json ui/package-lock.json* ./
RUN npm install

# Copy frontend source and build
COPY ui/ ./
RUN npm run build

# Stage 2: Build the FastAPI Backend
FROM python:3.9-slim
WORKDIR /app

# Install system dependencies if required for sqlite/mysql
RUN apt-get update && apt-get install -y default-mysql-client default-libmysqlclient-dev build-essential && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source
COPY . .

# Copy built React app from stage 1
COPY --from=frontend-builder /app/ui/dist /app/ui/dist

# Expose port
EXPOSE 8000

# Run FastAPI
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
