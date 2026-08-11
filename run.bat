@echo off
echo Starting SecureFlow Platform...

echo [1/2] Starting FastAPI Backend on port 8077...
start "SecureFlow Backend" cmd /k "cd backend && .venv\Scripts\activate && uvicorn app.main:app --reload --port 8077"

echo [2/2] Starting Vite Frontend...
start "SecureFlow Frontend" cmd /k "cd frontend && npm run dev"

echo Done! Both services are opening in new windows.
echo You can now access the app at http://localhost:5173
