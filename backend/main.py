from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

# Initialize FastAPI app
app = FastAPI()

# Enable CORS for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # OK for development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define request model
class CalculationRequest(BaseModel):
    num1: float
    num2: float
    operator: str

# Root route for testing
@app.get("/")
def read_root():
    return {"message": "Welcome to FastAPI Calculator!"}

# Calculation route
@app.post("/calculate")
def calculate(data: CalculationRequest):
    try:
        if data.operator == '+':
            result = data.num1 + data.num2
        elif data.operator == '-':
            result = data.num1 - data.num2
        elif data.operator == '*':
            result = data.num1 * data.num2
        elif data.operator == '/':
            if data.num2 == 0:
                return {"error": "Division by zero is not allowed"}
            result = data.num1 / data.num2
        else:
            return {"error": "Invalid operator"}
        return {"result": result}
    except Exception as e:
        return {"error": str(e)}
