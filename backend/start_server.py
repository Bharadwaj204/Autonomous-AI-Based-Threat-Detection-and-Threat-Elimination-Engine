import uvicorn
import os

if __name__ == "__main__":
    print("=======================================================")
    print("   Starting THREAT SENTINEL Backend API...")
    print("=======================================================")
    
    # Ensure working directory is backend
    if not os.getcwd().endswith("backend"):
        os.chdir("backend")
        
    # Start the server securely against single-points of failure using uvicorn reload
    uvicorn.run("api.server:app", host="0.0.0.0", port=8000, reload=True)
