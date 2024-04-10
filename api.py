#/api/api.py
from fastapi import FastAPI, Header
from fastapi.middleware.cors import CORSMiddleware
import requests
import os

api_key = os.getenv("API_KEY")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/check-redirects")
def check_redirects(url: str):
    response = requests.get(url)
    redirects = []
    final_url = response.url
    final_status_code = response.status_code

    if response.history:
        for redirect in response.history:
            redirects.append({
                "url": redirect.url,
                "status_code": redirect.status_code
            })

    return {
        "url": final_url,
        "status_code": final_status_code,
        "redirects": redirects
    }

@app.get("/check-ip-reputation")
def check_ip_reputation(ip: str, x_key: str = Header(None)):
    try:
        if x_key != api_key:
            return {"error": "Invalid API key"}
        
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", 
                                headers={"Key": api_key, 
                                         "Accept": "application/json"})
        data = response.json()
        return data
    except Exception as e:
        return {"error": str(e)}
