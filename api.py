#/api/api.py
from fastapi import FastAPI, Header
from fastapi.middleware.cors import CORSMiddleware
import requests

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
        if x_key != "44537bf504d736ece21c79b60c23a8bb2254d1508e255501d29139194b0fd4774074afed10c5192e":
            return {"error": "Invalid API key"}
        
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", 
                                headers={"Key": "44537bf504d736ece21c79b60c23a8bb2254d1508e255501d29139194b0fd4774074afed10c5192e", 
                                         "Accept": "application/json"})
        data = response.json()
        return data
    except Exception as e:
        return {"error": str(e)}
