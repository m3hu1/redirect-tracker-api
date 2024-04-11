# /api/api.py
from fastapi import FastAPI, Header, HTTPException
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
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", 
                                headers={"Key": "44537bf504d736ece21c79b60c23a8bb2254d1508e255501d29139194b0fd4774074afed10c5192e", 
                                         "Accept": "application/json"})
        data = response.json()
        return data
    except Exception as e:
        return {"error": str(e)}

@app.get("/check-ssl")
def check_ssl(url: str):
    try:
        headers = {
            "X-RapidAPI-Key": "876ec4f793msh46e01bc9724cf74p127786jsn2d01e3fe7ae0",
            "X-RapidAPI-Host": "ssl-certificate-checker2.p.rapidapi.com"
        }

        querystring = {"host": url}

        response = requests.get("https://ssl-certificate-checker2.p.rapidapi.com/ssl-certificate-checker/check",
                                headers=headers, params=querystring)

        data = response.json()

        cert_info = {
            "subject": data["subject"]["CN"],
            "issuer": data["issuer"]["CN"],
            "valid_from": data["validFrom"],
            "valid_until": data["validTo"],
            "expires_in_days": data["expiresInDays"],
            "fingerprint": data["fingerprint"],
            "fingerprint256": data["fingerprint256"],
            "serial_number": data["serialNumber"],
            "pem": data["pem"],
            "protocol": data["protocol"],
            "cipher_name": data["cipher"]["name"],
            "cipher_standard_name": data["cipher"]["standardName"],
            "cipher_version": data["cipher"]["version"],
            "ocsp_uri": data["infoAccess"]["OCSP - URI"],
            "ca_issuers_uri": data["infoAccess"]["CA Issuers - URI"]
        }
        return cert_info
    except Exception as e:
        return {"error": str(e)}
