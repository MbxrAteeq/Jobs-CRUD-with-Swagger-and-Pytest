import json
import requests
from requests.structures import CaseInsensitiveDict


def test_invalid_data_signIn():
    headers = CaseInsensitiveDict()
    headers["Authorization"] = "ldasiYXNoYjqkmkqa"
    r = requests.post("http://127.0.0.1:5000/signIn", headers = headers)
    assert r.status_code == 401
    assert r.headers["Content-Type"] == "application/json"

def test_valid_data_signIn():
    headers = CaseInsensitiveDict()
    headers["Authorization"] = "Basic bXViYXNoYXJhdGVlcTptdWJhc2hhcg=="
    r = requests.post("http://127.0.0.1:5000/signIn", headers = headers)
    assert r.status_code, 200
    assert r.headers["Content-Type"], "application/json"

def test_invalid_data_singUp():
    r = requests.post("http://127.0.0.1:5000/signUp", json={"firstName":"Mubashar","lastName":"Ateeq","email":"mubashar@gmail.com","userName":"ateeq","password":"abcdef"})
    assert r.status_code, 401
    assert r.headers["Content-Type"], "application/json"

def test_valid_data_singUp():
    r = requests.post("http://127.0.0.1:5000/signUp", json={"firstName":"Mubashar","lastName":"Ateeq","email":"mubashar@gmail.com","userName":"ateeqmubashar1","password":"flaskproject"})
    assert r.status_code, 200
    assert r.headers["Content-Type"], "application/json"

# Getting access token
def token():
    headers = CaseInsensitiveDict()
    headers["Authorization"] = "Basic bXViYXNoYXJhdGVlcTptdWJhc2hhcg=="
    r = requests.post("http://127.0.0.1:5000/signIn", headers = headers)
    headers["x-access-tokens"] = r.json()["x-access-tokens"]
    accessToken = headers
    return (accessToken)


def test_get_all_jobs():
    accessToken = token()
    response = requests.get("http://127.0.0.1:5000/alljobs", headers = accessToken)
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/json"

def test_get_job_by_distance():
    accessToken = token()
    response = requests.get("http://127.0.0.1:5000/alljobs?latitude=31.5102&longitude=74.3441", headers = accessToken)
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/json"

def test_add_job():
    accessToken= token()
    response = requests.post("http://localhost:5000/jobs" , headers = accessToken, json={"jobTitle":"Software Engineer","jobDesc":"multan","latitiude":"31.5204","longitude":"74.3587","jobRate":"30k"})
    assert response.status_code, 200
    assert response.headers["Content-Type"], "application/json"

def test_edit_job():
    accessToken = token()
    response = requests.put("http://localhost:5000/jobs/7", headers = accessToken, json={"isActive": True, "jobDesc": "Jr. Python Developer", "jobRate": "kldwde", "jobTitle": "Jr. Python Developer", "latitude": "34.1234", "longitude": "71.4321"})
    assert response.status_code, 200
    assert response.headers["Content-Type"], "application/json"