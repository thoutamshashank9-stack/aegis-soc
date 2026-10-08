import httpx

res = httpx.get("http://127.0.0.1:8000/api/dashboard/stats")
print("Status code:", res.status_code)
print("Stats response:", res.json())
