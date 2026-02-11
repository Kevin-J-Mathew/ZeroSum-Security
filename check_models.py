import os
from dotenv import load_dotenv
from google import genai

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    print("❌ Error: GEMINI_API_KEY not found in .env")
    exit(1)

print(f"✅ Found API Key: {api_key[:10]}...")

try:
    client = genai.Client(api_key=api_key)
    print("\n🔍 Contacting Google API to list models...")

    # Simple iteration - just print the name
    for m in client.models.list():
        print(f" • {m.name}")

except Exception as e:
    print(f"\n❌ API CONNECTION FAILED: {e}")