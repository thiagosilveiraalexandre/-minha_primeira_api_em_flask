# Crie um arquivo teste_instalacao.py
try:
    from flask import Flask
    from flask_jwt_extended import JWTManager
    from flask_limiter import Limiter
    from flask_cors import CORS
    from dotenv import load_dotenv
    print("✅ TODAS as bibliotecas instaladas com sucesso!")
except ImportError as e:
    print(f"❌ Falta biblioteca: {e}")