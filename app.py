import os
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Carregar variáveis do arquivo .env
load_dotenv()

app = Flask(__name__)

# 🔒 CONFIGURAÇÕES DE SEGURANÇA
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'chave-secreta-padrao')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600  # 1 hora

jwt = JWTManager(app)
limiter = Limiter(get_remote_address, app=app)

CORS(app)

# "Banco de dados" em memória
users = [
    {"id": 1, "name": "João Silva", "email": "joao@email.com", "role": "user"},
    {"id": 2, "name": "Maria Santos", "email": "maria@email.com", "role": "admin"}
]

# Usuários para autenticação (em produção, use banco de dados)
users_db = {
    "admin": generate_password_hash("admin123"),
    "usuario": generate_password_hash("senha123")
}

# 🔓 ROTA PÚBLICA - Página inicial
@app.route('/')
def home():
    return """
    <html>
    <head>
        <title>Minha API Segura</title>
        <link rel="stylesheet" href="/static/style.css">
    </head>
    <body>
        <div class="container">
            <h1>🚀 Minha API Segura</h1>
            <p>Esta é uma API protegida com autenticação JWT</p>
            <div class="endpoints">
                <h3>Endpoints disponíveis:</h3>
                <ul>
                    <li><strong>POST /api/login</strong> - Fazer login</li>
                    <li><strong>GET /api/users</strong> - Listar usuários (protegido)</li>
                    <li><strong>GET /api/users/&lt;id&gt;</strong> - Buscar usuário (protegido)</li>
                    <li><strong>GET /api/health</strong> - Health check</li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """

# 🔓 ROTA PÚBLICA - Health Check
@app.route('/api/health')
@limiter.limit("30 per minute")
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "Minha API Segura",
        "timestamp": "2024-01-01T00:00:00Z"
    })

# 🔓 ROTA PÚBLICA - Login
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # Prevenir brute force
def login():
    try:
        if not request.is_json:
            return jsonify({"error": "JSON expected"}), 400
            
        username = request.json.get('username')
        password = request.json.get('password')
        
        if not username or not password:
            return jsonify({"error": "Username e password são obrigatórios"}), 400
        
        if username in users_db and check_password_hash(users_db[username], password):
            access_token = create_access_token(identity=username)
            return jsonify({
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": 3600,
                "user": username
            })
        
        return jsonify({"error": "Credenciais inválidas"}), 401
    
    except Exception as e:
        return jsonify({"error": "Erro interno do servidor"}), 500

# 🔒 ROTA PROTEGIDA - Listar usuários
@app.route('/api/users')
@jwt_required()
@limiter.limit("10 per minute")
def get_users():
    return jsonify({
        "users": users,
        "count": len(users),
        "message": "Dados protegidos por JWT"
    })

# 🔒 ROTA PROTEGIDA - Buscar usuário específico
@app.route('/api/users/<int:user_id>')
@jwt_required()
def get_user(user_id):
    if user_id <= 0:
        return jsonify({"error": "ID de usuário inválido"}), 400
    
    user = next((u for u in users if u['id'] == user_id), None)
    
    if not user:
        return jsonify({"error": "Usuário não encontrado"}), 404
    
    return jsonify(user)

# 🔒 HEADERS DE SEGURANÇA
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Manipulador de erro para JWT
@jwt.unauthorized_loader
def unauthorized_response(callback):
    return jsonify({
        "error": "Token de acesso requerido",
        "message": "Faça login em /api/login"
    }), 401

if __name__ == '__main__':
    app.run(debug=False)