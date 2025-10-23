import os
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import datetime

# Carregar variáveis do arquivo .env
load_dotenv()

app = Flask(__name__, 
    static_folder='static',  # Adicione esta linha
    template_folder='templates'  # E esta se tiver templates
)

# 🔒 CONFIGURAÇÕES DE SEGURANÇA
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'chave-secreta-padrao-mais-longa-para-seguranca')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)

jwt = JWTManager(app)

# ✅ CORREÇÃO: Configurar o Limiter corretamente
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

CORS(app)

# "Banco de dados" em memória
users = [
    {"id": 1, "name": "João Silva", "email": "joao@email.com", "role": "user"},
    {"id": 2, "name": "Maria Santos", "email": "maria@email.com", "role": "admin"}
]

# ✅ CORREÇÃO: Criar senhas de forma mais confiável
def init_users_db():
    return {
        "admin": generate_password_hash("admin123"),
        "usuario": generate_password_hash("senha123"),
        "test": generate_password_hash("test123")
    }

users_db = init_users_db()

# 🔓 ROTA PÚBLICA - Página inicial
@app.route('/')
def home():
    return """
    <html>
    <head>
        <title>Minha API Segura</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 800px; margin: 0 auto; }
            .endpoints { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        </style>
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
                <p><strong>Credenciais para teste:</strong></p>
                <ul>
                    <li>Usuário: <code>admin</code> | Senha: <code>admin123</code></li>
                    <li>Usuário: <code>usuario</code> | Senha: <code>senha123</code></li>
                    <li>Usuário: <code>test</code> | Senha: <code>test123</code></li>
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
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    })

# 🔓 ROTA PÚBLICA - Login
@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")  # Prevenir brute force
def login():
    try:
        # ✅ CORREÇÃO: Verificar conteúdo JSON de forma mais robusta
        if not request.json:
            return jsonify({"error": "JSON expected"}), 400
            
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({"error": "Username e password são obrigatórios"}), 400
        
        # ✅ CORREÇÃO: Verificar usuário e senha
        if username in users_db:
            if check_password_hash(users_db[username], password):
                access_token = create_access_token(identity=username)
                return jsonify({
                    "access_token": access_token,
                    "token_type": "bearer",
                    "expires_in": 3600,
                    "user": username
                })
        
        return jsonify({"error": "Credenciais inválidas"}), 401
    
    except Exception as e:
        print(f"Erro no login: {str(e)}")  # Para debug nos logs
        return jsonify({"error": "Erro interno do servidor"}), 500

# 🔒 ROTA PROTEGIDA - Listar usuários
@app.route('/api/users')
@jwt_required()
@limiter.limit("20 per minute")
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

# ✅ CORREÇÃO: Adicionar handler para erros do JWT
@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        "error": "Token inválido",
        "message": "Faça login novamente"
    }), 422

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        "error": "Token expirado",
        "message": "Faça login novamente"
    }), 401

@jwt.unauthorized_loader
def unauthorized_response(callback):
    return jsonify({
        "error": "Token de acesso requerido",
        "message": "Faça login em /api/login"
    }), 401

# 🔒 HEADERS DE SEGURANÇA
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)