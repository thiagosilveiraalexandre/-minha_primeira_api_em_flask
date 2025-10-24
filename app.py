import os
from flask import Flask, jsonify, request, send_from_directory
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
    static_folder='static',
    template_folder='templates'
)

# 🔒 CONFIGURAÇÕES DE SEGURANÇA
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'chave-secreta-padrao-mais-longa-para-seguranca')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)

jwt = JWTManager(app)

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

# Usuários para autenticação
users_db = {
    "admin": generate_password_hash("admin123"),
    "usuario": generate_password_hash("senha123"),
    "test": generate_password_hash("test123")
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
                    <li><strong>GET /login</strong> - Página de login visual</li>
                </ul>
                <p><em>Consulte a documentação para credenciais de teste</em></p>
            </div>
        </div>
    </body>
    </html>
    """

# 🔓 PÁGINA DE LOGIN VISUAL
@app.route('/login')
def login_page():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Minha API</title>
        <link rel="stylesheet" href="/static/style.css">
        <style>
            .login-form {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                max-width: 400px;
                margin: 50px auto;
            }
            
            .login-form input {
                width: 100%;
                padding: 12px;
                margin: 10px 0;
                border: 1px solid #ddd;
                border-radius: 5px;
                box-sizing: border-box;
                font-size: 16px;
            }
            
            .login-form button {
                width: 100%;
                padding: 12px;
                background: #3498db;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 16px;
                margin-top: 15px;
            }
            
            .login-form button:hover {
                background: #2980b9;
            }
            
            .info-box {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 5px;
                margin-top: 20px;
                border-left: 4px solid #3498db;
                font-size: 14px;
            }
            
            #resultado {
                margin-top: 15px;
                padding: 10px;
                border-radius: 5px;
            }
            
            .success-message {
                color: green;
                background: #d4edda;
                padding: 15px;
                border-radius: 5px;
                border: 1px solid #c3e6cb;
            }
            
            .error-message {
                color: red;
                background: #f8d7da;
                padding: 15px;
                border-radius: 5px;
                border: 1px solid #f5c6cb;
            }
            
            .test-button {
                margin-top: 10px;
                padding: 8px 15px;
                background: #28a745;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
            }
        </style>
    </head>
    <body>
        <div class="container login-form">
            <h1>🔐 Login</h1>
            <form onsubmit="fazerLogin(event)">
                <input type="text" id="username" placeholder="Usuário" required>
                <input type="password" id="password" placeholder="Senha" required>
                <button type="submit">Entrar</button>
            </form>
            
            <div class="info-box">
                <strong>💡 Informação:</strong><br>
                Use as credenciais fornecidas separadamente para testes.
            </div>
            
            <div id="resultado"></div>
        </div>

        <script>
        async function fazerLogin(event) {
            event.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const resultado = document.getElementById('resultado');
            
            // Limpar resultado anterior
            resultado.innerHTML = '';
            resultado.className = '';
            
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({username, password})
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    resultado.innerHTML = `
                        <div class="success-message">
                            <strong>✅ Login bem-sucedido!</strong><br>
                            Usuário: ${data.user}<br>
                            <button class="test-button" onclick="testarAPI('${data.access_token}')">
                                Testar API Protegida
                            </button>
                        </div>
                    `;
                } else {
                    resultado.innerHTML = `
                        <div class="error-message">
                            <strong>❌ Erro:</strong> ${data.error}
                        </div>
                    `;
                }
            } catch (error) {
                resultado.innerHTML = `
                    <div class="error-message">
                        <strong>❌ Erro de conexão:</strong> ${error}
                    </div>
                `;
            }
        }
        
        async function testarAPI(token) {
            try {
                const response = await fetch('/api/users', {
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                const data = await response.json();
                alert(`✅ API funcionando!\\nEncontrados ${data.count} usuários.`);
            } catch (error) {
                alert('❌ Erro ao acessar API: ' + error);
            }
        }
        </script>
    </body>
    </html>
    '''

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
@limiter.limit("10 per minute")
def login():
    try:
        if not request.json:
            return jsonify({"error": "JSON expected"}), 400
            
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({"error": "Username e password são obrigatórios"}), 400
        
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
        print(f"Erro no login: {str(e)}")
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

# ROTA DE TESTE SIMPLES - Adicione isso temporariamente
@app.route('/teste')
def teste():
    return '''
    <html>
    <body>
        <h1>Teste Simples</h1>
        <input type="text" placeholder="Digite algo">
        <button>Clique aqui</button>
    </body>
    </html>
    '''

# ✅ Handlers para erros do JWT
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

# Servir arquivos estáticos
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)