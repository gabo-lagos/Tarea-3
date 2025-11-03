from flask import Flask, jsonify, request, render_template
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt
from pymongo import MongoClient
import os
from datetime import timedelta
import sys

app = Flask(__name__)
load_dotenv()

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
PORT = int(os.getenv('FLASK_PORT', 8003))
MONGO_URI = os.getenv('MONGO_URI')
try:
    client = MongoClient(os.getenv("MONGO_URI"), serverSelectionTimeoutMS=2000)
    client.server_info()  # fuerza chequeo
    db = client["flask_jwt_db"]
    juguetes_col = db["juguetes"]
    usuarios_col = db["usuarios"]
    print("Conectado correctamente a MongoDB")
except Exception as e:
    print("No se pudo conectar a MongoDB:", e)
    client = None
    db = None
    juguetes_col = None
    usuarios_col = None
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app)
#MONGO_URI = os.getenv("MONGO_URI")
#client = MongoClient(MONGO_URI)
#db = client["flask_jwt_db"]

#usuarios_col = db["usuarios"]
#juguetes_col = db["juguetes"]
users = {
    'alice': {'password': generate_password_hash('alicepass'), 'role': 'client'},
    'bob': {'password': generate_password_hash('bobpass'), 'role': 'manager'},
    'carol': {'password': generate_password_hash('carolpass'), 'role': 'admin'}
}

juguetes = [
    {
        "id": 1,
        "nombre": "Porsche 917LH",
        "categoria": "Carros",
        "edad_recomendada": "3+",
        "precio": 10000.0,
        "marca": "Hot Wheels"
    },
    {
        "id": 2,
        "nombre": "Aston Martin DB4GT",
        "categoria": "Carros",
        "edad_recomendada": "3+",
        "precio": 10000.0,
        "marca": "Hot Wheels"
    },
    {
        "id": 3,
        "nombre": "Hot Wheels NIGHTBURNERZ",
        "categoria": "Paquetes de carros",
        "edad_recomendada": "3+",
        "precio": 54900.0,
        "marca": "Hot Wheels"
    },
    {
        "id": 4,
        "nombre": "Monoplaza Ferrari F1",
        "categoria": "Carros a escala",
        "edad_recomendada": "6+",
        "precio": 20000.0,
        "marca": "LEGO"
    },
    {
        "id": 5,
        "nombre": "Pelota de futbol",
        "categoria": "Deportes",
        "edad_recomendada": "7+",
        "precio": 160000.0,
        "marca": "Adidas"
    }
]

def role_required(allowed_roles):
    def wrapper(fn):
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            role = claims.get('role')
            if role not in allowed_roles:
                return jsonify({"msg": "El usuario no tiene el rol requerido"}), 403
            return fn(*args, **kwargs)
        decorator.__name__ = fn.__name__
        return decorator
    return wrapper

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "mensaje": "API Flask JWT en ejecucion",
    }), 200

@app.route('/juguetes', methods=['GET'])
def get_all_juguetes():
    
    categoria = request.args.get('categoria')
    marca = request.args.get('marca')

    resultados = juguetes
    if categoria:
        resultados = [j for j in resultados if j["categoria"].lower() == categoria.lower()]
    if marca:
        resultados = [j for j in resultados if j["marca"].lower() == marca.lower()]

    return jsonify(resultados)

@app.route('/juguetes', methods=['POST'])
@jwt_required()
def add_juguete():
    data = request.get_json()
    if not data:
        return jsonify({"msg": "Falta el cuerpo JSON"}), 400
    data["id"] = (juguetes[-1]['id'] + 1) if juguetes else 1
    juguetes.append(data)
    return jsonify(data), 201

@app.route('/juguetes/<int:id>', methods=['DELETE'])
@role_required(['manager', 'admin'])
def delete_juguete(id):
    global juguetes
    encontrado = [j for j in juguetes if j['id'] == id]
    if not encontrado:
        return jsonify({"error": "Juguete no encontrado"}), 404
    juguetes = [j for j in juguetes if j['id'] != id]
    return jsonify({"mensaje": f"Juguete con ID {id} eliminado"}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"msg": "Falta nombre de usuario o contraseña"}), 400

    username = data['username']
    password = data['password']
    user = users.get(username)
    if not user or not check_password_hash(user['password'], password):
        return jsonify({"msg": "Usuario o contraseña incorrectos"}), 401

    claims = {"role": user['role']}
    token = create_access_token(identity=username, additional_claims=claims)
    return jsonify(access_token=token, role=user['role']), 200

@app.route('/usuarios', methods=['POST'])
@role_required(['admin'])
def add_user():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data or 'role' not in data:
        return jsonify({"msg": "Se requiere username, password y role"}), 400

    username = data['username']
    if username in users:
        return jsonify({"msg": "El usuario ya existe"}), 409

    role = data['role']
    if role not in ['client', 'manager', 'admin']:
        return jsonify({"msg": "Rol inválido"}), 400

    users[username] = {
        'password': generate_password_hash(data['password']),
        'role': role
    }
    return jsonify({"msg": "Usuario creado", "username": username, "role": role}), 201

@app.route('/reports', methods=['GET'])
@role_required(['manager', 'admin'])
def reports():
    return jsonify({"msg": "Datos de reporte confidenciales"}), 200

@app.route('/panel')
def panel():
    try:
        juguetes_db = list(juguetes_col.find({}, {"_id": 0}))
    except Exception as e:
        print("⚠️ No se pudo conectar a MongoDB:", e)
        juguetes_db = juguetes  # usa la lista local
    return render_template("dashboard.html", juguetes=juguetes_db)
@jwt.unauthorized_loader
def custom_unauthorized_response(callback):
    return jsonify({"msg": "Falta el encabezado de autorización"}), 401

@jwt.invalid_token_loader
def custom_invalid_token(reason):
    return jsonify({"msg": "Token inválido"}), 422


def run_basic_tests():
    print("Ejecutando pruebas básicas...")
    client = app.test_client()

    rv = client.post('/login', json={'username': 'carol', 'password': 'carolpass'})
    print('/login (carol) estado:', rv.status_code, 'respuesta:', rv.get_json())
    assert rv.status_code == 200
    token = rv.get_json().get('access_token')

    rv = client.post('/login', json={'username': 'carol', 'password': 'wrong'})
    print('/login contraseña incorrecta estado:', rv.status_code, 'respuesta:', rv.get_json())
    assert rv.status_code == 401

    rv = client.post('/juguetes', json={'nombre': 'X'})
    print('/juguetes sin token estado:', rv.status_code, 'respuesta:', rv.get_json())
    assert rv.status_code == 401

    rv = client.get('/reports', headers={'Authorization': 'Bearer invalid.token'})
    print('/reports token inválido estado:', rv.status_code, 'respuesta:', rv.get_json())
    assert rv.status_code == 422

    rv = client.post('/login', json={'username': 'alice', 'password': 'alicepass'})
    alice_token = rv.get_json().get('access_token')
    rv = client.delete('/juguetes/1', headers={'Authorization': f'Bearer {alice_token}'})
    print('/juguetes eliminar como alice estado:', rv.status_code, 'respuesta:', rv.get_json())
    assert rv.status_code == 403

@app.route('/migrar_juguetes')
def migrar_juguetes():
    from pprint import pprint
    try:
        print("Iniciando migración de juguetes...")

        if db is None or juguetes_col is None:
            print("La base de datos no está inicializada")
            return jsonify({"msg": "MongoDB no está disponible"}), 503

        print("Conectado a la base:", db.name)

        existentes = [doc.get("id") for doc in juguetes_col.find({}, {"id": 1, "_id": 0})]
        print(f"Juguetes existentes en Mongo: {existentes}")

        nuevos = [j for j in juguetes if j["id"] not in existentes]
        print(f"Juguetes nuevos para insertar: {len(nuevos)}")

        if not nuevos:
            return jsonify({"msg": "No hay nuevos juguetes para migrar"}), 200

        resultado = juguetes_col.insert_many(nuevos)
        print(f"Insertados {len(resultado.inserted_ids)} juguetes.")
        pprint(nuevos)
        return jsonify({"msg": f"Se migraron {len(resultado.inserted_ids)} juguetes a MongoDB"}), 201

    except Exception as e:
        import traceback
        print("Error al migrar juguetes:", e)
        traceback.print_exc()
        return jsonify({"msg": "Error al migrar", "error": str(e)}), 500
@app.route('/migrar_usuarios')
@role_required(['admin'])
def migrar_usuarios():
    try:
        if db is None or usuarios_col is None:
            return jsonify({"msg": "MongoDB no está disponible"}), 503

        existentes = [u["username"] for u in usuarios_col.find({}, {"username": 1, "_id": 0})]
        nuevos = []

        for username, data in users.items():
            if username not in existentes:
                nuevos.append({
                    "username": username,
                    "password": data["password"],
                    "role": data["role"]
                })

        if not nuevos:
            return jsonify({"msg": "No hay nuevos usuarios para migrar"}), 200

        result = usuarios_col.insert_many(nuevos)
        print(f"Insertados {len(result.inserted_ids)} usuarios en MongoDB")
        return jsonify({"msg": f"Se migraron {len(result.inserted_ids)} usuarios a MongoDB"}), 201

    except Exception as e:
        import traceback
        print("Error al migrar usuarios:", e)
        traceback.print_exc()
        return jsonify({"msg": "Error al migrar usuarios", "error": str(e)}), 500

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        run_basic_tests()
    else:
        if client:
            print(" Colecciones existentes:", db.list_collection_names())
        app.run(host='0.0.0.0',
                 port=8003, 
                 debug=False, 
                 use_reloader=False
            )
