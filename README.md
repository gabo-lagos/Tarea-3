# Tarea Flask 

Proyecto en **Flask** con autenticación **JWT** y control de acceso por roles (`cliente`, `gerente`, `admin`).



##  Instalación

```bash
pip install flask flask-jwt-extended werkzeug
```

---

## Ejecución del servidor

```bash
python tarea_app.py
```

El servidor se ejecutará en:  
 http://127.0.0.1:8003/


## Burned Users

| Usuario  | Contraseña  | Rol      |
|----------|-------------|----------|
| alice    | alicepass   | cliente  |
| bob      | bobpass     | gerente  |
| carol    | carolpass   | admin    |

##  Endpoints

### `POST /login`
Obtiene un token JWT al iniciar sesión.

**Cuerpo del JSON:**
```json
{
  "username": "carol",
  "password": "carolpass"
}
```

**Respuesta que se espera:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "rol": "admin"
}
```


###  `GET /juguetes`
Obtiene la lista de juguetes

**Filtros opcionales:**
- `?categoria=Carros`
- `?marca=LEGO`

**Ejemplo:**
```
GET http://127.0.0.1:8003/juguetes?marca=Hot%20Wheels
```

---

### `POST /juguetes`
Agrega un nuevo juguete (requiere el token del usuario).

**Headers:**
```
Authorization: Bearer <tu_token>
```

**Body JSON:**
```json
{
  "nombre": "LEGO Batimóvil",
  "categoria": "Construcción",
  "edad_recomendada": "8+",
  "precio": 75000,
  "marca": "LEGO"
}
```

**Respuesta:**
```json
{
  "id": 6,
  "nombre": "LEGO Batimóvil",
  "categoria": "Construcción",
  "edad_recomendada": "8+",
  "precio": 75000,
  "marca": "LEGO"
}
```

### `DELETE /juguetes/<id>`
Elimina un juguete (solo `gerente` o `admin` lo pueden hacer, un `cliente` no lo puede hacer).

**Ejemplo:**
```
DELETE http://127.0.0.1:8003/juguetes/1
```

**Headers:**
```
Authorization: Bearer <tu_token>
```

---

###  `GET /reportes`
Acceso restringido a `gerente` o `admin`.

**Headers:**
```
Authorization: Bearer <tu_token>
```

**Respuesta:**
```json
{
  "msg": "Datos de reportes confidenciales"
}
```

###  `POST /usuarios`
Crea un nuevo usuario (solo `admin` lo puede hacer).

**Body JSON:**
```json
{
  "username": "david",
  "password": "davidpass",
  "rol": "cliente"
}
```

**Hedaders:**
```
Authorization: Bearer <token_admin>
```

**Respuesta:**
```json
{
  "msg": "Usuario creado correctamente",
  "usuario": "david",
  "rol": "cliente"
}
```

---

## Errores comunes

| Código |       Causa       |                           Mensaje                         |
|--------|-------------------|-----------------------------------------------------------|
| 401    | Falta token       | `Falta el encabezado de autorización (token)`             |
| 422    | Token inválido    | `Token inválido`                                          |
| 403    | Rol no autorizado | `El usuario no tiene permiso para acceder a este recurso` |
| 400    | Datos faltantes   | `Debe enviar username, password y rol`                    |
| 409    | Usuario ya existe | `El usuario ya existe`                                    |

### `POST /migrar_usuarios`

Migra los usuarios a MongoDB (Solo `admin` lo puede hacer)

**Headers:**
```
Authorization: Bearer <tu_token>
```
**Respuesta**
``` json
{
    "msg": "Se migraron 3 usuarios a MongoDB"
}
```
### `POST /migrar_juguetes`

Migra los usuarios a MongoDB (Solo `admin` lo puede hacer)

**Headers:**
```
Authorization: Bearer <tu_token>
```
``` json
{
    "msg": "Se migraron 5 juguetes a MongoDB"
}
```