<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

  <p align="center">A progressive <a href="http://nodejs.org" target="_blank">Node.js</a> framework for building efficient and scalable server-side applications.</p>
    <p align="center">

# **Sistema de Autenticación con NestJS**

Este proyecto proporciona una estructura para crear un sistema de autenticación en una API usando **NestJS**. Incluye funcionalidades como:

- Registro de usuarios.
- Inicio de sesión con JWT (JSON Web Tokens).
- Protección de rutas mediante autenticación.
- Módulo NodeMailer para verificación y restablecimiento de contraseñas.
- Integración con una base de datos SQL (MySQL).
- Envío de correos electrónicos de verificación y restablecimiento de contraseñas.
- Envio de mensajes con WhatsappWebJs


## 🆕 **Características adicionales implementadas**

### 📱 Notificaciones por WhatsApp Web.js

El sistema ahora incluye **notificaciones automáticas vía WhatsApp Web** al registrarse e iniciar sesión. Esto se logra mediante integración con la librería `whatsapp-web.js`.

- Se envía un mensaje de bienvenida al registrarse
- Se notifica al usuario al iniciar sesión exitosamente

Esto se encuentra modularizado en el directorio `modules/whatsapp`.


<img src="./docs/assets/whatsapp-web-js.jpg" alt="Vista previa del login" width="400"/>

---

### 📸 Subida de imagen de perfil

Ahora los usuarios pueden subir su imagen de perfil. Este módulo:

- Usa `@nestjs/platform-express` con `multer` para procesar el archivo
- Sube la imagen a **Cloudinary**
- Guarda la URL en la base de datos del usuario

**Endpoint disponible:**

- **URL**: `/api/v1/files/upload-profile-picture`
- **Método**: `POST`
- **Requiere autenticación (JWT)**

**Headers:**
```http
Authorization: Bearer <token>
```

**Form Data:**
- `file`: imagen en formato `.jpg`, `.jpeg`, `.png` u otro compatible con Cloudinary

**Respuesta:**
```json
{
  "message": "Imagen subida correctamente",
  "imageUrl": "https://res.cloudinary.com/..."
}
```

---

### 🗂️ Estructura modular extendida

La arquitectura sigue el principio de separación de responsabilidades, ahora incluyendo:

- `modules/whatsapp`: envío de mensajes
- `modules/files`: subida de imágenes
- `services/cloudinary.service.ts`: encapsula la lógica de Cloudinary


# 🛠️ Iniciar el Proyecto

Antes de comenzar, asegúrate de tener instalados los siguientes requisitos:

- [Node.js](https://nodejs.org/)
- npm
- [MySQL](https://www.mysql.com/)
- Una cuenta en [Cloudinary](https://cloudinary.com/) para la gestión de archivos (opcional pero recomendada).

---

## 📦 Instalación de Dependencias

```bash
npm install
```

---

## ⚙️ Configuración del Entorno

Crea un archivo `.env` en la raíz del proyecto y agrega las siguientes variables:

```env
# Base de datos
DATABASE_HOST=localhost
DATABASE_PORT=3306
DATABASE_NAME=yourdatabasename
DATABASE_USERNAME=root
DATABASE_PASSWORD=yourpassword

# JWT Secrets
JWT_SECRET=mainSecret
JWT_EMAIL_SECRET=emailSecretJWT
JWT_PASSWORD_SECRET=passwordSecretJWT
JWT_REFRESH_TOKEN_SECRET=refreshSecretJWT

# Configuración de correo
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USER=user
MAIL_PASSWORD=yourpassword
MAIL_FROM=your-email@example.com

# Frontend
FRONTEND_URL=https://yoursiteurl.com

# Cloudinary
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
```

---

## 🚀 Ejecutar el Proyecto

### 🔧 Modo desarrollo

```bash
npm run start:dev
```

### 🚀 Modo producción

```bash
npm run start:prod
```

### 🧪 Modo desarrollo sin reinicio automático

```bash
npm run start
```

---

## 🗃️ Estructura del Proyecto

```bash
src/
├── auth/
│   ├── services/
│   │   ├── login.service.ts
│   │   ├── register.service.ts
│   │   ├── verify-email.service.ts
│   │   └── ...
│   └── controllers/
│       ├── auth.controller.ts
│       └── ...
└── ...
```

Separación por servicios individuales mejora la organización, pruebas y mantenimiento.

---

## 🧩 Base de Datos

Asegúrate de haber importado el archivo `db.sql` para la creación de las tablas necesarias. Puedes hacerlo mediante tu gestor de base de datos MySQL favorito o por consola.

---

## 🔐 Endpoints de Autenticación

Base URL: `/api/v1/auth`

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/register` | POST | Registrar nuevo usuario |
| `/login` | POST | Iniciar sesión |
| `/verify-email` | GET | Verificar correo electrónico |
| `/resend-verification-email` | POST | Reenviar verificación |
| `/forgot-password` | POST | Solicitar restablecimiento |
| `/reset-password` | POST | Restablecer contraseña |
| `/refresh-token` | POST | Renovar JWT |
| `/logout` | POST | Cerrar sesión |

---

## 🔐 Flujo de Autenticación

1. **Registro** ➝ Usuario se registra y recibe correo de verificación.
2. **Verificación** ➝ Usuario activa su cuenta desde el correo.
3. **Login** ➝ Recibe JWT y Refresh Token.
4. **Restablecimiento** ➝ Puede solicitar y actualizar contraseña.
5. **Refresh Token** ➝ Solicita nuevo JWT con refresh.
6. **Logout** ➝ Se invalidan tokens (requiere implementación de lista negra).

---

## 🔎 Notas Técnicas

- Sistema protegido por JWT.
- Verificación por correo con tokens únicos.
- Soporte de NodeMailer.
- Tokens con expiración configurada.
- Implementación futura de lista negra para tokens y manejo de sesión segura.

## 🧾 Versión

**Versión actual:** `v3.0.0`

### 🆕 Cambios destacados:
- Separación completa de servicios (`login.service.ts`, `register.service.ts`, etc).
- Implementación de control de autenticación modularizada.
- Soporte para Cloudinary y configuración avanzada por entorno.
- Mejoras en el flujo de autenticación: refresh token, logout y verificación de email.
