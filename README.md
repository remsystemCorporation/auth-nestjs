<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

  <p align="center">A progressive <a href="http://nodejs.org" target="_blank">Node.js</a> framework for building efficient and scalable server-side applications.</p>
    <p align="center">
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/v/@nestjs/core.svg" alt="NPM Version" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/l/@nestjs/core.svg" alt="Package License" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/dm/@nestjs/common.svg" alt="NPM Downloads" /></a>
<a href="https://circleci.com/gh/nestjs/nest" target="_blank"><img src="https://img.shields.io/circleci/build/github/nestjs/nest/master" alt="CircleCI" /></a>
<a href="https://coveralls.io/github/nestjs/nest?branch=master" target="_blank"><img src="https://coveralls.io/repos/github/nestjs/nest/badge.svg?branch=master#9" alt="Coverage" /></a>
<a href="https://discord.gg/G7Qnnhy" target="_blank"><img src="https://img.shields.io/badge/discord-online-brightgreen.svg" alt="Discord"/></a>
<a href="https://opencollective.com/nest#backer" target="_blank"><img src="https://opencollective.com/nest/backers/badge.svg" alt="Backers on Open Collective" /></a>
<a href="https://opencollective.com/nest#sponsor" target="_blank"><img src="https://opencollective.com/nest/sponsors/badge.svg" alt="Sponsors on Open Collective" /></a>
  <a href="https://paypal.me/kamilmysliwiec" target="_blank"><img src="https://img.shields.io/badge/Donate-PayPal-ff3f59.svg" alt="Donate us"/></a>
    <a href="https://opencollective.com/nest#sponsor"  target="_blank"><img src="https://img.shields.io/badge/Support%20us-Open%20Collective-41B883.svg" alt="Support us"></a>
  <a href="https://twitter.com/nestframework" target="_blank"><img src="https://img.shields.io/twitter/follow/nestframework.svg?style=social&label=Follow" alt="Follow us on Twitter"></a>
</p>
  <!--[![Backers on Open Collective](https://opencollective.com/nest/backers/badge.svg)](https://opencollective.com/nest#backer)
  [![Sponsors on Open Collective](https://opencollective.com/nest/sponsors/badge.svg)](https://opencollective.com/nest#sponsor)-->

# **Sistema de Autenticación con NestJS**

Este proyecto proporciona una estructura para crear un sistema de autenticación en una API usando **NestJS**. Incluye funcionalidades como:

- Registro de usuarios.
- Inicio de sesión con JWT (JSON Web Tokens).
- Protección de rutas mediante autenticación.
- Módulo NodeMailer para verificación y restablecimiento de contraseñas.
- Integración con una base de datos SQL (MySQL).
- Envío de correos electrónicos de verificación y restablecimiento de contraseñas.

---

## **Iniciar el Proyecto**

Antes de comenzar, asegúrate de tener instalado **Node.js**, **npm** y **MySQL**.

1. **Instalación de dependencias**:

    ```bash
    $ npm install
    ```

2. **Configuración del entorno**:

    Crea un archivo `.env` en la raíz del proyecto y agrega las siguientes variables de entorno:

    ```
    DATABASE_HOST=localhost
    DATABASE_PORT=3306
    DATABASE_NAME=yourdatabasename
    DATABASE_USERNAME=root
    DATABASE_PASSWORD=yourpassword
    JWT_SECRET=yoursecretkey

    MAIL_HOST=smtp.gmail.com
    MAIL_PORT=587
    MAIL_USER=user
    MAIL_PASSWORD=yourpassword
    MAIL_FROM=your-email@example.com

    FRONTEND_URL=https://yoursiteurl.com

    JWT_SECRET=mainSecret
    JWT_EMAIL_SECRET=emailSecretJWT
    JWT_PASSWORD_SECRET=passwordSecretJWT
    JWT_REFRESH_TOKEN_SECRET=refreshSecretJWT
    ```

---

## **Compilar y Correr el Proyecto**

Para iniciar el proyecto, puedes usar los siguientes comandos:

1. **Modo de desarrollo**:

    ```bash
    $ npm run start:dev
    ```

2. **Modo de producción**:

    ```bash
    $ npm run start:prod
    ```

3. **Modo de desarrollo (sin reiniciar automáticamente)**:

    ```bash
    $ npm run start
    ```

---

## **Base de Datos**

Asegúrate de que tu base de datos esté configurada correctamente y de que hayas importado el archivo `db.sql` para crear las tablas necesarias.

Para importar las tablas, usa el siguiente comando en tu base de datos MySQL:

## API Endpoints

## Endpoint Main
- **URL**: `/api/v1/`

### 1. **Registrar un nuevo usuario**
- **URL**: `/api/v1/auth/register`
- **Método**: POST

### 2. **Iniciar sesión**
- **URL**: `/api/v1/auth/login`
- **Método**: POST

### 3. **Verificar email**
- **URL**: `/api/v1/auth/verify-email`
- **Método**: GET
- **Query Parameter**: `token`

### 4. **Reenviar email de verificación**
- **URL**: `/api/v1/auth/resend-verification-email`
- **Método**: POST

### 5. **Olvidé mi contraseña**
- **URL**: `/api/v1/auth/forgot-password`
- **Método**: POST

### 6. **Actualizar contraseña**
- **URL**: `/api/v1/auth/reset-password`
- **Método**: POST
- **Query Parameter**: `token`

### 7. **Refrescar token**
- **URL**: `/api/v1/auth/refresh-token`
- **Método**: POST
- **Query Parameter**: `refreshToken`

### 9. **Logout**
- **URL**: `/api/v1/auth/logout`
- **Método**: POST
- **Authorization**: Bearer Token
- **Query Parameter**: `refreshToken`

## **Flujo de Autenticación**

1. **Registro**: El usuario se registra proporcionando su correo y contraseña. El sistema genera un correo de verificación y lo envía.
2. **Verificación de correo**: El usuario hace clic en el enlace del correo de verificación, lo que activa su cuenta.
3. **Inicio de sesión**: El usuario puede iniciar sesión con su correo y contraseña. Si las credenciales son correctas, el sistema devuelve un JWT.
4. **Restablecimiento de contraseña**: Si el usuario olvida su contraseña, puede solicitar un enlace de restablecimiento por correo.
5. **Refrescar token**: Si el token expira se solicita un nuevo Token y de retorna un Token y un Refresh Token.
6. **Logout**: si el usuario cierra sesion se invalidan los tokens.

---

## **Notas adicionales**

- El sistema de autenticación está protegido con JWT para garantizar la seguridad en las rutas que requieren autenticación.
- El sistema de verificación de correo electrónico utiliza un token único para cada usuario.
- El módulo NodeMailer se utiliza para enviar los correos de verificación y restablecimiento de contraseña.
- Los tokens JWT tienen tiempos de expiración que deben ser gestionados correctamente para asegurar la experiencia de usuario.

- Para la implementación de refresco de tokens y logout, asegúrate de implementar correctamente la lista negra de tokens para invalidar el refresh token.

---