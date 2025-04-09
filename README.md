<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

[circleci-image]: https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456
[circleci-url]: https://circleci.com/gh/nestjs/nest

<p align="center">A secure, scalable authentication backend built with <strong>NestJS</strong> and <strong>TypeORM</strong>.</p>

## 🔐 NestJS Backend
Features:

- ✅ JWT authentication
- 🔁 Refresh token rotation
- 🛡️ Role-based and permission-based access control
- 🔒 OAuth2 login with Google
- 🧠 Custom decorators for permission logic
- 📁 MySQL support with TypeORM

Perfect as a plug-and-play backend for your modern web apps.

---

### 📦 Stack
- **NestJS**
- **TypeORM**
- **JWT & Passport**
- **MySQL**
- **Google OAuth2**
- **Role & Permission decorators**

## Project setup
### 📚 Install the dependencies
```bash
# Install the dependencies
$ npm install
```
### 📄 Create your .env
```bash
# Then copy the `.env.sample` to `.env` and fill in the required values.
$ cp .env.sample .env
```
### 🔧 Google OAuth2 Setup
1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. In the top bar, click the **Project selector** and create a new project (or select an existing one).
3. In the left sidebar, navigate to **APIs & Services** → **OAuth consent screen**:
   - Select the **External** user type.
   - Fill in the **App name**, **User support email**, and **Developer contact info**.
   - Click **Save and Continue** (you can skip scopes for now).
4. Go to **APIs & Services** → **Credentials**:
   - Click **+ Create Credentials** → **OAuth client ID**.
   - Select **Web application**.
   - Set a name, e.g., **NestJS Auth Backend**.
   - Under **Authorized redirect URIs**, add your backend redirect URL:
     ```bash
     # (replace with your production URL if deploying)
     http://localhost:5000/auth/google/callback
     ```
   - Click **Create**.
5. After creating the OAuth client:
   - Copy the **Client ID** and **Client Secret**.
   - Add them to your `.env` file:
     ```bash
     GOOGLE_CLIENT_ID=your-client-id
     GOOGLE_CLIENT_SECRET=your-client-secret
     GOOGLE_CALLBACK_URL=http://localhost:5000/auth/google/callback
     ```
### 🆕 Create default User and Permissions
To create the default permissions (which are defined in the `scripts/permission.seed.ts`) and a user with email, password and permission:
```bash
# In case you dont need a user you can run the command without passing the parameters
# If you want you can pass multiple permissions like --permission ADMIN,USER
npx ts-node scripts/init.ts --email admin@example.com --password mySecurePassword --permission ADMIN
```
> [!WARNING]
> If you change the `USER` permission in the `scripts/permission.seed.ts` make sure to change it in the `auth.controller.ts` too.

## Compile and run the project
```bash
# development
$ npm run start

# watch mode
$ npm run start:dev

# production mode
$ npm run start:prod
```
---
# How It Works
## Decorators
### 🔑 `@Permissions()`
The **@Permissions()** decorator is used to restrict access to specific routes based on the user's permissions.
It supports:
* AND logic
* OR logic
* Combined logic
* Wildcard matching

> [!IMPORTANT]
> The permissions are automatically converted to **UPPERCASE** during validation. So even if you write them in lowercase in the decorator, it will still work.

#### ➕ AND Logic
`@Permissions('permission1', 'permission2')`
> [!NOTE]
> Requires both **PERMISSION1** and **PERMISSION2**.

#### 🔁 OR Logic
`@Permissions(['permission1', 'permission2'])`
> [!NOTE]
> Requires at least one between **PERMISSION1** and **PERMISSION2**.

#### 🔀 Combined (OR + AND)
`@Permissions(['permission1', 'permission2'], 'permission3')`
> [!NOTE]
> Requires: (**PERMISSION1** OR **PERMISSION2**) AND **PERMISSION3**.

#### 🌟 Wildcard Matching
`@Permissions('permission_*')`
> [!NOTE]
> Matches any permission starting with **PERMISSION_**. For example: **PERMISSION_VIEW**, **PERMISSION_EDIT**, **PERMISSION_ADMIN**, etc.

### `🌐 Public()`
There may be cases where you want certain routes or controllers to be publicly accessible (without requiring authentication).\ 
In such cases, you can use the **@Public()** decorator to skip the AuthGuard for specific endpoints or controllers.
Example:
```javascript
@Controller('auth')
@Public()
export class AuthController { } 
```
---
## 🛡️ Guards
### 🔒 AuthGuard
> Handles user authentication using JWT tokens.

#### What it does:
* Protects routes by default (unless explicitly marked as public).
* Checks for a valid access_token in:
  * Authorization header (Bearer ...)
  * or cookies (access_token)
* If the access_token is missing or expired, and a refresh_token is available:
  * ✅ It will automatically use the refresh_token to generate new tokens and save them in cookies.
  * ❌ If both tokens are invalid or missing, the request is rejected with **401 Unauthorized**.

#### Public routes:
As stated before you can make a route public by using the **@Public()** decorator.
### 🔐 PermissionsGuard
> Handles authorization: checks if the authenticated user has the required permissions to access a route.

#### What it does:
* Reads the required permissions defined on a route using a **@Permissions()** decorator.
* Gets the authenticated user's permissions from the database.
* Compares the user’s permissions with the required ones:
  * ✅ If the user has all required permissions, access is allowed.
  * ❌ If not, access is denied with a 403 Forbidden.

#### Advanced features:
✅ Supports wildcard matching (e.g. USER.*)\
🔠 Case-insensitive

---
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
---   
## Contact
For any issues or questions, feel free to get in touch.\
Deyvid Manolov - [Telegram](https://t.me/FileExists) - [My Website](https://www.deyvid.dev)
