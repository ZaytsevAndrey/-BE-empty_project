# AuthService Documentation

## AuthService

### registerUser
- **Description:** Registers a new user.
- **Parameters:**
  - `RegisterDto`: Contains email, password, and confirmPassword.
- **Errors:**
  - `PASSWORDS_DO_NOT_MATCH`: If passwords do not match.
  - `EMAIL_ALREADY_EXISTS`: If the email is already registered.

### validateUser
- **Description:** Validates user credentials and returns tokens.
- **Parameters:**
  - `LoginDto`: Contains username and password.
- **Errors:**
  - `INVALID_CREDENTIALS`: If username or password is incorrect.

### generateNewTokens
- **Description:** Generates new access and refresh tokens.
- **Parameters:**
  - `refreshToken`: The current refresh token.
- **Errors:**
  - `INVALID_REFRESH_TOKEN`: If the refresh token is invalid.

### resetUserPassword
- **Description:** Resets the user's password using a reset token.
- **Parameters:**
  - `ResetPasswordDto`: Contains token and newPassword.
- **Errors:**
  - `INVALID_RESET_TOKEN`: If the reset token is invalid.

### sendPasswordResetInstructions
- **Description:** Sends password reset instructions to the user's email.
- **Parameters:**
  - `ForgotPasswordDto`: Contains email.
- **Errors:**
  - `EMAIL_NOT_FOUND`: If the email is not registered.

### logout
- **Description:** Logs out the user by clearing the refresh token.
- **Parameters:**
  - `userId`: The ID of the user.

## AuthController

### register
- **Description:** Endpoint to register a new user.
- **Route:** `POST /auth/register`
- **Body:** `RegisterDto`

### login
- **Description:** Endpoint to log in a user.
- **Route:** `POST /auth/login`
- **Body:** `LoginDto`

### refreshToken
- **Description:** Endpoint to refresh tokens.
- **Route:** `POST /auth/refresh`
- **Body:** Contains `refreshToken`

### resetPassword
- **Description:** Endpoint to reset password.
- **Route:** `POST /auth/reset-password`
- **Body:** `ResetPasswordDto`

### forgotPassword
- **Description:** Endpoint to send password reset instructions.
- **Route:** `POST /auth/forgot-password`
- **Body:** `ForgotPasswordDto`

### logout
- **Description:** Endpoint to log out a user.
- **Route:** `POST /auth/logout`
- **Body:** Contains `userId`

## 1. User Registration (`registerUser`)

- **Accepts:**
  - `RegisterDto`: contains `email`, `password`, `confirmPassword`.

- **Processing:**
  - Checks if passwords match.
  - Checks if a user with the given `email` already exists.
  - Hashes the password.
  - Creates a new user in the database.

- **Actions:**
  - Saves the new user.
  - Sends a welcome email.

- **Purpose:**
  - Registers a new user in the system.

## 2. User Validation (`validateUser`)

- **Accepts:**
  - `LoginDto`: contains `username`, `password`.

- **Processing:**
  - Checks if a user with the given `username` exists.
  - Verifies if the password is correct.

- **Actions:**
  - Generates an access token pair.
  - Stores the refresh token.

- **Purpose:**
  - Authenticates the user.

## 3. Generate New Tokens (`generateNewTokens`)

- **Accepts:**
  - `refreshToken`: refresh token.

- **Processing:**
  - Validates the refresh token.

- **Actions:**
  - Generates a new token pair.
  - Stores the new refresh token.

- **Purpose:**
  - Refreshes access tokens.

## 4. Password Reset (`resetUserPassword`)

- **Accepts:**
  - `ResetPasswordDto`: contains `token`, `newPassword`.

- **Processing:**
  - Validates the reset token.
  - Hashes the new password.

- **Actions:**
  - Updates the user's password.
  - Sends a password reset confirmation email.

- **Purpose:**
  - Resets the user's password.

## 5. Send Password Reset Instructions (`sendPasswordResetInstructions`)

- **Accepts:**
  - `ForgotPasswordDto`: contains `email`.

- **Processing:**
  - Checks if a user with the given `email` exists.

- **Actions:**
  - Generates a reset token.
  - Sends an email with password reset instructions.

- **Purpose:**
  - Provides the user with the ability to reset their password.

## Implemented Routes

### 1. **POST /auth/register**

- **Description:** Registers a new user.
- **Request Body:**
  - `email`: User's email address.
  - `password`: User's password.
  - `confirmPassword`: Password confirmation.
- **Response:**
  - Confirmation of successful registration.

### 2. **POST /auth/login**

- **Description:** Authenticates a user.
- **Request Body:**
  - `username`: User's username or email address.
  - `password`: User's password.
- **Response:**
  - Access token pair.

### 3. **POST /auth/refresh**

- **Description:** Refreshes access tokens.
- **Request Body:**
  - `refreshToken`: Refresh token.
- **Response:**
  - New access token pair.

### 4. **POST /auth/reset-password**

- **Description:** Resets the user's password.
- **Request Body:**
  - `token`: Password reset token.
  - `newPassword`: New password.
- **Response:**
  - Confirmation of successful password reset.

### 5. **POST /auth/forgot-password**

- **Description:** Sends password reset instructions.
- **Request Body:**
  - `email`: User's email address.
- **Response:**
  - Confirmation of instructions sent. 