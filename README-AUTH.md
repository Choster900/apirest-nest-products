
## Tabla: `users`

Almacena la información básica de cada usuario del sistema.

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | UUID | Identificador único del usuario |
| `email` | texto | Correo electrónico (debe ser único) |
| `password` | texto | Contraseña encriptada |
| `isActive` | booleano | Si el usuario está activo o bloqueado (true/false) |
| `failedAttempts` | número | Cuántas veces falló al intentar iniciar sesión |
| `lastFailedAt` | fecha | Última vez que falló al iniciar sesión |
| `blockedUntil` | fecha | Hasta qué fecha está bloqueado el usuario (si aplicó) |

**Relación**: Un usuario puede tener múltiples sesiones activas.

---

## Tabla: `sessions`

Guarda información de cada sesión activa de un usuario (cada dispositivo).

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | UUID | Identificador único de la sesión |
| `userId` | UUID | ID del usuario al que pertenece esta sesión |
| `deviceToken` | texto | Token del dispositivo (para login con huella/Face ID) |
| `biometricEnabled` | booleano | Si tiene activado el login biométrico |
| `isActive` | booleano | Si la sesión está activa o fue cerrada ( utilizada para cerrar seccion en dispositivos en especificos ) |
| `createdAt` | fecha | Cuándo se creó la sesión |
| `expiresAt` | fecha | Cuándo expira la sesión |
| `deviceInfo` | texto | Info del dispositivo (ej: "iPhone 13 iOS 17") |
| `pushToken` | texto | Token de FCM para enviar notificaciones push |

**Relación**: Cada sesión pertenece a un usuario específico.

---

## Tabla: `app_settings`

Configuración global del sistema de autenticación (solo existe 1 registro).

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | número | Siempre es 1 (solo hay una configuración global) |
| `allowMultipleSessions` | booleano | Si los usuarios pueden tener varias sesiones activas al mismo tiempo |
| `globalSessionVersion` | número | Versión global de sesiones (se incrementa para invalidar todas las sesiones) |
| `defaultMaxSessionMinutes` | número | Cuántos minutos dura una sesión antes de expirar (ej: 60 = 1 hora) |
| `maxLoginAttempts` | número | Cuántos intentos fallidos de login antes de bloquear al usuario (ej: 5) |
| `loginBlockDurationMinutes` | número | Cuántos minutos queda bloqueado el usuario tras fallar muchas veces (ej: 1) |
| `updatedAt` | fecha | Última vez que se actualizó la configuración |

**Importante**: Esta tabla controla el comportamiento de toda la autenticación del sistema.

---

## ¿Cómo funciona?

1. **Usuario se registra** → Se crea un registro en `users`
2. **Usuario inicia sesión** → Se crea un registro en `sessions` con sus id user
6. **Usuario falla login muchas veces** → Se actualiza `failedAttempts` y si pasa el límite, se bloquea con `blockedUntil`

## Configuración importante

- Un usuario puede tener varias sesiones activas a la vez (varios dispositivos)
- La configuración de cuánto tiempo dura una sesión se controla desde `app-settings`
- Si un usuario se bloquea por intentos fallidos, debe esperar un tiempo definido o un admin debe desbloquearlo
