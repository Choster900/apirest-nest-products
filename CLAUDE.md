# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Teslo Shop API - A NestJS REST API with authentication, push notifications, and session management. The project uses PostgreSQL with TypeORM, JWT authentication with session tracking, Firebase Cloud Messaging for push notifications, and includes disabled Bull/Redis queue infrastructure.

## Development Commands

### Setup
```bash
npm install
# Copy .env.template to .env and configure environment variables
docker-compose up -d  # Start PostgreSQL database
npm run start:dev     # Start development server with hot reload
```

### Common Commands
```bash
npm run build         # Build the project
npm run start:prod    # Run production build
npm run lint          # Run ESLint with auto-fix
npm run format        # Format code with Prettier
npm run test          # Run unit tests
npm run test:watch    # Run tests in watch mode
npm run test:cov      # Run tests with coverage
npm run test:e2e      # Run end-to-end tests
```

## Architecture

### Core Module Structure

- **AppModule** (`src/app.module.ts`): Root module with TypeORM PostgreSQL configuration (SSL enabled for Neon), ServeStaticModule for public files, and disabled Bull/Redis queue setup
- **AuthModule**: JWT authentication, session management, user blocking on failed attempts, biometric login support
- **PushNotificationsModule**: Firebase Cloud Messaging integration for sending notifications (global and user-specific)
- **SeedModule**: Database seeding for app settings
- **AppSettingsModule**: Application-wide configuration (session settings, multiple sessions control)
- **CommonModule**: Shared utilities including Firebase configuration

### Authentication & Session Architecture

The authentication system uses a **session-based approach** with JWT tokens:

- **User Entity** (`src/auth/entities/user.entity.ts`): Stores user credentials, roles, failed login attempts, and account blocking state
- **Session Entity** (`src/auth/entities/sessions.entity.ts`): Tracks active sessions per user with:
  - Access tokens and refresh tokens
  - Device tokens for biometric authentication
  - Push notification tokens (Expo)
  - Device information
  - Session expiration tracking
  - Flags for biometric enabled, push notifications active

**Key Authentication Patterns**:
- JWT tokens are signed with `JWT_PRIVATE_SECRET` from config
- Token expiration is controlled by `AppSettings.defaultMaxSessionMinutes`
- Users can have multiple sessions if `AppSettings.defaultAllowMultipleSessions` is enabled
- Failed login attempts are tracked with automatic account blocking (`User.failedAttempts`, `User.blockedUntil`)
- User validation can be done by email OR ID (see `src/auth/auth.service.ts`)
- `@Auth()` decorator applies `JwtAuthGuard` for route protection
- JwtStrategy validates tokens by checking user existence and active status

### Database Configuration

TypeORM with PostgreSQL configured in `app.module.ts`:
- SSL enabled with `rejectUnauthorized: false` (required for Neon hosting)
- Auto-loads entities, synchronize enabled (development mode)
- Connection pooling configured (max: 10 connections)
- Timeouts: connection (10s), idle (30s), statement (30s)

### Environment Configuration

All environment variables are validated using Joi schema in `src/config/envs.ts`:
- Database credentials (POSTGRES_*)
- JWT secrets (JWT_SECRET, JWT_PRIVATE_SECRET, JWT_PUBLIC_SECRET)
- PUBLIC_KEY for additional JWT validation
- Redis configuration (currently disabled)
- Firebase credentials (PROJECT_ID, CLIENT_EMAIL, PRIVATE_KEY)
- Push notification settings (timeout, retries, retry delay)
- EXPO_ACCESS_TOKEN (optional)

### Global Configuration

**Main Application** (`src/main.ts`):
- Global prefix: `/api`
- Cookie parser enabled for session management
- Global ValidationPipe with:
  - `transform: true` - auto-converts types
  - `whitelist: true` - strips unknown properties
  - `forbidNonWhitelisted: true` - errors on unknown properties
  - `enableImplicitConversion: true` - automatic type coercion

### Disabled Infrastructure

**Bull/Redis Queue System**: Temporarily disabled throughout the codebase
- Comments indicate `// TEMPORALMENTE DESHABILITADO` in `app.module.ts` and `auth.module.ts`
- `UserProcessor` service is commented out
- When re-enabling, configure Redis connection with TLS support for production

### Push Notifications

Firebase Cloud Messaging integration via `PushNotificationsModule`:
- Sends notifications to specific users by email or ID
- Supports both personal (login/logout) and global notifications
- Session-level control over notification delivery (`pushActive`, `allowGeneralNotifications`)
- Retry logic configured via environment variables
- Service uses HttpModule for Expo push API

### Seeding

`SeedService` provides database initialization:
- Seeds app settings (creates default if not exists)
- Uses `initialAppSettingsData` from `app-settings-seed`
- Endpoint available via `SeedModule` for development

## Key Implementation Patterns

### Cascade Operations
- User entity cascades to Session (delete user → delete sessions)
- Session entity has `onDelete: 'CASCADE'` for user relationship

### TypeORM Relations
- Users: `@OneToMany` with Session
- Sessions: `@ManyToOne` with User

### Session Management
When implementing features involving sessions:
1. Check `AppSettings.defaultAllowMultipleSessions` to determine if old sessions should be invalidated
2. Always set `expiresAt` based on `AppSettings.defaultMaxSessionMinutes`
3. Store device information and push tokens during login
4. Validate session `isActive` status and expiration before processing requests
