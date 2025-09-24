


import 'dotenv/config'
import * as joi from 'joi'

interface EnvsVars {
    PORT: number
    POSTGRES_USER: string
    POSTGRES_PASSWORD: string
    POSTGRES_DB: string
    POSTGRES_PORT: number
    POSTGRES_HOST: string
    JWT_SECRET: string
    JWT_PRIVATE_SECRET: string
    JWT_PUBLIC_SECRET: string
    PUBLIC_KEY: string
    REDIS_HOST: string
    REDIS_PORT: number
    REDIS_PASSWORD: string
    FIREBASE_PROJECT_ID: string
    FIREBASE_CLIENT_EMAIL: string
    FIREBASE_PRIVATE_KEY: string
    EXPO_ACCESS_TOKEN?: string
    PUSH_NOTIFICATION_TIMEOUT: number
    PUSH_NOTIFICATION_MAX_RETRIES: number
    PUSH_NOTIFICATION_RETRY_DELAY: number
}

const envSchema = joi.object<EnvsVars>({
    PORT: joi.number().default(3000),
    POSTGRES_USER: joi.string(),
    POSTGRES_PASSWORD: joi.string(),
    POSTGRES_DB: joi.string(),
    POSTGRES_PORT: joi.number(),
    POSTGRES_HOST: joi.string(),
    JWT_SECRET: joi.string().default('MySecretKey'),
    JWT_PRIVATE_SECRET: joi.string().default('MyPrivateSecretKey'),
    JWT_PUBLIC_SECRET: joi.string().default('MyPublicSecretKey'),
    PUBLIC_KEY: joi.string().required(),
    REDIS_HOST: joi.string().default('localhost'),
    REDIS_PORT: joi.number().default(6379),
    REDIS_PASSWORD: joi.string().optional().allow(''),
    FIREBASE_PROJECT_ID: joi.string().required(),
    FIREBASE_CLIENT_EMAIL: joi.string().required(),
    FIREBASE_PRIVATE_KEY: joi.string().required(),
    EXPO_ACCESS_TOKEN: joi.string().optional(),
    PUSH_NOTIFICATION_TIMEOUT: joi.number().default(10000),
    PUSH_NOTIFICATION_MAX_RETRIES: joi.number().default(3),
    PUSH_NOTIFICATION_RETRY_DELAY: joi.number().default(1000),
}).unknown(true)

const { error, value: EnvsVars } = envSchema.validate({
    ...process.env,
})

if (error) {
    throw new Error(`Config validation error: ${error.message}`)
}

export const envs = {
    PORT: EnvsVars.PORT,
    POSTGRES_USER: EnvsVars.POSTGRES_USER,
    POSTGRES_PASSWORD: EnvsVars.POSTGRES_PASSWORD,
    POSTGRES_DB: EnvsVars.POSTGRES_DB,
    POSTGRES_PORT: EnvsVars.POSTGRES_PORT,
    POSTGRES_HOST: EnvsVars.POSTGRES_HOST,
    JWT_SECRET: EnvsVars.JWT_SECRET,
    JWT_PRIVATE_SECRET: EnvsVars.JWT_PRIVATE_SECRET,
    JWT_PUBLIC_SECRET: EnvsVars.JWT_PUBLIC_SECRET,
    PUBLIC_KEY: EnvsVars.PUBLIC_KEY,
    REDIS_HOST: EnvsVars.REDIS_HOST,
    REDIS_PORT: EnvsVars.REDIS_PORT,
    REDIS_PASSWORD: EnvsVars.REDIS_PASSWORD,
    FIREBASE_PROJECT_ID: EnvsVars.FIREBASE_PROJECT_ID,
    FIREBASE_CLIENT_EMAIL: EnvsVars.FIREBASE_CLIENT_EMAIL,
    FIREBASE_PRIVATE_KEY: EnvsVars.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    EXPO_ACCESS_TOKEN: EnvsVars.EXPO_ACCESS_TOKEN,
    PUSH_NOTIFICATION_TIMEOUT: EnvsVars.PUSH_NOTIFICATION_TIMEOUT,
    PUSH_NOTIFICATION_MAX_RETRIES: EnvsVars.PUSH_NOTIFICATION_MAX_RETRIES,
    PUSH_NOTIFICATION_RETRY_DELAY: EnvsVars.PUSH_NOTIFICATION_RETRY_DELAY,
}
