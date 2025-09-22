


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
    REDIS_PASSWORD: joi.string().optional().allow('')
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
}
