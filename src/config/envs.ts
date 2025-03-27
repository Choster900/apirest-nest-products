


import 'dotenv/config'
import * as joi from 'joi'

interface EnvsVars {
    PORT: number
    POSTGRES_USER: string
    POSTGRES_PASSWORD: string
    POSTGRES_DB: string
    POSTGRES_PORT: number
    POSTGRES_HOST: string
}

const envSchema = joi.object<EnvsVars>({
    PORT: joi.number().default(3000),
    POSTGRES_USER: joi.string(),
    POSTGRES_PASSWORD: joi.string(),
    POSTGRES_DB: joi.string(),
    POSTGRES_PORT: joi.number(),
    POSTGRES_HOST: joi.string()
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
}
