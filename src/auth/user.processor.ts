import { Processor, Process } from '@nestjs/bull';
import { Job } from 'bull';
import { Logger } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto';

@Processor('users')
export class UserProcessor {
    private readonly logger = new Logger(UserProcessor.name);

    constructor(private readonly authService: AuthService) {}

    @Process('register')
    async handleUserRegistration(job: Job<{ userData: CreateUserDto; jobId: string }>) {
        const { userData, jobId } = job.data;

        this.logger.log(`🔄 Processing user registration job: ${jobId}`);
        this.logger.log(`📧 Registering user: ${userData.email}`);

        try {
            // Procesar el registro del usuario
            const result = await this.authService.create(userData);

            this.logger.log(`✅ User registration completed for: ${userData.email}`);

            // Retornar el resultado (esto se almacenará en Redis para consulta posterior)
            return {
                success: true,
                user: result,
                processedAt: new Date().toISOString(),
                jobId
            };
        } catch (error) {
            this.logger.error(`❌ User registration failed for: ${userData.email}`, error.stack);

            // Lanzar el error para que Bull lo marque como fallido
            throw error;
        }
    }
}
