import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, JoinColumn } from "typeorm";
import { User } from "./user.entity";

@Entity('sessions')
export class Session {

    @PrimaryGeneratedColumn('uuid')
    id: string;

    @ManyToOne(() => User, user => user.sessions, { onDelete: 'CASCADE' })
    @JoinColumn({ name: 'userId' })
    user: User;

    @Column('uuid')
    userId: string;

    @Column('text', { nullable: true })
    accessToken: string | null;

    @Column('text', { nullable: true })
    refreshToken: string | null;

    @Column('text', { nullable: true })
    deviceToken: string | null; // para login biométrico

    @Column('boolean', { default: false })
    biometricEnabled: boolean; // biometría habilitada para este dispositivo específico

    @Column('boolean', { default: true })
    isActive: boolean;

    @Column('timestamp', { default: () => 'CURRENT_TIMESTAMP' })
    createdAt: Date;

    @Column('timestamp', { nullable: true })
    expiresAt: Date | null;

    @Column('text', { nullable: true })
    deviceInfo: string | null; // ej: "iPhone 13 iOS 17" o "Honor X7b Android 14"
}
