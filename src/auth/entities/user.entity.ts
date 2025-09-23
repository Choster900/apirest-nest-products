import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from "typeorm";
import { Session } from "./sessions.entity";


@Entity('users')
export class User {

    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column('text', {
        unique: true
    })
    email: string;

    @Column('text')
    password: string;

    @Column('text')
    fullName: string;

    @Column('bool', {
        default: true
    })
    isActive: boolean;

    @Column('text', {
        array: true,
        default: ['user']
    })
    roles: string[]

    @Column('int', {
        default: 0
    })
    failedAttempts: number;  // número de intentos fallidos

    @Column('timestamp', {
        nullable: true
    })
    lastFailedAt: Date;      // última vez que falló

    @Column('timestamp', {
        nullable: true
    })
    blockedUntil?: Date;     // si está bloqueado, hasta cuándo

    /*  @Column('text', {
         nullable: true
     })
     deviceToken: string | null; */

    /*  @Column('boolean', {
         default: false
     })
     allowMultipleSessions: boolean; */

    @OneToMany(() => Session, session => session.user, { cascade: true })
    sessions: Session[];

}
