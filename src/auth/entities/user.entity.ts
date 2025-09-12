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
