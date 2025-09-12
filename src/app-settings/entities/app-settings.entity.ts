import { Column, Entity, PrimaryColumn, UpdateDateColumn } from 'typeorm';

@Entity('app_settings')
export class AppSettings {
  @PrimaryColumn({ type: 'int' })
  id: number; // Always 1 - single row configuration

  @Column({ name: 'allow_multiple_sessions', type: 'boolean', default: true })
  allowMultipleSessions: boolean;

  @Column({ name: 'global_session_version', type: 'int', default: 0 })
  globalSessionVersion: number;

  @Column({ name: 'default_max_session_minutes', type: 'int', default: 60 })
  defaultMaxSessionMinutes: number;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamp with time zone' })
  updatedAt: Date;
}
