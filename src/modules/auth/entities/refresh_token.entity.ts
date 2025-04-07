import { UserEntity } from 'src/modules/users/entities/user.entity';
import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, JoinColumn } from 'typeorm';

@Entity('refresh_tokens')
export class RefreshTokenEntity {
  @PrimaryGeneratedColumn({ name: "id_refresh" })
  idRefresh: number;

  @ManyToOne(() => UserEntity, (user) => user.refreshTokens, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  userId: UserEntity;

  @Column({ name:"token", type: 'varchar', length: 512, unique: true })
  token: string;

  @Column({ name: "jti", type: 'uuid', unique: true })
  jti: string;

  @Column({ name:"expires_at", type: 'datetime' })
  expiresAt: Date;

  @Column({ name:"created_at", type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @Column({ name:"revoked", type: 'boolean', default: false })
  revoked: boolean;
}