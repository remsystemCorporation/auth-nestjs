import { Column, CreateDateColumn, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";
import { UserEntity } from "src/modules/users/entities/user.entity";

@Entity({ name: "password_resets" })
export class PasswordResetEntity {
  @PrimaryGeneratedColumn({ name: "id_reset" })
  idReset: number;

  @ManyToOne(() => UserEntity, (user) => user.passwordResets)
  @JoinColumn({ name: "user_id" })
  userId: UserEntity;

  @Column({ name: "reset_token", type: "varchar", length: 255 })
  resetToken: string;

  @Column({ name: "isUsed", type: "tinyint", default: false })
  isUsed: boolean;

  @Column({ name: "revoked", type: "tinyint", default: false })
  revoked: boolean;

  @Column({ name: "reset_expires", type: "datetime" })
  resetExpires: Date;

  @Column({ name: "reset_count", type: "int", default: 0 })
  resetCount: number;

  @Column({ name: "reset_block_until", type: "datetime", nullable: true })
  resetBlockUntil: Date;

  @CreateDateColumn({ name: "created_at" })
  createdAt: Date;

  @UpdateDateColumn({ name: "updated_at" })
  updatedAt: Date;

}
