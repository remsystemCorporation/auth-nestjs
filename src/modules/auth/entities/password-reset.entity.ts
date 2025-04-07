import { Column, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from "typeorm";
import { UserEntity } from "src/modules/users/entities/user.entity";

@Entity({ name: "password_resets" })
export class PasswordResetEntity {
  @PrimaryGeneratedColumn({ name: "id_reset" })
  idReset: number;

  @ManyToOne(() => UserEntity, (user) => user.passwordResets)
  @JoinColumn({ name: "user_id" })
  userId: UserEntity;

  @Column({ name: "reset_password_token", type: "varchar", length: 255 })
  resetPasswordToken: string;

  @Column({ name: "isUsed", type: "tinyint", default: "null" })
  isUsed: boolean;

  @Column({ name: "revoked", type: "tinyint", default: "null" })
  revoked: boolean;

  @Column({ name: "reset_password_expires", type: "datetime" })
  resetPasswordExpires: Date;

  @Column({ name: "password_reset_count", type: "int", default: 0 })
  passwordResetCount: number;

  @Column({ name: "reset_password_block_until", type: "datetime", nullable: true })
  resetPasswordBlockUntil: Date;
}
