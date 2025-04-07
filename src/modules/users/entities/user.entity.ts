import { Column, Entity, JoinColumn, ManyToOne, OneToMany, PrimaryGeneratedColumn } from "typeorm";
import { UserInfoEntity } from "./users-information.entity";
import { RoleEntity } from "src/modules/roles/entities/role.entity";
import { PasswordResetEntity } from "src/modules/auth/entities/password-reset.entity";
import { EmailVerificationEntity } from "src/modules/auth/entities/email-verification.entity";
import { RefreshTokenEntity } from "src/modules/auth/entities/refresh_token.entity";

@Entity({ name: "users" })
export class UserEntity {
  @PrimaryGeneratedColumn({ name: "id_user" })
  idUser: number;

  @Column({ name: "full_name", type: "varchar", length: 255, nullable: true })
  fullName: string;

  @Column({ type: "varchar", length: 255, nullable: true })
  email: string;

  @Column({ type: "varchar", length: 255, nullable: true })
  password: string;

  @Column({ name: "profile_picture", type: "varchar", length: 500, nullable: true })
  profilePicture: string;

  @Column({ name: "create_at", type: "timestamp", default: () => "CURRENT_TIMESTAMP" })
  createdAt: Date;

  @Column({ name: "last_login", type: "timestamp", nullable: true, default: null })
  lastLogin: Date;

  @Column({ name: "is_active", type: "tinyint", default: true })
  isActive: boolean;

  @Column({ name: "is_verified", type: "tinyint", default: false })
  isVerified: boolean; 

  @ManyToOne(() => RoleEntity, (rol) => rol.users)
  @JoinColumn({ name: "role_id" })
  role: RoleEntity;

  @Column({ name: "deleted_at", type: "timestamp", nullable: true })
  deletedAt: Date;

  @OneToMany(() => UserInfoEntity, (userInformation) => userInformation.user)
  userInformation: UserInfoEntity[];

  @OneToMany(() => PasswordResetEntity, (passwordReset) => passwordReset.userId)
  passwordResets: PasswordResetEntity[];

  @OneToMany(() => EmailVerificationEntity, (emailVerification) => emailVerification.userId)
  emailVerifications: EmailVerificationEntity[];

  @OneToMany(() => RefreshTokenEntity, (refreshToken) => refreshToken.userId)
  refreshTokens: RefreshTokenEntity[];
}
