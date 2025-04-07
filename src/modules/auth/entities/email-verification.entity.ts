import { Column, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from "typeorm";
import { UserEntity } from "src/modules/users/entities/user.entity";

@Entity({ name: "email_verification" })
export class EmailVerificationEntity {
  @PrimaryGeneratedColumn({ name: "id_verification" })
  idVerification: number;

  @ManyToOne(() => UserEntity, (user)=> user.emailVerifications)
  @JoinColumn({ name: "user_id" })
  userId: UserEntity;

  @Column({ name: "verification_token", type: "varchar", length: 255 })
  verificationToken: string;

  @Column({ name: "verification_expires", type: "datetime" })
  verificationExpires: Date;
}
