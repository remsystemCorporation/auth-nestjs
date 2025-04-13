import { Column, CreateDateColumn, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";
import { UserEntity } from "src/modules/users/entities/user.entity";

@Entity({ name: "user_verifications" })
export class UserVerificationEntity  {
  @PrimaryGeneratedColumn({ name: "id_verification" })
  idVerification: number;

  @ManyToOne(() => UserEntity, (user)=> user.userVerifications)
  @JoinColumn({ name: "user_id" })
  userId: UserEntity;

  @Column({ name: "verification_token", type: "varchar", length: 255 })
  verificationToken: string;

  @Column({ name: 'method', type: 'varchar', length: 50 })
  method: string;

  @Column({ name: "verification_expires", type: "datetime" })
  verificationExpires: Date;

  @Column({ default: false })
  used: boolean;

  @Column({ name: 'verified_at', type: 'datetime', nullable: true })
  verifiedAt: Date;

  
  @CreateDateColumn({ name: 'created_at', type: 'datetime' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'datetime' })
  updatedAt: Date;
}
