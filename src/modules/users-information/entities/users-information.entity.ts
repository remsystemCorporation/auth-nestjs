import { UserEntity } from "src/modules/users/entities/user.entity";
import { Column, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from "typeorm";

@Entity({ name: "user_information" })
export class UserInfoEntity {
  @PrimaryGeneratedColumn({ name: "id_info" })
  id_info: number;

  @ManyToOne(() => UserEntity, (user) => user.userInformation)
  @JoinColumn({ name: "user_id" })
  user: UserEntity;

  @Column({ name: "full_name", type: "varchar", length: 255, nullable: true })
  full_name: string;

  @Column({ name: "company", type: "varchar", length: 255, nullable: true })
  company: string;

  @Column({ name: "phone", type: "varchar", length: 20, nullable: true })
  phone: string;

  @Column({ name: "address", type: "varchar", length: 255, nullable: true })
  address: string;

  @Column({ name: "birthdate", type: "date", nullable: true })
  birthdate: Date;

  @Column({ name: "deleted_at", type: "timestamp", nullable: true })
  deleted_at: Date;
}