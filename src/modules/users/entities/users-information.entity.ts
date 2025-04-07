import { UserEntity } from "src/modules/users/entities/user.entity";
import { Column, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from "typeorm";

@Entity({ name: "user_information" })
export class UserInfoEntity {
  @PrimaryGeneratedColumn({ name: "id_info" })
  idInfo: number;

  @ManyToOne(() => UserEntity, (user) => user.userInformation, { onDelete: "CASCADE" })
  @JoinColumn({ name: "user_id" })
  user: UserEntity;

  @Column({ name: "full_name", type: "varchar", length: 255 })
  fullName: string;

  @Column({ name: "company", type: "varchar", length: 255, nullable: true })
  company: string;

  @Column({ name: "tax_id", type: "varchar", length: 50, nullable: true })
  taxId: string;

  @Column({ name: "phone", type: "varchar", length: 20, nullable: true })
  phone: string;

  @Column({ name: "address", type: "varchar", length: 255, nullable: true })
  address: string;

  @Column({ name: "birthdate", type: "date", nullable: true })
  birthdate: Date;

  @Column({ name: "country", type: "varchar", length: 100 })
  country: string;

  @Column({ name: "state", type: "varchar", length: 100, nullable: true })
  state: string;

  @Column({ name: "city", type: "varchar", length: 100, nullable: true })
  city: string;

  @Column({ name: "postal_code", type: "varchar", length: 10, nullable: true })
  postalCode: string;

  @Column({ name: "created_at", type: "timestamp", default: () => "CURRENT_TIMESTAMP" })
  createdAt: Date;

  @Column({ name: "updated_at", type: "timestamp", nullable: true, onUpdate: "CURRENT_TIMESTAMP" })
  updatedAt: Date;

  @Column({ name: "deleted_at", type: "timestamp", nullable: true })
  deletedAt: Date;
}
