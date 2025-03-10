import { Exclude } from "class-transformer";
import { RoleEntity } from "src/modules/roles/entities/role.entity";
import { UserInfoEntity } from "src/modules/users-information/entities/users-information.entity";
import { Column, Entity, JoinColumn, ManyToOne, OneToMany, PrimaryGeneratedColumn } from "typeorm";

@Entity({ name: "users" })
export class UserEntity {
  @PrimaryGeneratedColumn()
  id_user: number;

  @Column({ type: "varchar", length: 255, nullable: true })
  full_name: string;

  @Column({ type: "varchar", length: 255, nullable: true })
  email: string;

  @Column({ type: "varchar", length: 255, nullable: true })
  password: string;

  @Column({ type: "timestamp", default: () => "CURRENT_TIMESTAMP" })
  create_at: Date;

  @Column({ type: "timestamp", nullable: true, default: null })
  last_login: Date;

  @Column({ type: "tinyint", default: true })
  is_active: boolean;

  @Column({ type: "tinyint", default: false })
  is_verified: boolean;

  @ManyToOne(() => RoleEntity, (rol) => rol.users)
  @JoinColumn({ name: "role_id" })
  rol: RoleEntity;

  @Column({ type: "timestamp", nullable: true })
  deleted_at: Date;

  @OneToMany(() => UserInfoEntity, (userInformation) => userInformation.user)
  userInformation: UserInfoEntity[];
}