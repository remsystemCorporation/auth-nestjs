import { UserEntity } from "src/modules/users/entities/user.entity";
import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from "typeorm";

@Entity({ name: "roles" })
export class RoleEntity {
  @PrimaryGeneratedColumn()
  id_rol: number;

  @Column({ type: "varchar", length: 255 })
  rol_name: string;

  @OneToMany(() => UserEntity, (user) => user.rol)
  users: UserEntity[];
}
