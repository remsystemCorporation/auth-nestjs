import { UserEntity } from "src/modules/users/entities/user.entity";
import { Column, Entity, JoinColumn, OneToMany, PrimaryGeneratedColumn } from "typeorm";

@Entity({ name: "roles" })
export class RoleEntity {
  @PrimaryGeneratedColumn({name: "id_rol"})
  idRol: number;

  @Column({name: "rol_name", type: "varchar", length: 255 })
  rolName: string;

  @OneToMany(() => UserEntity, (user) => user.role)
  users: UserEntity[];
}
