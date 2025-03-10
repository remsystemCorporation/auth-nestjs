import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

@Entity({name: 'password_resets'})
export class PasswordResetEntity{
    @PrimaryGeneratedColumn()
    id_reset: number;

    @Column({type: 'int'})
    user_id: number;

    @Column({type: 'varchar', length: 255}) 
    reset_password_token: string;

    @Column({type: 'datetime'}) 
    reset_password_expires: Date;

    @Column({type: 'int'})
    password_reset_count: number;

    @Column({type: 'datetime'})
    reset_password_block_until: Date;
}