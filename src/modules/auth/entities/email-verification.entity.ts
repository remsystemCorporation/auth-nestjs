import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

@Entity({name: 'email_verification'})
export class EmailVerificationEntity {
    @PrimaryGeneratedColumn()
    id_verification: number;

    @Column({type: 'int'})
    user_id: number;

    @Column({type: 'varchar', length: 255})
    verification_token: string;
    
    @Column({type: 'datetime'})
    verification_expires: Date;
}