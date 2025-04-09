import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Column({ nullable: true, unique: true })
    username: string;

    @Column({ unique: true })
    email: string;

    @Column()
    password: string;

    @Column({ nullable: true, type: 'text' })
    resetToken: string | null;

    @Column({ nullable: true, type: 'text' })
    refreshToken: string | null;

    @Column({ default: false })
    isEmailVerified: boolean;
}
