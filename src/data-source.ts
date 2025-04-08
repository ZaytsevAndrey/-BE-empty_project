import 'reflect-metadata';
import { DataSource } from 'typeorm';
import { User } from './modules/users/user.entity';

export const AppDataSource = new DataSource({
    type: 'sqlite',
    database: 'db.sqlite',
    synchronize: true,
    logging: false,
    entities: [User],
    migrations: ['src/db/migrations/*.ts'],
    subscribers: [],
}); 