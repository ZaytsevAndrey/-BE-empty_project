import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddEmailToUser20240408 implements MigrationInterface {
    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.addColumn('user', new TableColumn({
            name: 'email',
            type: 'varchar',
            isUnique: true,
            isNullable: false,
        }));
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.dropColumn('user', 'email');
    }
} 