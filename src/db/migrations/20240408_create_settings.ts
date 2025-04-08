import { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
    await knex.schema.createTable('settings', (table) => {
        table.string('key').primary();
        table.string('value').notNullable();
    });

    await knex('settings').insert([
        { key: 'accessTokenTtl', value: '15m' },
        { key: 'refreshTokenTtl', value: '7d' },
        { key: 'verificationCodeTtl', value: '10m' },
    ]);
}

export async function down(knex: Knex): Promise<void> {
    await knex.schema.dropTableIfExists('settings');
}
