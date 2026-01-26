import {
    mysqlTable,
    serial,
    varchar,
    int,
    boolean
} from 'drizzle-orm/mysql-core';

export const usersTable = mysqlTable("users_table", {
    id: serial("id").primaryKey(),
    username: varchar("username", { length: 255 }),
    email: varchar("email", { length: 255 }),
    password_hash: varchar("password_hash", { length: 255 }).notNull(),
    isVerified: boolean("is_verified").default(false),
});

export const passwordResetsRequestTable = mysqlTable("password_resets_requests", {
    id: serial("id").primaryKey(),
    user_id: int("user_id").notNull(),
    token: varchar("token", { length: 255 }).notNull(),
    expires_at: int("expires_at").notNull(), // UNIX timestamp
});
