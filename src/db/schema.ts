// src/db/schema.ts
import {
    mysqlTable,
    serial,
    varchar,
    int,
    boolean,
    timestamp, datetime
} from 'drizzle-orm/mysql-core';

export const usersTable = mysqlTable("users_table", {
    id: serial("id").primaryKey(),
    username: varchar("username", { length: 255 }),
    email: varchar("email", { length: 255 }),
    password: varchar("password", { length: 255 }),
    isVerified: boolean("is_verified").default(false),
    age: int("age").default(0), // now optional
});
