-- A PostgreSQL database "on this server": a role that owns only its database, and a superuser.
CREATE ROLE shop_owner LOGIN PASSWORD 'ShopPg-2026!';
CREATE DATABASE shop OWNER shop_owner;
\connect shop shop_owner
CREATE TABLE products (id int PRIMARY KEY, name text NOT NULL);
INSERT INTO products VALUES (1, 'Keyboard'), (2, 'Mouse');
\connect postgres postgres
CREATE ROLE boss_admin LOGIN SUPERUSER PASSWORD 'BossPg-2026!';
