CREATE DATABASE shop;
CREATE TABLE shop.products (id INT PRIMARY KEY, name VARCHAR(50) NOT NULL);
INSERT INTO shop.products VALUES (1, 'Keyboard'), (2, 'Mouse');

-- A user with only what it needs
CREATE USER 'shop_admin'@'%' IDENTIFIED BY 'ShopPass-2026!';
GRANT SELECT, INSERT, UPDATE, DELETE ON shop.* TO 'shop_admin'@'%';

-- An over-privileged user, to check the superuser warning
CREATE USER 'super_admin'@'%' IDENTIFIED BY 'SuperPass-2026!';
GRANT ALL PRIVILEGES ON *.* TO 'super_admin'@'%';
FLUSH PRIVILEGES;
