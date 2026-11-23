-- Test only: a user whose first sign-in is without TLS, so MySQL's caching_sha2_password does its
-- full authentication (the password is RSA-encrypted with the server's key, never sent in clear text).
CREATE USER 'plain_user'@'%' IDENTIFIED BY 'PlainMy-2026!';
GRANT SELECT ON legacy.* TO 'plain_user'@'%';
