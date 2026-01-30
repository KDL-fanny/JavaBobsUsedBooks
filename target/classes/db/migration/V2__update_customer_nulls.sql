-- Update any null boolean fields in customers table to ensure they have default values
UPDATE customers 
SET account_expired = false 
WHERE account_expired IS NULL;

UPDATE customers 
SET credentials_expired = false 
WHERE credentials_expired IS NULL;

UPDATE customers 
SET account_locked = false 
WHERE account_locked IS NULL;

UPDATE customers 
SET email_verified = true 
WHERE email_verified IS NULL AND username = 'admin';

UPDATE customers 
SET email_verified = false 
WHERE email_verified IS NULL AND username != 'admin';
