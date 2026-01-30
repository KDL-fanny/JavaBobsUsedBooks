-- Add new columns to books table
ALTER TABLE books ADD COLUMN seller_id INTEGER REFERENCES customers(id);
ALTER TABLE books ADD COLUMN listing_status INTEGER DEFAULT 0;
ALTER TABLE books ADD COLUMN is_user_listing BOOLEAN DEFAULT FALSE;

-- Migrate data from offers to books (if needed)
INSERT INTO books (
    name, author, isbn, publisher_id, book_type_id, genre_id, condition_id, 
    price, quantity, cover_image_url, summary, seller_id, listing_status, 
    is_user_listing, created_by, created_on, updated_on
)
SELECT 
    o.book_name, o.author, o.isbn, o.publisher_id, o.book_type_id, o.genre_id, o.condition_id,
    o.offer_price, 1, o.cover_image_url, o.summary, o.customer_id, 
    CASE 
        WHEN o.offer_status = 1 THEN 0 -- APPROVED -> AVAILABLE
        WHEN o.offer_status = 3 THEN 1 -- SOLD -> SOLD
        WHEN o.offer_status = 4 THEN 2 -- CANCELLED -> CANCELLED
        ELSE 0
    END,
    TRUE, o.created_by, o.created_on, o.updated_on
FROM offers o
WHERE o.offer_status IN (1, 3, 4); -- Only migrate approved, sold, or cancelled offers

-- Drop the offers table (after confirming data migration is successful)
-- DROP TABLE offers;
