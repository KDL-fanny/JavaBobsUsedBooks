-- Oracle version of data.sql for production deployment

SET DEFINE OFF

-- Reference data for book conditions
INSERT INTO conditions (name, description) 
VALUES('New', 'Brand new, never used, in perfect condition');

INSERT INTO conditions (name, description) 
VALUES('Like New', 'Looks new but may have been read once or twice');

INSERT INTO conditions (name, description) 
VALUES('Good', 'Shows some signs of wear, may have markings');

INSERT INTO conditions (name, description) 
VALUES('Acceptable', 'Definitely used, may have markings or damage');



-- Reference data for book types
INSERT INTO book_types (name, description) 
VALUES ('Hardcover', 'Book with a rigid binding');

INSERT INTO book_types (name, description) 
VALUES ('Trade Paperback', 'Book with a flexible paper binding, higher quality');

INSERT INTO book_types (name, description) 
VALUES ('Mass Market Paperback', 'Smaller format paperback book');



-- Reference data for genres
INSERT INTO genres (name, description) 
VALUES ('Biographies', 'Non-fiction account of someone''s life');

INSERT INTO genres (name, description)
VALUES ('Children''s Books', 'Books for children');

INSERT INTO genres (name, description)
VALUES ('History', 'Non-fiction about past events');

INSERT INTO genres (name, description)
VALUES ('Literature & Fiction', 'Literary works based on imagination');

INSERT INTO genres (name, description)
VALUES ('Mystery, Thriller & Suspense', 'Fiction dealing with suspense, crime or puzzles');

INSERT INTO genres (name, description)
VALUES ('Science Fiction & Fantasy', 'Fiction with scientific or fantastical elements');

INSERT INTO genres (name, description)
VALUES ('Travel', 'Books about travel and destinations');


-- Reference data for publishers
INSERT INTO publishers (name, description) 
VALUES ('Arcadia Books', 'Independent publisher');

INSERT INTO publishers (name, description) 
VALUES ('Astral Publishing', 'Publishing company');

INSERT INTO publishers (name, description) 
VALUES ('Moonlight Publishing', 'Publishing company');

INSERT INTO publishers (name, description) 
VALUES ('Dreamscape Press', 'Publishing company');

INSERT INTO publishers (name, description) 
VALUES ('Enchanted Library', 'Publishing company');

INSERT INTO publishers (name, description) 
VALUES ('Fantasia House', 'Publishing company');

INSERT INTO publishers (name, description) 
VALUES ('Horizon Books', 'Publishing company');

INSERT INTO publishers (name, description) 
VALUES ('Infinity Press', 'Publishing company');

INSERT INTO publishers (name, description) 
VALUES ('Paradigm Publishing', 'Publishing company');

INSERT INTO publishers (name, description) 
VALUES ('Aurora Publishing', 'Publishing company');


-- Sample books
Insert into books (author,book_type_id,condition_id,cover_image_url,created_by,created_on,description,genre_id,is_available,is_bestseller,is_featured,is_new_arrival,is_user_listing,is_user_offer,isbn,last_restock_date,listing_status,name,offer_source_id,price,publish_date,publisher_id,quantity,seller_id,summary,updated_on,year)
values ('Li Juan',1,2,'/images/coverimages/apocalypse.png','system',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null,6, null,0,1,1, null, null,'6556784356', null, null,'2020: The Apocalypse', null,10.95, null,1,25, null, 'A chilling science fiction tale that imagines the world on the brink of collapse during the tumultuous year 2020. Li Juan weaves a haunting narrative of survival, resilience, and unexpected hope as society faces unprecedented global challenges that test the limits of humanity.',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null);

Insert into books (author,book_type_id,condition_id,cover_image_url,created_by,created_on,description,genre_id,is_available,is_bestseller,is_featured,is_new_arrival,is_user_listing,is_user_offer,isbn,last_restock_date,listing_status,name,offer_source_id,price,publish_date,publisher_id,quantity,seller_id,summary,updated_on,year)
values ('Nikki Wolf',1,3,'/images/coverimages/childrenofiron.png','system',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null,4, null,1,0,0, null, null,'7665438976', null, null,'Children Of Iron', null,13.95, null,2,3, null, 'Set in a post-industrial wasteland, this literary masterpiece follows three siblings born into a society where humans are classified by their utility. As they discover their true heritage, they must navigate a world where compassion is scarce and rebellion means death. Wolf''s prose is both lyrical and devastating.',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null);

Insert into books (author,book_type_id,condition_id,cover_image_url,created_by,created_on,description,genre_id,is_available,is_bestseller,is_featured,is_new_arrival,is_user_listing,is_user_offer,isbn,last_restock_date,listing_status,name,offer_source_id,price,publish_date,publisher_id,quantity,seller_id,summary,updated_on,year)
values ('Richard Roe',1,1,'/images/coverimages/goldinthedark.png','system',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null,6, null,1,1,0, null, null,'5442280765', null, null,'Gold In The Dark', null,6.5, null,3,10, null, 'A mesmerizing fantasy adventure where a young prospector discovers a mysterious substance that glows only in complete darkness. As she unravels its origins, she becomes entangled in an ancient conflict between shadow dwellers and light bearers that could determine the fate of both their realms.',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null);

Insert into books (author,book_type_id,condition_id,cover_image_url,created_by,created_on,description,genre_id,is_available,is_bestseller,is_featured,is_new_arrival,is_user_listing,is_user_offer,isbn,last_restock_date,listing_status,name,offer_source_id,price,publish_date,publisher_id,quantity,seller_id,summary,updated_on,year)
values ('Pat Candella',2,3,'/images/coverimages/leaguesofsmoke.png','system',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null,4, null,0,0,0, null, null,'4556789542', null, null,'Leagues Of Smoke', null,3, null,4,1, null, 'An atmospheric novel set in a fog-shrouded coastal town where reality blurs with myth. When strange ships appear on the horizon, bringing with them an impenetrable mist, the townspeople must confront their darkest secrets and the ancient legends they''ve long dismissed as mere superstition.',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null);

Insert into books (author,book_type_id,condition_id,cover_image_url,created_by,created_on,description,genre_id,is_available,is_bestseller,is_featured,is_new_arrival,is_user_listing,is_user_offer,isbn,last_restock_date,listing_status,name,offer_source_id,price,publish_date,publisher_id,quantity,seller_id,summary,updated_on,year)
values ('Carlos Salazar',2,1,'/images/coverimages/alonewiththestars.png','system',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null,5, null,1,0,1, null, null,'4563358087', null, null,'Alone With The Stars', null,15.95, null,5,5, null, 'A gripping psychological thriller about an astronaut stranded on the International Space Station after a catastrophic event on Earth cuts off all communication. As isolation takes its toll, she begins receiving mysterious radio transmissions that challenge her perception of reality and her will to survive.',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null);

Insert into books (author,book_type_id,condition_id,cover_image_url,created_by,created_on,description,genre_id,is_available,is_bestseller,is_featured,is_new_arrival,is_user_listing,is_user_offer,isbn,last_restock_date,listing_status,name,offer_source_id,price,publish_date,publisher_id,quantity,seller_id,summary,updated_on,year)
values ('Terri Whitlock',1,2,'/images/coverimages/girlinthepolaroid.png','system',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null,5, null,0,1,1, null, null,'2354435678', null, null,'The Girl In The Polaroid', null,8.25, null,6,2, null, 'When a vintage Polaroid camera is discovered in an estate sale, the new owner becomes obsessed with a mysterious girl who appears in every photo taken, despite not being present when the pictures were snapped. This haunting mystery blends supernatural elements with a cold-case investigation that spans decades.',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null);

Insert into books (author,book_type_id,condition_id,cover_image_url,created_by,created_on,description,genre_id,is_available,is_bestseller,is_featured,is_new_arrival,is_user_listing,is_user_offer,isbn,last_restock_date,listing_status,name,offer_source_id,price,publish_date,publisher_id,quantity,seller_id,summary,updated_on,year)
values ('Mary Major',2,1,'/images/coverimages/1001jokes.png','system',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null,6, null,0,0,1, null, null,'6554789632', null, null,'1001 Jokes', null,13.95, null,7,7, null, 'A hilarious collection of jokes, puns, and witty one-liners for all occasions, curated by renowned comedian Mary Major. From clever wordplay to laugh-out-loud situational humor, this book promises to brighten any day and is perfect for breaking the ice or entertaining friends and family.',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null);

Insert into books (author,book_type_id,condition_id,cover_image_url,created_by,created_on,description,genre_id,is_available,is_bestseller,is_featured,is_new_arrival,is_user_listing,is_user_offer,isbn,last_restock_date,listing_status,name,offer_source_id,price,publish_date,publisher_id,quantity,seller_id,summary,updated_on,year)
values ('Mateo Jackson',3,3,'/images/coverimages/mysearchformeaning.png','system',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null,1, null,1,1,0, null, null,'4558786554', null, null,'My Search For Meaning', null,5, null,8,15, null, 'In this profound memoir, Mateo Jackson recounts his journey from tragedy to purpose after losing everything in a natural disaster. Through encounters with diverse philosophies and spiritual traditions, he crafts a deeply personal framework for finding significance in life''s most challenging moments. A moving testament to human resilience.',to_timestamp('24/03/25 11:32:29.372642000','DD/MM/RR HH24:MI:SSXFF'), null);
commit;

-- Sample customers (for development only)
-- Password is 'password' encrypted with BCrypt
REM INSERTING into CUSTOMERS
SET DEFINE OFF;


Insert into customers (account_expired,account_locked,created_on,credentials_expired,date_of_birth,email,email_verified,first_name,last_login,last_name,password_hash,phone_number,role,sub,username) 
values (0,0,to_timestamp('24/03/25 11:34:21.441957000','DD/MM/RR HH24:MI:SSXFF'),0,to_date('15/05/85','DD/MM/RR'),'john.doe@example.com',1,'John', null,'Doe','$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG','555-123-4567','USER','auth0|123456','johndoe');
Insert into customers (account_expired,account_locked,created_on,credentials_expired,date_of_birth,email,email_verified,first_name,last_login,last_name,password_hash,phone_number,role,sub,username) 
values (0,0,to_timestamp('24/03/25 11:34:21.481827000','DD/MM/RR HH24:MI:SSXFF'),0,to_date('20/10/90','DD/MM/RR'),'jane.doe@example.com',1,'Jane', null,'Doe','$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG','555-234-5678','USER','auth0|234567','janedoe');
Insert into customers (account_expired,account_locked,created_on,credentials_expired,date_of_birth,email,email_verified,first_name,last_login,last_name,password_hash,phone_number,role,sub,username) 
values (0,0,to_timestamp('24/03/25 11:34:21.528644000','DD/MM/RR HH24:MI:SSXFF'),0,to_date('01/01/80','DD/MM/RR'),'admin@bobsusedbooks.com',1,'Admin', null,'User','$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG','555-999-8888','ADMIN', null,'admin');


-- Sample addresses
Insert into addresses (address_line1,address_line2,address_type,city,country,customer_id,is_default,postal_code,state) 
values ('123 Main St','Apt 4B', null,'Seattle','USA',1,1,'98101','WA');
Insert into addresses (address_line1,address_line2,address_type,city,country,customer_id,is_default,postal_code,state) 
values ('456 Oak Ave', null, null,'Portland','USA',2,1,'97205','OR');

commit;


SET DEFINE OFF



-- Additional Data
-- Additional 10 genres for Bob's Used Books
INSERT INTO genres (name, description) 
VALUES ('Business & Economics', 'Books about business practices, economics, and finance');

INSERT INTO genres (name, description)
VALUES ('Self-Help', 'Books focused on personal development and improvement');

INSERT INTO genres (name, description)
VALUES ('Cookbooks & Food', 'Recipe collections and books about food and cooking');

INSERT INTO genres (name, description)
VALUES ('Art & Photography', 'Books about visual arts, design, and photography');

INSERT INTO genres (name, description)
VALUES ('Religion & Spirituality', 'Books exploring religious and spiritual topics');

INSERT INTO genres (name, description)
VALUES ('Science & Technology', 'Books about scientific discoveries and technological advancements');

INSERT INTO genres (name, description)
VALUES ('Health & Wellness', 'Books about physical and mental health');

INSERT INTO genres (name, description)
VALUES ('Poetry', 'Collections of poems and works about poetry');

INSERT INTO genres (name, description)
VALUES ('Comics & Graphic Novels', 'Illustrated stories and sequential art');

INSERT INTO genres (name, description)
VALUES ('Education & Reference', 'Textbooks, encyclopedias, and educational materials');

COMMIT;


-- Enhanced book data with summaries for Bob's Used Books
-- Format follows the pattern from the original data.sql with proper Oracle SQL syntax

-- First 10 books with summaries
INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Emma Roberts', 1, 2, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 1, null, 0, 0, 1, null, null, '9781234567890', null, null, 'The Journey Home', null, 12.99, null, 1, 5, null, 'A poignant memoir chronicling Emma Roberts'' path from small-town roots to self-discovery. Through vivid storytelling, she reflects on family relationships, personal challenges, and the unexpected moments that shaped her identity. Her honest narrative offers readers both comfort and inspiration for their own life journeys.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('James Patterson', 2, 1, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 5, null, 1, 0, 0, null, null, '9780316412674', null, null, 'The Midnight Detective', null, 9.99, null, 2, 8, null, 'When a series of bizarre murders rocks a quiet coastal town, Detective Sarah Winters must confront both a cunning killer and her own troubled past. Patterson''s signature fast-paced narrative delivers unexpected twists as Sarah races against time to prevent the next killing, uncovering a conspiracy that reaches the highest levels of local power.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Michelle Obama', 1, 1, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 1, null, 1, 1, 0, null, null, '9781524763138', null, null, 'Becoming', null, 18.50, null, 3, 12, null, 'In this intimate and powerful memoir, Michelle Obama invites readers into her world, chronicling the experiences that shaped her—from her childhood in Chicago to her years balancing motherhood and career to her time at the White House. With honesty and wit, she describes her triumphs and disappointments, both public and private.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Neil Gaiman', 1, 2, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 6, null, 0, 1, 0, null, null, '9780062255655', null, null, 'Shadows and Starlight', null, 11.25, null, 4, 3, null, 'In this enchanting fantasy, a young woman discovers a hidden door in her grandmother''s house that leads to a realm where stars take human form and shadows have their own consciousness. As she navigates this magical world, she uncovers secrets about her family''s connection to this realm and her own extraordinary destiny.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Agatha Christie', 3, 3, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 5, null, 0, 0, 0, null, null, '9780062073488', null, null, 'Murder at Thornfield Manor', null, 5.99, null, 5, 7, null, 'When the wealthy patriarch of Thornfield Manor is found dead in his locked study, everyone in the household becomes a suspect. Christie''s beloved detective Hercule Poirot must untangle a web of family secrets, hidden motives, and clever deceptions to reveal the killer in this classic whodunit that keeps readers guessing until the final page.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Yuval Noah Harari', 1, 1, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 3, null, 1, 0, 0, null, null, '9780062316097', null, null, 'Sapiens: A Brief History of Humankind', null, 14.99, null, 6, 9, null, 'This groundbreaking narrative explores how an insignificant ape rose to become the dominant species on Earth. Harari traces the evolution of Homo sapiens through major historical revolutions—cognitive, agricultural, and scientific—examining how our species has shaped and been shaped by our environment, beliefs, and social structures.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('J.K. Rowling', 1, 2, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 6, null, 1, 1, 0, null, null, '9780545790352', null, null, 'Harry Potter and the Philosopher''s Stone', null, 12.50, null, 7, 15, null, 'The first book in the beloved series follows an orphaned boy who discovers he''s a wizard on his eleventh birthday. Whisked away to Hogwarts School of Witchcraft and Wizardry, Harry Potter finds friendship, adventure, and danger as he uncovers the truth about his parents'' deaths and confronts the dark wizard responsible for his lightning-bolt scar.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Malcolm Gladwell', 2, 1, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 8, null, 0, 0, 1, null, null, '9780316204361', null, null, 'Outliers: The Story of Success', null, 10.99, null, 8, 6, null, 'Challenging conventional wisdom about success, Gladwell examines the factors that contribute to high achievement. Through compelling case studies—from Beatles and Bill Gates to cultural legacies and educational advantages—he demonstrates that success isn''t just about individual merit, but also about timing, opportunity, cultural background, and accumulated advantages.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Toni Morrison', 1, 2, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 4, null, 0, 1, 0, null, null, '9781400033416', null, null, 'Beloved', null, 8.75, null, 9, 4, null, 'Set after the American Civil War, this Pulitzer Prize-winning novel tells the story of Sethe, a former slave haunted by the trauma of her past and the ghost of her baby daughter. Morrison''s lyrical prose explores the psychological effects of slavery, the power of community, and the complexity of maternal love in the face of impossible choices.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Stephen King', 1, 1, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 5, null, 1, 0, 0, null, null, '9781501156700', null, null, 'The Shining', null, 13.99, null, 10, 11, null, 'When Jack Torrance becomes winter caretaker at the isolated Overlook Hotel, he sees it as an opportunity to reconnect with his family and work on his writing. But as snowbound isolation sets in, the hotel''s sinister influence awakens Jack''s demons while his psychically gifted son Danny perceives terrifying premonitions from both the hotel''s past and future.', CURRENT_TIMESTAMP, null);
-- Next 10 books with summaries
INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Chimamanda Ngozi Adichie', 2, 2, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 4, null, 0, 0, 1, null, null, '9780307455925', null, null, 'Americanah', null, 9.50, null, 1, 7, null, 'This powerful novel follows Ifemelu and Obinze, young lovers who depart military-ruled Nigeria for the West. Ifemelu heads to America, where she encounters racism and discovers what it means to be Black in the U.S., while Obinze plunges into a dangerous undocumented life in London. Years later, they reunite in a newly democratic Nigeria.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Haruki Murakami', 1, 3, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 4, null, 0, 1, 0, null, null, '9780307476463', null, null, 'Norwegian Wood', null, 11.25, null, 2, 5, null, 'Set in Tokyo during the late 1960s, this nostalgic story follows Toru Watanabe, who is devoted to the beautiful but emotionally troubled Naoko. Their relationship is marked by the tragic suicide of their best friend years before. As Naoko retreats into herself, Toru is drawn to the outgoing, lively Midori, forcing him to choose between his past and his future.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Brené Brown', 2, 1, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 8, null, 1, 0, 0, null, null, '9781592408412', null, null, 'Daring Greatly', null, 10.99, null, 3, 8, null, 'Based on twelve years of research, this transformative book challenges everything we think we know about vulnerability. Brown argues that vulnerability isn''t weakness but our clearest path to courage and meaningful connection. Through engaging storytelling and research, she explores how embracing our imperfections can transform the way we live, love, parent, and lead.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('George R.R. Martin', 1, 2, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 6, null, 1, 1, 0, null, null, '9780553593716', null, null, 'A Game of Thrones', null, 15.99, null, 4, 9, null, 'In this epic fantasy series opener, noble families fight for control of the Seven Kingdoms of Westeros. Political and sexual intrigue abound as the Stark, Lannister, and Targaryen families navigate a landscape where seasons last for years and an ancient evil awakens beyond the great Wall in the frozen north. Loyalty, honor, and betrayal drive this complex tale.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Gillian Flynn', 3, 1, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 5, null, 0, 0, 1, null, null, '9780307588371', null, null, 'Gone Girl', null, 7.99, null, 5, 12, null, 'When beautiful Amy Dunne disappears on her fifth wedding anniversary, her husband Nick becomes the prime suspect. Through alternating perspectives and unreliable narrators, this psychological thriller explores the tensions of a marriage gone terribly wrong. As the investigation unfolds, shocking revelations force readers to question everything they thought they knew.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Ta-Nehisi Coates', 2, 2, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 1, null, 0, 1, 0, null, null, '9780812993547', null, null, 'Between the World and Me', null, 11.50, null, 6, 6, null, 'Written as a letter to his teenage son, Coates confronts the painful reality of what it means to be Black in America. Through personal narrative and historical context, he explores how American society has built and sustained racial oppression, offering a powerful framework for understanding our nation''s history and present crisis around race and identity.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Donna Tartt', 1, 1, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 4, null, 1, 0, 0, null, null, '9780316055437', null, null, 'The Goldfinch', null, 13.75, null, 7, 4, null, 'After surviving an accident that kills his mother, thirteen-year-old Theo Decker is taken in by a wealthy family. Adrift in his new life and haunted by grief, he clings to a small painting that reminds him of his mother. This Pulitzer Prize-winning novel follows Theo''s journey through loss, friendship, love, and redemption across decades and continents.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Colson Whitehead', 2, 3, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 4, null, 0, 0, 1, null, null, '9780385542364', null, null, 'The Underground Railroad', null, 9.99, null, 8, 7, null, 'In this Pulitzer Prize-winning novel, Whitehead reimagines the Underground Railroad as an actual subterranean train system helping enslaved people escape to freedom. Following the harrowing journey of Cora from a Georgia plantation through different states—each representing a different facet of American racism—the book offers a powerful meditation on history and human resilience.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Madeline Miller', 1, 2, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 6, null, 0, 1, 0, null, null, '9780062060624', null, null, 'Circe', null, 10.50, null, 9, 8, null, 'This feminist retelling of Greek mythology follows Circe, daughter of the sun god Helios, who discovers her power of witchcraft after being banished to a remote island. Over centuries of solitude, she encounters famous mythological figures and must choose between the gods who rejected her and the mortals she''s come to love, ultimately finding her own place in the world.', CURRENT_TIMESTAMP, null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Andy Weir', 1, 1, '/images/coverimages/default.png', 'system', CURRENT_TIMESTAMP, null, 6, null, 1, 0, 0, null, null, '9780553418026', null, null, 'The Martian', null, 12.25, null, 10, 10, null, 'When a dust storm forces his crew to evacuate Mars, astronaut Mark Watney is accidentally left behind, presumed dead. With limited supplies and no way to contact Earth, he must use his ingenuity and scientific knowledge to survive the hostile planet. This gripping tale of survival combines technical accuracy with humor as Watney fights to stay alive until rescue is possible.', CURRENT_TIMESTAMP, null);

-- Additional 10 books with summaries (Batch 3)

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Celeste Ng', 2, 2, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 4, null, 0, 1, 0, null, null, '9780735224292', null, null, 'Little Fires Everywhere', null, 11.99, null, 1, 6, null, 'In the meticulously planned community of Shaker Heights, the Richardson family''s orderly life is upended when enigmatic artist Mia Warren and her daughter Pearl rent a house nearby. As the families become intertwined, a custody battle over an adopted Chinese-American baby divides the town and forces everyone to examine their beliefs about motherhood, identity, and belonging.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Erik Larson', 1, 1, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 3, null, 0, 0, 1, null, null, '9780307408846', null, null, 'The Devil in the White City', null, 14.50, null, 2, 5, null, 'This gripping non-fiction narrative intertwines two remarkable stories set against the backdrop of the 1893 Chicago World''s Fair: the brilliant architect Daniel Burnham who built the "White City," and H.H. Holmes, a serial killer who used the fair to lure victims to his "Murder Castle." Larson masterfully blends beauty and horror in this meticulously researched historical account.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Kristin Hannah', 1, 3, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 4, null, 1, 0, 0, null, null, '9780312577223', null, null, 'The Nightingale', null, 9.99, null, 3, 8, null, 'Set in France during World War II, this powerful novel follows two sisters—one rebellious, one traditional—as they each embark on dangerous paths to survival under Nazi occupation. Vianne must protect her daughter when a German officer requisitions her home, while Isabelle joins the Resistance, risking her life to save others. A heart-wrenching exploration of courage, resilience, and sisterhood.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Amor Towles', 2, 2, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 4, null, 0, 1, 0, null, null, '9780670026197', null, null, 'A Gentleman in Moscow', null, 12.75, null, 4, 4, null, 'In 1922, Count Alexander Rostov is sentenced by a Bolshevik tribunal to house arrest in Moscow''s grand Metropol Hotel. As decades pass outside his door, the Count crafts a new life of purpose within his confined circumstances, forming unexpected friendships and discovering the true meaning of home. Towles'' elegant prose creates a captivating world within the hotel''s walls.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Anthony Doerr', 1, 1, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 4, null, 1, 0, 0, null, null, '9781501173219', null, null, 'All the Light We Cannot See', null, 13.50, null, 5, 7, null, 'This Pulitzer Prize-winning novel follows a blind French girl and a German boy whose paths collide in occupied France during World War II. Marie-Laure takes refuge with her great-uncle in Saint-Malo, carrying a dangerous secret, while Werner, a radio expert, tracks the resistance. Their stories converge in a meditation on the power of human connection amid darkness.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Delia Owens', 2, 2, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 4, null, 1, 1, 0, null, null, '9780735219090', null, null, 'Where the Crawdads Sing', null, 11.25, null, 6, 9, null, 'For years, rumors of the "Marsh Girl" haunted the quiet fishing village of Barkley Cove. Kya Clark, abandoned by her family, raised herself in the marshlands, becoming both naturalist and outcast. When the town''s golden boy is found dead, suspicion falls on Kya. This coming-of-age story explores loneliness, survival, and the deep human need for connection.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Trevor Noah', 1, 1, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 1, null, 0, 0, 1, null, null, '9780399588174', null, null, 'Born a Crime', null, 10.99, null, 7, 6, null, 'In this compelling memoir, comedian Trevor Noah recounts his childhood in South Africa during the twilight of apartheid. Born to a Black mother and white father when such relationships were punishable by imprisonment, Noah''s very existence was evidence of his parents'' crime. With wit and insight, he shares stories of poverty, abuse, and ultimately triumph through his mother''s unconditional love.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Tara Westover', 2, 3, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 1, null, 1, 0, 0, null, null, '9780399590504', null, null, 'Educated', null, 12.50, null, 8, 5, null, 'Born to survivalist parents in the mountains of Idaho, Tara Westover was seventeen before she ever set foot in a classroom. Her quest for knowledge took her from self-education to Harvard and Cambridge. This extraordinary memoir explores the transformative power of education and the price of severing family ties to become your authentic self.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Min Jin Lee', 1, 2, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 4, null, 0, 1, 0, null, null, '9781455563920', null, null, 'Pachinko', null, 13.99, null, 9, 4, null, 'This sweeping saga follows four generations of a Korean family who move to Japan in the early 20th century. Beginning with Sunja, a pregnant teenager who refuses to be bought, the novel chronicles the family''s struggles with identity and belonging as ethnic Koreans in Japan. Through war, peace, and cultural upheaval, they persevere against discrimination and historical forces beyond their control.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);


-- Additional 10 books with summaries (Batch 4)

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Brit Bennett', 2, 1, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 4, null, 0, 0, 1, null, null, '9780525536291', null, null, 'The Vanishing Half', null, 11.75, null, 10, 7, null, 'The Vignes twin sisters run away from their small, southern Black community at sixteen. Years later, one sister lives with her Black daughter in the same town she tried to escape, while the other secretly passes for white. This stunning novel explores the lasting influence of the past as it shapes decisions, desires, and expectations across generations, examining the American history of passing and racial identity.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Lisa Wingate', 1, 2, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 4, null, 1, 0, 0, null, null, '9780425284681', null, null, 'Before We Were Yours', null, 9.99, null, 1, 8, null, 'Based on a notorious real-life scandal, this novel follows Rill Foss, who at twelve years old must protect her four siblings when they''re taken from their family''s Mississippi River shantyboat to a Tennessee Children''s Home Society orphanage. Decades later, a privileged young woman uncovers the shocking truth about her family''s past, revealing the heartbreaking injustices that changed so many lives.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Yaa Gyasi', 2, 1, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 4, null, 0, 1, 0, null, null, '9781101947135', null, null, 'Homegoing', null, 10.50, null, 2, 5, null, 'This remarkable debut novel follows the parallel paths of two half-sisters born in eighteenth-century Ghana and their descendants. One sister marries a British slaver, while the other is sold into slavery. Through eight generations and 300 years of history, Gyasi explores how the legacy of slavery affects each new generation, from the Gold Coast of Africa to the plantations of Mississippi to modern-day Harlem.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Fredrik Backman', 1, 3, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 4, null, 0, 0, 1, null, null, '9781476738024', null, null, 'A Man Called Ove', null, 8.99, null, 3, 6, null, 'Meet Ove, a curmudgeon with staunch principles, strict routines, and a short fuse who finds his solitary world turned upside down when a boisterous young family moves in next door. Behind his cranky exterior lies a story of true love and profound grief. This heartwarming tale shows how unexpected friendships can change one''s life and reveals the impact we have on those around us.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Jeanine Cummins', 2, 2, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 4, null, 1, 0, 0, null, null, '9781250209764', null, null, 'American Dirt', null, 12.25, null, 4, 7, null, 'Lydia Quixano Pérez lives a comfortable life in Acapulco with her journalist husband and son, until he publishes an exposé on a powerful drug cartel leader. After violence claims her entire family, Lydia and her son flee north toward the United States. This gripping story illuminates the experience of migrants forced to leave their homes in search of safety and a better life.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Erin Morgenstern', 1, 1, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 6, null, 0, 1, 0, null, null, '9780385534635', null, null, 'The Night Circus', null, 13.50, null, 5, 4, null, 'The circus arrives without warning, appearing at night and open only from sunset to sunrise. Within its black-and-white striped tents lies an utterly unique experience, a feast for the senses. But behind the scenes, two young magicians, Celia and Marco, compete in a dangerous game orchestrated by their instructors, unaware that only one can survive as they fall deeply in love.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Silvia Moreno-Garcia', 2, 2, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 6, null, 0, 0, 1, null, null, '9780525620785', null, null, 'Mexican Gothic', null, 10.99, null, 6, 5, null, 'When socialite Noemí receives a frantic letter from her newly-wed cousin begging to be rescued from a mysterious doom, she heads to High Place, a distant house in the Mexican countryside. There she finds a decaying mansion, a strange family, and a house that begins to invade her dreams with visions of blood and doom. This atmospheric horror novel blends elements of gothic fiction with Mexican folklore.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('V.E. Schwab', 1, 1, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 6, null, 1, 0, 0, null, null, '9780765387561', null, null, 'A Darker Shade of Magic', null, 11.25, null, 7, 8, null, 'Kell is one of the last Antari—magicians with the rare ability to travel between parallel Londons: Red, Grey, White, and once upon a time, Black. After an exchange goes awry, Kell escapes to Grey London and encounters Delilah Bard, a cut-purse with lofty aspirations. Now perilous magic is afoot, and treachery lurks at every turn as the two must work together to save all worlds.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('N.K. Jemisin', 2, 3, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 6, null, 0, 1, 0, null, null, '9780316229296', null, null, 'The Fifth Season', null, 12.99, null, 8, 6, null, 'In a world where catastrophic climate events threaten civilization, people with the ability to control energy—orogenes—are both feared and exploited. When Essun discovers her husband has murdered their son and kidnapped their daughter upon learning they are orogenes, she sets out on a mission of rescue and revenge across a continent literally tearing itself apart. The first book in Jemisin''s revolutionary trilogy.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

-- Additional 10 books with summaries (Batch 5)

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Blake Crouch', 1, 2, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 6, null, 0, 0, 1, null, null, '9781101904220', null, null, 'Dark Matter', null, 9.75, null, 9, 7, null, 'Jason Dessen, a physics professor, is knocked unconscious and awakens to find himself in a world where his life took a dramatically different path. In this alternate reality, he never married his wife and never had his son, but instead achieved professional success beyond his wildest dreams. This mind-bending thriller explores questions of identity, choice, and the road not taken.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Martha Wells', 2, 1, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 6, null, 1, 0, 0, null, null, '9781250229861', null, null, 'All Systems Red', null, 8.99, null, 10, 9, null, 'In this Hugo Award-winning novella, a self-aware security android who has hacked its own governor module and nicknamed itself "Murderbot" just wants to be left alone to watch entertainment feeds. When a neighboring mission goes dark, Murderbot must overcome its antisocial tendencies to protect the humans it''s assigned to protect, even though it doesn''t particularly like them.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Bill Bryson', 1, 2, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 7, null, 0, 1, 0, null, null, '9780767908184', null, null, 'A Walk in the Woods', null, 11.50, null, 1, 5, null, 'After spending twenty years in England, Bill Bryson returns to America and decides to reacquaint himself with his native country by hiking the 2,100-mile Appalachian Trail. Accompanied by his friend Stephen Katz, Bryson confronts nature at its most uncompromising. With his trademark humor, he chronicles their misadventures while offering fascinating insights into the trail''s history, ecology, and the characters they meet along the way.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Elizabeth Gilbert', 2, 1, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 7, null, 0, 0, 1, null, null, '9780143038412', null, null, 'Eat, Pray, Love', null, 9.99, null, 2, 6, null, 'After a painful divorce and personal crisis, Elizabeth Gilbert embarks on a year-long journey of self-discovery. She spends four months in Italy savoring food and language, four months in India exploring spirituality at an ashram, and four months in Bali seeking balance and unexpected love. This intimate memoir chronicles her quest to find pleasure, devotion, and equilibrium in her life.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Paul Theroux', 1, 3, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 7, null, 1, 0, 0, null, null, '9780618658978', null, null, 'The Great Railway Bazaar', null, 10.75, null, 3, 4, null, 'In this classic travel narrative, Theroux recounts his epic journey by rail through Asia. Beginning in London, he travels through Europe, the Middle East, India, and Southeast Asia, circling back through the Soviet Union. With keen observation and wit, he captures the essence of train travel and the diverse landscapes, cultures, and characters he encounters, creating an unforgettable portrait of a continent in transition.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Cheryl Strayed', 2, 2, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 7, null, 0, 1, 0, null, null, '9780307476074', null, null, 'Wild', null, 12.25, null, 4, 7, null, 'At twenty-two, Cheryl Strayed thought she had lost everything. After her mother''s death, her family scattered and her marriage crumbled. With nothing to lose, she made the impulsive decision to hike the Pacific Crest Trail from the Mojave Desert to Washington State—alone, with no experience. This powerful memoir chronicles her physical and psychological journey toward healing and self-discovery.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Jon Krakauer', 1, 1, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 7, null, 0, 0, 1, null, null, '9780385494786', null, null, 'Into the Wild', null, 11.99, null, 5, 5, null, 'In April 1992, Christopher McCandless hitchhiked to Alaska and walked alone into the wilderness. Four months later, his decomposed body was found by a moose hunter. This compelling narrative explores what drove this young man to abandon his possessions, give away his savings, and seek radical freedom in the wilderness, ultimately leading to his tragic death in an abandoned bus in the Alaskan interior.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Frances Mayes', 2, 2, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 7, null, 1, 0, 0, null, null, '9780767900386', null, null, 'Under the Tuscan Sun', null, 9.50, null, 6, 6, null, 'When American professor Frances Mayes buys and restores an abandoned villa in the Tuscan countryside, she begins a life-changing journey. Through evocative descriptions of the landscape, food, and local characters, she captures the essence of Tuscany while reflecting on the pleasures of building a new life in a foreign land. Part travel memoir, part renovation story, and part celebration of Italian culture.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

INSERT INTO books (author, book_type_id, condition_id, cover_image_url, created_by, created_on, description, genre_id, is_available, is_bestseller, is_featured, is_new_arrival, is_user_listing, is_user_offer, isbn, last_restock_date, listing_status, name, offer_source_id, price, publish_date, publisher_id, quantity, seller_id, summary, updated_on, year)
VALUES ('Eric Carle', 3, 1, '/images/coverimages/default.png', 'system', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null, 2, null, 0, 1, 0, null, null, '9780399226908', null, null, 'The Very Hungry Caterpillar', null, 7.99, null, 7, 12, null, 'This beloved children''s classic follows a caterpillar as it eats its way through an increasing amount of food before pupating and emerging as a beautiful butterfly. With its distinctive collage illustrations and die-cut pages, this simple tale teaches children about numbers, days of the week, foods, and the life cycle of a butterfly in an engaging, accessible way.', to_timestamp('24/03/25 11:32:29.372642000', 'DD/MM/RR HH24:MI:SSXFF'), null);

COMMIT;

