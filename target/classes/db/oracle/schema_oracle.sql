  CREATE TABLE BOOK_TYPES 
   (	ID NUMBER(19,0) GENERATED ALWAYS AS IDENTITY MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER  NOCYCLE  NOKEEP  NOSCALE  NOT NULL ENABLE, 
	CREATED_ON TIMESTAMP (6), 
	DESCRIPTION VARCHAR2(255 CHAR), 
	NAME VARCHAR2(255 CHAR) NOT NULL ENABLE, 
	UPDATED_ON TIMESTAMP (6), 
	 PRIMARY KEY (ID)
  USING INDEX  ENABLE
   ) ;

  CREATE TABLE CONDITIONS 
   (	ID NUMBER(19,0) GENERATED ALWAYS AS IDENTITY MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER  NOCYCLE  NOKEEP  NOSCALE  NOT NULL ENABLE, 
	CREATED_ON TIMESTAMP (6), 
	DESCRIPTION VARCHAR2(255 CHAR), 
	NAME VARCHAR2(255 CHAR) NOT NULL ENABLE, 
	UPDATED_ON TIMESTAMP (6), 
	 PRIMARY KEY (ID)
  USING INDEX  ENABLE
   ) ;


  CREATE TABLE GENRES 
   (	ID NUMBER(19,0) GENERATED ALWAYS AS IDENTITY MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER  NOCYCLE  NOKEEP  NOSCALE  NOT NULL ENABLE, 
	CREATED_ON TIMESTAMP (6), 
	DESCRIPTION VARCHAR2(255 CHAR), 
	NAME VARCHAR2(255 CHAR) NOT NULL ENABLE, 
	UPDATED_ON TIMESTAMP (6), 
	 PRIMARY KEY (ID)
  USING INDEX  ENABLE
   ) ;

  CREATE TABLE PUBLISHERS 
   (	ID NUMBER(19,0) GENERATED ALWAYS AS IDENTITY MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER  NOCYCLE  NOKEEP  NOSCALE  NOT NULL ENABLE, 
	CREATED_ON TIMESTAMP (6), 
	DESCRIPTION VARCHAR2(255 CHAR), 
	NAME VARCHAR2(255 CHAR) NOT NULL ENABLE, 
	UPDATED_ON TIMESTAMP (6), 
	WEBSITE VARCHAR2(255 CHAR), 
	 PRIMARY KEY (ID)
  USING INDEX  ENABLE
   ) ;



  CREATE TABLE BOOKS 
   (	ID NUMBER(19,0) GENERATED ALWAYS AS IDENTITY MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER  NOCYCLE  NOKEEP  NOSCALE  NOT NULL ENABLE, 
	AUTHOR VARCHAR2(255 CHAR), 
	BOOK_TYPE_ID NUMBER(19,0), 
	CONDITION_ID NUMBER(19,0), 
	COVER_IMAGE_URL VARCHAR2(255 CHAR), 
	CREATED_BY VARCHAR2(255 CHAR), 
	CREATED_ON TIMESTAMP (6), 
	DESCRIPTION VARCHAR2(255 CHAR), 
	GENRE_ID NUMBER(19,0), 
	IS_AVAILABLE NUMBER(1,0), 
	IS_BESTSELLER NUMBER(1,0), 
	IS_FEATURED NUMBER(1,0), 
	IS_NEW_ARRIVAL NUMBER(1,0), 
	IS_USER_LISTING NUMBER(1,0), 
	IS_USER_OFFER NUMBER(1,0), 
	ISBN VARCHAR2(255 CHAR), 
	LAST_RESTOCK_DATE DATE, 
	LISTING_STATUS NUMBER(10,0), 
	NAME VARCHAR2(255 CHAR), 
	OFFER_SOURCE_ID NUMBER(19,0), 
	PRICE NUMBER(38,2), 
	PUBLISH_DATE DATE, 
	PUBLISHER_ID NUMBER(19,0), 
	QUANTITY NUMBER(10,0), 
	SELLER_ID NUMBER(19,0), 
	SUMMARY VARCHAR2(1000 CHAR), 
	UPDATED_ON TIMESTAMP (6), 
	YEAR NUMBER(10,0), 
	SEARCH_TEXT VARCHAR2(1000), 
	 CHECK (is_available in (0,1)) ENABLE, 
	 CHECK (is_bestseller in (0,1)) ENABLE, 
	 CHECK (is_featured in (0,1)) ENABLE, 
	 CHECK (is_new_arrival in (0,1)) ENABLE, 
	 CHECK (is_user_listing in (0,1)) ENABLE, 
	 CHECK (is_user_offer in (0,1)) ENABLE, 
	 PRIMARY KEY (ID)
  USING INDEX  ENABLE, 
	 CONSTRAINT FK_BOOKS_BOOK_TYPE FOREIGN KEY (BOOK_TYPE_ID)
	  REFERENCES BOOK_TYPES (ID) ENABLE, 
	 CONSTRAINT FK_BOOKS_CONDITION FOREIGN KEY (CONDITION_ID)
	  REFERENCES CONDITIONS (ID) ENABLE, 
	 CONSTRAINT FK_BOOKS_GENRE FOREIGN KEY (GENRE_ID)
	  REFERENCES GENRES (ID) ENABLE, 
	 CONSTRAINT FK_BOOKS_PUBLISHER FOREIGN KEY (PUBLISHER_ID)
	  REFERENCES PUBLISHERS (ID) ENABLE
   ) ;

  CREATE TABLE AUTHORS 
   (	ID NUMBER(19,0) GENERATED ALWAYS AS IDENTITY MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER  NOCYCLE  NOKEEP  NOSCALE  NOT NULL ENABLE, 
	CREATED_BY VARCHAR2(255 CHAR), 
	CREATED_ON TIMESTAMP (6), 
	UPDATED_ON TIMESTAMP (6), 
	BIOGRAPHY VARCHAR2(255 CHAR), 
	BIRTH_DATE DATE, 
	IMAGE_URL VARCHAR2(255 CHAR), 
	NAME VARCHAR2(255 CHAR), 
	 PRIMARY KEY (ID)
  USING INDEX  ENABLE
   ) ;


  CREATE TABLE CUSTOMERS 
   (	ID NUMBER(19,0) GENERATED ALWAYS AS IDENTITY MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER  NOCYCLE  NOKEEP  NOSCALE  NOT NULL ENABLE, 
	ACCOUNT_EXPIRED NUMBER(1,0), 
	ACCOUNT_LOCKED NUMBER(1,0), 
	CREATED_ON TIMESTAMP (6), 
	CREDENTIALS_EXPIRED NUMBER(1,0), 
	DATE_OF_BIRTH DATE, 
	EMAIL VARCHAR2(255 CHAR), 
	EMAIL_VERIFIED NUMBER(1,0), 
	FIRST_NAME VARCHAR2(255 CHAR), 
	LAST_LOGIN TIMESTAMP (6), 
	LAST_NAME VARCHAR2(255 CHAR), 
	PASSWORD_HASH VARCHAR2(255 CHAR), 
	PHONE_NUMBER VARCHAR2(255 CHAR), 
	ROLE VARCHAR2(255 CHAR), 
	SUB VARCHAR2(255 CHAR), 
	USERNAME VARCHAR2(255 CHAR), 
	 CHECK (account_expired in (0,1)) ENABLE, 
	 CHECK (account_locked in (0,1)) ENABLE, 
	 CHECK (credentials_expired in (0,1)) ENABLE, 
	 CHECK (email_verified in (0,1)) ENABLE, 
	 PRIMARY KEY (ID) USING INDEX  ENABLE
) ;

CREATE TABLE ADDRESSES 
   (	ID NUMBER(19,0) GENERATED ALWAYS AS IDENTITY MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER  NOCYCLE  NOKEEP  NOSCALE  NOT NULL ENABLE, 
	ADDRESS_LINE1 VARCHAR2(255 CHAR), 
	ADDRESS_LINE2 VARCHAR2(255 CHAR), 
	ADDRESS_TYPE VARCHAR2(255 CHAR), 
	CITY VARCHAR2(255 CHAR), 
	COUNTRY VARCHAR2(255 CHAR), 
	CUSTOMER_ID NUMBER(19,0), 
	IS_DEFAULT NUMBER(1,0), 
	POSTAL_CODE VARCHAR2(255 CHAR), 
	STATE VARCHAR2(255 CHAR), 
	 CHECK (is_default in (0,1)) ENABLE, 
	 PRIMARY KEY (ID)
  USING INDEX  ENABLE, 
	 CONSTRAINT FK_ADDRESSES_CUSTOMER FOREIGN KEY (CUSTOMER_ID)
	  REFERENCES CUSTOMERS (ID) ENABLE
   ) ;


  CREATE TABLE OFFERS 
   (	ID NUMBER(19,0) GENERATED ALWAYS AS IDENTITY MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER  NOCYCLE  NOKEEP  NOSCALE  NOT NULL ENABLE, 
	ADMIN_NOTES VARCHAR2(1000 CHAR), 
	OFFERED_PRICE NUMBER(38,2), 
	BOOK_AUTHOR VARCHAR2(255 CHAR), 
	BOOK_COMMENT VARCHAR2(1000 CHAR), 
	BOOK_ID NUMBER(19,0), 
	BOOK_PRICE NUMBER(38,2), 
	BOOK_TITLE VARCHAR2(255 CHAR) NOT NULL ENABLE, 
	BOOK_TYPE_ID NUMBER(19,0), 
	CONDITION_ID NUMBER(19,0), 
	CONTACT_EMAIL VARCHAR2(255 CHAR), 
	CONTACT_NAME VARCHAR2(255 CHAR), 
	CONTACT_PHONE VARCHAR2(255 CHAR), 
	CREATED_ON TIMESTAMP (6), 
	CUSTOMER_ID NUMBER(19,0), 
	DESCRIPTION VARCHAR2(1000 CHAR), 
	FRONT_URL VARCHAR2(255 CHAR), 
	GENRE_ID NUMBER(19,0), 
	IS_APPROVED NUMBER(1,0), 
	IS_REJECTED NUMBER(1,0), 
	ISBN VARCHAR2(255 CHAR), 
	OFFER_STATUS NUMBER(10,0), 
	PROCESSED_AT TIMESTAMP (6), 
	PROCESSED_BY NUMBER(19,0), 
	PUBLISHER_ID NUMBER(19,0), 
	REJECTION_REASON VARCHAR2(1000 CHAR), 
	STATUS NUMBER(10,0) NOT NULL ENABLE, 
	SUMMARY VARCHAR2(1000 CHAR), 
	UPDATED_ON TIMESTAMP (6), 
	 CHECK (is_approved in (0,1)) ENABLE, 
	 CHECK (is_rejected in (0,1)) ENABLE, 
	 PRIMARY KEY (ID)
  USING INDEX  ENABLE, 
	 CONSTRAINT FK_OFFERS_BOOK FOREIGN KEY (BOOK_ID)
	  REFERENCES BOOKS (ID) ENABLE, 
	 CONSTRAINT FK_OFFERS_CONDITION FOREIGN KEY (CONDITION_ID)
	  REFERENCES CONDITIONS (ID) ENABLE, 
	 CONSTRAINT FK_OFFERS_CUSTOMER FOREIGN KEY (CUSTOMER_ID)
	  REFERENCES CUSTOMERS (ID) ENABLE
   ) ;


  CREATE TABLE ORDERS 
   (	ID NUMBER(19,0) GENERATED ALWAYS AS IDENTITY MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER  NOCYCLE  NOKEEP  NOSCALE  NOT NULL ENABLE, 
	ADDRESS_ID NUMBER(19,0), 
	CANCELLATION_REASON VARCHAR2(255 CHAR), 
	CANCELLED_DATE DATE, 
	CREATED_ON TIMESTAMP (6) NOT NULL ENABLE, 
	CUSTOMER_ID NUMBER(19,0), 
	DELIVERED_DATE DATE, 
	DELIVERY_DATE DATE, 
	NOTES VARCHAR2(255 CHAR), 
	ORDER_DATE DATE, 
	ORDER_STATUS NUMBER(10,0) NOT NULL ENABLE, 
	SHIPPED_DATE DATE, 
	SHIPPING_ADDRESS VARCHAR2(255 CHAR), 
	STATUS VARCHAR2(255 CHAR), 
	TOTAL_AMOUNT NUMBER(38,2), 
	TRACKING_NUMBER VARCHAR2(255 CHAR), 
	 PRIMARY KEY (ID)
  USING INDEX  ENABLE
   ) ;


  CREATE TABLE ORDER_ITEMS 
   (	ID NUMBER(19,0) GENERATED ALWAYS AS IDENTITY MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER  NOCYCLE  NOKEEP  NOSCALE  NOT NULL ENABLE, 
	BOOK_ID NUMBER(19,0), 
	BOOK_PRICE NUMBER(38,2) NOT NULL ENABLE, 
	DISCOUNT NUMBER(38,2), 
	ORDER_ID NUMBER(19,0), 
	PRICE NUMBER(38,2), 
	QUANTITY NUMBER(10,0), 
	 PRIMARY KEY (ID)
  USING INDEX  ENABLE, 
	 CONSTRAINT FK_ORDER_ITEMS_BOOK FOREIGN KEY (BOOK_ID)
	  REFERENCES BOOKS (ID) ENABLE, 
	 CONSTRAINT FK_ORDER_ITEMS_ORDER FOREIGN KEY (ORDER_ID)
	  REFERENCES ORDERS (ID) ENABLE
   ) ;


  CREATE TABLE PASSWORD_RESET_TOKENS 
   (	ID NUMBER(19,0) GENERATED ALWAYS AS IDENTITY MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER  NOCYCLE  NOKEEP  NOSCALE  NOT NULL ENABLE, 
	EXPIRY_DATE TIMESTAMP (6), 
	TOKEN VARCHAR2(255 CHAR), 
	USED NUMBER(1,0), 
	CUSTOMER_ID NUMBER(19,0), 
	 CHECK (used in (0,1)) ENABLE, 
	 PRIMARY KEY (ID)
  USING INDEX  ENABLE, 
	 CONSTRAINT FK_PASSWORD_RESET_CUSTOMER FOREIGN KEY (CUSTOMER_ID)
	  REFERENCES CUSTOMERS (ID) ENABLE
   ) ;

  CREATE TABLE PERSISTENT_LOGINS 
   (USERNAME VARCHAR2(64) NOT NULL ENABLE, 
	SERIES VARCHAR2(64), 
	TOKEN VARCHAR2(64) NOT NULL ENABLE, 
	LAST_USED TIMESTAMP (6) NOT NULL ENABLE, 
	 PRIMARY KEY (SERIES)
  USING INDEX  ENABLE
   ) ;



  CREATE TABLE REFERENCE_DATA 
   (ID NUMBER(19,0) GENERATED ALWAYS AS IDENTITY MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER  NOCYCLE  NOKEEP  NOSCALE  NOT NULL ENABLE, 
	CREATED_BY VARCHAR2(255 CHAR), 
	CREATED_ON TIMESTAMP (6), 
	UPDATED_ON TIMESTAMP (6), 
	DESCRIPTION VARCHAR2(255 CHAR), 
	IS_ACTIVE NUMBER(1,0) NOT NULL ENABLE, 
	NAME VARCHAR2(255 CHAR), 
	TYPE VARCHAR2(255 CHAR), 
	 CHECK (is_active in (0,1)) ENABLE, 
	 CHECK (type in ('PUBLISHER','BOOK_TYPE','GENRE','CONDITION')) ENABLE, 
	 PRIMARY KEY (ID)
  USING INDEX  ENABLE
   ) ;



  CREATE TABLE SHOPPING_CART_ITEMS 
   (	ID NUMBER(19,0) GENERATED ALWAYS AS IDENTITY MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER  NOCYCLE  NOKEEP  NOSCALE  NOT NULL ENABLE, 
	BOOK_ID NUMBER(19,0), 
	CUSTOMER_ID NUMBER(19,0), 
	IS_WISHLIST_ITEM NUMBER(1,0), 
	QUANTITY NUMBER(10,0), 
	 CHECK (is_wishlist_item in (0,1)) ENABLE, 
	 PRIMARY KEY (ID)
  USING INDEX  ENABLE, 
	 CONSTRAINT FK_CART_ITEMS_BOOK FOREIGN KEY (BOOK_ID)
	  REFERENCES BOOKS (ID) ENABLE
   ) ;


-- Indexes for BOOKS table foreign keys
CREATE INDEX IDX_BOOKS_BOOK_TYPE_ID ON BOOKS(BOOK_TYPE_ID);
CREATE INDEX IDX_BOOKS_CONDITION_ID ON BOOKS(CONDITION_ID);
CREATE INDEX IDX_BOOKS_GENRE_ID ON BOOKS(GENRE_ID);
CREATE INDEX IDX_BOOKS_PUBLISHER_ID ON BOOKS(PUBLISHER_ID);

-- Index for ADDRESSES table foreign key
CREATE INDEX IDX_ADDRESSES_CUSTOMER_ID ON ADDRESSES(CUSTOMER_ID);

-- Indexes for OFFERS table foreign keys
CREATE INDEX IDX_OFFERS_BOOK_ID ON OFFERS(BOOK_ID);
CREATE INDEX IDX_OFFERS_CONDITION_ID ON OFFERS(CONDITION_ID);
CREATE INDEX IDX_OFFERS_CUSTOMER_ID ON OFFERS(CUSTOMER_ID);
CREATE INDEX IDX_OFFERS_PUBLISHER_ID ON OFFERS(PUBLISHER_ID);
CREATE INDEX IDX_OFFERS_BOOK_TYPE_ID ON OFFERS(BOOK_TYPE_ID);
CREATE INDEX IDX_OFFERS_GENRE_ID ON OFFERS(GENRE_ID);

-- Indexes for ORDER_ITEMS table foreign keys
CREATE INDEX IDX_ORDER_ITEMS_BOOK_ID ON ORDER_ITEMS(BOOK_ID);
CREATE INDEX IDX_ORDER_ITEMS_ORDER_ID ON ORDER_ITEMS(ORDER_ID);

-- Index for PASSWORD_RESET_TOKENS table foreign key
CREATE INDEX IDX_PASSWORD_RESET_CUSTOMER_ID ON PASSWORD_RESET_TOKENS(CUSTOMER_ID);

-- Indexes for SHOPPING_CART_ITEMS table foreign keys
CREATE INDEX IDX_CART_ITEMS_BOOK_ID ON SHOPPING_CART_ITEMS(BOOK_ID);
CREATE INDEX IDX_CART_ITEMS_CUSTOMER_ID ON SHOPPING_CART_ITEMS(CUSTOMER_ID);

-- Additional index for ORDERS table (not a foreign key but likely used in joins)
CREATE INDEX IDX_ORDERS_CUSTOMER_ID ON ORDERS(CUSTOMER_ID);


-- Prepare data for Full Text Search
CREATE OR REPLACE TRIGGER trg_book_search_text
BEFORE INSERT OR UPDATE OF NAME, AUTHOR, ISBN ON BOOKS
FOR EACH ROW
BEGIN
  :NEW.SEARCH_TEXT := LOWER(:NEW.NAME) || ' ' ||
                     LOWER(NVL(:NEW.AUTHOR, '')) || ' ' ||
                     LOWER(NVL(:NEW.ISBN, ''));
END;
/

-- Create the Oracle Text index
CREATE INDEX BOOKS_TEXT_IDX ON BOOKS(SEARCH_TEXT)
INDEXTYPE IS CTXSYS.CONTEXT
PARAMETERS ('SYNC (ON COMMIT)');



-- Package specification
CREATE OR REPLACE PACKAGE bookpkg AS
    -- Procedure to update order status from PROCESSING to DELIVERED
    PROCEDURE update_order_status;
    
    -- Procedure to schedule the job to run every 5 minutes
    PROCEDURE schedule_status_update_job;
END bookpkg;
/

-- Package body
CREATE OR REPLACE PACKAGE BODY bookpkg AS
    -- Procedure to update order status from PROCESSING to DELIVERED
    PROCEDURE update_order_status IS
    BEGIN
        -- Update orders with status 'PROCESSING' to 'DELIVERED'
        UPDATE orders
        SET status = 'DELIVERED'
        WHERE status = 'PROCESSING';
        
        -- Commit the transaction
        COMMIT;
        
        -- Log the update (optional)
        DBMS_OUTPUT.PUT_LINE('Order status update completed at ' || TO_CHAR(SYSDATE, 'DD-MON-YYYY HH24:MI:SS'));
        
    EXCEPTION
        WHEN OTHERS THEN
            -- Log error and rollback
            DBMS_OUTPUT.PUT_LINE('Error updating order status: ' || SQLERRM);
            ROLLBACK;
    END update_order_status;
    
    -- Procedure to schedule the job to run every 5 minutes
    PROCEDURE schedule_status_update_job IS
        v_job_exists NUMBER;
    BEGIN
        -- Check if job already exists
        SELECT COUNT(*) INTO v_job_exists
        FROM user_scheduler_jobs
        WHERE job_name = 'ORDER_STATUS_UPDATE_JOB';
        
        -- If job exists, drop it
        IF v_job_exists > 0 THEN
            DBMS_SCHEDULER.DROP_JOB(
                job_name => 'ORDER_STATUS_UPDATE_JOB',
                force => TRUE
            );
        END IF;
        
        -- Create a new job that runs every 5 minutes
        DBMS_SCHEDULER.CREATE_JOB(
            job_name => 'ORDER_STATUS_UPDATE_JOB',
            job_type => 'STORED_PROCEDURE',
            job_action => 'bookpkg.update_order_status',
            start_date => SYSTIMESTAMP,
            repeat_interval => 'FREQ=MINUTELY;INTERVAL=5', -- Run every 5 minutes
            enabled => TRUE,
            comments => 'Job to update order status from PROCESSING to DELIVERED every 5 minutes'
        );
        
        DBMS_OUTPUT.PUT_LINE('Job ORDER_STATUS_UPDATE_JOB scheduled successfully');
        
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('Error scheduling job: ' || SQLERRM);
    END schedule_status_update_job;
    
END bookpkg;
/

-- Grant necessary privileges (run as DBA)
-- GRANT CREATE JOB TO your_schema_name;
-- GRANT EXECUTE ON DBMS_SCHEDULER TO your_schema_name;

-- Example of how to call the procedure to schedule the job
-- EXEC bookpkg.schedule_status_update_job;





-- Extra schema objects to demostrate Oracle to other database migration


-- Create the order history table
CREATE TABLE ORDER_HISTORY (
    ORDER_ID NUMBER(19,0) NOT NULL,
    CUSTOMER_ID NUMBER(19,0),
    ORDER_DATE DATE,
    ORIGINAL_STATUS VARCHAR2(255 CHAR),
    NEW_STATUS VARCHAR2(255 CHAR),
    STATUS_CHANGE_DATE TIMESTAMP(6) NOT NULL,
    TOTAL_AMOUNT NUMBER(38,2),
    TRACKING_NUMBER VARCHAR2(255 CHAR),
    NOTES VARCHAR2(255 CHAR),
    CHANGE_REASON VARCHAR2(255 CHAR),
    PRIMARY KEY (ORDER_ID, STATUS_CHANGE_DATE)
);



-- 1. Simple function to get book count by genre
CREATE OR REPLACE FUNCTION get_book_count_by_genre(p_genre_id NUMBER)
RETURN NUMBER
IS
  v_count NUMBER(10,0);  -- Integer count with no decimal places
BEGIN
  SELECT  /*+ FIRST_ROWS(10) */ 
    COUNT(*) INTO v_count
  FROM BOOKS
  WHERE GENRE_ID = p_genre_id;

  RETURN v_count;
END;
/

-- 2. Simple procedure to update book price
CREATE OR REPLACE PROCEDURE update_book_price(
  p_book_id IN NUMBER,
  p_new_price IN NUMBER
)
IS
BEGIN
  UPDATE BOOKS
  SET PRICE = p_new_price,
      UPDATED_ON = SYSTIMESTAMP
  WHERE ID = p_book_id;
END;
/

-- 3. Simple materialized view for bestsellers
CREATE MATERIALIZED VIEW MV_BESTSELLERS
REFRESH ON DEMAND
AS
SELECT B.ID, B.NAME, B.AUTHOR, B.PRICE, B.ISBN
FROM BOOKS B
WHERE B.IS_BESTSELLER = 1
ORDER BY B.NAME;

-- 4. Medium complexity function to calculate order total with discount
CREATE OR REPLACE FUNCTION calculate_order_total(p_order_id NUMBER)
RETURN NUMBER
IS
  v_total ORDER_ITEMS.BOOK_PRICE%TYPE := 0;  -- Using anchored declaration
BEGIN
  SELECT SUM(OI.BOOK_PRICE * OI.QUANTITY - NVL(OI.DISCOUNT, 0))
  INTO v_total
  FROM ORDER_ITEMS OI
  WHERE OI.ORDER_ID = p_order_id;

  RETURN NVL(v_total, 0);
END;
/

-- 5. Medium complexity procedure to process book offer
CREATE OR REPLACE PROCEDURE process_book_offer(
  p_offer_id IN NUMBER,
  p_approved IN BOOLEAN,
  p_admin_notes IN VARCHAR2,
  p_admin_id IN NUMBER
)
IS
  v_book_id OFFERS.BOOK_ID%TYPE;
BEGIN
  IF p_approved THEN
    -- Get offer details
    SELECT BOOK_ID INTO v_book_id
    FROM OFFERS
    WHERE ID = p_offer_id;

    -- Update offer status
    UPDATE OFFERS
    SET IS_APPROVED = 1,
        IS_REJECTED = 0,
        ADMIN_NOTES = p_admin_notes,
        PROCESSED_AT = SYSTIMESTAMP,
        PROCESSED_BY = p_admin_id,
        OFFER_STATUS = 2, -- Approved status
        UPDATED_ON = SYSTIMESTAMP
    WHERE ID = p_offer_id;

    -- If no book exists yet, we'd create one here
    IF v_book_id IS NULL THEN
      -- Logic to create book from offer would go here
      NULL;
    END IF;
  ELSE
    -- Reject the offer
    UPDATE OFFERS
    SET IS_APPROVED = 0,
        IS_REJECTED = 1,
        ADMIN_NOTES = p_admin_notes,
        PROCESSED_AT = SYSTIMESTAMP,
        PROCESSED_BY = p_admin_id,
        OFFER_STATUS = 3, -- Rejected status
        UPDATED_ON = SYSTIMESTAMP
    WHERE ID = p_offer_id;
  END IF;

END;
/


-- 6. Procedure to populate order history from orders table
CREATE OR REPLACE PROCEDURE populate_order_history AS
BEGIN
    INSERT INTO ORDER_HISTORY (
        ORDER_ID,
        CUSTOMER_ID,
        ORDER_DATE,
        ORIGINAL_STATUS,
        NEW_STATUS,
        STATUS_CHANGE_DATE,
        TOTAL_AMOUNT,
        TRACKING_NUMBER,
        NOTES,
        CHANGE_REASON
    )
    SELECT
        o.ID,
        c.ID,  -- Getting customer ID from CUSTOMERS table
        o.ORDER_DATE,
        'NEW',
        'PROCESSING',
        SYSDATE,
        o.TOTAL_AMOUNT,
        o.TRACKING_NUMBER,
        'Order status updated via batch process',
        'System status update'
    FROM
        ORDERS o
    JOIN
        CUSTOMERS c ON o.CUSTOMER_ID = c.ID
    WHERE
        o.ORDER_STATUS = 1  -- New orders
        AND NOT EXISTS (
            -- Subquery to avoid duplicate entries
            SELECT 1 FROM ORDER_HISTORY oh
            WHERE oh.ORDER_ID = o.ID
            AND oh.NEW_STATUS = 'PROCESSING'
        );

    DBMS_OUTPUT.PUT_LINE('Added ' || SQL%ROWCOUNT || ' orders to history.');
END;
/


-- 7. Complex function to calculate customer loyalty score
CREATE OR REPLACE FUNCTION calculate_customer_loyalty_score(p_customer_id NUMBER)
RETURN NUMBER
IS
  v_order_count NUMBER(10,0);
  v_total_spent ORDERS.TOTAL_AMOUNT%TYPE;  -- Anchored to table column
  v_days_since_first_order NUMBER(10,0);
  v_days_since_last_order NUMBER(10,0);
  v_loyalty_score NUMBER(10,2);
BEGIN
  -- Get order statistics
  SELECT
    COUNT(*),
    NVL(SUM(TOTAL_AMOUNT), 0),
    NVL(TRUNC(SYSDATE) - TRUNC(MIN(CREATED_ON)), 0),
    NVL(TRUNC(SYSDATE) - TRUNC(MAX(CREATED_ON)), 999)
  INTO
    v_order_count,
    v_total_spent,
    v_days_since_first_order,
    v_days_since_last_order
  FROM ORDERS
  WHERE CUSTOMER_ID = p_customer_id;

  -- Calculate loyalty score based on multiple factors
  -- More orders, more spent, longer customer history, and recent activity all increase score
  v_loyalty_score := (v_order_count * 10) +
                    (v_total_spent / 100) +
                    (LEAST(v_days_since_first_order, 1000) / 10) -
                    (LEAST(v_days_since_last_order, 365) / 10);

  RETURN GREATEST(0, ROUND(v_loyalty_score, 2));
END;
/

-- 8. This demonstrates "tables as a target in the MERGE statement" feature
CREATE OR REPLACE PROCEDURE merge_order_status_updates AS
BEGIN
    -- Using MERGE statement with ORDER_HISTORY as the target table
    MERGE INTO ORDER_HISTORY oh
    USING (
        -- Complex source query joining multiple tables and using analytical functions
        SELECT
            o.ID AS ORDER_ID,
            o.CUSTOMER_ID,
            o.ORDER_DATE,
            LAG(o.STATUS) OVER (PARTITION BY o.ID ORDER BY o.CREATED_ON) AS PREVIOUS_STATUS,
            o.STATUS AS CURRENT_STATUS,
            o.CREATED_ON AS STATUS_CHANGE_DATE,
            o.TOTAL_AMOUNT,
            o.TRACKING_NUMBER,
            o.NOTES,
            CASE
                WHEN o.STATUS = 'SHIPPED' THEN 'Order shipped with tracking: ' || o.TRACKING_NUMBER
                WHEN o.STATUS = 'DELIVERED' THEN 'Order delivered on ' || TO_CHAR(o.DELIVERED_DATE, 'YYYY-MM-DD')
                WHEN o.STATUS = 'CANCELLED' THEN o.CANCELLATION_REASON
                ELSE 'Status updated to ' || o.STATUS
            END AS CHANGE_REASON,
            ROW_NUMBER() OVER (PARTITION BY o.ID ORDER BY o.CREATED_ON DESC) AS rn
        FROM
            ORDERS o
        WHERE
            o.ORDER_STATUS > 0
    ) src
    ON (oh.ORDER_ID = src.ORDER_ID AND oh.STATUS_CHANGE_DATE = src.STATUS_CHANGE_DATE)

    -- When matched, update the existing record
    WHEN MATCHED THEN
        UPDATE SET
            oh.NEW_STATUS = src.CURRENT_STATUS,
            oh.NOTES = NVL(src.NOTES, oh.NOTES),
            oh.CHANGE_REASON = src.CHANGE_REASON

    -- When not matched, insert a new record
    WHEN NOT MATCHED THEN
        INSERT (
            ORDER_ID,
            CUSTOMER_ID,
            ORDER_DATE,
            ORIGINAL_STATUS,
            NEW_STATUS,
            STATUS_CHANGE_DATE,
            TOTAL_AMOUNT,
            TRACKING_NUMBER,
            NOTES,
            CHANGE_REASON
        )
        VALUES (
            src.ORDER_ID,
            src.CUSTOMER_ID,
            src.ORDER_DATE,
            NVL(src.PREVIOUS_STATUS, 'NEW'),
            src.CURRENT_STATUS,
            src.STATUS_CHANGE_DATE,
            src.TOTAL_AMOUNT,
            src.TRACKING_NUMBER,
            src.NOTES,
            src.CHANGE_REASON
        );

    DBMS_OUTPUT.PUT_LINE('Added ' || SQL%ROWCOUNT || ' financial classification records.');
END;
/

-- 9. Complex materialized view for book sales analytics
CREATE MATERIALIZED VIEW MV_BOOK_SALES_ANALYTICS
REFRESH COMPLETE ON DEMAND
START WITH SYSDATE
NEXT SYSDATE + 1
AS
SELECT
  B.ID AS BOOK_ID,
  B.NAME AS BOOK_NAME,
  B.AUTHOR,
  G.NAME AS GENRE_NAME,
  P.NAME AS PUBLISHER_NAME,
  COUNT(OI.ID) AS TIMES_ORDERED,
  SUM(OI.QUANTITY) AS TOTAL_QUANTITY_SOLD,
  SUM(OI.BOOK_PRICE * OI.QUANTITY) AS GROSS_REVENUE,
  SUM(OI.DISCOUNT) AS TOTAL_DISCOUNTS,
  SUM(OI.BOOK_PRICE * OI.QUANTITY - NVL(OI.DISCOUNT, 0)) AS NET_REVENUE,
  ROUND(AVG(OI.BOOK_PRICE), 2) AS AVG_SELLING_PRICE,
  MIN(O.CREATED_ON) AS FIRST_SALE_DATE,
  MAX(O.CREATED_ON) AS LAST_SALE_DATE
FROM BOOKS B
JOIN ORDER_ITEMS OI ON B.ID = OI.BOOK_ID
JOIN ORDERS O ON OI.ORDER_ID = O.ID
LEFT JOIN GENRES G ON B.GENRE_ID = G.ID
LEFT JOIN PUBLISHERS P ON B.PUBLISHER_ID = P.ID
GROUP BY B.ID, B.NAME, B.AUTHOR, G.NAME, P.NAME;

-- 10. Simple package for customer management
CREATE OR REPLACE PACKAGE customer_mgmt AS
  -- Get customer by ID
  FUNCTION get_customer(p_customer_id NUMBER) RETURN CUSTOMERS%ROWTYPE;

  -- Create new customer
  PROCEDURE create_customer(
    p_first_name IN VARCHAR2,
    p_last_name IN VARCHAR2,
    p_email IN VARCHAR2,
    p_phone_number IN VARCHAR2,
    p_username IN VARCHAR2,
    p_password_hash IN VARCHAR2,
    p_customer_id OUT NUMBER
  );

  -- Update customer email
  PROCEDURE update_email(
    p_customer_id IN NUMBER,
    p_new_email IN VARCHAR2
  );
END customer_mgmt;
/

CREATE OR REPLACE PACKAGE BODY customer_mgmt AS
  -- Get customer by ID
  FUNCTION get_customer(p_customer_id NUMBER) RETURN CUSTOMERS%ROWTYPE IS
    v_customer CUSTOMERS%ROWTYPE;
  BEGIN
    SELECT * INTO v_customer
    FROM CUSTOMERS
    WHERE ID = p_customer_id;

    RETURN v_customer;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      RETURN NULL;
  END get_customer;

  -- Create new customer
  PROCEDURE create_customer(
    p_first_name IN VARCHAR2,
    p_last_name IN VARCHAR2,
    p_email IN VARCHAR2,
    p_phone_number IN VARCHAR2,
    p_username IN VARCHAR2,
    p_password_hash IN VARCHAR2,
    p_customer_id OUT NUMBER
  ) IS
  BEGIN
    INSERT INTO CUSTOMERS (
      FIRST_NAME,
      LAST_NAME,
      EMAIL,
      PHONE_NUMBER,
      USERNAME,
      PASSWORD_HASH,
      CREATED_ON,
      ACCOUNT_EXPIRED,
      ACCOUNT_LOCKED,
      CREDENTIALS_EXPIRED,
      EMAIL_VERIFIED,
      ROLE
    ) VALUES (
      p_first_name,
      p_last_name,
      p_email,
      p_phone_number,
      p_username,
      p_password_hash,
      SYSTIMESTAMP,
      0, -- not expired
      0, -- not locked
      0, -- credentials not expired
      0, -- email not verified yet
      'USER' -- default role
    )
    RETURNING ID INTO p_customer_id;

  END create_customer;

  -- Update customer email
  PROCEDURE update_email(
    p_customer_id IN NUMBER,
    p_new_email IN VARCHAR2
  ) IS
  BEGIN
    UPDATE CUSTOMERS
    SET EMAIL = p_new_email,
        EMAIL_VERIFIED = 0 -- Reset verification status
    WHERE ID = p_customer_id;
  END update_email;
END customer_mgmt;
/

-- 11. Medium complexity package for order processing
CREATE OR REPLACE PACKAGE order_processing AS
  -- Create a new order
  PROCEDURE create_order(
    p_customer_id IN NUMBER,
    p_address_id IN NUMBER,
    p_notes IN VARCHAR2,
    p_order_id OUT NUMBER
  );

  -- Add item to order
  PROCEDURE add_order_item(
    p_order_id IN NUMBER,
    p_book_id IN NUMBER,
    p_quantity IN NUMBER,
    p_discount IN NUMBER DEFAULT NULL
  );

  -- Update order status
  PROCEDURE update_order_status(
    p_order_id IN NUMBER,
    p_status IN NUMBER
  );

  -- Calculate order total
  FUNCTION get_order_total(p_order_id NUMBER) RETURN NUMBER;

  -- Cancel order
  PROCEDURE cancel_order(
    p_order_id IN NUMBER,
    p_reason IN VARCHAR2
  );
END order_processing;
/

CREATE OR REPLACE PACKAGE BODY order_processing AS
  -- Create a new order
  PROCEDURE create_order(
    p_customer_id IN NUMBER,
    p_address_id IN NUMBER,
    p_notes IN VARCHAR2,
    p_order_id OUT NUMBER
  ) IS
  BEGIN
    INSERT INTO ORDERS (
      CUSTOMER_ID,
      ADDRESS_ID,
      NOTES,
      ORDER_DATE,
      ORDER_STATUS,
      CREATED_ON
    ) VALUES (
      p_customer_id,
      p_address_id,
      p_notes,
      SYSDATE,
      1, -- New order status
      SYSTIMESTAMP
    )
    RETURNING ID INTO p_order_id;

  END create_order;

  -- Add item to order
  PROCEDURE add_order_item(
    p_order_id IN NUMBER,
    p_book_id IN NUMBER,
    p_quantity IN NUMBER,
    p_discount IN NUMBER DEFAULT NULL
  ) IS
    v_book_price NUMBER;
  BEGIN
    -- Get current book price
    SELECT PRICE INTO v_book_price
    FROM BOOKS
    WHERE ID = p_book_id;

    -- Add item to order
    INSERT INTO ORDER_ITEMS (
      ORDER_ID,
      BOOK_ID,
      QUANTITY,
      BOOK_PRICE,
      DISCOUNT
    ) VALUES (
      p_order_id,
      p_book_id,
      p_quantity,
      v_book_price,
      p_discount
    );

    -- Update book inventory
    UPDATE BOOKS
    SET QUANTITY = QUANTITY - p_quantity,
        IS_AVAILABLE = CASE
                         WHEN QUANTITY - p_quantity > 0 THEN 1
                         ELSE 0
                       END,
        UPDATED_ON = SYSTIMESTAMP
    WHERE ID = p_book_id;

    -- Update order total
    UPDATE ORDERS
    SET TOTAL_AMOUNT = get_order_total(p_order_id)
    WHERE ID = p_order_id;

  END add_order_item;

  -- Update order status
  PROCEDURE update_order_status(
    p_order_id IN NUMBER,
    p_status IN NUMBER
  ) IS
  BEGIN
    UPDATE ORDERS
    SET ORDER_STATUS = p_status,
        SHIPPED_DATE = CASE WHEN p_status = 2 THEN SYSDATE ELSE SHIPPED_DATE END,
        DELIVERED_DATE = CASE WHEN p_status = 3 THEN SYSDATE ELSE DELIVERED_DATE END
    WHERE ID = p_order_id;

  END update_order_status;

  -- Calculate order total
  FUNCTION get_order_total(p_order_id NUMBER) RETURN NUMBER IS
    v_total ORDER_ITEMS.BOOK_PRICE%TYPE;
  BEGIN
    SELECT SUM(BOOK_PRICE * QUANTITY - NVL(DISCOUNT, 0))
    INTO v_total
    FROM ORDER_ITEMS
    WHERE ORDER_ID = p_order_id;

    RETURN NVL(v_total, 0);
  END get_order_total;

  -- Cancel order
  PROCEDURE cancel_order(
    p_order_id IN NUMBER,
    p_reason IN VARCHAR2
  ) IS
    CURSOR c_order_items IS
      SELECT BOOK_ID, QUANTITY
      FROM ORDER_ITEMS
      WHERE ORDER_ID = p_order_id;
  BEGIN
    -- Update order status
    UPDATE ORDERS
    SET ORDER_STATUS = 4, -- Cancelled status
        CANCELLATION_REASON = p_reason,
        CANCELLED_DATE = SYSDATE
    WHERE ID = p_order_id;

    -- Return items to inventory
    FOR item IN c_order_items LOOP
      UPDATE BOOKS
      SET QUANTITY = QUANTITY + item.QUANTITY,
          IS_AVAILABLE = 1,
          UPDATED_ON = SYSTIMESTAMP
      WHERE ID = item.BOOK_ID;
    END LOOP;

    COMMIT;
  EXCEPTION
    WHEN OTHERS THEN
      ROLLBACK;
      RAISE;
  END cancel_order;
END order_processing;
/

-- 13. Simple materialized view for book inventory status
CREATE MATERIALIZED VIEW MV_BOOK_INVENTORY_STATUS
REFRESH ON DEMAND
AS
SELECT
  B.ID,
  B.NAME,
  B.AUTHOR,
  B.ISBN,
  B.QUANTITY,
  B.PRICE,
  B.IS_AVAILABLE,
  G.NAME AS GENRE,
  P.NAME AS PUBLISHER
FROM BOOKS B
LEFT JOIN GENRES G ON B.GENRE_ID = G.ID
LEFT JOIN PUBLISHERS P ON B.PUBLISHER_ID = P.ID;

-- 14. Medium complexity materialized view for customer shopping patterns
CREATE MATERIALIZED VIEW MV_CUSTOMER_SHOPPING_PATTERNS
REFRESH COMPLETE ON DEMAND
START WITH SYSDATE
NEXT SYSDATE + 7
AS
SELECT
  C.ID AS CUSTOMER_ID,
  C.FIRST_NAME || ' ' || C.LAST_NAME AS CUSTOMER_NAME,
  G.NAME AS GENRE_NAME,
  COUNT(DISTINCT OI.ID) AS PURCHASE_COUNT,
  SUM(OI.QUANTITY) AS BOOKS_PURCHASED,
  ROUND(AVG(OI.BOOK_PRICE), 2) AS AVG_BOOK_PRICE,
  MIN(O.CREATED_ON) AS FIRST_PURCHASE_DATE,
  MAX(O.CREATED_ON) AS LAST_PURCHASE_DATE
FROM CUSTOMERS C
JOIN ORDERS O ON C.ID = O.CUSTOMER_ID
JOIN ORDER_ITEMS OI ON O.ID = OI.ORDER_ID
JOIN BOOKS B ON OI.BOOK_ID = B.ID
JOIN GENRES G ON B.GENRE_ID = G.ID
GROUP BY C.ID, C.FIRST_NAME || ' ' || C.LAST_NAME, G.NAME;

-- 15. Simple function to get book availability
CREATE OR REPLACE FUNCTION is_book_available(p_book_id INT)
RETURN VARCHAR2
IS
  -- Use anchored declarations to match table column types
  v_quantity BOOKS.QUANTITY%TYPE;
  v_is_available BOOKS.IS_AVAILABLE%TYPE;
BEGIN
  SELECT QUANTITY, IS_AVAILABLE
  INTO v_quantity, v_is_available
  FROM BOOKS
  WHERE ID = p_book_id;

  IF v_is_available = 1 AND v_quantity > 0 THEN
    RETURN 'Available';
  ELSIF v_quantity = 0 THEN
    RETURN 'Out of Stock';
  ELSE
    RETURN 'Unavailable';
  END IF;
EXCEPTION
  WHEN NO_DATA_FOUND THEN
    RETURN 'Book Not Found';
END;
/

-- 16. Simple procedure to add item to shopping cart
CREATE OR REPLACE PROCEDURE add_to_cart(
  p_customer_id IN NUMBER,
  p_book_id IN NUMBER,
  p_quantity IN NUMBER DEFAULT 1,
  p_is_wishlist IN NUMBER DEFAULT 0
)
IS
  v_cart_item_id SHOPPING_CART_ITEMS.ID%TYPE;
  v_existing_quantity SHOPPING_CART_ITEMS.QUANTITY%TYPE;
BEGIN
  -- Check if item already exists in cart
  BEGIN
    SELECT ID, QUANTITY
    INTO v_cart_item_id, v_existing_quantity
    FROM SHOPPING_CART_ITEMS
    WHERE CUSTOMER_ID = p_customer_id
      AND BOOK_ID = p_book_id
      AND IS_WISHLIST_ITEM = p_is_wishlist;

    -- Update existing cart item
    UPDATE SHOPPING_CART_ITEMS
    SET QUANTITY = v_existing_quantity + p_quantity
    WHERE ID = v_cart_item_id;

  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      -- Add new cart item
      INSERT INTO SHOPPING_CART_ITEMS (
        CUSTOMER_ID,
        BOOK_ID,
        QUANTITY,
        IS_WISHLIST_ITEM
      ) VALUES (
        p_customer_id,
        p_book_id,
        p_quantity,
        p_is_wishlist
      );
  END;

  COMMIT;
EXCEPTION
  WHEN OTHERS THEN
    ROLLBACK;
    RAISE;
END;
/

-- 17. Medium complexity function to get recommended books
CREATE OR REPLACE FUNCTION get_recommended_books(
  p_customer_id NUMBER,
  p_limit NUMBER DEFAULT 10
) RETURN SYS_REFCURSOR
IS
  v_result SYS_REFCURSOR;
BEGIN
  -- This function recommends books based on customer's purchase history
  -- It finds genres the customer has purchased before and recommends other books in those genres
  -- that the customer hasn't purchased yet
  OPEN v_result FOR
    WITH customer_genres AS (
      -- Find genres this customer has purchased
      SELECT DISTINCT B.GENRE_ID
      FROM ORDERS O
      JOIN ORDER_ITEMS OI ON O.ID = OI.ORDER_ID
      JOIN BOOKS B ON OI.BOOK_ID = B.ID
      WHERE O.CUSTOMER_ID = p_customer_id
    ),
    purchased_books AS (
      -- Books the customer has already purchased
      SELECT DISTINCT OI.BOOK_ID
      FROM ORDERS O
      JOIN ORDER_ITEMS OI ON O.ID = OI.ORDER_ID
      WHERE O.CUSTOMER_ID = p_customer_id
    )
    SELECT B.ID, B.NAME, B.AUTHOR, B.PRICE, B.ISBN,
           G.NAME AS GENRE_NAME,
           P.NAME AS PUBLISHER_NAME
    FROM BOOKS B
    JOIN GENRES G ON B.GENRE_ID = G.ID
    JOIN PUBLISHERS P ON B.PUBLISHER_ID = P.ID
    WHERE B.GENRE_ID IN (SELECT GENRE_ID FROM customer_genres)
      AND B.IS_AVAILABLE = 1
      AND B.ID NOT IN (SELECT BOOK_ID FROM purchased_books)
    ORDER BY
      B.IS_BESTSELLER DESC,
      B.IS_FEATURED DESC,
      DBMS_RANDOM.VALUE  -- Add some randomness to recommendations
    FETCH FIRST p_limit ROWS ONLY;

  RETURN v_result;
END;
/

-- 18. pivit table
CREATE OR REPLACE FUNCTION get_book_status_by_year
RETURN SYS_REFCURSOR AS
    v_result SYS_REFCURSOR;
BEGIN
    -- Open cursor with PIVOT query using only BOOKS table
    OPEN v_result FOR
        SELECT
            *
        FROM (
            -- Source query with book status
            SELECT
                CASE
                    WHEN b.IS_BESTSELLER = 1 THEN 'BESTSELLER'
                    WHEN b.IS_NEW_ARRIVAL = 1 THEN 'NEW_ARRIVAL'
                    WHEN b.IS_FEATURED = 1 THEN 'FEATURED'
                    ELSE 'REGULAR'
                END AS BOOK_STATUS,
                COUNT(*) AS BOOK_COUNT
            FROM
                BOOKS b
            GROUP BY
                CASE
                    WHEN b.IS_BESTSELLER = 1 THEN 'BESTSELLER'
                    WHEN b.IS_NEW_ARRIVAL = 1 THEN 'NEW_ARRIVAL'
                    WHEN b.IS_FEATURED = 1 THEN 'FEATURED'
                    ELSE 'REGULAR'
                END
        )
        PIVOT (
            -- PIVOT to count books by status for each publication year
            SUM(BOOK_COUNT)
            FOR BOOK_STATUS IN (
                'BESTSELLER' AS BESTSELLERS,
                'NEW_ARRIVAL' AS NEW_ARRIVALS,
                'FEATURED' AS FEATURED,
                'REGULAR' AS REGULAR
            )
        );
        

    RETURN v_result;
END;
/

-- 19. pipelined table functions

-- Create a simple object type for book statistics
CREATE OR REPLACE TYPE genre_stat_obj AS OBJECT (
    genre_name VARCHAR2(255),
    bestsellers NUMBER,
    new_arrivals NUMBER,
    featured NUMBER,
    regular NUMBER
);
/

-- Create a table type based on our object type
CREATE OR REPLACE TYPE genre_stat_tab AS TABLE OF genre_stat_obj;
/

-- Create a simple pipelined function
CREATE OR REPLACE FUNCTION get_genre_book_counts
RETURN genre_stat_tab PIPELINED IS
BEGIN
    -- For each genre, pipe a row with book counts by status
    FOR genre_rec IN (
        SELECT
            g.NAME AS genre_name,
            SUM(CASE WHEN b.IS_BESTSELLER = 1 THEN 1 ELSE 0 END) AS bestsellers,
            SUM(CASE WHEN b.IS_NEW_ARRIVAL = 1 THEN 1 ELSE 0 END) AS new_arrivals,
            SUM(CASE WHEN b.IS_FEATURED = 1 THEN 1 ELSE 0 END) AS featured,
            SUM(CASE WHEN b.IS_BESTSELLER = 0 AND b.IS_NEW_ARRIVAL = 0 AND b.IS_FEATURED = 0 THEN 1 ELSE 0 END) AS regular
        FROM
            GENRES g
        LEFT JOIN
            BOOKS b ON g.ID = b.GENRE_ID
        GROUP BY
            g.NAME
        ORDER BY
            g.NAME
    ) LOOP
        -- Pipe the row to the output
        PIPE ROW(genre_stat_obj(
            genre_rec.genre_name,
            genre_rec.bestsellers,
            genre_rec.new_arrivals,
            genre_rec.featured,
            genre_rec.regular
        ));
    END LOOP;

    RETURN;
END get_genre_book_counts;
/

CREATE OR REPLACE FUNCTION display_genre_book_counts
RETURN SYS_REFCURSOR AS
    v_result SYS_REFCURSOR;
BEGIN
    -- Open a cursor that calls our pipelined function
    OPEN v_result FOR
        SELECT * FROM TABLE(get_genre_book_counts);

    -- Return the cursor to the caller
    RETURN v_result;
END display_genre_book_counts;
/



-- Demostrate Oracle Specific Features

-- Example 1: Oracle PRAGMA AUTONOMOUS_TRANSACTION
-- This feature allows a PL/SQL block to have its own independent transaction

CREATE OR REPLACE PROCEDURE update_book_quantity(
  p_book_id IN NUMBER,
  p_quantity_change IN NUMBER
) AS
  PRAGMA AUTONOMOUS_TRANSACTION;
  v_current_quantity BOOKS.QUANTITY%TYPE;
BEGIN
  -- Get current quantity
  SELECT QUANTITY INTO v_current_quantity 
  FROM BOOKS 
  WHERE ID = p_book_id;
  
  -- Update the quantity
  UPDATE BOOKS 
  SET QUANTITY = v_current_quantity + p_quantity_change,
      UPDATED_ON = SYSTIMESTAMP
  WHERE ID = p_book_id;
  
  -- Commit the autonomous transaction
  COMMIT;
EXCEPTION
  WHEN OTHERS THEN
    -- Rollback only affects this autonomous transaction
    ROLLBACK;
    RAISE;
END update_book_quantity;
/

-- Example 2: Oracle Database Links
-- Database links allow access to objects in remote databases

-- Create a database link to a remote Oracle database
CREATE DATABASE LINK remote_bookstore
CONNECT TO demo IDENTIFIED BY "Welcome123_"
USING '(DESCRIPTION=
         (ADDRESS=(PROTOCOL=TCP)(HOST=localhost)(PORT=1521))
         (CONNECT_DATA=(SERVICE_NAME=XEPDB1)))';

CREATE SYNONYM remote_books FOR BOOKS@remote_bookstore;

-- Example 3: Oracle-specific syntax (DBMS_OUTPUT.PUT_LINE and DBMS_LOCK)

CREATE OR REPLACE FUNCTION check_book_availability(
  p_book_id IN NUMBER,
  p_quantity IN NUMBER
) RETURN BOOLEAN AS
  v_available_quantity BOOKS.QUANTITY%TYPE;
  v_book_name BOOKS.NAME%TYPE;
BEGIN
  -- Get book information
  SELECT NAME, QUANTITY INTO v_book_name, v_available_quantity
  FROM BOOKS
  WHERE ID = p_book_id;
  
  -- Log the check
  DBMS_OUTPUT.PUT_LINE('Checking availability for book: ' || v_book_name);
  DBMS_OUTPUT.PUT_LINE('Requested quantity: ' || p_quantity);
  DBMS_OUTPUT.PUT_LINE('Available quantity: ' || v_available_quantity);
  
  -- Simulate a delay for inventory verification
  DBMS_OUTPUT.PUT_LINE('Verifying inventory...');
  DBMS_LOCK.SLEEP(1);
  
  -- Check if enough quantity is available
  IF v_available_quantity >= p_quantity THEN
    DBMS_OUTPUT.PUT_LINE('Book is available in requested quantity');
    RETURN TRUE;
  ELSE
    DBMS_OUTPUT.PUT_LINE('Insufficient quantity available');
    RETURN FALSE;
  END IF;
EXCEPTION
  WHEN NO_DATA_FOUND THEN
    DBMS_OUTPUT.PUT_LINE('Book with ID ' || p_book_id || ' not found');
    RETURN FALSE;
  WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('Error: ' || SQLERRM);
    RETURN FALSE;
END check_book_availability;
/


-- Example 4: Oracle Synonyms
-- Synonyms provide alternative names for database objects

CREATE PUBLIC SYNONYM GENRES FOR GENRES;
CREATE PUBLIC SYNONYM BOOK_TYPES FOR BOOK_TYPES;
CREATE PUBLIC SYNONYM CONDITIONS FOR CONDITIONS;
CREATE PUBLIC SYNONYM PUBLISHERS FOR PUBLISHERS;
CREATE PUBLIC SYNONYM BOOKS FOR BOOKS;
CREATE PUBLIC SYNONYM ORDERS FOR ORDERS;
CREATE PUBLIC SYNONYM ORDER_ITEMS FOR ORDER_ITEMS;
CREATE PUBLIC SYNONYM CUSTOMERS FOR CUSTOMERS;
-- Private Synonym
CREATE SYNONYM CLIENT_LISTS FOR CUSTOMERS;

-- Example 5: Oracle BLOB for storing book cover images

-- Create a separate table for book cover images
CREATE TABLE BOOKS_COVER (
  BOOK_ID NUMBER(19,0) PRIMARY KEY,
  COVER_IMAGE BLOB,
  CREATED_ON TIMESTAMP(6),
  UPDATED_ON TIMESTAMP(6),
  CONSTRAINT FK_BOOKS_COVER_BOOK FOREIGN KEY (BOOK_ID) REFERENCES BOOKS(ID)
);

-- Create Oracle directory object for image files
-- Note: This requires appropriate privileges
CREATE OR REPLACE DIRECTORY BOOK_IMAGES_DIR AS '/path/to/book/images';

-- PL/SQL procedure to load book cover image from a file
CREATE OR REPLACE PROCEDURE load_book_cover_image(
  p_book_id IN NUMBER,
  p_image_dir IN VARCHAR2,
  p_file_name IN VARCHAR2
) AS
  v_blob BLOB;
  v_bfile BFILE;
  v_dest_offset INTEGER := 1;
  v_src_offset INTEGER := 1;
  v_exists NUMBER;
  v_cover_exists NUMBER;
BEGIN
  -- Check if book exists
  SELECT COUNT(*) INTO v_exists
  FROM BOOKS
  WHERE ID = p_book_id;

  IF v_exists = 0 THEN
    RAISE_APPLICATION_ERROR(-20001, 'Book ID ' || p_book_id || ' does not exist');
  END IF;

  -- Initialize BFILE locator to the source file
  v_bfile := BFILENAME(p_image_dir, p_file_name);

  -- Check if file exists
  IF DBMS_LOB.FILEEXISTS(v_bfile) = 0 THEN
    RAISE_APPLICATION_ERROR(-20002, 'File ' || p_file_name || ' does not exist in directory ' || p_image_dir);
  END IF;

  -- Open the BFILE for reading
  DBMS_LOB.OPEN(v_bfile, DBMS_LOB.LOB_READONLY);

  -- Check if cover record already exists
  SELECT COUNT(*) INTO v_cover_exists
  FROM BOOKS_COVER
  WHERE BOOK_ID = p_book_id;

  IF v_cover_exists > 0 THEN
    -- Update existing record
    -- First, lock the row for update
    SELECT COVER_IMAGE INTO v_blob
    FROM BOOKS_COVER
    WHERE BOOK_ID = p_book_id
    FOR UPDATE;

    -- Clear any existing content
    DBMS_LOB.TRIM(v_blob, 0);

    -- Copy the BFILE data to the BLOB
    DBMS_LOB.LOADFROMFILE(
      dest_lob    => v_blob,
      src_lob     => v_bfile,
      amount      => DBMS_LOB.GETLENGTH(v_bfile)
    );

    -- Update the timestamp
    UPDATE BOOKS_COVER
    SET UPDATED_ON = SYSTIMESTAMP
    WHERE BOOK_ID = p_book_id;

  ELSE
    -- Insert new record
    -- Create a temporary BLOB
    DBMS_LOB.CREATETEMPORARY(v_blob, TRUE);

    -- Copy the BFILE data to the BLOB
    DBMS_LOB.LOADFROMFILE(
      dest_lob    => v_blob,
      src_lob     => v_bfile,
      amount      => DBMS_LOB.GETLENGTH(v_bfile)
    );

    -- Insert the new record
    INSERT INTO BOOKS_COVER (
      BOOK_ID,
      COVER_IMAGE,
      CREATED_ON,
      UPDATED_ON
    ) VALUES (
      p_book_id,
      v_blob,
      SYSTIMESTAMP,
      SYSTIMESTAMP
    );

    -- Free the temporary BLOB
    DBMS_LOB.FREETEMPORARY(v_blob);
  END IF;

  -- Close the BFILE
  DBMS_LOB.CLOSE(v_bfile);

  -- Commit the transaction
  COMMIT;

  DBMS_OUTPUT.PUT_LINE('Successfully loaded image ' || p_file_name || ' for book ID ' || p_book_id);

EXCEPTION
  WHEN NO_DATA_FOUND THEN
    ROLLBACK;
    RAISE_APPLICATION_ERROR(-20003, 'Book ID ' || p_book_id || ' not found');
  WHEN OTHERS THEN
    ROLLBACK;
    -- Close the BFILE if it's open
    IF DBMS_LOB.ISOPEN(v_bfile) = 1 THEN
      DBMS_LOB.CLOSE(v_bfile);
    END IF;
    RAISE_APPLICATION_ERROR(-20004, 'Error loading image: ' || SQLERRM);
END load_book_cover_image;
/

-- Example usage:
-- EXEC load_book_cover_image(101, 'BOOK_IMAGES_DIR', 'book101_cover.jpg');

-- Oracle date time expresssion
CREATE OR REPLACE PROCEDURE p_oracle_datetime_expressions AS
    -- Variables to hold various date/time values
    v_current_date DATE;
    v_current_timestamp TIMESTAMP;
    v_current_timestamp_tz TIMESTAMP WITH TIME ZONE;

BEGIN
    -- Current date and time functions
    v_current_date := SYSDATE;
    v_current_timestamp := SYSTIMESTAMP;
    v_current_timestamp_tz := CURRENT_TIMESTAMP;

    -- Output current date/time values
    DBMS_OUTPUT.PUT_LINE('===== Current Date/Time Values =====');
    DBMS_OUTPUT.PUT_LINE('SYSDATE: ' || TO_CHAR(v_current_date, 'YYYY-MM-DD HH24:MI:SS'));
    DBMS_OUTPUT.PUT_LINE('SYSTIMESTAMP: ' || TO_CHAR(v_current_timestamp, 'YYYY-MM-DD HH24:MI:SS.FF'));
    DBMS_OUTPUT.PUT_LINE('CURRENT_TIMESTAMP: ' || TO_CHAR(v_current_timestamp_tz, 'YYYY-MM-DD HH24:MI:SS.FF TZH:TZM'));

    -- Date arithmetic
    DBMS_OUTPUT.PUT_LINE('===== Date Arithmetic =====');
    DBMS_OUTPUT.PUT_LINE('Tomorrow: ' || TO_CHAR(v_current_date + 1, 'YYYY-MM-DD'));
    DBMS_OUTPUT.PUT_LINE('Yesterday: ' || TO_CHAR(v_current_date - 1, 'YYYY-MM-DD'));
    DBMS_OUTPUT.PUT_LINE('Next week: ' || TO_CHAR(v_current_date + 7, 'YYYY-MM-DD'));
    DBMS_OUTPUT.PUT_LINE('3 hours later: ' || TO_CHAR(v_current_date + (3/24), 'YYYY-MM-DD HH24:MI:SS'));
    DBMS_OUTPUT.PUT_LINE('45 minutes later: ' || TO_CHAR(v_current_date + (45/(24*60)), 'YYYY-MM-DD HH24:MI:SS'));

EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Error: ' || SQLERRM);
END p_oracle_datetime_expressions;
/
