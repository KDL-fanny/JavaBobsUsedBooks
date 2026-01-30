--
-- PostgreSQL database dump
--

-- Dumped from database version 15.10
-- Dumped by pg_dump version 16.8 (Ubuntu 16.8-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: demo; Type: SCHEMA; Schema: -; Owner: postgres
--

CREATE SCHEMA demo;


ALTER SCHEMA demo OWNER TO postgres;

--
-- Name: genre_stat_obj; Type: TYPE; Schema: demo; Owner: postgres
--

CREATE TYPE demo.genre_stat_obj AS (
	genre_name character varying(255),
	bestsellers double precision,
	new_arrivals double precision,
	featured double precision,
	regular double precision
);


ALTER TYPE demo.genre_stat_obj OWNER TO postgres;

--
-- Name: genre_stat_tab; Type: DOMAIN; Schema: demo; Owner: postgres
--

CREATE DOMAIN demo.genre_stat_tab AS demo.genre_stat_obj[];


ALTER DOMAIN demo.genre_stat_tab OWNER TO postgres;

--
-- Name: add_numbers(numeric, numeric); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo.add_numbers(number1 numeric, number2 numeric) RETURNS numeric
    LANGUAGE sql
    AS $$
    SELECT number1 + number2;
$$;


ALTER FUNCTION demo.add_numbers(number1 numeric, number2 numeric) OWNER TO postgres;

--
-- Name: add_to_cart(double precision, double precision, double precision, double precision); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo.add_to_cart(IN p_customer_id double precision, IN p_book_id double precision, IN p_quantity double precision DEFAULT 1, IN p_is_wishlist double precision DEFAULT 0)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_cart_item_id demo.shopping_cart_items.id%TYPE;
    v_existing_quantity demo.shopping_cart_items.quantity%TYPE;
BEGIN
/* Check if item already exists in cart */
    BEGIN
        SELECT
            id, quantity
            INTO STRICT v_cart_item_id, v_existing_quantity
            FROM demo.shopping_cart_items
            WHERE customer_id = p_customer_id AND book_id = p_book_id AND is_wishlist_item = p_is_wishlist;
        /* Update existing cart item */
        UPDATE demo.shopping_cart_items
        SET quantity = v_existing_quantity + p_quantity
            WHERE id = v_cart_item_id;
        EXCEPTION
            WHEN no_data_found THEN
                /* Add new cart item */
                INSERT INTO demo.shopping_cart_items (customer_id, book_id, quantity, is_wishlist_item)
                VALUES (p_customer_id, p_book_id, p_quantity, p_is_wishlist);
    END;
    /*
    [5035 - Severity CRITICAL - Your code ends a transaction inside a block with exception handlers. Revise your code to move transaction control to the application side and try again.]
    COMMIT
    */
    EXCEPTION
        WHEN others THEN
            /*
            [5035 - Severity CRITICAL - Your code ends a transaction inside a block with exception handlers. Revise your code to move transaction control to the application side and try again.]
            ROLLBACK
            */
            RAISE;
END;
$$;


ALTER PROCEDURE demo.add_to_cart(IN p_customer_id double precision, IN p_book_id double precision, IN p_quantity double precision, IN p_is_wishlist double precision) OWNER TO postgres;

--
-- Name: bookpkg$schedule_status_update_job(); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo."bookpkg$schedule_status_update_job"()
    LANGUAGE plpgsql
    AS $_$
DECLARE
    v_job_exists DOUBLE PRECISION;
BEGIN
/* Check if job already exists */
    
    /*
    [5591 - Severity CRITICAL - DMS SC can't convert the SYS.USER_SCHEDULER_JOBS system object. Convert your source code manually., 5578 - Severity CRITICAL - DMS SC can't convert the SELECT statement. Revise your SELECT statement and try again.]
    SELECT COUNT(*) INTO v_job_exists
            FROM user_scheduler_jobs
            WHERE job_name = 'ORDER_STATUS_UPDATE_JOB'
    */
    /* If job exists, drop it */
    IF v_job_exists > 0 THEN
        BEGIN
        /*
        [5501 - Severity CRITICAL - PostgreSQL doesn't support functionality similar to the SYS.DBMS_SCHEDULER.DROP_JOB(VARCHAR2,BOOLEAN,BOOLEAN,VARCHAR2) module. Revise your converted code to use AWS Lambda with scheduled events.]
        DBMS_SCHEDULER.DROP_JOB(
                        job_name => 'ORDER_STATUS_UPDATE_JOB',
                        force => TRUE
                    )
        */
        END;
    END IF;
    /* Create a new job that runs every 5 minutes */
    
    /*
    [5501 - Severity CRITICAL - PostgreSQL doesn't support functionality similar to the SYS.DBMS_SCHEDULER.CREATE_JOB(VARCHAR2,VARCHAR2,VARCHAR2,PLS_INTEGER,TIMESTAMP WITH TIME ZONE,VARCHAR2,TIMESTAMP WITH TIME ZONE,VARCHAR2,BOOLEAN,BOOLEAN,VARCHAR2,VARCHAR2,VARCHAR2) module. Revise your converted code to use AWS Lambda with scheduled events.]
    DBMS_SCHEDULER.CREATE_JOB(
                job_name => 'ORDER_STATUS_UPDATE_JOB',
                job_type => 'STORED_PROCEDURE',
                job_action => 'bookpkg.update_order_status',
                start_date => SYSTIMESTAMP,
                repeat_interval => 'FREQ=MINUTELY;INTERVAL=5', -- Run every 5 minutes
                enabled => TRUE,
                comments => 'Job to update order status from PROCESSING to DELIVERED every 5 minutes'
            )
    */
    CALL aws_oracle_ext.dbms_output$put_line(a => 'Job ORDER_STATUS_UPDATE_JOB scheduled successfully');
    EXCEPTION
        WHEN others THEN
            CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'Error scheduling job: ', SQLERRM));
END;
$_$;


ALTER PROCEDURE demo."bookpkg$schedule_status_update_job"() OWNER TO postgres;

--
-- Name: bookpkg$update_order_status(); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo."bookpkg$update_order_status"()
    LANGUAGE plpgsql
    AS $_$
BEGIN
/* Update orders with status 'PROCESSING' to 'DELIVERED' */
    UPDATE demo.orders
    SET status = 'DELIVERED'
        WHERE status = 'PROCESSING';
    /* Commit the transaction */
    
    /*
    [5035 - Severity CRITICAL - Your code ends a transaction inside a block with exception handlers. Revise your code to move transaction control to the application side and try again.]
    COMMIT
    */
    /* Log the update (optional) */
    CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'Order status update completed at ', aws_oracle_ext.TO_CHAR((CLOCK_TIMESTAMP() AT TIME ZONE COALESCE(CURRENT_SETTING('aws_oracle_ext.tz', TRUE), 'UTC'))::TIMESTAMP(0), 'DD-MON-YYYY HH24:MI:SS')));
    EXCEPTION
        WHEN others THEN
            /* Log error and rollback */
            CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'Error updating order status: ', SQLERRM));
            /*
            [5035 - Severity CRITICAL - Your code ends a transaction inside a block with exception handlers. Revise your code to move transaction control to the application side and try again.]
            ROLLBACK
            */
END;
$_$;


ALTER PROCEDURE demo."bookpkg$update_order_status"() OWNER TO postgres;

--
-- Name: calculate_customer_loyalty_score(double precision); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo.calculate_customer_loyalty_score(p_customer_id double precision) RETURNS double precision
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_order_count NUMERIC(10, 0);
    v_total_spent demo.orders.total_amount%TYPE;
    /* Anchored to table column */
    v_days_since_first_order NUMERIC(10, 0);
    v_days_since_last_order NUMERIC(10, 0);
    v_loyalty_score NUMERIC(10, 2);
BEGIN
/* Get order statistics */
    SELECT
        COUNT(*), COALESCE(SUM(total_amount), 0), COALESCE((EXTRACT (EPOCH FROM aws_oracle_ext.TRUNC((CLOCK_TIMESTAMP() AT TIME ZONE COALESCE(CURRENT_SETTING('aws_oracle_ext.tz', TRUE), 'UTC'))::TIMESTAMP(0)) - DATE(MIN(created_on))) / 86400)::NUMERIC, 0), COALESCE((EXTRACT (EPOCH FROM aws_oracle_ext.TRUNC((CLOCK_TIMESTAMP() AT TIME ZONE COALESCE(CURRENT_SETTING('aws_oracle_ext.tz', TRUE), 'UTC'))::TIMESTAMP(0)) - DATE(MAX(created_on))) / 86400)::NUMERIC, 999)
        INTO STRICT v_order_count, v_total_spent, v_days_since_first_order, v_days_since_last_order
        FROM demo.orders
        WHERE customer_id = p_customer_id;
    /* Calculate loyalty score based on multiple factors */
    /* More orders, more spent, longer customer history, and recent activity all increase score */
    v_loyalty_score := (v_order_count * 10) + (v_total_spent / 100::NUMERIC) + (aws_oracle_ext.least(v_days_since_first_order::NUMERIC, 1000::NUMERIC)::NUMERIC / 10::NUMERIC) - (aws_oracle_ext.least(v_days_since_last_order::NUMERIC, 365::NUMERIC)::NUMERIC / 10::NUMERIC);
    RETURN aws_oracle_ext.greatest(0::NUMERIC, ROUND(v_loyalty_score, 2)::NUMERIC);
END;
$$;


ALTER FUNCTION demo.calculate_customer_loyalty_score(p_customer_id double precision) OWNER TO postgres;

--
-- Name: calculate_order_total(double precision); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo.calculate_order_total(p_order_id double precision) RETURNS double precision
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_total demo.order_items.book_price%TYPE := 0;
/* Using anchored declaration */
BEGIN
    SELECT
        SUM(oi.book_price * oi.quantity - COALESCE(oi.discount, 0))
        INTO STRICT v_total
        FROM demo.order_items AS oi
        WHERE oi.order_id = p_order_id;
    RETURN COALESCE(v_total, 0);
END;
$$;


ALTER FUNCTION demo.calculate_order_total(p_order_id double precision) OWNER TO postgres;

--
-- Name: calculate_order_total_old(double precision); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo.calculate_order_total_old(p_order_id double precision) RETURNS double precision
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_total DOUBLE PRECISION := 0;
BEGIN
    SELECT
        SUM(oi.book_price * oi.quantity - COALESCE(oi.discount, 0))
        INTO STRICT v_total
        FROM demo.order_items AS oi
        WHERE oi.order_id = p_order_id;
    RETURN COALESCE(v_total, 0);
END;
$$;


ALTER FUNCTION demo.calculate_order_total_old(p_order_id double precision) OWNER TO postgres;

--
-- Name: check_book_availability(double precision, double precision); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo.check_book_availability(p_book_id double precision, p_quantity double precision) RETURNS boolean
    LANGUAGE plpgsql
    AS $_$
DECLARE
    v_available_quantity demo.books.quantity%TYPE;
    v_book_name demo.books.name%TYPE;
BEGIN
/* Get book information */
    SELECT
        name, quantity
        INTO STRICT v_book_name, v_available_quantity
        FROM demo.books
        WHERE id = p_book_id;
    /* Log the check */
    CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'Checking availability for book: ', v_book_name));
    CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'Requested quantity: ', p_quantity));
    CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'Available quantity: ', v_available_quantity));
    /* Simulate a delay for inventory verification */
    CALL aws_oracle_ext.dbms_output$put_line(a => 'Verifying inventory...');
    PERFORM pg_sleep(1);
    /* Check if enough quantity is available */

    IF v_available_quantity >= p_quantity THEN
        CALL aws_oracle_ext.dbms_output$put_line(a => 'Book is available in requested quantity');
        RETURN TRUE;
    ELSE
        CALL aws_oracle_ext.dbms_output$put_line(a => 'Insufficient quantity available');
        RETURN FALSE;
    END IF;
    EXCEPTION
        WHEN no_data_found THEN
            CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'Book with ID ', p_book_id, ' not found'));
            RETURN FALSE;
        WHEN others THEN
            CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'Error: ', SQLERRM));
            RETURN FALSE;
END;
$_$;


ALTER FUNCTION demo.check_book_availability(p_book_id double precision, p_quantity double precision) OWNER TO postgres;

--
-- Name: customer_mgmt$create_customer(text, text, text, text, text, text); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo."customer_mgmt$create_customer"(IN p_first_name text, IN p_last_name text, IN p_email text, IN p_phone_number text, IN p_username text, IN p_password_hash text, OUT p_customer_id double precision)
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO demo.customers (first_name, last_name, email, phone_number, username, password_hash, created_on, account_expired, account_locked, credentials_expired, email_verified, role)
    VALUES (p_first_name, p_last_name, p_email, p_phone_number, p_username, p_password_hash, aws_oracle_ext.systimestamp(), 0,
    /* not expired */
    0,
    /* not locked */
    0,
    /* credentials not expired */
    0,
    /* email not verified yet */
    'USER'
    /* default role */
    )
    RETURNING id INTO p_customer_id;
END;
$$;


ALTER PROCEDURE demo."customer_mgmt$create_customer"(IN p_first_name text, IN p_last_name text, IN p_email text, IN p_phone_number text, IN p_username text, IN p_password_hash text, OUT p_customer_id double precision) OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: customers; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.customers (
    id bigint NOT NULL,
    account_expired integer,
    account_locked integer,
    created_on timestamp(6) without time zone,
    credentials_expired integer,
    date_of_birth timestamp(0) without time zone,
    email character varying(255),
    email_verified integer,
    first_name character varying(255),
    last_login timestamp(6) without time zone,
    last_name character varying(255),
    password_hash character varying(255),
    phone_number character varying(255),
    role character varying(255),
    sub character varying(255),
    username character varying(255),
    CONSTRAINT customers_account_expired_check CHECK ((account_expired = ANY (ARRAY[0, 1]))),
    CONSTRAINT customers_account_locked_check CHECK ((account_locked = ANY (ARRAY[0, 1]))),
    CONSTRAINT customers_credentials_expired_check CHECK ((credentials_expired = ANY (ARRAY[0, 1]))),
    CONSTRAINT customers_email_verified_check CHECK ((email_verified = ANY (ARRAY[0, 1])))
);


ALTER TABLE demo.customers OWNER TO postgres;

--
-- Name: customer_mgmt$get_customer(double precision); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo."customer_mgmt$get_customer"(p_customer_id double precision) RETURNS demo.customers
    LANGUAGE plpgsql
    AS $_$
DECLARE
    v_customer demo.customers := ROW (NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)::demo.customers;
    aws$rec RECORD;
BEGIN
    SELECT
        *
        INTO STRICT aws$rec
        FROM demo.customers
        WHERE id = p_customer_id;
    v_customer := aws$rec;
    RETURN v_customer;
    EXCEPTION
        WHEN no_data_found THEN
            RETURN NULL;
END;
$_$;


ALTER FUNCTION demo."customer_mgmt$get_customer"(p_customer_id double precision) OWNER TO postgres;

--
-- Name: customer_mgmt$update_email(double precision, text); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo."customer_mgmt$update_email"(IN p_customer_id double precision, IN p_new_email text)
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE demo.customers
    SET email = p_new_email, email_verified = 0
        /* Reset verification status */
        WHERE id = p_customer_id;
END;
$$;


ALTER PROCEDURE demo."customer_mgmt$update_email"(IN p_customer_id double precision, IN p_new_email text) OWNER TO postgres;

--
-- Name: delete_records_by_name(character varying); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo.delete_records_by_name(p_name character varying) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_deleted_count INTEGER;
BEGIN
    -- Input validation
    IF p_name IS NULL THEN
        RAISE EXCEPTION 'Name parameter cannot be NULL';
    END IF;

    -- Delete records and get count of deleted rows
    WITH deleted_rows AS (
        DELETE FROM demo_table
        WHERE name = p_name
        RETURNING *
    )
    SELECT COUNT(*) INTO v_deleted_count
    FROM deleted_rows;

    -- Log the deletion
    RAISE NOTICE 'Deleted % record(s) with name: %', v_deleted_count, p_name;

    RETURN v_deleted_count;

EXCEPTION
    WHEN others THEN
        RAISE EXCEPTION 'Error deleting records: %', SQLERRM;
END;
$$;


ALTER FUNCTION demo.delete_records_by_name(p_name character varying) OWNER TO postgres;

--
-- Name: display_genre_book_counts(); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo.display_genre_book_counts() RETURNS refcursor
    LANGUAGE plpgsql
    AS $_$
DECLARE
    v_result REFCURSOR;
    v_result$ATTRIBUTES aws_oracle_data.TCursorAttributes := ROW (FALSE, NULL, NULL, NULL);
BEGIN
/* Open a cursor that calls our pipelined function */
    v_result := NULL;
    /*
    [5651 - Severity CRITICAL - DMS SC can't convert pipelined table functions. Change conversion settings and try again., 5578 - Severity CRITICAL - DMS SC can't convert the SELECT statement. Revise your SELECT statement and try again.]
    OPEN v_result FOR
            SELECT * FROM TABLE(get_genre_book_counts)
    */
    v_result$ATTRIBUTES := ROW (TRUE, 0, NULL, NULL);
    /* Return the cursor to the caller */
    RETURN v_result;
END;
$_$;


ALTER FUNCTION demo.display_genre_book_counts() OWNER TO postgres;

--
-- Name: genre_stat_obj(character varying, double precision, double precision, double precision, double precision); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo.genre_stat_obj(genre_name character varying DEFAULT NULL::character varying, bestsellers double precision DEFAULT NULL::double precision, new_arrivals double precision DEFAULT NULL::double precision, featured double precision DEFAULT NULL::double precision, regular double precision DEFAULT NULL::double precision) RETURNS demo.genre_stat_obj
    LANGUAGE sql
    AS $$
SELECT ROW(genre_name,bestsellers,new_arrivals,featured,regular)::demo.genre_stat_obj;
$$;


ALTER FUNCTION demo.genre_stat_obj(genre_name character varying, bestsellers double precision, new_arrivals double precision, featured double precision, regular double precision) OWNER TO postgres;

--
-- Name: get_book_count_by_genre(double precision); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo.get_book_count_by_genre(p_genre_id double precision) RETURNS double precision
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_count NUMERIC(10, 0);
/* Integer count with no decimal places */
BEGIN
    SELECT
        COUNT(*)
        INTO STRICT v_count
        FROM demo.books
        WHERE genre_id = p_genre_id;
    RETURN v_count;
END;
$$;


ALTER FUNCTION demo.get_book_count_by_genre(p_genre_id double precision) OWNER TO postgres;

--
-- Name: get_book_status_by_year(); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo.get_book_status_by_year() RETURNS refcursor
    LANGUAGE plpgsql
    AS $_$
DECLARE
    v_result REFCURSOR;
    v_result$ATTRIBUTES aws_oracle_data.TCursorAttributes := ROW (FALSE, NULL, NULL, NULL);
BEGIN
/* Open cursor with PIVOT query using only BOOKS table */
    v_result := NULL;
    OPEN v_result FOR
    /*
    [5077 - Severity CRITICAL - PostgreSQL doesn't support the PIVOT clause for SELECT statements. Revise your code to use a procedure to prepare data and then return data as a view., 5578 - Severity CRITICAL - DMS SC can't convert the SELECT statement. Revise your SELECT statement and try again.]
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
            )
    */
    /* >> DMS SC preserves the tuple structure of the transformed statement due to the detection of the critical Action Item >> */
    SELECT
        NULL::CHARACTER VARYING(8000) AS "CASEWHENB.IS_BESTSELLER=1THEN'", NULL::NUMERIC(38) AS "COUNT(*)"
    /* << DMS SC preserves the tuple structure of the transformed statement due to the detection of the critical Action Item << */;
    v_result$ATTRIBUTES := ROW (TRUE, 0, NULL, NULL);
    RETURN v_result;
END;
$_$;


ALTER FUNCTION demo.get_book_status_by_year() OWNER TO postgres;

--
-- Name: get_genre_book_counts(); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo.get_genre_book_counts() RETURNS SETOF demo.genre_stat_tab
    LANGUAGE plpgsql
    AS $$
DECLARE
    genre_rec RECORD;
BEGIN
/* For each genre, pipe a row with book counts by status */
    FOR genre_rec IN
    SELECT
        g.name AS genre_name, SUM(CASE
            WHEN b.is_bestseller = 1 THEN 1
            ELSE 0
        END) AS bestsellers, SUM(CASE
            WHEN b.is_new_arrival = 1 THEN 1
            ELSE 0
        END) AS new_arrivals, SUM(CASE
            WHEN b.is_featured = 1 THEN 1
            ELSE 0
        END) AS featured, SUM(CASE
            WHEN b.is_bestseller = 0 AND b.is_new_arrival = 0 AND b.is_featured = 0 THEN 1
            ELSE 0
        END) AS regular
        FROM demo.genres AS g
        LEFT OUTER JOIN demo.books AS b
            ON g.id = b.genre_id
        GROUP BY g.name
        ORDER BY g.name
    LOOP
        /* Pipe the row to the output */
        BEGIN
        /* [5340 - Severity CRITICAL - PostgreSQL doesn't support the DEMO.GENRE_STAT_OBJ function. Revise your code to use another function or create a user-defined function.] */
        END;
    END LOOP;
    RETURN;
END;
$$;


ALTER FUNCTION demo.get_genre_book_counts() OWNER TO postgres;

--
-- Name: get_name_by_id(integer); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo.get_name_by_id(p_id integer) RETURNS character varying
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_name varchar;
BEGIN
    SELECT name INTO v_name
    FROM demo_table
    WHERE id = p_id;
    
    RETURN v_name;
END;
$$;


ALTER FUNCTION demo.get_name_by_id(p_id integer) OWNER TO postgres;

--
-- Name: get_recommended_books(double precision, double precision); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo.get_recommended_books(p_customer_id double precision, p_limit double precision DEFAULT 10) RETURNS refcursor
    LANGUAGE plpgsql
    AS $_$
DECLARE
    v_result REFCURSOR;
    v_result$ATTRIBUTES aws_oracle_data.TCursorAttributes := ROW (FALSE, NULL, NULL, NULL);
BEGIN
/* This function recommends books based on customer's purchase history */
/* It finds genres the customer has purchased before and recommends other books in those genres */
/* that the customer hasn't purchased yet */
    v_result := NULL;
    OPEN v_result FOR
    WITH customer_genres
    AS (
    /* Find genres this customer has purchased */
    SELECT DISTINCT
        b.genre_id
        FROM demo.orders AS o
        JOIN demo.order_items AS oi
            ON o.id = oi.order_id
        JOIN demo.books AS b
            ON oi.book_id = b.id
        WHERE o.customer_id = p_customer_id), purchased_books
    AS (
    /* Books the customer has already purchased */
    SELECT DISTINCT
        oi.book_id
        FROM demo.orders AS o
        JOIN demo.order_items AS oi
            ON o.id = oi.order_id
        WHERE o.customer_id = p_customer_id)
    SELECT
        b.id, b.name, b.author, b.price, b.isbn, g.name AS genre_name, p.name AS publisher_name
        FROM demo.books AS b
        JOIN demo.genres AS g
            ON b.genre_id = g.id
        JOIN demo.publishers AS p
            ON b.publisher_id = p.id
        WHERE b.genre_id IN (SELECT
            genre_id
            FROM customer_genres) AND b.is_available = 1 AND b.id NOT IN (SELECT
            book_id
            FROM purchased_books)
        ORDER BY b.is_bestseller DESC, b.is_featured DESC, aws_oracle_ext.dbms_random$value()
        /* Add some randomness to recommendations */
        FETCH FIRST (TRUNC(p_limit::NUMERIC)) ROWS ONLY;
    v_result$ATTRIBUTES := ROW (TRUE, 0, NULL, NULL);
    RETURN v_result;
END;
$_$;


ALTER FUNCTION demo.get_recommended_books(p_customer_id double precision, p_limit double precision) OWNER TO postgres;

--
-- Name: is_book_available(numeric); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo.is_book_available(p_book_id numeric) RETURNS text
    LANGUAGE plpgsql
    AS $$
/* Use anchored declarations to match table column types */
DECLARE
    v_quantity demo.books.quantity%TYPE;
    v_is_available demo.books.is_available%TYPE;
BEGIN
    SELECT
        quantity, is_available
        INTO STRICT v_quantity, v_is_available
        FROM demo.books
        WHERE id = p_book_id;

    IF v_is_available = 1 AND v_quantity > 0 THEN
        RETURN 'Available';
    ELSIF v_quantity = 0 THEN
        RETURN 'Out of Stock';
    ELSE
        RETURN 'Unavailable';
    END IF;
    EXCEPTION
        WHEN no_data_found THEN
            RETURN 'Book Not Found';
END;
$$;


ALTER FUNCTION demo.is_book_available(p_book_id numeric) OWNER TO postgres;

--
-- Name: load_book_cover_image(double precision, text, text); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo.load_book_cover_image(IN p_book_id double precision, IN p_image_dir text, IN p_file_name text)
    LANGUAGE plpgsql
    AS $_$
DECLARE
    v_blob BYTEA;
    v_bfile CHARACTER VARYING(255);
    v_dest_offset NUMERIC(38) := 1;
    v_src_offset NUMERIC(38) := 1;
    v_exists DOUBLE PRECISION;
    v_cover_exists DOUBLE PRECISION;
BEGIN
/* Check if book exists */
    SELECT
        COUNT(*)
        INTO STRICT v_exists
        FROM demo.books
        WHERE id = p_book_id;

    IF v_exists = 0 THEN
        RAISE USING hint = -20001, message = CONCAT_WS('', 'Book ID ', p_book_id, ' does not exist'), detail = 'User-defined exception';
    END IF;
    /* Initialize BFILE locator to the source file */
    
    /*
    [5340 - Severity CRITICAL - PostgreSQL doesn't support the STANDARD.BFILENAME(VARCHAR2,VARCHAR2) function. Revise your code to use another function or create a user-defined function.]
    v_bfile := BFILENAME(p_image_dir, p_file_name)
    */
    /* Check if file exists */
    
    /*
    [5340 - Severity CRITICAL - PostgreSQL doesn't support the SYS.DBMS_LOB.FILEEXISTS(BFILE) function. Revise your code to use another function or create a user-defined function.]
    IF DBMS_LOB.FILEEXISTS(v_bfile) = 0 THEN
        RAISE_APPLICATION_ERROR(-20002, 'File ' || p_file_name || ' does not exist in directory ' || p_image_dir);
      END IF
    */
    /* Open the BFILE for reading */
    
    /*
    [5340 - Severity CRITICAL - PostgreSQL doesn't support the SYS.DBMS_LOB.OPEN(BFILE,BINARY_INTEGER) function. Revise your code to use another function or create a user-defined function.]
    DBMS_LOB.OPEN(v_bfile, DBMS_LOB.LOB_READONLY)
    */
    /* Check if cover record already exists */
    SELECT
        COUNT(*)
        INTO STRICT v_cover_exists
        FROM demo.books_cover
        WHERE book_id = p_book_id;

    IF v_cover_exists > 0 THEN
        /* Update existing record */
        /* First, lock the row for update */
        SELECT
            cover_image
            INTO STRICT v_blob
            FROM demo.books_cover
            WHERE book_id = p_book_id
            FOR UPDATE;
        /* Clear any existing content */
        CALL aws_oracle_ext.dbms_lob$trim(lob_loc => v_blob, newlen => 0);
        /* Copy the BFILE data to the BLOB */
        
        /*
        [5340 - Severity CRITICAL - PostgreSQL doesn't support the GETLENGTH(BFILE) function. Revise your code to use another function or create a user-defined function., 5340 - Severity CRITICAL - PostgreSQL doesn't support the SYS.DBMS_LOB.LOADFROMFILE(BLOB,BFILE,INTEGER,INTEGER,INTEGER) function. Revise your code to use another function or create a user-defined function.]
        DBMS_LOB.LOADFROMFILE(
              dest_lob    => v_blob,
              src_lob     => v_bfile,
              amount      => DBMS_LOB.GETLENGTH(v_bfile)
            )
        */
        /* Update the timestamp */
        UPDATE demo.books_cover
        SET updated_on = aws_oracle_ext.systimestamp()
            WHERE book_id = p_book_id;
    ELSE
        /* Insert new record */
        /* Create a temporary BLOB */
        CALL aws_oracle_ext.dbms_lob$createtemporary(lob_loc => v_blob);
        /* Copy the BFILE data to the BLOB */
        
        /*
        [5340 - Severity CRITICAL - PostgreSQL doesn't support the GETLENGTH(BFILE) function. Revise your code to use another function or create a user-defined function., 5340 - Severity CRITICAL - PostgreSQL doesn't support the SYS.DBMS_LOB.LOADFROMFILE(BLOB,BFILE,INTEGER,INTEGER,INTEGER) function. Revise your code to use another function or create a user-defined function.]
        DBMS_LOB.LOADFROMFILE(
              dest_lob    => v_blob,
              src_lob     => v_bfile,
              amount      => DBMS_LOB.GETLENGTH(v_bfile)
            )
        */
        /* Insert the new record */
        INSERT INTO demo.books_cover (book_id, cover_image, created_on, updated_on)
        VALUES (p_book_id, v_blob, aws_oracle_ext.systimestamp(), aws_oracle_ext.systimestamp());
        /* Free the temporary BLOB */
        CALL aws_oracle_ext.dbms_lob$freetemporary(lob_loc => v_blob);
    END IF;
    /* Close the BFILE */
    
    /*
    [5340 - Severity CRITICAL - PostgreSQL doesn't support the SYS.DBMS_LOB.CLOSE(BFILE) function. Revise your code to use another function or create a user-defined function.]
    DBMS_LOB.CLOSE(v_bfile)
    */
    /* Commit the transaction */
    
    /*
    [5035 - Severity CRITICAL - Your code ends a transaction inside a block with exception handlers. Revise your code to move transaction control to the application side and try again.]
    COMMIT
    */
    CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'Successfully loaded image ', p_file_name, ' for book ID ', p_book_id));
    EXCEPTION
        WHEN no_data_found THEN
            /*
            [5035 - Severity CRITICAL - Your code ends a transaction inside a block with exception handlers. Revise your code to move transaction control to the application side and try again.]
            ROLLBACK
            */
            RAISE USING hint = -20003, message = CONCAT_WS('', 'Book ID ', p_book_id, ' not found'), detail = 'User-defined exception';
        WHEN others THEN
            /*
            [5035 - Severity CRITICAL - Your code ends a transaction inside a block with exception handlers. Revise your code to move transaction control to the application side and try again.]
            ROLLBACK
            */
            /* Close the BFILE if it's open */
            
            /*
            [5340 - Severity CRITICAL - PostgreSQL doesn't support the SYS.DBMS_LOB.ISOPEN(BFILE) function. Revise your code to use another function or create a user-defined function., 5340 - Severity CRITICAL - PostgreSQL doesn't support the SYS.DBMS_LOB.CLOSE(BFILE) function. Revise your code to use another function or create a user-defined function.]
            IF DBMS_LOB.ISOPEN(v_bfile) = 1 THEN
                  DBMS_LOB.CLOSE(v_bfile);
                END IF
            */
            RAISE USING hint = -20004, message = CONCAT_WS('', 'Error loading image: ', SQLERRM), detail = 'User-defined exception';
END;
$_$;


ALTER PROCEDURE demo.load_book_cover_image(IN p_book_id double precision, IN p_image_dir text, IN p_file_name text) OWNER TO postgres;

--
-- Name: merge_order_status_updates(); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo.merge_order_status_updates()
    LANGUAGE plpgsql
    AS $_$
DECLARE
    sql$rowcount BIGINT;
BEGIN
/* Using MERGE statement with ORDER_HISTORY as the target table */
    
    /*
    [5340 - Severity CRITICAL - PostgreSQL doesn't support the {SUBQUERY}.ORDER_ID function. Revise your code to use another function or create a user-defined function., 5340 - Severity CRITICAL - PostgreSQL doesn't support the {SUBQUERY}.STATUS_CHANGE_DATE function. Revise your code to use another function or create a user-defined function., 5340 - Severity CRITICAL - PostgreSQL doesn't support the {SUBQUERY}.CURRENT_STATUS function. Revise your code to use another function or create a user-defined function., 5340 - Severity CRITICAL - PostgreSQL doesn't support the {SUBQUERY}.CHANGE_REASON function. Revise your code to use another function or create a user-defined function., 5340 - Severity CRITICAL - PostgreSQL doesn't support the {SUBQUERY}.ORDER_ID function. Revise your code to use another function or create a user-defined function., 5340 - Severity CRITICAL - PostgreSQL doesn't support the {SUBQUERY}.PREVIOUS_STATUS function. Revise your code to use another function or create a user-defined function., 5340 - Severity CRITICAL - PostgreSQL doesn't support the {SUBQUERY}.CURRENT_STATUS function. Revise your code to use another function or create a user-defined function., 5340 - Severity CRITICAL - PostgreSQL doesn't support the {SUBQUERY}.STATUS_CHANGE_DATE function. Revise your code to use another function or create a user-defined function., 5340 - Severity CRITICAL - PostgreSQL doesn't support the {SUBQUERY}.CHANGE_REASON function. Revise your code to use another function or create a user-defined function.]
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
            )
    */
    GET DIAGNOSTICS sql$rowcount = ROW_COUNT;
    CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'Added ', sql$rowcount, ' financial classification records.'));
END;
$_$;


ALTER PROCEDURE demo.merge_order_status_updates() OWNER TO postgres;

--
-- Name: order_processing$add_order_item(double precision, double precision, double precision, double precision); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo."order_processing$add_order_item"(IN p_order_id double precision, IN p_book_id double precision, IN p_quantity double precision, IN p_discount double precision DEFAULT NULL::double precision)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_book_price DOUBLE PRECISION;
BEGIN
/* Get current book price */
    SELECT
        price
        INTO STRICT v_book_price
        FROM demo.books
        WHERE id = p_book_id;
    /* Add item to order */
    INSERT INTO demo.order_items (order_id, book_id, quantity, book_price, discount)
    VALUES (p_order_id, p_book_id, p_quantity, v_book_price, p_discount);
    /* Update book inventory */
    UPDATE demo.books
    SET quantity = quantity - p_quantity, is_available =
    CASE
        WHEN quantity - p_quantity > 0 THEN 1
        ELSE 0
    END, updated_on = aws_oracle_ext.systimestamp()
        WHERE id = p_book_id;
    /* Update order total */
    
    /*
    [5340 - Severity CRITICAL - PostgreSQL doesn't support the DEMO.ORDER_PROCESSING.GET_ORDER_TOTAL(NUMBER) function. Revise your code to use another function or create a user-defined function.]
    UPDATE ORDERS
        SET TOTAL_AMOUNT = get_order_total(p_order_id)
        WHERE ID = p_order_id
    */
END;
$$;


ALTER PROCEDURE demo."order_processing$add_order_item"(IN p_order_id double precision, IN p_book_id double precision, IN p_quantity double precision, IN p_discount double precision) OWNER TO postgres;

--
-- Name: order_processing$cancel_order(double precision, text); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo."order_processing$cancel_order"(IN p_order_id double precision, IN p_reason text)
    LANGUAGE plpgsql
    AS $_$
DECLARE
    c_order_items CURSOR FOR
    SELECT
        book_id, quantity
        FROM demo.order_items
        WHERE order_id = p_order_id;
    c_order_items$ATTRIBUTES aws_oracle_data.TCursorAttributes := ROW (FALSE, NULL, NULL, NULL);
BEGIN
/* Update order status */
    UPDATE demo.orders
    SET order_status = 4,
    /* Cancelled status */
    cancellation_reason = p_reason, cancelled_date = (CLOCK_TIMESTAMP() AT TIME ZONE COALESCE(CURRENT_SETTING('aws_oracle_ext.tz', TRUE), 'UTC'))::TIMESTAMP(0)
        WHERE id = p_order_id;
    /* Return items to inventory */

    FOR item IN c_order_items LOOP
        UPDATE demo.books
        SET quantity = quantity + item.quantity, is_available = 1, updated_on = aws_oracle_ext.systimestamp()
            WHERE id = item.book_id;
    END LOOP;
    /*
    [5035 - Severity CRITICAL - Your code ends a transaction inside a block with exception handlers. Revise your code to move transaction control to the application side and try again.]
    COMMIT
    */
    EXCEPTION
        WHEN others THEN
            /*
            [5035 - Severity CRITICAL - Your code ends a transaction inside a block with exception handlers. Revise your code to move transaction control to the application side and try again.]
            ROLLBACK
            */
            RAISE;
END;
$_$;


ALTER PROCEDURE demo."order_processing$cancel_order"(IN p_order_id double precision, IN p_reason text) OWNER TO postgres;

--
-- Name: order_processing$create_order(double precision, double precision, text); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo."order_processing$create_order"(IN p_customer_id double precision, IN p_address_id double precision, IN p_notes text, OUT p_order_id double precision)
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO demo.orders (customer_id, address_id, notes, order_date, order_status, created_on)
    VALUES (p_customer_id, p_address_id, p_notes, (CLOCK_TIMESTAMP() AT TIME ZONE COALESCE(CURRENT_SETTING('aws_oracle_ext.tz', TRUE), 'UTC'))::TIMESTAMP(0), 1,
    /* New order status */
    aws_oracle_ext.systimestamp())
    RETURNING id INTO p_order_id;
END;
$$;


ALTER PROCEDURE demo."order_processing$create_order"(IN p_customer_id double precision, IN p_address_id double precision, IN p_notes text, OUT p_order_id double precision) OWNER TO postgres;

--
-- Name: order_processing$get_order_total(double precision); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo."order_processing$get_order_total"(p_order_id double precision) RETURNS double precision
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_total demo.order_items.book_price%TYPE;
BEGIN
    SELECT
        SUM(book_price * quantity - COALESCE(discount, 0))
        INTO STRICT v_total
        FROM demo.order_items
        WHERE order_id = p_order_id;
    RETURN COALESCE(v_total, 0);
END;
$$;


ALTER FUNCTION demo."order_processing$get_order_total"(p_order_id double precision) OWNER TO postgres;

--
-- Name: order_processing$update_order_status(double precision, double precision); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo."order_processing$update_order_status"(IN p_order_id double precision, IN p_status double precision)
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE demo.orders
    SET order_status = p_status, shipped_date =
    CASE
        WHEN p_status = 2 THEN (CLOCK_TIMESTAMP() AT TIME ZONE COALESCE(CURRENT_SETTING('aws_oracle_ext.tz', TRUE), 'UTC'))::TIMESTAMP(0)
        ELSE shipped_date
    END, delivered_date =
    CASE
        WHEN p_status = 3 THEN (CLOCK_TIMESTAMP() AT TIME ZONE COALESCE(CURRENT_SETTING('aws_oracle_ext.tz', TRUE), 'UTC'))::TIMESTAMP(0)
        ELSE delivered_date
    END
        WHERE id = p_order_id;
END;
$$;


ALTER PROCEDURE demo."order_processing$update_order_status"(IN p_order_id double precision, IN p_status double precision) OWNER TO postgres;

--
-- Name: p_oracle_datetime_expressions(); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo.p_oracle_datetime_expressions()
    LANGUAGE plpgsql
    AS $_$
/* Variables to hold various date/time values */
DECLARE
    v_current_date TIMESTAMP(0) WITHOUT TIME ZONE;
    v_current_timestamp TIMESTAMP(6) WITHOUT TIME ZONE;
    v_current_timestamp_tz TIMESTAMP(6) WITH TIME ZONE;
BEGIN
/* Current date and time functions */
    v_current_date := (CLOCK_TIMESTAMP() AT TIME ZONE COALESCE(CURRENT_SETTING('aws_oracle_ext.tz', TRUE), 'UTC'))::TIMESTAMP(0);
    v_current_timestamp := aws_oracle_ext.systimestamp();
    v_current_timestamp_tz := aws_oracle_ext.current_timestamp();
    /* Output current date/time values */
    CALL aws_oracle_ext.dbms_output$put_line(a => '===== Current Date/Time Values =====');
    CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'SYSDATE: ', aws_oracle_ext.TO_CHAR(v_current_date, 'YYYY-MM-DD HH24:MI:SS')));
    CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'SYSTIMESTAMP: ', aws_oracle_ext.TO_CHAR(v_current_timestamp, 'YYYY-MM-DD HH24:MI:SS.FF')));
    CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'CURRENT_TIMESTAMP: ', aws_oracle_ext.TO_CHAR(v_current_timestamp_tz, 'YYYY-MM-DD HH24:MI:SS.FF TZH:TZM')));
    /* Date arithmetic */
    CALL aws_oracle_ext.dbms_output$put_line(a => '===== Date Arithmetic =====');
    CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'Tomorrow: ', aws_oracle_ext.TO_CHAR(v_current_date + (1::NUMERIC || ' days')::INTERVAL, 'YYYY-MM-DD')));
    CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'Yesterday: ', aws_oracle_ext.TO_CHAR(v_current_date - (1::NUMERIC || ' days')::INTERVAL, 'YYYY-MM-DD')));
    CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'Next week: ', aws_oracle_ext.TO_CHAR(v_current_date + (7::NUMERIC || ' days')::INTERVAL, 'YYYY-MM-DD')));
    CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', '3 hours later: ', aws_oracle_ext.TO_CHAR(v_current_date + ((3::NUMERIC / 24::NUMERIC) || ' days')::INTERVAL, 'YYYY-MM-DD HH24:MI:SS')));
    CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', '45 minutes later: ', aws_oracle_ext.TO_CHAR(v_current_date + ((45::NUMERIC / (24 * 60)::NUMERIC) || ' days')::INTERVAL, 'YYYY-MM-DD HH24:MI:SS')));
    EXCEPTION
        WHEN others THEN
            CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'Error: ', SQLERRM));
END;
$_$;


ALTER PROCEDURE demo.p_oracle_datetime_expressions() OWNER TO postgres;

--
-- Name: populate_order_history(); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo.populate_order_history()
    LANGUAGE plpgsql
    AS $_$
DECLARE
    sql$rowcount BIGINT;
BEGIN
    INSERT INTO demo.order_history (order_id, customer_id, order_date, original_status, new_status, status_change_date, total_amount, tracking_number, notes, change_reason)
    SELECT
        o.id, c.id,
        /* Getting customer ID from CUSTOMERS table */
        o.order_date, 'NEW', 'PROCESSING', (CLOCK_TIMESTAMP() AT TIME ZONE COALESCE(CURRENT_SETTING('aws_oracle_ext.tz', TRUE), 'UTC'))::TIMESTAMP(0), o.total_amount, o.tracking_number, 'Order status updated via batch process', 'System status update'
        FROM demo.orders AS o
        JOIN demo.customers AS c
            ON o.customer_id = c.id
        WHERE o.order_status = 1 AND
        /* New orders */
        NOT EXISTS
        /* Subquery to avoid duplicate entries */
        (SELECT
            1
            FROM demo.order_history AS oh
            WHERE oh.order_id = o.id AND oh.new_status = 'PROCESSING');
    GET DIAGNOSTICS sql$rowcount = ROW_COUNT;
    CALL aws_oracle_ext.dbms_output$put_line(a => CONCAT_WS('', 'Added ', sql$rowcount, ' orders to history.'));
END;
$_$;


ALTER PROCEDURE demo.populate_order_history() OWNER TO postgres;

--
-- Name: process_book_offer(double precision, boolean, text, double precision); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo.process_book_offer(IN p_offer_id double precision, IN p_approved boolean, IN p_admin_notes text, IN p_admin_id double precision)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_book_id demo.offers.book_id%TYPE;
BEGIN
    IF p_approved THEN
        /* Get offer details */
        SELECT
            book_id
            INTO STRICT v_book_id
            FROM demo.offers
            WHERE id = p_offer_id;
        /* Update offer status */
        UPDATE demo.offers
        SET is_approved = 1, is_rejected = 0, admin_notes = p_admin_notes, processed_at = aws_oracle_ext.systimestamp(), processed_by = p_admin_id, offer_status = 2,
        /* Approved status */
        updated_on = aws_oracle_ext.systimestamp()
            WHERE id = p_offer_id;
        /* If no book exists yet, we'd create one here */

        IF v_book_id IS NULL THEN
            /* Logic to create book from offer would go here */
            NULL;
        END IF;
    ELSE
        /* Reject the offer */
        UPDATE demo.offers
        SET is_approved = 0, is_rejected = 1, admin_notes = p_admin_notes, processed_at = aws_oracle_ext.systimestamp(), processed_by = p_admin_id, offer_status = 3,
        /* Rejected status */
        updated_on = aws_oracle_ext.systimestamp()
            WHERE id = p_offer_id;
    END IF;
END;
$$;


ALTER PROCEDURE demo.process_book_offer(IN p_offer_id double precision, IN p_approved boolean, IN p_admin_notes text, IN p_admin_id double precision) OWNER TO postgres;

--
-- Name: sp_get_records(refcursor); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo.sp_get_records(INOUT par_my_cursor refcursor)
    LANGUAGE plpgsql
    AS $$
BEGIN
    /* Open a cursor for the SELECT query */
    OPEN par_my_cursor FOR
    SELECT
        id, name
        FROM demo_table;
END;
$$;


ALTER PROCEDURE demo.sp_get_records(INOUT par_my_cursor refcursor) OWNER TO postgres;

--
-- Name: trg_book_search_text$books(); Type: FUNCTION; Schema: demo; Owner: postgres
--

CREATE FUNCTION demo."trg_book_search_text$books"() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    new.search_text := CONCAT_WS('', LOWER(new.name), ' ', LOWER(COALESCE(new.author, NULL)), ' ', LOWER(COALESCE(new.isbn, NULL)));

    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        RETURN NEW;
    END IF;
END;
$$;


ALTER FUNCTION demo."trg_book_search_text$books"() OWNER TO postgres;

--
-- Name: update_book_price(double precision, double precision); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo.update_book_price(IN p_book_id double precision, IN p_new_price double precision)
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE demo.books
    SET price = p_new_price, updated_on = aws_oracle_ext.systimestamp()
        WHERE id = p_book_id;
END;
$$;


ALTER PROCEDURE demo.update_book_price(IN p_book_id double precision, IN p_new_price double precision) OWNER TO postgres;

--
-- Name: update_book_quantity(double precision, double precision); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo.update_book_quantity(IN p_book_id double precision, IN p_quantity_change double precision)
    LANGUAGE plpgsql
    AS $_$
DECLARE
    aws_params JSON := json_build_object('p_book_id', p_book_id, 'p_quantity_change', p_quantity_change);
    aws_session_env JSON;
BEGIN
    SELECT
        *
        FROM aws_oracle_ext.autonomous_exec('CALL demo.update_book_quantity$at('||quote_nullable(aws_params)||','||quote_nullable(aws_session_env)||')')
        INTO aws_params, aws_session_env;
END
$_$;


ALTER PROCEDURE demo.update_book_quantity(IN p_book_id double precision, IN p_quantity_change double precision) OWNER TO postgres;

--
-- Name: update_book_quantity$at(json, json); Type: PROCEDURE; Schema: demo; Owner: postgres
--

CREATE PROCEDURE demo."update_book_quantity$at"(INOUT aws_params json, INOUT aws_session_env json)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_current_quantity demo.books.quantity%TYPE;
    p_book_id DOUBLE PRECISION;
    p_quantity_change DOUBLE PRECISION;
BEGIN
/* Get current quantity */
    SELECT
        t.p_book_id, t.p_quantity_change
        INTO p_book_id, p_quantity_change
        FROM json_to_record(aws_params)
            AS t (p_book_id DOUBLE PRECISION, p_quantity_change DOUBLE PRECISION);
    SELECT
        quantity
        INTO STRICT v_current_quantity
        FROM demo.books
        WHERE id = p_book_id;
    /* Update the quantity */
    UPDATE demo.books
    SET quantity = v_current_quantity + p_quantity_change, updated_on = aws_oracle_ext.systimestamp()
        WHERE id = p_book_id;
    /* Commit the autonomous transaction */
    
    /*
    [5035 - Severity CRITICAL - Your code ends a transaction inside a block with exception handlers. Revise your code to move transaction control to the application side and try again.]
    COMMIT
    */
    EXCEPTION
        WHEN others THEN
            /* Rollback only affects this autonomous transaction */
            
            /*
            [5035 - Severity CRITICAL - Your code ends a transaction inside a block with exception handlers. Revise your code to move transaction control to the application side and try again.]
            ROLLBACK
            */
            RAISE;
END;
$$;


ALTER PROCEDURE demo."update_book_quantity$at"(INOUT aws_params json, INOUT aws_session_env json) OWNER TO postgres;

--
-- Name: PROCEDURE "update_book_quantity$at"(INOUT aws_params json, INOUT aws_session_env json); Type: COMMENT; Schema: demo; Owner: postgres
--

COMMENT ON PROCEDURE demo."update_book_quantity$at"(INOUT aws_params json, INOUT aws_session_env json) IS 'Belongs to: demo.update_book_quantity';


--
-- Name: addresses; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.addresses (
    id bigint NOT NULL,
    address_line1 character varying(255),
    address_line2 character varying(255),
    address_type character varying(255),
    city character varying(255),
    country character varying(255),
    customer_id bigint,
    is_default integer,
    postal_code character varying(255),
    state character varying(255),
    CONSTRAINT addresses_is_default_check CHECK ((is_default = ANY (ARRAY[0, 1])))
);


ALTER TABLE demo.addresses OWNER TO postgres;

--
-- Name: addresses_id_seq; Type: SEQUENCE; Schema: demo; Owner: postgres
--

ALTER TABLE demo.addresses ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME demo.addresses_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 20
);


--
-- Name: authors; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.authors (
    id bigint NOT NULL,
    created_by character varying(255),
    created_on timestamp(6) without time zone,
    updated_on timestamp(6) without time zone,
    biography character varying(255),
    birth_date timestamp(0) without time zone,
    image_url character varying(255),
    name character varying(255)
);


ALTER TABLE demo.authors OWNER TO postgres;

--
-- Name: authors_id_seq; Type: SEQUENCE; Schema: demo; Owner: postgres
--

ALTER TABLE demo.authors ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME demo.authors_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 20
);


--
-- Name: book_types; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.book_types (
    id bigint NOT NULL,
    created_on timestamp(6) without time zone,
    description character varying(255),
    name character varying(255) NOT NULL,
    updated_on timestamp(6) without time zone
);


ALTER TABLE demo.book_types OWNER TO postgres;

--
-- Name: book_types_id_seq; Type: SEQUENCE; Schema: demo; Owner: postgres
--

ALTER TABLE demo.book_types ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME demo.book_types_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 20
);


--
-- Name: books; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.books (
    id bigint NOT NULL,
    author character varying(255),
    book_type_id numeric(19,0),
    condition_id numeric(19,0),
    cover_image_url character varying(255),
    created_by character varying(255),
    created_on timestamp(6) without time zone,
    description character varying(255),
    genre_id numeric(19,0),
    is_available integer,
    is_bestseller integer,
    is_featured integer,
    is_new_arrival integer,
    is_user_listing integer,
    is_user_offer integer,
    isbn character varying(255),
    last_restock_date timestamp(0) without time zone,
    listing_status bigint,
    name character varying(255),
    offer_source_id numeric(19,0),
    price numeric(38,2),
    publish_date timestamp(0) without time zone,
    publisher_id numeric(19,0),
    quantity bigint,
    seller_id numeric(19,0),
    summary character varying(1000),
    updated_on timestamp(6) without time zone,
    year bigint,
    search_text character varying(1000),
    CONSTRAINT books_is_available_check CHECK ((is_available = ANY (ARRAY[0, 1]))),
    CONSTRAINT books_is_bestseller_check CHECK ((is_bestseller = ANY (ARRAY[0, 1]))),
    CONSTRAINT books_is_featured_check CHECK ((is_featured = ANY (ARRAY[0, 1]))),
    CONSTRAINT books_is_new_arrival_check CHECK ((is_new_arrival = ANY (ARRAY[0, 1]))),
    CONSTRAINT books_is_user_listing_check CHECK ((is_user_listing = ANY (ARRAY[0, 1]))),
    CONSTRAINT books_is_user_offer_check CHECK ((is_user_offer = ANY (ARRAY[0, 1])))
);


ALTER TABLE demo.books OWNER TO postgres;

--
-- Name: books_cover; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.books_cover (
    book_id numeric(19,0) NOT NULL,
    cover_image bytea,
    created_on timestamp(6) without time zone,
    updated_on timestamp(6) without time zone
);


ALTER TABLE demo.books_cover OWNER TO postgres;

--
-- Name: books_id_seq; Type: SEQUENCE; Schema: demo; Owner: postgres
--

ALTER TABLE demo.books ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME demo.books_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 20
);


--
-- Name: conditions; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.conditions (
    id bigint NOT NULL,
    created_on timestamp(6) without time zone,
    description character varying(255),
    name character varying(255) NOT NULL,
    updated_on timestamp(6) without time zone
);


ALTER TABLE demo.conditions OWNER TO postgres;

--
-- Name: conditions_id_seq; Type: SEQUENCE; Schema: demo; Owner: postgres
--

ALTER TABLE demo.conditions ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME demo.conditions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 20
);


--
-- Name: customers_id_seq; Type: SEQUENCE; Schema: demo; Owner: postgres
--

ALTER TABLE demo.customers ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME demo.customers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 20
);


--
-- Name: demo_table; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.demo_table (
    id integer NOT NULL,
    name character varying(20)
);


ALTER TABLE demo.demo_table OWNER TO postgres;

--
-- Name: dr$books_text_idx$b; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo."dr$books_text_idx$b" (
    min_docid numeric,
    max_docid numeric,
    status numeric
);


ALTER TABLE demo."dr$books_text_idx$b" OWNER TO postgres;

--
-- Name: dr$books_text_idx$c; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo."dr$books_text_idx$c" (
    dml_scn numeric,
    dml_id numeric,
    dml_op numeric,
    dml_rid character(255)
);


ALTER TABLE demo."dr$books_text_idx$c" OWNER TO postgres;

--
-- Name: dr$books_text_idx$i; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo."dr$books_text_idx$i" (
    token_text character varying(255) NOT NULL,
    token_type bigint NOT NULL,
    token_first bigint NOT NULL,
    token_last bigint NOT NULL,
    token_count bigint NOT NULL,
    token_info bytea
);


ALTER TABLE demo."dr$books_text_idx$i" OWNER TO postgres;

--
-- Name: dr$books_text_idx$k; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo."dr$books_text_idx$k" (
    docid numeric,
    textkey character(255)
);


ALTER TABLE demo."dr$books_text_idx$k" OWNER TO postgres;

--
-- Name: dr$books_text_idx$n; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo."dr$books_text_idx$n" (
    nlt_docid numeric(38,0) NOT NULL,
    nlt_mark character(1) NOT NULL
);


ALTER TABLE demo."dr$books_text_idx$n" OWNER TO postgres;

--
-- Name: dr$books_text_idx$q; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo."dr$books_text_idx$q" (
    dml_id numeric,
    dml_op numeric,
    dml_rid character(255)
);


ALTER TABLE demo."dr$books_text_idx$q" OWNER TO postgres;

--
-- Name: dr$books_text_idx$u; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo."dr$books_text_idx$u" (
    rid character(255) NOT NULL
);


ALTER TABLE demo."dr$books_text_idx$u" OWNER TO postgres;

--
-- Name: genres; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.genres (
    id bigint NOT NULL,
    created_on timestamp(6) without time zone,
    description character varying(255),
    name character varying(255) NOT NULL,
    updated_on timestamp(6) without time zone
);


ALTER TABLE demo.genres OWNER TO postgres;

--
-- Name: genres_id_seq; Type: SEQUENCE; Schema: demo; Owner: postgres
--

ALTER TABLE demo.genres ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME demo.genres_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 20
);


--
-- Name: mv_bestsellers; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.mv_bestsellers (
    id numeric(19,0) NOT NULL,
    name character varying(255),
    author character varying(255),
    price numeric(38,2),
    isbn character varying(255)
);


ALTER TABLE demo.mv_bestsellers OWNER TO postgres;

--
-- Name: mv_book_inventory_status; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.mv_book_inventory_status (
    id numeric(19,0) NOT NULL,
    name character varying(255),
    author character varying(255),
    isbn character varying(255),
    quantity numeric(10,0),
    price numeric(38,2),
    is_available numeric(1,0),
    genre character varying(255),
    publisher character varying(255)
);


ALTER TABLE demo.mv_book_inventory_status OWNER TO postgres;

--
-- Name: mv_book_sales_analytics; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.mv_book_sales_analytics (
    book_id numeric(19,0) NOT NULL,
    book_name character varying(255),
    author character varying(255),
    genre_name character varying(255),
    publisher_name character varying(255),
    times_ordered double precision,
    total_quantity_sold double precision,
    gross_revenue double precision,
    total_discounts double precision,
    net_revenue double precision,
    avg_selling_price double precision,
    first_sale_date timestamp(6) without time zone,
    last_sale_date timestamp(6) without time zone
);


ALTER TABLE demo.mv_book_sales_analytics OWNER TO postgres;

--
-- Name: mv_customer_shopping_patterns; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.mv_customer_shopping_patterns (
    customer_id numeric(19,0) NOT NULL,
    customer_name character varying(511),
    genre_name character varying(255) NOT NULL,
    purchase_count double precision,
    books_purchased double precision,
    avg_book_price double precision,
    first_purchase_date timestamp(6) without time zone,
    last_purchase_date timestamp(6) without time zone
);


ALTER TABLE demo.mv_customer_shopping_patterns OWNER TO postgres;

--
-- Name: offers; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.offers (
    id bigint NOT NULL,
    admin_notes character varying(1000),
    offered_price numeric(38,2),
    book_author character varying(255),
    book_comment character varying(1000),
    book_id numeric(19,0),
    book_price numeric(38,2),
    book_title character varying(255) NOT NULL,
    book_type_id numeric(19,0),
    condition_id numeric(19,0),
    contact_email character varying(255),
    contact_name character varying(255),
    contact_phone character varying(255),
    created_on timestamp(6) without time zone,
    customer_id numeric(19,0),
    description character varying(1000),
    front_url character varying(255),
    genre_id numeric(19,0),
    is_approved integer,
    is_rejected integer,
    isbn character varying(255),
    offer_status bigint,
    processed_at timestamp(6) without time zone,
    processed_by numeric(19,0),
    publisher_id numeric(19,0),
    rejection_reason character varying(1000),
    status bigint NOT NULL,
    summary character varying(1000),
    updated_on timestamp(6) without time zone,
    CONSTRAINT offers_is_approved_check CHECK ((is_approved = ANY (ARRAY[0, 1]))),
    CONSTRAINT offers_is_rejected_check CHECK ((is_rejected = ANY (ARRAY[0, 1])))
);


ALTER TABLE demo.offers OWNER TO postgres;

--
-- Name: offers_id_seq; Type: SEQUENCE; Schema: demo; Owner: postgres
--

ALTER TABLE demo.offers ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME demo.offers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 20
);


--
-- Name: order_history; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.order_history (
    order_id numeric(19,0) NOT NULL,
    customer_id numeric(19,0),
    order_date timestamp(0) without time zone,
    original_status character varying(255),
    new_status character varying(255),
    status_change_date timestamp(6) without time zone NOT NULL,
    total_amount numeric(38,2),
    tracking_number character varying(255),
    notes character varying(255),
    change_reason character varying(255)
);


ALTER TABLE demo.order_history OWNER TO postgres;

--
-- Name: order_items; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.order_items (
    id bigint NOT NULL,
    book_id numeric(19,0),
    book_price numeric(38,2) NOT NULL,
    discount numeric(38,2),
    order_id numeric(19,0),
    price numeric(38,2),
    quantity bigint
);


ALTER TABLE demo.order_items OWNER TO postgres;

--
-- Name: order_items_id_seq; Type: SEQUENCE; Schema: demo; Owner: postgres
--

ALTER TABLE demo.order_items ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME demo.order_items_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 20
);


--
-- Name: orders; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.orders (
    id bigint NOT NULL,
    address_id numeric(19,0),
    cancellation_reason character varying(255),
    cancelled_date timestamp(0) without time zone,
    created_on timestamp(6) without time zone NOT NULL,
    customer_id numeric(19,0),
    delivered_date timestamp(0) without time zone,
    delivery_date timestamp(0) without time zone,
    notes character varying(255),
    order_date timestamp(0) without time zone,
    order_status bigint NOT NULL,
    shipped_date timestamp(0) without time zone,
    shipping_address character varying(255),
    status character varying(255),
    total_amount numeric(38,2),
    tracking_number character varying(255)
);


ALTER TABLE demo.orders OWNER TO postgres;

--
-- Name: orders_id_seq; Type: SEQUENCE; Schema: demo; Owner: postgres
--

ALTER TABLE demo.orders ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME demo.orders_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 20
);


--
-- Name: password_reset_tokens; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.password_reset_tokens (
    id bigint NOT NULL,
    expiry_date timestamp(6) without time zone,
    token character varying(255),
    used integer,
    customer_id numeric(19,0),
    CONSTRAINT password_reset_tokens_used_check CHECK ((used = ANY (ARRAY[0, 1])))
);


ALTER TABLE demo.password_reset_tokens OWNER TO postgres;

--
-- Name: password_reset_tokens_id_seq; Type: SEQUENCE; Schema: demo; Owner: postgres
--

ALTER TABLE demo.password_reset_tokens ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME demo.password_reset_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 20
);


--
-- Name: persistent_logins; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.persistent_logins (
    username character varying(64) NOT NULL,
    series character varying(64) NOT NULL,
    token character varying(64) NOT NULL,
    last_used timestamp(6) without time zone NOT NULL
);


ALTER TABLE demo.persistent_logins OWNER TO postgres;

--
-- Name: publishers; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.publishers (
    id bigint NOT NULL,
    created_on timestamp(6) without time zone,
    description character varying(255),
    name character varying(255) NOT NULL,
    updated_on timestamp(6) without time zone,
    website character varying(255)
);


ALTER TABLE demo.publishers OWNER TO postgres;

--
-- Name: publishers_id_seq; Type: SEQUENCE; Schema: demo; Owner: postgres
--

ALTER TABLE demo.publishers ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME demo.publishers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 20
);


--
-- Name: reference_data; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.reference_data (
    id bigint NOT NULL,
    created_by character varying(255),
    created_on timestamp(6) without time zone,
    updated_on timestamp(6) without time zone,
    description character varying(255),
    is_active integer NOT NULL,
    name character varying(255),
    type character varying(255),
    CONSTRAINT reference_data_is_active_check CHECK ((is_active = ANY (ARRAY[0, 1]))),
    CONSTRAINT reference_data_type_check CHECK (((type)::text = ANY ((ARRAY['PUBLISHER'::character varying, 'BOOK_TYPE'::character varying, 'GENRE'::character varying, 'CONDITION'::character varying])::text[])))
);


ALTER TABLE demo.reference_data OWNER TO postgres;

--
-- Name: reference_data_id_seq; Type: SEQUENCE; Schema: demo; Owner: postgres
--

ALTER TABLE demo.reference_data ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME demo.reference_data_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 20
);


--
-- Name: shopping_cart_items; Type: TABLE; Schema: demo; Owner: postgres
--

CREATE TABLE demo.shopping_cart_items (
    id bigint NOT NULL,
    book_id numeric(19,0),
    customer_id numeric(19,0),
    is_wishlist_item integer,
    quantity bigint,
    CONSTRAINT shopping_cart_items_is_wishlist_item_check CHECK ((is_wishlist_item = ANY (ARRAY[0, 1])))
);


ALTER TABLE demo.shopping_cart_items OWNER TO postgres;

--
-- Name: shopping_cart_items_id_seq; Type: SEQUENCE; Schema: demo; Owner: postgres
--

ALTER TABLE demo.shopping_cart_items ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME demo.shopping_cart_items_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 20
);


--
-- Name: addresses addresses_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.addresses
    ADD CONSTRAINT addresses_pkey PRIMARY KEY (id);


--
-- Name: authors authors_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.authors
    ADD CONSTRAINT authors_pkey PRIMARY KEY (id);


--
-- Name: book_types book_types_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.book_types
    ADD CONSTRAINT book_types_pkey PRIMARY KEY (id);


--
-- Name: books_cover books_cover_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.books_cover
    ADD CONSTRAINT books_cover_pkey PRIMARY KEY (book_id);


--
-- Name: books books_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.books
    ADD CONSTRAINT books_pkey PRIMARY KEY (id);


--
-- Name: conditions conditions_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.conditions
    ADD CONSTRAINT conditions_pkey PRIMARY KEY (id);


--
-- Name: customers customers_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.customers
    ADD CONSTRAINT customers_pkey PRIMARY KEY (id);


--
-- Name: demo_table demo_table_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.demo_table
    ADD CONSTRAINT demo_table_pkey PRIMARY KEY (id);


--
-- Name: dr$books_text_idx$n dr$books_text_idx$n_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo."dr$books_text_idx$n"
    ADD CONSTRAINT "dr$books_text_idx$n_pkey" PRIMARY KEY (nlt_docid);


--
-- Name: dr$books_text_idx$u dr$books_text_idx$u_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo."dr$books_text_idx$u"
    ADD CONSTRAINT "dr$books_text_idx$u_pkey" PRIMARY KEY (rid);


--
-- Name: genres genres_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.genres
    ADD CONSTRAINT genres_pkey PRIMARY KEY (id);


--
-- Name: offers offers_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.offers
    ADD CONSTRAINT offers_pkey PRIMARY KEY (id);


--
-- Name: order_history order_history_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.order_history
    ADD CONSTRAINT order_history_pkey PRIMARY KEY (order_id, status_change_date);


--
-- Name: order_items order_items_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.order_items
    ADD CONSTRAINT order_items_pkey PRIMARY KEY (id);


--
-- Name: orders orders_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (id);


--
-- Name: password_reset_tokens password_reset_tokens_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (id);


--
-- Name: persistent_logins persistent_logins_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.persistent_logins
    ADD CONSTRAINT persistent_logins_pkey PRIMARY KEY (series);


--
-- Name: publishers publishers_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.publishers
    ADD CONSTRAINT publishers_pkey PRIMARY KEY (id);


--
-- Name: reference_data reference_data_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.reference_data
    ADD CONSTRAINT reference_data_pkey PRIMARY KEY (id);


--
-- Name: shopping_cart_items shopping_cart_items_pkey; Type: CONSTRAINT; Schema: demo; Owner: postgres
--

ALTER TABLE ONLY demo.shopping_cart_items
    ADD CONSTRAINT shopping_cart_items_pkey PRIMARY KEY (id);


--
-- Name: dr$books_text_idx$kd; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE UNIQUE INDEX "dr$books_text_idx$kd" ON demo."dr$books_text_idx$k" USING btree (docid, textkey);


--
-- Name: dr$books_text_idx$kr; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE UNIQUE INDEX "dr$books_text_idx$kr" ON demo."dr$books_text_idx$k" USING btree (textkey, docid);


--
-- Name: dr$books_text_idx$x; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX "dr$books_text_idx$x" ON demo."dr$books_text_idx$i" USING btree (token_text, token_type, token_first, token_last, token_count);


--
-- Name: idx_addresses_customer_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_addresses_customer_id ON demo.addresses USING btree (customer_id);


--
-- Name: idx_books_book_type_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_books_book_type_id ON demo.books USING btree (book_type_id);


--
-- Name: idx_books_condition_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_books_condition_id ON demo.books USING btree (condition_id);


--
-- Name: idx_books_genre_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_books_genre_id ON demo.books USING btree (genre_id);


--
-- Name: idx_books_publisher_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_books_publisher_id ON demo.books USING btree (publisher_id);


--
-- Name: idx_cart_items_book_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_cart_items_book_id ON demo.shopping_cart_items USING btree (book_id);


--
-- Name: idx_cart_items_customer_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_cart_items_customer_id ON demo.shopping_cart_items USING btree (customer_id);


--
-- Name: idx_offers_book_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_offers_book_id ON demo.offers USING btree (book_id);


--
-- Name: idx_offers_book_type_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_offers_book_type_id ON demo.offers USING btree (book_type_id);


--
-- Name: idx_offers_condition_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_offers_condition_id ON demo.offers USING btree (condition_id);


--
-- Name: idx_offers_customer_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_offers_customer_id ON demo.offers USING btree (customer_id);


--
-- Name: idx_offers_genre_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_offers_genre_id ON demo.offers USING btree (genre_id);


--
-- Name: idx_offers_publisher_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_offers_publisher_id ON demo.offers USING btree (publisher_id);


--
-- Name: idx_order_items_book_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_order_items_book_id ON demo.order_items USING btree (book_id);


--
-- Name: idx_order_items_order_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_order_items_order_id ON demo.order_items USING btree (order_id);


--
-- Name: idx_orders_customer_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_orders_customer_id ON demo.orders USING btree (customer_id);


--
-- Name: idx_password_reset_customer_id; Type: INDEX; Schema: demo; Owner: postgres
--

CREATE INDEX idx_password_reset_customer_id ON demo.password_reset_tokens USING btree (customer_id);


--
-- Name: books trg_book_search_text; Type: TRIGGER; Schema: demo; Owner: postgres
--

CREATE TRIGGER trg_book_search_text BEFORE INSERT OR UPDATE OF author, name, isbn ON demo.books FOR EACH ROW EXECUTE FUNCTION demo."trg_book_search_text$books"();


--
-- PostgreSQL database dump complete
--

