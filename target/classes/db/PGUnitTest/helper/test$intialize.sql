CREATE OR REPLACE PROCEDURE test.test$initialize() LANGUAGE plpgsql as $$
BEGIN
    -- Try to create the table
    CREATE TEMPORARY TABLE test_results (
        test_name text,
        passed boolean,
        error_message text
    );
    RAISE NOTICE 'New test_results table created';
EXCEPTION 
    WHEN duplicate_table THEN
        -- If table already exists, truncate it
        TRUNCATE TABLE test_results;
        RAISE NOTICE 'Existing test_results table truncated';
END;
$$;