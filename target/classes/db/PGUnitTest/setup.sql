
alter role postgres in database demodb set search_path="$user", demo, public, test;
-- run helper functions 


-- clean up
drop schema if exists test cascade;
drop table if exists demo.demo_table;
drop procedure if exists demo.sp_get_records;

-- Create objects in default demo schema
set search_path=demo;

create schema test;

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

CREATE OR REPLACE PROCEDURE test.test$record_result(test_name text, test_passed boolean, error_msg text DEFAULT NULL) AS 
$$
BEGIN
    INSERT INTO test_results VALUES (test_name, test_passed, error_msg);
END;
$$ LANGUAGE plpgsql;



CREATE OR REPLACE PROCEDURE test.test$report_result() LANGUAGE plpgsql as $$
DECLARE
    v_test_case text;
    v_total_tests integer := 0;
    v_passed_tests integer := 0;
BEGIN
    -- Report Results
    SELECT count(*), count(*) FILTER (WHERE passed)
    INTO v_total_tests, v_passed_tests
    FROM test_results;
    
    RAISE NOTICE 'Test Summary: % of % tests passed', v_passed_tests, v_total_tests;

    -- Display failed tests
    IF v_passed_tests < v_total_tests THEN
        RAISE NOTICE 'Failed Tests:';
        FOR v_test_case IN 
            SELECT format('- %s: %s', v_test_case, error_message) 
            FROM test_results 
            WHERE NOT passed 
        LOOP
            RAISE NOTICE '%', v_test_case;
        END LOOP;
    END IF;
END;
$$;

CREATE OR REPLACE PROCEDURE test.test$close_cursor(INOUT p_cursor REFCURSOR)
LANGUAGE plpgsql AS $$
BEGIN
    -- Attempt to close cursor
    BEGIN
        CLOSE p_cursor;
    EXCEPTION WHEN others THEN
        -- Ignore error if cursor is already closed
        NULL;
    END;
    
    -- Set cursor to NULL
    p_cursor := NULL;
END;
$$;

CREATE OR REPLACE PROCEDURE test.test$cleanup() LANGUAGE plpgsql as $$
BEGIN

    TRUNCATE TABLE test_results;
END;
$$;


CREATE OR REPLACE PROCEDURE test.test$drop_temp_table(table_name text) AS $$
DECLARE
    temp_schema text;
BEGIN
    -- Find the temporary schema name for the current session
    SELECT nspname INTO temp_schema
    FROM pg_namespace
    WHERE oid =  pg_my_temp_schema();
    -- Check if the table exists in the temporary schema
    IF EXISTS (
        SELECT 1
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = temp_schema
            AND c.relname = table_name
            AND c.relkind = 'r' -- 'r' indicates a regular table (in this context, a temp table)
    ) THEN
        -- Construct the dynamic SQL to drop the table
        EXECUTE format('DROP TABLE %I', table_name);
    END IF;
END;
$$ LANGUAGE plpgsql;


-- Run all test starts with "test_"
CREATE OR REPLACE PROCEDURE test.test$run_all() LANGUAGE 'plpgsql' AS $$
declare
    -- skip_prefix constant name = 'test$';
    test_prefix constant name = 'test\_';
    test_schema_name constant name = 'test';
    proc pg_catalog.pg_proc%rowtype;
    started timestamptz;
begin

    raise notice 'Time(m)   Name';
    for proc in select p.* from pg_catalog.pg_proc p join pg_catalog.pg_namespace n on pronamespace = n.oid 
                where nspname = test_schema_name and proname like test_prefix||'%' order by proname
    loop
        started = clock_timestamp();
        execute format('call %s.%s();', test_schema_name, proc.proname);
        raise notice '% %.%()', to_char(clock_timestamp() - started, 'MI:SS:MS'), test_schema_name, proc.proname;
    end loop;  

end 
$$;


create table demo_table (id int primary key, name varchar(20));
insert into demo_table values (1,'test1'),(2,'test2');

CREATE OR REPLACE FUNCTION add_numbers(
    number1 numeric,
    number2 numeric)
RETURNS numeric
AS $$
    SELECT number1 + number2;
$$ LANGUAGE sql;


CREATE OR REPLACE FUNCTION get_name_by_id(p_id integer)
RETURNS varchar
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



CREATE PROCEDURE sp_get_records(INOUT par_my_cursor refcursor)
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

CREATE OR REPLACE FUNCTION delete_records_by_name(
    p_name VARCHAR
)
RETURNS INTEGER
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

CREATE OR REPLACE PROCEDURE test.test_add_numbers() LANGUAGE plpgsql as $$
DECLARE
    -- Variables for test execution and results
    v_test_case text;

BEGIN

    -- Initialize
    call test$initialize();

    -- Arrange
    -- Act
    -- Assert
    
    BEGIN
        v_test_case := 'Basic positive numbers';
        ASSERT add_numbers(2, 3) = 5;
        CALL test$record_result(v_test_case, true);
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, SQLERRM);
    END;

    BEGIN
        v_test_case := 'Decimal numbers';
        ASSERT add_numbers(2.5, 3.5) = 6.0;
        CALL test$record_result(v_test_case, true);
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, SQLERRM);
    END;

    BEGIN
        v_test_case := 'NULL handling';
        ASSERT add_numbers(NULL, 5) IS NULL;
        CALL test$record_result(v_test_case, true);
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, SQLERRM);
    END;

    -- Print test results
    CALL test$report_result();

    -- Cleanup
    call test$cleanup();

EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Test suite failed: %', SQLERRM;
END;
$$;

CREATE OR REPLACE PROCEDURE test.test_delete_records_by_name()
LANGUAGE plpgsql AS $$
DECLARE
    -- Variables for test execution and results
    v_test_case text;
    v_deleted_count integer;
    v_expected_count integer;
    v_actual_count integer;
BEGIN
    -- Initialize
    CALL test$initialize();

    -- Arrange: Set up test data
    CREATE TEMPORARY TABLE IF NOT EXISTS demo_table (
        id integer PRIMARY KEY,
        name varchar
    );

    -- Insert test data with comments explaining each scenario
    INSERT INTO demo_table (id, name) VALUES
        (1, 'John Doe'),                    -- Standard case - single record
        (2, 'John Doe'),                    -- Duplicate name
        (3, NULL),                          -- NULL name
        (4, ''),                            -- Empty string
        (5, 'Name with spaces'),            -- Spaces in name
        (6, 'Special-#@$-chars'),           -- Special characters
        (7, '张三'),                         -- Unicode characters
        (8, 'John Doe');                    -- Another duplicate for multiple delete test

    -- Act & Assert: Test different scenarios
    BEGIN
        -- Test Case 1: Delete multiple records with same name
        v_test_case := 'Delete multiple records with same name';
        v_deleted_count := delete_records_by_name('John Doe');
        v_expected_count := 3;
        
        IF v_deleted_count = v_expected_count THEN
            CALL test$record_result(v_test_case, true);
        ELSE
            CALL test$record_result(v_test_case, false, 
                format('Expected %s records deleted, but got %s', v_expected_count, v_deleted_count));
        END IF;
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, SQLERRM);
    END;

    BEGIN
        -- Test Case 2: Delete non-existent name
        v_test_case := 'Delete non-existent name';
        v_deleted_count := delete_records_by_name('NonExistentName');
        
        IF v_deleted_count = 0 THEN
            CALL test$record_result(v_test_case, true);
        ELSE
            CALL test$record_result(v_test_case, false, 
                'Expected 0 records deleted for non-existent name');
        END IF;
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, SQLERRM);
    END;

    BEGIN
        -- Test Case 3: Delete record with special characters
        v_test_case := 'Delete record with special characters';
        v_deleted_count := delete_records_by_name('Special-#@$-chars');
        
        IF v_deleted_count = 1 THEN
            CALL test$record_result(v_test_case, true);
        ELSE
            CALL test$record_result(v_test_case, false, 
                'Expected 1 record deleted for special characters');
        END IF;
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, SQLERRM);
    END;

    BEGIN
        -- Test Case 4: Delete record with Unicode characters
        v_test_case := 'Delete record with Unicode characters';
        v_deleted_count := delete_records_by_name('张三');
        
        IF v_deleted_count = 1 THEN
            CALL test$record_result(v_test_case, true);
        ELSE
            CALL test$record_result(v_test_case, false, 
                'Expected 1 record deleted for Unicode characters');
        END IF;
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, SQLERRM);
    END;

    BEGIN
        -- Test Case 5: Delete with NULL input
        v_test_case := 'Delete with NULL input';
        BEGIN
            v_deleted_count := delete_records_by_name(NULL);
            -- Should not reach here as function should throw exception
            CALL test$record_result(v_test_case, false, 
                'Expected exception for NULL input, but none was thrown');
        EXCEPTION WHEN OTHERS THEN
            -- Exception is expected behavior
            CALL test$record_result(v_test_case, true);
        END;
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, SQLERRM);
    END;

    BEGIN
        -- Test Case 6: Delete record with empty string
        v_test_case := 'Delete record with empty string';
        v_deleted_count := delete_records_by_name('');
        
        IF v_deleted_count = 1 THEN
            CALL test$record_result(v_test_case, true);
        ELSE
            CALL test$record_result(v_test_case, false, 
                'Expected 1 record deleted for empty string');
        END IF;
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, SQLERRM);
    END;

    -- Verify remaining records count
    BEGIN
        v_test_case := 'Verify final record count';
        SELECT COUNT(*) INTO v_actual_count FROM demo_table;
        v_expected_count := 2; -- Should only have NULL name and 'Name with spaces' left
        
        IF v_actual_count = v_expected_count THEN
            CALL test$record_result(v_test_case, true);
        ELSE
            CALL test$record_result(v_test_case, false, 
                format('Expected %s records remaining, but got %s', v_expected_count, v_actual_count));
        END IF;
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, SQLERRM);
    END;

    -- Print test results
    CALL test$report_result();

    -- Cleanup
    CALL test$drop_temp_table('demo_table');
    CALL test$cleanup();

EXCEPTION 
    WHEN OTHERS THEN
        -- Log any unexpected errors
        CALL test$record_result('Unexpected error in test execution', false, SQLERRM);
        
        -- Cleanup
        CALL test$drop_temp_table('demo_table');
        CALL test$cleanup();
END;
$$;

CREATE OR REPLACE PROCEDURE test.test_get_name_by_id() 
LANGUAGE plpgsql AS $$
DECLARE
    -- Variables for test execution and results
    v_test_case text;
    v_actual_result varchar;
    
    -- Constants for test data
    c_valid_id constant integer := 1;
    c_valid_name constant varchar := 'John Doe';
    c_max_id constant integer := 2147483647;  -- Max integer value
BEGIN
    
    -- Initialize
    call test$initialize();

    -- Arrange: Set up test data
    BEGIN
        CREATE TEMPORARY TABLE IF NOT EXISTS demo_table (
            id integer PRIMARY KEY,
            name varchar
        );

        -- Insert test data with comments explaining each scenario
        INSERT INTO demo_table (id, name) VALUES
            (c_valid_id, c_valid_name),           -- Standard case
            (2, 'Jane Smith'),                    -- Another valid case
            (3, NULL),                            -- NULL name
            (4, ''),                              -- Empty string name
            (5, 'Name with spaces'),              -- Spaces in name
            (6, 'Special-#@$-chars'),             -- Special characters
            (7, '张三'),                          -- Unicode characters
            (c_max_id, 'Max ID');                 -- Boundary case
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Failed to set up test data: %', SQLERRM;
    END;

    -- Test Cases

    -- 1. Happy Path Tests
    BEGIN
        v_test_case := 'Happy Path: Valid ID returns correct name';
        v_actual_result := get_name_by_id(c_valid_id);
        ASSERT v_actual_result = c_valid_name;
        CALL test$record_result(v_test_case, true);
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, 
            format('Expected: %s, Got: %s, Error: %s', 
                   c_valid_name, COALESCE(v_actual_result::text, 'NULL'), SQLERRM));
    END;

    -- 2. Edge Cases
    BEGIN
        v_test_case := 'Edge Case: NULL name in database';
        v_actual_result := get_name_by_id(3);
        ASSERT v_actual_result IS NULL;
        CALL test$record_result(v_test_case, true);
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false,
            format('Expected: NULL, Got: %s, Error: %s', 
                   COALESCE(v_actual_result::text, 'NULL'), SQLERRM));
    END;

    BEGIN
        v_test_case := 'Edge Case: Empty string name';
        v_actual_result := get_name_by_id(4);
        ASSERT v_actual_result = '';
        CALL test$record_result(v_test_case, true);
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false,
            format('Expected empty string, Got: %s, Error: %s', 
                   COALESCE(v_actual_result::text, 'NULL'), SQLERRM));
    END;

    -- 3. Error Cases
    BEGIN
        v_test_case := 'Error Case: Non-existent ID';
        v_actual_result := get_name_by_id(999);
        ASSERT v_actual_result IS NULL;
        CALL test$record_result(v_test_case, true);
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false,
            format('Expected: NULL, Got: %s, Error: %s', 
                   COALESCE(v_actual_result::text, 'NULL'), SQLERRM));
    END;

    -- 4. Special Cases
    BEGIN
        v_test_case := 'Special Case: Unicode characters';
        v_actual_result := get_name_by_id(7);
        ASSERT v_actual_result = '张三';
        CALL test$record_result(v_test_case, true);
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false,
            format('Expected: 张三, Got: %s, Error: %s', 
                   COALESCE(v_actual_result::text, 'NULL'), SQLERRM));
    END;

    BEGIN
        v_test_case := 'Special Case: Maximum integer ID';
        v_actual_result := get_name_by_id(c_max_id);
        ASSERT v_actual_result = 'Max ID';
        CALL test$record_result(v_test_case, true);
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false,
            format('Expected: Max ID, Got: %s, Error: %s', 
                   COALESCE(v_actual_result::text, 'NULL'), SQLERRM));
    END;

    -- Print test results
    CALL test$report_result();

    -- Cleanup
    CALL test$drop_temp_table('demo_table');
    call test$cleanup();

EXCEPTION WHEN OTHERS THEN
    -- Ensure cleanup on critical failure
    CALL test$drop_temp_table('demo_table');
    CALL test$cleanup();
    RAISE EXCEPTION 'Critical test failure: %', SQLERRM;
END;
$$;

CREATE OR REPLACE PROCEDURE test.test_sp_get_records()
LANGUAGE plpgsql AS $$
DECLARE
    v_test_case text;
    v_result_cursor REFCURSOR;
    v_expected_cursor REFCURSOR;
    v_result demo_table%ROWTYPE;
    v_expected demo_table%ROWTYPE;
    v_match BOOLEAN;
    v_count INTEGER;
BEGIN
    -- Initialize test environment
    CALL test$initialize();

    -- Create temporary table for expected results
    CREATE TEMPORARY TABLE temp_expected_results AS 
    SELECT * FROM demo_table;

    -- -- Create temporary table for actual reslts,with same structure as expected results
    CREATE TEMPORARY TABLE temp_actual_results AS 
    SELECT * FROM demo_table WITH NO DATA;

    -- Test 1: Happy Path - Basic Data Retrieval
    BEGIN
        v_test_case := 'Happy Path - Verify all records are retrieved correctly';
        
        -- Act: Call the procedure
        CALL sp_get_records(v_result_cursor);
        
        -- Fetch and insert records from cursor
        LOOP
            FETCH v_result_cursor INTO v_result;
            EXIT WHEN NOT FOUND;

            INSERT INTO temp_actual_results 
            VALUES (v_result.*);
        END LOOP;

        -- Assert: Compare results
        v_match := EXISTS (
            SELECT * FROM temp_actual_results
            EXCEPT
            SELECT * FROM temp_expected_results
        ) OR EXISTS (
            SELECT * FROM temp_expected_results
            EXCEPT
            SELECT * FROM temp_actual_results
        );
        
        CALL test$record_result(
            v_test_case,
            NOT v_match,
            CASE WHEN v_match THEN 'Results do not match expected data' END
        );
        
        -- Clean up cursor
        CALL test$close_cursor(v_result_cursor);
        
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, SQLERRM);
    END;

    -- Test 2: Data Consistency Test
    BEGIN
        v_test_case := 'Consistency - Multiple calls return same results';
        
        -- First call
        CALL sp_get_records(v_result_cursor);

        CREATE TEMPORARY TABLE temp_first_result AS
        SELECT * FROM demo_table WITH NO DATA;

        -- Fetch and insert records from cursor
        LOOP
            FETCH v_result_cursor INTO v_result;
            EXIT WHEN NOT FOUND;

            INSERT INTO temp_actual_results 
            VALUES (v_result.*);
        END LOOP;

        CALL test$close_cursor(v_result_cursor);
        
        -- Second call
        CALL sp_get_records(v_result_cursor);
        CREATE TEMPORARY TABLE temp_second_result AS
        SELECT * FROM demo_table WITH NO DATA;

        -- Fetch and insert records from cursor
        LOOP
            FETCH v_result_cursor INTO v_result;
            EXIT WHEN NOT FOUND;

            INSERT INTO temp_actual_results 
            VALUES (v_result.*);
        END LOOP;

        CALL test$close_cursor(v_result_cursor);
        
        -- Compare results
        v_match := EXISTS (
            SELECT * FROM temp_first_result
            EXCEPT
            SELECT * FROM temp_second_result
        );
        
        CALL test$record_result(
            v_test_case,
            NOT v_match,
            CASE WHEN v_match THEN 'Inconsistent results between calls' END
        );
        
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, SQLERRM);
    END;

    -- Cleanup
    CALL test$drop_temp_table('temp_expected_results');
    CALL test$drop_temp_table('temp_actual_results');
    CALL test$drop_temp_table('temp_first_result');
    CALL test$drop_temp_table('temp_second_result');

    -- Report results
    CALL test$report_result();
    
    -- Final cleanup
    CALL test$cleanup();

EXCEPTION WHEN OTHERS THEN
    -- Ensure cursors are closed in case of error
    IF v_result_cursor IS NOT NULL THEN
        CALL test$close_cursor(v_result_cursor);
    END IF;
    IF v_expected_cursor IS NOT NULL THEN
        CALL test$close_cursor(v_expected_cursor);
    END IF;
    
    -- Clean up temporary tables
    CALL test$drop_temp_table('temp_expected_results');
    CALL test$drop_temp_table('temp_actual_results');
    CALL test$drop_temp_table('temp_first_result');
    CALL test$drop_temp_table('temp_second_result');
    
    -- Record the error
    CALL test$record_result('Unexpected error in test execution', false, SQLERRM);
    
    -- Report results even in case of error
    CALL test$report_result();
    CALL test$cleanup();
    
    RAISE;
END;
$$;








