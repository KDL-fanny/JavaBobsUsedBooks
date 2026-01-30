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
