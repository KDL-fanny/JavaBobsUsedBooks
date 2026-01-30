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

    -- Arrange: test data preparation

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
