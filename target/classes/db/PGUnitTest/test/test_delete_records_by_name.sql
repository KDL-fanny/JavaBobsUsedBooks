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
