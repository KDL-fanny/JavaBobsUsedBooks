
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