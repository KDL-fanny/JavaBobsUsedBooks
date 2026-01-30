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
$$
