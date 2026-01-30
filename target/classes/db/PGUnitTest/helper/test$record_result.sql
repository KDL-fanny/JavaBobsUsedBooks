CREATE OR REPLACE PROCEDURE test.test$record_result(test_name text, test_passed boolean, error_msg text DEFAULT NULL) AS 
$$
BEGIN
	INSERT INTO test_results VALUES (test_name, test_passed, error_msg);
END;
$$ LANGUAGE plpgsql;
