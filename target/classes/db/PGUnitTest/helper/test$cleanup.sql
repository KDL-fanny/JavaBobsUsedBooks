CREATE OR REPLACE PROCEDURE test.test$cleanup() LANGUAGE plpgsql as $$
BEGIN

	TRUNCATE TABLE test_results;
END;
$$;