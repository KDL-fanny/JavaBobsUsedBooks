CREATE OR REPLACE PROCEDURE test.test_calculate_customer_loyalty_score()
LANGUAGE plpgsql AS $$
DECLARE
    -- Variables for test execution and results
    v_test_case text;
    v_expected_score numeric(10,2);
    v_actual_score numeric(10,2);
    v_customer_id bigint;
    v_order_id bigint;
    v_days_ago interval;
BEGIN
    -- Initialize
    CALL test$initialize();

    -- Arrange: Create temporary tables for testing
    CREATE TEMPORARY TABLE temp_customers (
        id bigint PRIMARY KEY,
        first_name varchar(255),
        last_name varchar(255),
        email varchar(255),
        created_on timestamp
    );
    
    CREATE TEMPORARY TABLE temp_orders (
        id bigint PRIMARY KEY,
        customer_id bigint,
        total_amount numeric(10,2),
        created_on timestamp,
        status varchar(20)
    );

    -- Insert test data
    -- Customer with no orders
    INSERT INTO temp_customers (id, first_name, last_name, email, created_on)
    VALUES (1, 'John', 'Doe', 'john@example.com', CURRENT_TIMESTAMP);
    
    -- Customer with multiple orders over time
    INSERT INTO temp_customers (id, first_name, last_name, email, created_on)
    VALUES (2, 'Jane', 'Smith', 'jane@example.com', CURRENT_TIMESTAMP - interval '1 year');
    
    -- Customer with recent high-value orders
    INSERT INTO temp_customers (id, first_name, last_name, email, created_on)
    VALUES (3, 'Bob', 'Johnson', 'bob@example.com', CURRENT_TIMESTAMP - interval '6 months');
    
    -- Customer with old orders only
    INSERT INTO temp_customers (id, first_name, last_name, email, created_on)
    VALUES (4, 'Alice', 'Williams', 'alice@example.com', CURRENT_TIMESTAMP - interval '2 years');

    -- Orders for customer 2 (multiple orders over time)
    v_days_ago := interval '300 days';
    INSERT INTO temp_orders (id, customer_id, total_amount, created_on, status)
    VALUES (101, 2, 50.00, CURRENT_TIMESTAMP - v_days_ago, 'DELIVERED');
    
    v_days_ago := interval '200 days';
    INSERT INTO temp_orders (id, customer_id, total_amount, created_on, status)
    VALUES (102, 2, 75.50, CURRENT_TIMESTAMP - v_days_ago, 'DELIVERED');
    
    v_days_ago := interval '100 days';
    INSERT INTO temp_orders (id, customer_id, total_amount, created_on, status)
    VALUES (103, 2, 120.25, CURRENT_TIMESTAMP - v_days_ago, 'DELIVERED');
    
    v_days_ago := interval '10 days';
    INSERT INTO temp_orders (id, customer_id, total_amount, created_on, status)
    VALUES (104, 2, 200.00, CURRENT_TIMESTAMP - v_days_ago, 'DELIVERED');

    -- Orders for customer 3 (recent high-value orders)
    v_days_ago := interval '5 days';
    INSERT INTO temp_orders (id, customer_id, total_amount, created_on, status)
    VALUES (201, 3, 500.00, CURRENT_TIMESTAMP - v_days_ago, 'DELIVERED');
    
    v_days_ago := interval '2 days';
    INSERT INTO temp_orders (id, customer_id, total_amount, created_on, status)
    VALUES (202, 3, 750.00, CURRENT_TIMESTAMP - v_days_ago, 'DELIVERED');

    -- Orders for customer 4 (old orders only)
    v_days_ago := interval '500 days';
    INSERT INTO temp_orders (id, customer_id, total_amount, created_on, status)
    VALUES (301, 4, 100.00, CURRENT_TIMESTAMP - v_days_ago, 'DELIVERED');
    
    v_days_ago := interval '450 days';
    INSERT INTO temp_orders (id, customer_id, total_amount, created_on, status)
    VALUES (302, 4, 150.00, CURRENT_TIMESTAMP - v_days_ago, 'DELIVERED');

    -- Test Cases

    -- Test Case 1: Customer with no orders
    BEGIN
        v_test_case := 'Customer with no orders';
        v_customer_id := 1;
        
        -- Act: Calculate loyalty score
        v_actual_score := calculate_customer_loyalty_score(v_customer_id);
        v_expected_score := 0; -- Expect zero for customer with no orders
        
        -- Assert
        ASSERT v_actual_score = v_expected_score;
        CALL test$record_result(v_test_case, true);
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, 
            format('Expected: %s, Got: %s, Error: %s', 
                   v_expected_score, COALESCE(v_actual_score::text, 'NULL'), SQLERRM));
    END;

    -- Test Case 2: Customer with multiple orders over time
    BEGIN
        v_test_case := 'Customer with multiple orders over time';
        v_customer_id := 2;
        
        -- Act: Calculate loyalty score
        v_actual_score := calculate_customer_loyalty_score(v_customer_id);
        
        -- Assert: Score should be positive and reflect order history
        -- Formula: (order_count * 10) + (total_spent / 100) + (days_since_first_order / 10) - (days_since_last_order / 10)
        -- Expected: (4 * 10) + (445.75 / 100) + (300 / 10) - (10 / 10) = 40 + 4.46 + 30 - 1 = 73.46
        v_expected_score := 73.46;
        
        -- Allow small difference due to timestamp calculations
        ASSERT abs(v_actual_score - v_expected_score) < 5;
        CALL test$record_result(v_test_case, true);
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, 
            format('Expected: around %s, Got: %s, Error: %s', 
                   v_expected_score, COALESCE(v_actual_score::text, 'NULL'), SQLERRM));
    END;

    -- Test Case 3: Customer with recent high-value orders
    BEGIN
        v_test_case := 'Customer with recent high-value orders';
        v_customer_id := 3;
        
        -- Act: Calculate loyalty score
        v_actual_score := calculate_customer_loyalty_score(v_customer_id);
        
        -- Assert: Score should be high due to high value and recency
        -- Formula: (order_count * 10) + (total_spent / 100) + (days_since_first_order / 10) - (days_since_last_order / 10)
        -- Expected: (2 * 10) + (1250 / 100) + (5 / 10) - (2 / 10) = 20 + 12.5 + 0.5 - 0.2 = 32.8
        v_expected_score := 32.8;
        
        -- Allow small difference due to timestamp calculations
        ASSERT abs(v_actual_score - v_expected_score) < 5;
        CALL test$record_result(v_test_case, true);
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, 
            format('Expected: around %s, Got: %s, Error: %s', 
                   v_expected_score, COALESCE(v_actual_score::text, 'NULL'), SQLERRM));
    END;

    -- Test Case 4: Customer with old orders only
    BEGIN
        v_test_case := 'Customer with old orders only';
        v_customer_id := 4;
        
        -- Act: Calculate loyalty score
        v_actual_score := calculate_customer_loyalty_score(v_customer_id);
        
        -- Assert: Score should be lower due to old orders
        -- Formula: (order_count * 10) + (total_spent / 100) + (days_since_first_order / 10) - (days_since_last_order / 10)
        -- Expected: (2 * 10) + (250 / 100) + (500 / 10) - (450 / 10) = 20 + 2.5 + 50 - 45 = 27.5
        v_expected_score := 27.5;
        
        -- Allow small difference due to timestamp calculations
        ASSERT abs(v_actual_score - v_expected_score) < 5;
        CALL test$record_result(v_test_case, true);
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, 
            format('Expected: around %s, Got: %s, Error: %s', 
                   v_expected_score, COALESCE(v_actual_score::text, 'NULL'), SQLERRM));
    END;

    -- Test Case 5: Edge case - Negative customer ID
    BEGIN
        v_test_case := 'Edge case - Negative customer ID';
        v_customer_id := -1;
        
        -- Act: Calculate loyalty score
        v_actual_score := calculate_customer_loyalty_score(v_customer_id);
        v_expected_score := 0; -- Expect zero for invalid customer ID
        
        -- Assert
        ASSERT v_actual_score = v_expected_score;
        CALL test$record_result(v_test_case, true);
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, 
            format('Expected: %s, Got: %s, Error: %s', 
                   v_expected_score, COALESCE(v_actual_score::text, 'NULL'), SQLERRM));
    END;

    -- Test Case 6: Edge case - Very large customer ID
    BEGIN
        v_test_case := 'Edge case - Very large customer ID';
        v_customer_id := 9999999999;
        
        -- Act: Calculate loyalty score
        v_actual_score := calculate_customer_loyalty_score(v_customer_id);
        v_expected_score := 0; -- Expect zero for non-existent customer ID
        
        -- Assert
        ASSERT v_actual_score = v_expected_score;
        CALL test$record_result(v_test_case, true);
    EXCEPTION WHEN OTHERS THEN
        CALL test$record_result(v_test_case, false, 
            format('Expected: %s, Got: %s, Error: %s', 
                   v_expected_score, COALESCE(v_actual_score::text, 'NULL'), SQLERRM));
    END;

    -- Print test results
    CALL test$report_result();

    -- Cleanup
    CALL test$drop_temp_table('temp_customers');
    CALL test$drop_temp_table('temp_orders');
    CALL test$cleanup();

EXCEPTION WHEN OTHERS THEN
    -- Ensure cleanup on critical failure
    CALL test$drop_temp_table('temp_customers');
    CALL test$drop_temp_table('temp_orders');
    CALL test$cleanup();
    
    -- Record the error
    CALL test$record_result('Unexpected error in test execution', false, SQLERRM);
    
    -- Report results even in case of error
    CALL test$report_result();
    
    RAISE EXCEPTION 'Critical test failure: %', SQLERRM;
END;
$$;