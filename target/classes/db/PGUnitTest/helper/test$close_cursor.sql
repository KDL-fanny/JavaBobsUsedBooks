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