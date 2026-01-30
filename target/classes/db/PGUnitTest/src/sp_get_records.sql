
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
