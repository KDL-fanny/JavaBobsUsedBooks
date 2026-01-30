CREATE OR REPLACE FUNCTION get_name_by_id(p_id integer)
RETURNS varchar
LANGUAGE plpgsql
AS $$
DECLARE
    v_name varchar;
BEGIN
    SELECT name INTO v_name
    FROM demo_table
    WHERE id = p_id;
    
    RETURN v_name;
END;
$$;