CREATE OR REPLACE FUNCTION add_numbers(
    number1 numeric,
    number2 numeric)
RETURNS numeric
AS $$
    SELECT number1 + number2;
$$ LANGUAGE sql;
