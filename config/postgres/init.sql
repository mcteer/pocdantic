CREATE TABLE public.poc_records (id integer PRIMARY KEY, status text NOT NULL);
INSERT INTO public.poc_records VALUES (1, 'healthy'), (2, 'review');
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON public.poc_records FROM PUBLIC;
