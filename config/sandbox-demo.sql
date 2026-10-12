-- Synthetic fixture for an explicitly authorized disposable database only.
-- The test administrator creates a separate SELECT-only role; never grant it writes.
CREATE TABLE public.poc_records (id bigint PRIMARY KEY, status text NOT NULL);
INSERT INTO public.poc_records VALUES (1, 'open'), (2, 'open'), (3, 'closed'), (4, 'pending');
