ALTER TABLE targets ADD COLUMN status TEXT NOT NULL DEFAULT 'pending';
UPDATE targets SET status = 'done' WHERE last_scanned_at IS NOT NULL;
