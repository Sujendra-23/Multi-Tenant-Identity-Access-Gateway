-- The permission catalogue. Resources and actions are deliberately coarse:
-- a vocabulary small enough that a tenant admin can reason about it, with
-- wildcards ("billing:*", "*:*") available for the broad grants.

BEGIN;

INSERT INTO permissions (resource, action, description) VALUES
    ('*',        '*',      'Full access to every resource and action'),
    ('users',    'read',   'View users in the tenant'),
    ('users',    'write',  'Create and update users'),
    ('users',    'delete', 'Remove users'),
    ('roles',    'read',   'View roles and their grants'),
    ('roles',    'write',  'Create roles and change their grants'),
    ('roles',    'delete', 'Remove roles'),
    ('billing',  'read',   'View invoices and plan details'),
    ('billing',  'write',  'Change plan and payment details'),
    ('audit',    'read',   'Read the tenant audit log'),
    ('sessions', 'read',   'View active sessions'),
    ('sessions', 'revoke', 'Terminate sessions'),
    ('reports',  'read',   'View reports'),
    ('reports',  'export', 'Export report data'),
    ('settings', 'read',   'View tenant settings'),
    ('settings', 'write',  'Change tenant settings')
ON CONFLICT (resource, action) DO NOTHING;

COMMIT;
