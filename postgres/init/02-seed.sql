-- Portal Cautivo — Datos iniciales

-- Grupo RADIUS base para usuarios del portal cautivo
INSERT INTO radgroupreply (groupname, attribute, op, value)
VALUES
    ('captive-portal-users', 'Session-Timeout',    ':=', '28800'),
    ('captive-portal-users', 'Idle-Timeout',       ':=', '1800'),
    ('captive-portal-users', 'WISPr-Bandwidth-Max-Up',   ':=', '5120000'),
    ('captive-portal-users', 'WISPr-Bandwidth-Max-Down', ':=', '10240000')
ON CONFLICT DO NOTHING;

-- Usuario de prueba (cédula válida de prueba: 1713175071)
-- password: test-uuid-1234-5678-abcd (se usa en radcheck)
INSERT INTO usuarios_portal (cedula, nombres, apellidos, email, radius_password)
VALUES ('1713175071', 'Usuario', 'Prueba', 'prueba@example.com', 'a1b2c3d4-e5f6-7890-abcd-ef1234567890')
ON CONFLICT (cedula) DO NOTHING;

INSERT INTO radcheck (username, attribute, op, value)
VALUES ('1713175071', 'Cleartext-Password', ':=', 'a1b2c3d4-e5f6-7890-abcd-ef1234567890')
ON CONFLICT DO NOTHING;

INSERT INTO radusergroup (username, groupname, priority)
VALUES ('1713175071', 'captive-portal-users', 1)
ON CONFLICT DO NOTHING;
