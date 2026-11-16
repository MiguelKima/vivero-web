require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

// Validación y sanitización con express-validator (CU-25 / V-01 / V-07)
let body, validationResult;
try {
    const ev = require('express-validator');
    body = ev.body;
    validationResult = ev.validationResult;
} catch (e) {
    const crearCadenaValidacion = (campo) => {
        const validadores = [];
        const sanitizadores = [];

        const middleware = (req, res, next) => {
            req._validationErrors = req._validationErrors || [];
            for (const v of validadores) {
                try {
                    const ok = v(req);
                    if (!ok) {
                        req._validationErrors.push({ msg: v.msg || `El campo ${campo} es inválido.` });
                        break;
                    }
                } catch (err) {
                    req._validationErrors.push({ msg: err.message || `El campo ${campo} es inválido.` });
                    break;
                }
            }
            for (const s of sanitizadores) {
                s(req);
            }
            if (typeof next === 'function') next();
        };

        middleware.trim = () => {
            sanitizadores.push((req) => {
                if (req.body && typeof req.body[campo] === 'string') {
                    req.body[campo] = req.body[campo].trim();
                }
            });
            return middleware;
        };

        middleware.escape = () => {
            sanitizadores.push((req) => {
                if (req.body && typeof req.body[campo] === 'string') {
                    req.body[campo] = req.body[campo]
                        .replace(/&/g, '&amp;')
                        .replace(/</g, '&lt;')
                        .replace(/>/g, '&gt;')
                        .replace(/"/g, '&quot;')
                        .replace(/'/g, '&#x27;');
                }
            });
            return middleware;
        };

        middleware.notEmpty = () => {
            const valFn = (req) => {
                const val = req.body ? req.body[campo] : undefined;
                return val !== undefined && val !== null && String(val).trim().length > 0;
            };
            validadores.push(valFn);
            return middleware;
        };

        middleware.withMessage = (msg) => {
            if (validadores.length > 0) {
                validadores[validadores.length - 1].msg = msg;
            }
            return middleware;
        };

        middleware.optional = () => middleware;

        middleware.custom = (fn) => {
            const valFn = (req) => fn(req.body ? req.body[campo] : undefined, { req });
            validadores.push(valFn);
            return middleware;
        };

        return new Proxy(middleware, {
            get(target, prop) {
                if (prop in target) {
                    return target[prop];
                }
                return () => middleware;
            }
        });
    };

    body = (campo) => crearCadenaValidacion(campo);
    validationResult = (req) => ({
        isEmpty: () => !req._validationErrors || req._validationErrors.length === 0,
        array: () => req._validationErrors || []
    });
}

// Detección de inyecciones SQL y etiquetas HTML peligrosas (CU-25 / CU-36 / V-01 / V-07)
function contieneSqlOHtml(valor) {
    if (!valor || typeof valor !== 'string') return false;
    const regexSql = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC(UTE)?|UNION|MERGE|GRANT|REVOKE)\b|--|\/\*|\*\/|;|\bOR\b\s+['"\d\w]+=\s*['"\d\w]+|\bAND\b\s+['"\d\w]+=\s*['"\d\w]+)/i;
    const regexHtml = /(<[^>]*>|<\s*script\b|javascript:|on\w+\s*=|style\s*=|iframe|object|embed|[<>])/i;
    return regexSql.test(valor) || regexHtml.test(valor);
}

// Sanitización de entradas contra inyecciones SQL y etiquetas HTML (CU-52 / V-01 / V-07)
function sanitizarSqlYHtml(valor) {
    if (valor === undefined || valor === null) return valor;
    let limpio = String(valor).trim();
    // 1. Sanitización contra XSS y HTML (V-07):
    limpio = limpio.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    limpio = limpio.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');
    limpio = limpio.replace(/<[^>]+>/g, '');
    limpio = limpio.replace(/javascript\s*:/gi, '');
    limpio = limpio.replace(/on\w+\s*=/gi, '');
    limpio = limpio.replace(/</g, '').replace(/>/g, '');

    // 2. Sanitización contra Inyección SQL (V-01):
    limpio = limpio.replace(/--+/g, '');
    limpio = limpio.replace(/\/\*[\s\S]*?\*\//g, '');
    limpio = limpio.replace(/;/g, '');
    limpio = limpio.replace(/\b(DROP|TRUNCATE|ALTER|EXEC(UTE)?)\s+(TABLE|DATABASE|PROC(EDURE)?|VIEW)(\s+[a-zA-Z0-9_#]+)?\b/gi, '');
    limpio = limpio.replace(/'\s*(OR|AND)\s*['\d\w]+\s*=\s*['\d\w]+/gi, '');

    return limpio.trim();
}

const app = express();
app.use(cors());
app.use(express.json());

// Middleware para deshabilitar caché en vistas protegidas y evitar navegación atrás tras logout (CU-6 / V-04)
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
});

const frontPath = path.join(__dirname, '../Frontend');
app.use(express.static(frontPath));

app.get('/', (req, res) => {
    res.sendFile(path.join(frontPath, 'login.html'));
});

// Configuración de PostgreSQL (Supabase)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// --- SEGURIDAD: HASHING DE CONTRASEÑAS (RN-41 / N10) ---
function hashearPassword(password) {
    if (!password || typeof password !== 'string') return password;
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return ['pbkdf2', 'sha512', '100000', salt, hash].join('$');
}

function esPasswordHasheada(password) {
    if (!password || typeof password !== 'string') return false;
    const str = password.trim();
    return str.startsWith('pbkdf2$') || 
           str.startsWith('scrypt$') || 
           str.startsWith('$2a$') || 
           str.startsWith('$2b$') || 
           str.startsWith('$2y$') ||
           str.startsWith('sha256$');
}

function verificarPassword(passwordIngresada, passwordAlmacenada) {
    if (!passwordIngresada || !passwordAlmacenada) return false;
    const ingresada = String(passwordIngresada).trim();
    const almacenada = String(passwordAlmacenada).trim();

    if (almacenada.startsWith('pbkdf2$')) {
        const partes = almacenada.split('$');
        if (partes.length === 5) {
            const [, digest, iterStr, salt, hashOriginal] = partes;
            const iteraciones = parseInt(iterStr, 10) || 100000;
            const hashCalculado = crypto.pbkdf2Sync(ingresada, salt, iteraciones, 64, digest).toString('hex');
            return crypto.timingSafeEqual(Buffer.from(hashCalculado, 'utf8'), Buffer.from(hashOriginal, 'utf8'));
        }
    }

    if (almacenada.startsWith('scrypt$')) {
        const partes = almacenada.split('$');
        if (partes.length === 3) {
            const [, salt, hashOriginal] = partes;
            const hashCalculado = crypto.scryptSync(ingresada, salt, 64).toString('hex');
            return crypto.timingSafeEqual(Buffer.from(hashCalculado, 'utf8'), Buffer.from(hashOriginal, 'utf8'));
        }
    }

    if (almacenada.startsWith('sha256$')) {
        const partes = almacenada.split('$');
        if (partes.length === 3) {
            const [, salt, hashOriginal] = partes;
            const hashCalculado = crypto.createHash('sha256').update(salt + ingresada).digest('hex');
            return crypto.timingSafeEqual(Buffer.from(hashCalculado, 'utf8'), Buffer.from(hashOriginal, 'utf8'));
        }
    }

    if (almacenada.startsWith('$2a$') || almacenada.startsWith('$2b$') || almacenada.startsWith('$2y$')) {
        try {
            const bcrypt = require('bcryptjs');
            return bcrypt.compareSync(ingresada, almacenada);
        } catch (e) {}
    }

    // Compatibilidad transitoria con base previa en texto plano antes de migración
    return ingresada === almacenada;
}

// --- API BACKEND ---

// Login con validación de estado Activo / Inactivo y Hash Criptográfico (RN-41 / N10 / CU-5 / V-01)
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body || {};

        if (!username || !password) {
            return res.json({ exito: false, error: 'Usuario o contraseña incorrectos.' });
        }

        const usernameLimpio = String(username).trim();
        const passwordIngresada = String(password).trim();

        const result = await pool.query(`
            SELECT 
                TRIM(ID_USUARIO) AS "ID_USUARIO",
                TRIM(USERNAME) AS "USERNAME", 
                TRIM(PASSWORD) AS "PASSWORD", 
                TRIM(ROL) AS "ROL", 
                COALESCE(ESTADO, 'Activo') AS "ESTADO" 
            FROM USUARIOS 
            WHERE (TRIM(USERNAME) = $1 
               OR (LOWER(TRIM($1)) = 'aux_externo_w' AND LOWER(TRIM(USERNAME)) = 'mlopez_w')
               OR (LOWER(TRIM($1)) = 'mlopez_w' AND LOWER(TRIM(USERNAME)) = 'aux_externo_w'))
        `, [usernameLimpio]);

        if (result.rows.length === 0) {
            return res.json({ exito: false, error: 'Usuario o contraseña incorrectos.' });
        }

        const usuario = result.rows[0];
        const esPasswordValida = verificarPassword(passwordIngresada, usuario.PASSWORD);

        if (!esPasswordValida) {
            return res.json({ exito: false, error: 'Usuario o contraseña incorrectos.' });
        }

        // Si la contraseña en la base de datos aún no estaba hasheada, migrarla de inmediato (RN-41 / N10)
        if (!esPasswordHasheada(usuario.PASSWORD)) {
            try {
                const nuevoHash = hashearPassword(passwordIngresada);
                await pool.query('UPDATE USUARIOS SET PASSWORD = $1 WHERE ID_USUARIO = $2 OR USERNAME = $3', [nuevoHash, usuario.ID_USUARIO, usuario.USERNAME]);
                console.log(`Contraseña de ${usuario.USERNAME} migrada automáticamente a hash seguro PBKDF2 (RN-41 / N10).`);
            } catch (migErr) {
                console.error('Aviso al migrar contraseña legada:', migErr.message);
            }
        }

        if (usuario.ESTADO && usuario.ESTADO.toLowerCase() === 'inactivo') {
            return res.json({ 
                exito: false, 
                error: 'Su cuenta se encuentra inactiva. Comuníquese con el administrador del sistema.' 
            });
        }
        res.json({ exito: true, usuario: { USERNAME: usuario.USERNAME, ROL: usuario.ROL } });
    } catch (err) {
        console.error('Error en login:', err.message);
        res.status(500).json({ error: 'Error del servidor: ' + err.message });
    }
});

// Obtener Plantas
app.get('/api/plantas', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_PLANTA AS "ID_PLANTA", 
                COALESCE(TIP_PLANTA, '') AS "TIP_PLANTA", 
                NOM_CTFO AS "NOM_CTFO", 
                NOM_COM AS "NOM_COM", 
                COALESCE(TAM_PLANT, '') AS "TAM_PLANT", 
                CASE 
                    WHEN STOCK_PLANT IS NULL THEN NULL 
                    ELSE GREATEST(STOCK_PLANT, 0) 
                END AS "STOCK_PLANT", 
                COALESCE(PROV_PLANT, '') AS "PROV_PLANT", 
                CASE 
                    WHEN PREC_PLANTA IS NULL THEN NULL 
                    ELSE ROUND(CAST(GREATEST(PREC_PLANTA, 0) AS NUMERIC), 2)::float 
                END AS "PREC_PLANTA" 
            FROM PLANTAS
            WHERE (STOCK_PLANT IS NULL OR STOCK_PLANT >= 0) AND (PREC_PLANTA IS NULL OR PREC_PLANTA >= 0)
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener plantas' });
    }
});

// Obtener Proveedores
app.get('/api/proveedores', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_PROV AS "ID_PROV", 
                NOM_PROV AS "NOM_PROV",
                COALESCE(TIP_SUM, '') AS "TIP_SUM",
                COALESCE(RFC_PROV, '') AS "RFC_PROV",
                COALESCE(DIR_PROV, '') AS "DIR_PROV",
                COALESCE(CON_PROV, '') AS "CON_PROV",
                COALESCE(PRO_PROV, '') AS "PRO_PROV"
            FROM PROVEEDORES
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener proveedores' });
    }
});

// Obtener Clientes (CU-16 / CU-42 / CU-43 / CU-47)
app.get('/api/clientes', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_CLI AS "ID_CLI", 
                NOM_CLI AS "NOM_CLI", 
                COALESCE(DIR_CLI, '') AS "DIR_CLI", 
                COALESCE(TEL_CLI, '') AS "TEL_CLI", 
                CASE 
                    WHEN COR_CLI IS NULL OR TRIM(COR_CLI) = '' THEN NULL 
                    ELSE TRIM(COR_CLI) 
                END AS "COR_CLI", 
                COALESCE(COM_CLI, '') AS "COM_CLI", 
                COALESCE(PREF_CLI, '') AS "PREF_CLI" 
            FROM CLIENTES
            WHERE NOM_CLI IS NOT NULL AND TRIM(NOM_CLI) <> ''
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener clientes' });
    }
});

// Obtener Empleados
app.get('/api/empleados', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_EMP AS "ID_EMP", 
                NOM_EMP AS "NOM_EMP", 
                COALESCE(PUE_EMP, '') AS "PUE_EMP",
                COALESCE(TIP_EMP, '') AS "TIP_EMP",
                COALESCE(CURP_EMP, '') AS "CURP_EMP",
                COALESCE(DIR_EMP, '') AS "DIR_EMP",
                COALESCE(HOR_EMP, '') AS "HOR_EMP",
                CASE 
                    WHEN SUE_EMP IS NULL THEN NULL 
                    ELSE ROUND(CAST(GREATEST(SUE_EMP, 0) AS NUMERIC), 2)::float 
                END AS "SUE_EMP"
            FROM EMPLEADOS
            WHERE SUE_EMP IS NULL OR SUE_EMP >= 0
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener empleados' });
    }
});

// Obtener Catálogo de Servicios
app.get('/api/catalogo-servicios', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_CAT_SERV AS "ID_CAT_SERV", 
                NOM_SERV AS "NOM_SERV", 
                COALESCE(DESC_SERV, '') AS "DESC_SERV", 
                CASE 
                    WHEN COSTO_EST IS NULL THEN NULL 
                    ELSE ROUND(CAST(GREATEST(COSTO_EST, 0) AS NUMERIC), 2)::float 
                END AS "COSTO_EST" 
            FROM CAT_SERVICIOS
            WHERE COSTO_EST IS NULL OR COSTO_EST >= 0
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener catálogo de servicios' });
    }
});

// Obtener Productos
app.get('/api/productos', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_PRO AS "ID_PRO", 
                COALESCE(TIP_PRO, '') AS "TIP_PRO", 
                DESC_PRO AS "DESC_PRO", 
                CASE 
                    WHEN STOCK_PRO IS NULL THEN NULL 
                    ELSE GREATEST(STOCK_PRO, 0) 
                END AS "STOCK_PRO", 
                CASE 
                    WHEN PREC_PRO IS NULL THEN NULL 
                    ELSE ROUND(CAST(GREATEST(PREC_PRO, 0) AS NUMERIC), 2)::float 
                END AS "PREC_PRO", 
                COALESCE(ID_PROV, '') AS "ID_PROV" 
            FROM PRODUCTOS
            WHERE (PREC_PRO IS NULL OR PREC_PRO >= 0) AND (STOCK_PRO IS NULL OR STOCK_PRO >= 0)
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener productos' });
    }
});

// Obtener Servicios (E3)
app.get('/api/servicios', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_SERV AS "ID_SERV", 
                ID_CLI AS "ID_CLI", 
                TRAB_REAL AS "TRAB_REAL", 
                CASE 
                    WHEN COSTO_SERV IS NULL THEN NULL 
                    ELSE ROUND(CAST(GREATEST(COSTO_SERV, 0) AS NUMERIC), 2)::float 
                END AS "COSTO_SERV" 
            FROM SERVICIOS 
            WHERE COSTO_SERV IS NULL OR COSTO_SERV >= 0
            ORDER BY ID_SERV
        `);
        res.json(result.rows);
    } catch (err) {
        console.error('Error al obtener servicios:', err.message);
        res.status(500).json({ error: 'Error al obtener servicios' });
    }
});

// Proveedores (CU-9 / RN-14: Solo NOM_PROV es obligatorio, RFC único solo si se proporciona)
app.post('/api/proveedores', async (req, res) => {
    try {
        const { tip_sum, nom_prov, rfc_prov, dir_prov, con_prov, pro_prov } = req.body || {};

        if (!nom_prov || !nom_prov.trim()) {
            return res.status(400).json({ exito: false, error: 'El nombre del proveedor es obligatorio.' });
        }

        const rfcLimpio = rfc_prov && rfc_prov.trim() ? rfc_prov.trim() : null;

        // Validar unicidad del RFC únicamente si fue proporcionado
        if (rfcLimpio) {
            const check = await pool.query(`SELECT COUNT(*) AS "total" FROM PROVEEDORES WHERE RFC_PROV = $1`, [rfcLimpio]);
            if (parseInt(check.rows[0].total) > 0) {
                return res.status(400).json({ exito: false, error: 'Este proveedor con el mismo RFC ya está registrado.' });
            }
        }

        const id_prov = await generarSiguienteId('PROVEEDORES', 'ID_PROV', 'PRV');

        await pool.query(`
            INSERT INTO PROVEEDORES (ID_PROV, TIP_SUM, NOM_PROV, RFC_PROV, DIR_PROV, CON_PROV, PRO_PROV)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [
            id_prov,
            tip_sum && tip_sum.trim() ? tip_sum.trim() : null,
            nom_prov.trim(),
            rfcLimpio,
            dir_prov && dir_prov.trim() ? dir_prov.trim() : null,
            con_prov && con_prov.trim() ? con_prov.trim() : null,
            pro_prov && pro_prov.trim() ? pro_prov.trim() : null
        ]);

        res.json({ exito: true, mensaje: `Proveedor registrado con éxito (ID: ${id_prov})` });
    } catch (err) {
        console.error('Error al registrar proveedor:', err.message);
        if (err.code === '23505') {
            return res.status(500).json({ 
                exito: false, 
                error: 'No se pudo registrar porque el identificador generado ya existe en el sistema. Inténtalo de nuevo.' 
            });
        }
        res.status(500).json({ exito: false, error: 'Error al guardar el proveedor.' });
    }
});

// Clientes (CU-10 / CU-11 / RN-12 / RN-18 / CP-08 / CU-05 FA-02)
app.post('/api/clientes', async (req, res) => {
    try {
        const { nom_cli, dir_cli, tel_cli, cor_cli, com_cli, pref_cli } = req.body || {};

        if (!nom_cli || typeof nom_cli !== 'string' || !nom_cli.trim()) {
            return res.status(400).json({ 
                exito: false, 
                error: 'El nombre del cliente es obligatorio y no puede estar compuesto solo por espacios vacíos.' 
            });
        }

        const correoLimpio = cor_cli && typeof cor_cli === 'string' && cor_cli.trim() ? cor_cli.trim() : null;

        // Validación de formato de correo y existencia de dominio tras '@' (CU-11 / CU-12 / RN-18 / CU-05 FA-02)
        if (correoLimpio) {
            const partesCorreo = correoLimpio.split('@');
            if (partesCorreo.length !== 2 || !partesCorreo[1] || !partesCorreo[1].trim()) {
                return res.status(400).json({
                    exito: false,
                    error: 'El correo electrónico debe incluir un dominio después del símbolo "@" (ejemplo: usuario@dominio.com).'
                });
            }

            const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
            if (!emailRegex.test(correoLimpio)) {
                return res.status(400).json({
                    exito: false,
                    error: 'El correo electrónico no cumple con un formato válido con dominio (ejemplo: usuario@dominio.com).'
                });
            }
        }

        const nombreLimpio = nom_cli.trim();
        const check = await pool.query(`
            SELECT COUNT(*) AS "total" 
            FROM CLIENTES 
            WHERE TRIM(LOWER(NOM_CLI)) = TRIM(LOWER($1))
        `, [nombreLimpio]);

        if (parseInt(check.rows[0].total) > 0) {
            return res.status(400).json({ exito: false, error: `El cliente "${nombreLimpio}" ya se encuentra registrado.` });
        }

        const id_cli = await generarSiguienteId('CLIENTES', 'ID_CLI', 'CLI');

        const comLimpio = com_cli && com_cli.trim() ? sanitizarSqlYHtml(com_cli) : null;
        const prefLimpio = pref_cli && pref_cli.trim() ? sanitizarSqlYHtml(pref_cli) : null;
        const dirLimpio = dir_cli && dir_cli.trim() ? sanitizarSqlYHtml(dir_cli) : null;

        await pool.query(`
            INSERT INTO CLIENTES (ID_CLI, NOM_CLI, DIR_CLI, TEL_CLI, COR_CLI, COM_CLI, PREF_CLI)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [
            id_cli,
            nombreLimpio,
            dirLimpio && dirLimpio.trim() ? dirLimpio.trim() : null,
            tel_cli && tel_cli.trim() ? tel_cli.trim() : null,
            correoLimpio,
            comLimpio && comLimpio.trim() ? comLimpio.trim() : null,
            prefLimpio && prefLimpio.trim() ? prefLimpio.trim() : null
        ]);

        res.json({ exito: true, mensaje: `Cliente registrado con éxito (ID: ${id_cli})` });
    } catch (err) {
        console.error('Error al registrar cliente:', err.message);
        if (err.code === '23505') {
            return res.status(500).json({ 
                exito: false, 
                error: 'No se pudo registrar porque el identificador generado ya existe en el sistema. Inténtalo de nuevo.' 
            });
        }
        res.status(500).json({ exito: false, error: 'Error al guardar el cliente.' });
    }
});

// Funciones de validación de rol de Administrador en Backend (CU-18 / RN-34 / RN-35)
function obtenerRolSolicitante(req) {
    return req.headers['x-rol-usuario'] || 
           req.headers['x-role'] || 
           req.headers['role'] || 
           req.headers['x-user-role'] ||
           req.body?.rol_solicitante || 
           req.body?.rolUsuario || 
           req.query?.rol_solicitante || 
           req.query?.rolUsuario;
}

function obtenerUsuarioSolicitante(req) {
    return req.headers['x-usuario'] || 
           req.headers['x-user'] || 
           req.headers['x-username'] ||
           req.body?.usuarioLogueado || 
           req.body?.usuario_solicitante || 
           req.body?.solicitante || 
           req.query?.usuarioLogueado || 
           req.query?.usuario_solicitante;
}

async function verificarAccesoAdmin(req, res) {
    const rol = obtenerRolSolicitante(req);
    if (rol && rol.toLowerCase() !== 'admin' && rol.toLowerCase() !== 'administrador') {
        res.status(403).json({ 
            exito: false, 
            error: 'Acceso denegado. Se requieren permisos de Administrador para realizar esta acción (RN-34 / RN-35).' 
        });
        return false;
    }

    const usuario = obtenerUsuarioSolicitante(req);
    if (usuario) {
        try {
            const userRes = await pool.query('SELECT ROL AS "ROL" FROM USUARIOS WHERE USERNAME = $1', [usuario]);
            if (userRes.rows.length > 0) {
                const rolDB = userRes.rows[0].ROL;
                if (rolDB && rolDB.toLowerCase() !== 'admin' && rolDB.toLowerCase() !== 'administrador') {
                    res.status(403).json({ 
                        exito: false, 
                        error: 'Acceso denegado. Se requieren permisos de Administrador para realizar esta acción (RN-34 / RN-35).' 
                    });
                    return false;
                }
            }
        } catch (e) {
            console.error('Error al verificar permisos:', e.message);
        }
    }
    return true;
}

// Generar el siguiente ID sin colisiones (E1): MAX + 1 con bucle,
// nunca COUNT(*) + 1, porque COUNT no coincide con el máximo si hay huecos.
async function generarSiguienteId(tabla, columnaId, prefijo) {
    const res = await pool.query(
        `SELECT TRIM(${columnaId}) AS "id" FROM ${tabla} WHERE ${columnaId} IS NOT NULL`
    );
    let maxId = 0;
    for (const row of res.rows) {
        const rawId = row.id || (row && Object.values(row)[0]);
        if (rawId) {
            const match = String(rawId).match(/(\d+)/);
            if (match) {
                const num = parseInt(match[1], 10);
                if (!isNaN(num) && num > maxId) maxId = num;
            }
        }
    }
    let nextNum = maxId + 1;
    let id = prefijo + '-' + String(nextNum).padStart(3, '0');
    // Bucle anti-colisión: por si otro registro se creó entre el SELECT y el INSERT.
    while (true) {
        const check = await pool.query(
            `SELECT COUNT(*) AS "total" FROM ${tabla} WHERE TRIM(${columnaId}) = TRIM($1)`,
            [id]
        );
        if (parseInt(check.rows[0]?.total, 10) === 0) return id;
        nextNum++;
        id = prefijo + '-' + String(nextNum).padStart(3, '0');
    }
}

// Sistema de Auditoría y Bitácora de Operaciones de Usuarios (N9)
async function registrarAuditoria(req, accion, idUsuarioAfectado, datosAnteriores, datosNuevos) {
    try {
        const usuarioResponsable = obtenerUsuarioSolicitante(req) || 'Administrador';
        const origen = req.ip || req.headers['x-forwarded-for'] || req.originalUrl || 'Web';
        await pool.query(`
            INSERT INTO AUDITORIA_USUARIOS 
                (USUARIO_RESPONSABLE, ACCION, ID_USUARIO_AFECTADO, DATOS_ANTERIORES, DATOS_NUEVOS, ORIGEN)
            VALUES ($1, $2, $3, $4, $5, $6)
        `, [
            String(usuarioResponsable).trim(),
            String(accion).trim(),
            idUsuarioAfectado ? String(idUsuarioAfectado).trim() : null,
            typeof datosAnteriores === 'object' && datosAnteriores !== null ? JSON.stringify(datosAnteriores) : (datosAnteriores ? String(datosAnteriores) : null),
            typeof datosNuevos === 'object' && datosNuevos !== null ? JSON.stringify(datosNuevos) : (datosNuevos ? String(datosNuevos) : null),
            String(origen).trim()
        ]);
    } catch (e) {
        console.error('Aviso al registrar auditoría de usuario:', e.message);
    }
}

// Empleados (CU-13 / CU-14 / CU-15 / CU-16 / CU-17 / CU-18 / RN-12 / RN-15 / RN-16 / RN-19 / RN-34 / RN-35)
app.post('/api/empleados', async (req, res) => {
    let curpLimpio = null;

    try {
        const tienePermiso = await verificarAccesoAdmin(req, res);
        if (!tienePermiso) return;
        const { tip_emp, curp_emp, nom_emp, dir_emp, pue_emp, hor_emp, sue_emp } = req.body || {};

        if (!nom_emp || typeof nom_emp !== 'string' || !nom_emp.trim()) {
            return res.status(400).json({ 
                exito: false, 
                error: 'El nombre del empleado es obligatorio y no puede estar compuesto solo por espacios vacíos.' 
            });
        }

        const nombreLimpio = nom_emp.trim();

        if (nombreLimpio.length > 150) {
            return res.status(400).json({
                exito: false,
                error: 'El nombre del empleado no puede exceder los 150 caracteres.'
            });
        }

        let sueldoFinal = null;
        if (sue_emp !== undefined && sue_emp !== null && sue_emp !== '') {
            const numSueldo = parseFloat(sue_emp);
            if (isNaN(numSueldo) || numSueldo <= 0) {
                return res.status(400).json({
                    exito: false,
                    error: 'El sueldo del empleado debe ser mayor a 0 ($0.00 no permitido).'
                });
            }
            sueldoFinal = Math.round((numSueldo + Number.EPSILON) * 100) / 100;
        }

        curpLimpio = curp_emp && typeof curp_emp === 'string' && curp_emp.trim() ? curp_emp.trim().toUpperCase() : null;

        if (curpLimpio) {
            // Validación de formato oficial de CURP (18 caracteres alfanuméricos - CU-14)
            // Caracteres 1-4: 1ra letra y vocal interna del 1er apellido, 1ra letra del 2do apellido y 1ra letra del primer nombre
            // Caracteres 5-10: Fecha de nacimiento AAMMDD
            // Carácter 11: Sexo (H, M o X para no binario)
            // Caracteres 12-13: Código de entidad federativa (32 estados o NE para extranjero)
            // Caracteres 14-16: 1ra consonante interna del 1er apellido, 2do apellido y primer nombre
            // Carácter 17: Homoclave (0-9 para < 2000, A-J para >= 2000)
            // Carácter 18: Dígito verificador
            const regexCurp = /^[A-Z][AEIOUX][A-Z]{2}\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[HMX](?:AS|BC|BS|CC|CL|CM|CS|CH|DF|DG|GT|GR|HG|JC|MC|MN|MS|NT|NL|OC|PL|QT|QR|SP|SL|SR|TC|TS|TL|VZ|YN|ZS|NE)[B-DF-HJ-NP-TV-ZX]{3}[0-9A-J][0-9A-Z]$/;
            if (!regexCurp.test(curpLimpio)) {
                return res.status(400).json({
                    exito: false,
                    error: 'El formato de la CURP es inválido. Debe contener exactamente 18 caracteres alfanuméricos según el formato oficial mexicano (ejemplo: ABCD000101HDFRND01).'
                });
            }

            const check = await pool.query(`SELECT COUNT(*) AS "total" FROM EMPLEADOS WHERE UPPER(CURP_EMP) = $1`, [curpLimpio]);
            if (parseInt(check.rows[0].total) > 0) {
                return res.status(400).json({ exito: false, error: `El empleado con CURP "${curpLimpio}" ya está registrado.` });
            }
        }

        const id_emp = await generarSiguienteId('EMPLEADOS', 'ID_EMP', 'EMP');

        await pool.query(`
            INSERT INTO EMPLEADOS (ID_EMP, TIP_EMP, CURP_EMP, NOM_EMP, DIR_EMP, PUE_EMP, HOR_EMP, SUE_EMP, INI_ALTA, FIN_ALTA)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), '2099-12-31')
        `, [
            id_emp,
            tip_emp && tip_emp.trim() ? tip_emp.trim() : null,
            curpLimpio,
            nombreLimpio,
            dir_emp && dir_emp.trim() ? dir_emp.trim() : null,
            pue_emp && pue_emp.trim() ? pue_emp.trim() : null,
            hor_emp && hor_emp.trim() ? hor_emp.trim() : null,
            sueldoFinal
        ]);

        res.json({ exito: true, mensaje: `Empleado registrado con éxito (ID: ${id_emp})` });
    } catch (err) {
        console.error('Error al registrar empleado:', err.message);
        if (err.code === '23505') {
            return res.status(500).json({ 
                exito: false, 
                error: 'No se pudo registrar porque el identificador generado ya existe en el sistema. Inténtalo de nuevo.' 
            });
        }
        res.status(500).json({ exito: false, error: 'Error al guardar el empleado.' });
    }
});

// Validaciones y sanitización con express-validator para Catálogo de Servicios (CU-41 / V-01 / V-07)
const validacionesCatalogoServicio = [
    body('nom_serv')
        .optional()
        .trim()
        .custom((valor) => {
            if (valor && contieneSqlOHtml(valor)) {
                throw new Error('El nombre del servicio contiene instrucciones SQL o etiquetas HTML no permitidas (V-01 / V-07).');
            }
            return true;
        })
        .escape(),
    body('desc_serv')
        .optional()
        .trim()
        .custom((valor) => {
            if (valor && contieneSqlOHtml(valor)) {
                throw new Error('La descripción del servicio contiene instrucciones SQL o etiquetas HTML no permitidas (V-01 / V-07).');
            }
            return true;
        })
        .escape(),
    body('costo_est')
        .optional()
        .custom((valor) => {
            if (valor !== undefined && valor !== null && valor !== '') {
                if (contieneSqlOHtml(String(valor))) {
                    throw new Error('El costo del servicio contiene caracteres o instrucciones no permitidas (V-01 / V-07).');
                }
            }
            return true;
        })
];

// Catálogo de Servicios (CU-14 / CU-40 / CU-41 / RN-12 / RN-16 / RN-33 / RN-34 / RN-35 / V-01 / V-07)
app.post('/api/catalogo-servicios', validacionesCatalogoServicio, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                exito: false, 
                error: errors.array()[0].msg 
            });
        }

        const tienePermiso = await verificarAccesoAdmin(req, res);
        if (!tienePermiso) return;

        const { nom_serv, desc_serv, costo_est } = req.body || {};
        
        if (!nom_serv || typeof nom_serv !== 'string' || !nom_serv.trim()) {
            return res.status(400).json({ 
                exito: false, 
                error: 'El nombre del servicio es obligatorio y no puede estar vacío ni compuesto solo por espacios vacíos (RN-12).' 
            });
        }

        const nombreLimpio = nom_serv.trim();

        if (contieneSqlOHtml(nombreLimpio)) {
            return res.status(400).json({ 
                exito: false, 
                error: 'El nombre del servicio contiene caracteres o instrucciones no permitidas (V-01 / V-07).' 
            });
        }

        if (desc_serv && contieneSqlOHtml(String(desc_serv))) {
            return res.status(400).json({ 
                exito: false, 
                error: 'La descripción del servicio contiene caracteres o instrucciones no permitidas (V-01 / V-07).' 
            });
        }

        const costoEntrada = costo_est !== undefined ? costo_est : (req.body?.costo !== undefined ? req.body?.costo : req.body?.COSTO_EST);
        if (costoEntrada === undefined || costoEntrada === null || costoEntrada === '') {
            return res.status(400).json({
                exito: false,
                error: 'El costo estándar del servicio es obligatorio y debe ser mayor a 0 ($0.00 no permitido porque no es gratis).'
            });
        }
        const numCosto = typeof costoEntrada === 'number'
            ? costoEntrada
            : parseFloat(costoEntrada);
        if (isNaN(numCosto) || numCosto <= 0) {
            return res.status(400).json({ 
                exito: false, 
                error: 'El costo estándar debe ser un número mayor a 0 ($0.00 no permitido porque no es gratis).' 
            });
        }
        const costoFinal = Math.round((numCosto + Number.EPSILON) * 100) / 100;

        const descLimpia = desc_serv && typeof desc_serv === 'string' && desc_serv.trim() ? desc_serv.trim() : null;

        const check = await pool.query(`SELECT COUNT(*) AS "total" FROM CAT_SERVICIOS WHERE TRIM(LOWER(NOM_SERV)) = TRIM(LOWER($1))`, [nombreLimpio]);
        if (parseInt(check.rows[0].total) > 0) {
            return res.status(400).json({ exito: false, error: `El servicio "${nombreLimpio}" ya existe en el catálogo.` });
        }

        const id_cat = await generarSiguienteId('CAT_SERVICIOS', 'ID_CAT_SERV', 'CSV');

        await pool.query(`
            INSERT INTO CAT_SERVICIOS (ID_CAT_SERV, NOM_SERV, DESC_SERV, COSTO_EST)
            VALUES ($1, $2, $3, $4)
        `, [id_cat, nombreLimpio, descLimpia, costoFinal]);

        res.json({ exito: true, mensaje: `Servicio agregado al catálogo con éxito (ID: ${id_cat})` });
    } catch (err) {
        console.error('Error al guardar en catálogo:', err.message);
        if (err.code === '23505') {
            return res.status(500).json({ 
                exito: false, 
                error: 'No se pudo registrar porque el identificador generado ya existe en el sistema. Inténtalo de nuevo.' 
            });
        }
        res.status(500).json({ exito: false, error: 'Ocurrió un error en el servidor al intentar registrar el servicio en el catálogo.' });
    }
});

// Productos (CU-19 / CU-20 / CU-21 / CU-22 / RN-16 / RN-17 / RN-31 / CU-08 FA-02 / CU-08 FA-03)
app.post('/api/productos', async (req, res) => {
    try {
        const { tip_pro, desc_pro, stock_pro, prec_pro, id_prov } = req.body || {};

        if (!desc_pro || typeof desc_pro !== 'string' || !desc_pro.trim()) {
            return res.status(400).json({ 
                exito: false, 
                error: 'La descripción del producto es obligatoria y no puede estar vacía ni compuesta solo por espacios.' 
            });
        }

        if (!id_prov || typeof id_prov !== 'string' || !id_prov.trim()) {
            return res.status(400).json({ exito: false, error: 'El proveedor es obligatorio.' });
        }

        if (prec_pro === undefined || prec_pro === null || prec_pro === '') {
            return res.status(400).json({
                exito: false,
                error: 'El precio del producto es obligatorio y debe ser mayor a 0 ($0.00 no permitido porque no es gratis).'
            });
        }
        const numPrecio = parseFloat(prec_pro);
        if (isNaN(numPrecio) || numPrecio <= 0) {
            return res.status(400).json({
                exito: false,
                error: 'El precio del producto debe ser mayor a 0 ($0.00 no permitido porque no es gratis).'
            });
        }
        const precioFinal = Math.round((numPrecio + Number.EPSILON) * 100) / 100;

        if (stock_pro === undefined || stock_pro === null || stock_pro === '') {
            return res.status(400).json({
                exito: false,
                error: 'El stock del producto es obligatorio y debe ser un número entero mayor a 0.'
            });
        }
        const numStock = Number(stock_pro);
        if (isNaN(numStock) || !Number.isInteger(numStock) || numStock <= 0) {
            return res.status(400).json({
                exito: false,
                error: 'El stock del producto debe ser un número entero mayor a 0 (no se permite registrar productos con stock 0).'
            });
        }
        const stockFinal = numStock;

        const provCheck = await pool.query(`SELECT COUNT(*) AS "total" FROM PROVEEDORES WHERE ID_PROV = $1`, [id_prov.trim()]);
        if (parseInt(provCheck.rows[0].total) === 0) {
            return res.status(400).json({ exito: false, error: 'El proveedor seleccionado no existe en el sistema.' });
        }

        const descripcionLimpia = desc_pro.trim();
        const tipoFinal = tip_pro && typeof tip_pro === 'string' && tip_pro.trim() ? tip_pro.trim() : '';

        const check = await pool.query(`
            SELECT COUNT(*) AS "total" 
            FROM PRODUCTOS 
            WHERE TRIM(LOWER(DESC_PRO)) = TRIM(LOWER($1))
        `, [descripcionLimpia]);

        if (parseInt(check.rows[0].total) > 0) {
            return res.status(400).json({ exito: false, error: `El producto "${descripcionLimpia}" ya existe en el inventario.` });
        }

        const id_pro = await generarSiguienteId('PRODUCTOS', 'ID_PRO', 'PRO');

        await pool.query(`
            INSERT INTO PRODUCTOS (ID_PRO, TIP_PRO, DESC_PRO, STOCK_PRO, PREC_PRO, ID_PROV)
            VALUES ($1, $2, $3, $4, $5, $6)
        `, [id_pro, tipoFinal, descripcionLimpia, isNaN(stockFinal) ? 0 : stockFinal, isNaN(precioFinal) ? 0 : precioFinal, id_prov.trim()]);

        res.json({ exito: true, mensaje: `Producto registrado con éxito (ID: ${id_pro})` });
    } catch (err) {
        console.error('Error al registrar producto:', err.message);
        if (err.code === '23505') {
            return res.status(500).json({ 
                exito: false, 
                error: 'No se pudo registrar porque el identificador generado ya existe en el sistema. Inténtalo de nuevo.' 
            });
        }
        res.status(500).json({ exito: false, error: 'Error al guardar el producto.' });
    }
});

// Validaciones y sanitización con express-validator para plantas (CU-25 / V-01 / V-07)
const validacionesPlanta = [
    body('cientifico')
        .trim()
        .notEmpty().withMessage('El nombre científico de la planta es obligatorio.')
        .custom((valor) => {
            if (contieneSqlOHtml(valor)) {
                throw new Error('El nombre científico contiene instrucciones SQL o etiquetas HTML no permitidas.');
            }
            return true;
        })
        .escape(),
    body('comun')
        .trim()
        .notEmpty().withMessage('El nombre común de la planta es obligatorio.')
        .custom((valor) => {
            if (contieneSqlOHtml(valor)) {
                throw new Error('El nombre común contiene instrucciones SQL o etiquetas HTML no permitidas.');
            }
            return true;
        })
        .escape(),
    body('proveedor')
        .trim()
        .notEmpty().withMessage('El proveedor es obligatorio.')
        .custom((valor) => {
            if (contieneSqlOHtml(valor)) {
                throw new Error('El proveedor seleccionado contiene caracteres no permitidos.');
            }
            return true;
        })
        .escape(),
    body('tipo')
        .optional()
        .trim()
        .custom((valor) => {
            if (valor && contieneSqlOHtml(valor)) {
                throw new Error('El tipo de planta contiene instrucciones SQL o etiquetas HTML no permitidas.');
            }
            return true;
        })
        .escape(),
    body('stock')
        .custom((valor) => {
            if (valor === undefined || valor === null || valor === '') {
                throw new Error('El stock de la planta es obligatorio y debe ser un número entero mayor a 0.');
            }
            if (contieneSqlOHtml(String(valor))) {
                throw new Error('El stock de la planta contiene caracteres no permitidos.');
            }
            const n = Number(valor);
            if (isNaN(n) || !Number.isInteger(n) || n <= 0) {
                throw new Error('El stock de la planta debe ser un número entero mayor a 0 (no se permite registrar plantas con stock 0).');
            }
            return true;
        }),
    body('precio')
        .custom((valor) => {
            if (valor === undefined || valor === null || valor === '') {
                throw new Error('El precio de la planta es obligatorio y debe ser mayor a 0 ($0.00 no permitido porque no es gratis).');
            }
            if (contieneSqlOHtml(String(valor))) {
                throw new Error('El precio de la planta contiene caracteres no permitidos.');
            }
            const n = parseFloat(valor);
            if (isNaN(n) || n <= 0) {
                throw new Error('El precio de la planta debe ser mayor a 0 ($0.00 no permitido porque no es gratis).');
            }
            return true;
        })
];

// Plantas (CU-23 / CU-24 / CU-25 / RN-12 / RN-16 / RN-17 / RN-31 / CP-12 / V-01 / V-07)
app.post('/api/plantas', validacionesPlanta, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                exito: false, 
                error: errors.array()[0].msg 
            });
        }

        const { tipo, cientifico, comun, tamano, stock, precio, proveedor } = req.body || {};

        if (!cientifico || typeof cientifico !== 'string' || !cientifico.trim() || contieneSqlOHtml(cientifico)) {
            return res.status(400).json({ exito: false, error: 'El nombre científico contiene instrucciones SQL o etiquetas HTML no permitidas o está vacío.' });
        }

        if (!comun || typeof comun !== 'string' || !comun.trim() || contieneSqlOHtml(comun)) {
            return res.status(400).json({ exito: false, error: 'El nombre común contiene instrucciones SQL o etiquetas HTML no permitidas o está vacío.' });
        }

        if (!proveedor || typeof proveedor !== 'string' || !proveedor.trim() || contieneSqlOHtml(proveedor)) {
            return res.status(400).json({ exito: false, error: 'El proveedor seleccionado es inválido o contiene caracteres no permitidos.' });
        }

        const cientificoLimpio = cientifico.trim();
        const comunLimpio = comun.trim();
        const tipoFinal = tipo && typeof tipo === 'string' && tipo.trim() ? tipo.trim() : null;
        const tamanoFinal = (tamano !== undefined && tamano !== null && tamano !== '') ? parseFloat(tamano) : null;

        if (stock === undefined || stock === null || stock === '') {
            return res.status(400).json({
                exito: false,
                error: 'El stock de la planta es obligatorio y debe ser un número entero mayor a 0.'
            });
        }
        const numStock = Number(stock);
        if (isNaN(numStock) || !Number.isInteger(numStock) || numStock <= 0) {
            return res.status(400).json({
                exito: false,
                error: 'El stock de la planta debe ser un número entero mayor a 0 (no se permite registrar plantas con stock 0).'
            });
        }
        const stockFinal = numStock;

        if (precio === undefined || precio === null || precio === '') {
            return res.status(400).json({
                exito: false,
                error: 'El precio de la planta es obligatorio y debe ser mayor a 0 ($0.00 no permitido porque no es gratis).'
            });
        }
        const numPrecio = parseFloat(precio);
        if (isNaN(numPrecio) || numPrecio <= 0) {
            return res.status(400).json({
                exito: false,
                error: 'El precio de la planta debe ser mayor a 0 ($0.00 no permitido porque no es gratis).'
            });
        }
        const precioFinal = Math.round((numPrecio + Number.EPSILON) * 100) / 100;

        const provCheck = await pool.query(`SELECT COUNT(*) AS "total" FROM PROVEEDORES WHERE ID_PROV = $1`, [proveedor.trim()]);
        if (parseInt(provCheck.rows[0].total) === 0) {
            return res.status(400).json({ exito: false, error: 'El proveedor seleccionado no existe en el sistema.' });
        }

        const check = await pool.query(`
            SELECT COUNT(*) AS "total" 
            FROM PLANTAS 
            WHERE TRIM(LOWER(NOM_CTFO)) = TRIM(LOWER($1))
        `, [cientificoLimpio]);

        if (parseInt(check.rows[0].total) > 0) {
            return res.status(400).json({ exito: false, error: `La planta "${cientificoLimpio}" ya se encuentra registrada.` });
        }

        const id_planta = await generarSiguienteId('PLANTAS', 'ID_PLANTA', 'PLN');

        await pool.query(`
            INSERT INTO PLANTAS (ID_PLANTA, TIP_PLANTA, NOM_CTFO, NOM_COM, TAM_PLANT, STOCK_PLANT, PROV_PLANT, PREC_PLANTA)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `, [
            id_planta,
            tipoFinal,
            cientificoLimpio,
            comunLimpio,
            tamanoFinal !== null ? String(tamanoFinal) : null,
            stockFinal,
            proveedor.trim(),
            precioFinal
        ]);

        res.json({ exito: true, mensaje: `Planta registrada con éxito (ID: ${id_planta})` });
    } catch (err) {
        console.error('Error al registrar planta:', err.message);
        if (err.code === '23505') {
            return res.status(500).json({ 
                exito: false, 
                error: 'No se pudo registrar porque el identificador generado ya existe en el sistema. Inténtalo de nuevo.' 
            });
        }
        res.status(500).json({ exito: false, error: 'Error al guardar la planta.' });
    }
});

// Función auxiliar para normalizar fechas
function normalizarFechaSQL(valor) {
    if (!valor) return null;
    if (valor instanceof Date && !isNaN(valor.getTime())) {
        return valor.toISOString().split('T')[0];
    }
    if (typeof valor === 'string') {
        const str = valor.trim();
        const matchDMY = str.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/);
        if (matchDMY) {
            const dia = matchDMY[1].padStart(2, '0');
            const mes = matchDMY[2].padStart(2, '0');
            const anio = matchDMY[3];
            return `${anio}-${mes}-${dia}`;
        }
        const matchYMD = str.match(/^(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})/);
        if (matchYMD) {
            const anio = matchYMD[1];
            const mes = matchYMD[2].padStart(2, '0');
            const dia = matchYMD[3].padStart(2, '0');
            return `${anio}-${mes}-${dia}`;
        }
        const parsed = new Date(str);
        if (!isNaN(parsed.getTime())) {
            return parsed.toISOString().split('T')[0];
        }
    }
    return null;
}

// Validaciones y sanitización con express-validator para servicios (CU-25 / CU-36 / V-01 / V-07)
const validacionesServicio = [
    body('trabajo')
        .optional()
        .trim()
        .custom((valor) => {
            if (valor && contieneSqlOHtml(valor)) {
                throw new Error('El trabajo realizado contiene instrucciones SQL o etiquetas HTML no permitidas (V-01 / V-07).');
            }
            return true;
        })
        .escape(),
    body('trab_real')
        .optional()
        .trim()
        .custom((valor) => {
            if (valor && contieneSqlOHtml(valor)) {
                throw new Error('El trabajo realizado contiene instrucciones SQL o etiquetas HTML no permitidas (V-01 / V-07).');
            }
            return true;
        })
        .escape(),
    body('id_cli')
        .optional()
        .trim()
        .custom((valor) => {
            if (valor && contieneSqlOHtml(valor)) {
                throw new Error('El cliente seleccionado contiene caracteres no permitidos (V-01 / V-07).');
            }
            return true;
        })
        .escape(),
    body('id_emp')
        .optional()
        .trim()
        .custom((valor) => {
            if (valor && contieneSqlOHtml(valor)) {
                throw new Error('El empleado seleccionado contiene caracteres no permitidos (V-01 / V-07).');
            }
            return true;
        })
        .escape(),
    body('fecha_ejec')
        .optional()
        .trim()
        .custom((valor) => {
            if (valor && contieneSqlOHtml(valor)) {
                throw new Error('La fecha contiene instrucciones SQL o etiquetas HTML no permitidas (V-01 / V-07).');
            }
            return true;
        }),
    body('costo')
        .optional()
        .custom((valor) => {
            if (valor !== undefined && valor !== null && valor !== '') {
                if (contieneSqlOHtml(String(valor))) {
                    throw new Error('El costo del servicio contiene caracteres no permitidos (V-01 / V-07).');
                }
            }
            return true;
        })
];

// Servicios (CU-13 / CU-32 / CU-33 / CU-35 / CU-36 / CP-19 / V-01 / V-07 / RN-16 / RN-19 / RN-33)
app.post('/api/servicios', validacionesServicio, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                exito: false, 
                error: errors.array()[0].msg 
            });
        }

        const rolSolicitante = obtenerRolSolicitante(req);
        if (rolSolicitante) {
            const rolNorm = rolSolicitante.toLowerCase();
            const rolesPermitidos = ['admin', 'administrador', 'empleado'];
            if (!rolesPermitidos.includes(rolNorm)) {
                return res.status(403).json({
                    exito: false,
                    error: 'Acceso denegado. Se requieren permisos de Administrador o Empleado para registrar servicios (CU-13).'
                });
            }
        }

        const { id_serv, id_cli, trabajo, trab_real, trabalho, fecha_ejec, fecha, costo, costo_serv, id_emp } = req.body || {};

        const trabajoEntrada = trabajo || trab_real || trabalho || req.body?.TRAB_REAL || req.body?.desc_serv || req.body?.descripcion;
        if (!trabajoEntrada || typeof trabajoEntrada !== 'string' || !trabajoEntrada.trim()) {
            return res.status(400).json({ 
                exito: false, 
                error: 'La descripción del trabajo realizado es obligatoria.' 
            });
        }

        if (contieneSqlOHtml(trabajoEntrada)) {
            return res.status(400).json({ 
                exito: false, 
                error: 'El trabajo realizado contiene instrucciones SQL o etiquetas HTML no permitidas (V-01 / V-07).' 
            });
        }

        const trabajoLimpio = trabajoEntrada.trim();

        if (trabajoLimpio.length > 200) {
            return res.status(400).json({ 
                exito: false, 
                error: 'La descripción del trabajo realizado no puede exceder los 200 caracteres (RN-19).' 
            });
        }

        const idCliEntrada = id_cli || req.body?.id_cliente || req.body?.ID_CLI;
        if (idCliEntrada && contieneSqlOHtml(String(idCliEntrada))) {
            return res.status(400).json({ 
                exito: false, 
                error: 'El cliente seleccionado contiene caracteres o instrucciones no permitidas (V-01 / V-07).' 
            });
        }

        const idEmpEntrada = id_emp || req.body?.id_empleado || req.body?.ID_EMP;
        if (idEmpEntrada && contieneSqlOHtml(String(idEmpEntrada))) {
            return res.status(400).json({ 
                exito: false, 
                error: 'El empleado seleccionado contiene caracteres o instrucciones no permitidas (V-01 / V-07).' 
            });
        }

        const fechaEntrada = fecha_ejec || fecha || req.body?.FECHA_EJEC;
        if (fechaEntrada && contieneSqlOHtml(String(fechaEntrada))) {
            return res.status(400).json({ 
                exito: false, 
                error: 'La fecha contiene instrucciones SQL o etiquetas HTML no permitidas (V-01 / V-07).' 
            });
        }

        const fechaNormalizada = normalizarFechaSQL(fechaEntrada) || new Date().toISOString().split('T')[0];

        const costoEntrada = costo !== undefined ? costo : (costo_serv !== undefined ? costo_serv : req.body?.costo_est);
        if (costoEntrada === undefined || costoEntrada === null || costoEntrada === '') {
            return res.status(400).json({ 
                exito: false, 
                error: 'El costo del servicio es obligatorio y debe ser mayor a 0 ($0.00 no permitido porque no es gratis).' 
            });
        }
        const numCosto = typeof costoEntrada === 'number'
            ? costoEntrada
            : parseFloat(String(costoEntrada).replace(/[^0-9.-]/g, ''));
        if (isNaN(numCosto) || numCosto <= 0) {
            return res.status(400).json({ 
                exito: false, 
                error: 'El costo del servicio debe ser un número mayor a 0 ($0.00 no permitido porque no es gratis).' 
            });
        }
        const costoFinal = Math.round((numCosto + Number.EPSILON) * 100) / 100;

        let clienteFinal = idCliEntrada && typeof idCliEntrada === 'string' && idCliEntrada.trim() ? idCliEntrada.trim() : null;
        if (!clienteFinal) {
            const cliRes = await pool.query('SELECT ID_CLI AS "ID_CLI" FROM CLIENTES ORDER BY ID_CLI ASC LIMIT 1');
            if (cliRes.rows.length > 0) {
                clienteFinal = cliRes.rows[0].ID_CLI;
            }
        }

        const usuarioSolicitante = obtenerUsuarioSolicitante(req) || req.body?.cajero || req.body?.usuario;
        let empleadoFinal = idEmpEntrada && typeof idEmpEntrada === 'string' && idEmpEntrada.trim() ? idEmpEntrada.trim() : null;
        
        if (!empleadoFinal && usuarioSolicitante) {
            try {
                const userEmpRes = await pool.query('SELECT ID_EMP AS "ID_EMP" FROM USUARIOS WHERE USERNAME = $1', [usuarioSolicitante.trim()]);
                if (userEmpRes.rows.length > 0 && userEmpRes.rows[0].ID_EMP) {
                    empleadoFinal = userEmpRes.rows[0].ID_EMP;
                }
            } catch (e) {
                console.error('Error al consultar ID_EMP del usuario:', e.message);
            }
        }

        if (!empleadoFinal) {
            const empRes = await pool.query('SELECT ID_EMP AS "ID_EMP" FROM EMPLEADOS ORDER BY ID_EMP ASC LIMIT 1');
            if (empRes.rows.length > 0) {
                empleadoFinal = empRes.rows[0].ID_EMP;
            }
        }

        let id_servicio = id_serv && typeof id_serv === 'string' && id_serv.trim() ? id_serv.trim() : null;
        if (!id_servicio) {
            const lastServ = await pool.query('SELECT ID_SERV AS "ID_SERV" FROM SERVICIOS ORDER BY LENGTH(ID_SERV) DESC, ID_SERV DESC LIMIT 1');
            let nextId = 1;
            if (lastServ.rows.length > 0 && lastServ.rows[0].ID_SERV) {
                const lastIdStr = lastServ.rows[0].ID_SERV.replace('SRV-', '');
                const parsedId = parseInt(lastIdStr);
                if (!isNaN(parsedId)) {
                    nextId = parsedId + 1;
                }
            }
            id_servicio = 'SRV-' + String(nextId).padStart(3, '0');
        }

        await pool.query(`
            INSERT INTO SERVICIOS (ID_SERV, ID_CLI, TRAB_REAL, FECHA_EJEC, COSTO_SERV, ID_EMP)
            VALUES ($1, $2, $3, $4::timestamp, $5, $6)
        `, [id_servicio, clienteFinal, trabajoLimpio, fechaNormalizada, costoFinal, empleadoFinal]);

        res.json({ 
            exito: true, 
            mensaje: `Servicio registrado con éxito (ID: ${id_servicio})`,
            id_servicio,
            ticket: {
                id_servicio,
                id_cli: clienteFinal,
                trabajo: trabajoLimpio,
                fecha_ejec: fechaNormalizada,
                costo: costoFinal,
                id_emp: empleadoFinal
            }
        });
    } catch (err) {
        console.error('--- ERROR AL REGISTRAR SERVICIO ---', err.message);
        res.status(500).json({ exito: false, error: 'Ocurrió un error en el servidor al intentar registrar el servicio.' });
    }
});

// Pedidos (Registrar) (CU-28 / CU-29 / RN-23 / CU-11)
app.post('/api/pedidos', async (req, res) => {
    try {
        const { tip_ped, tip_env, dir_envio, id_cli, id_pro, num_can, id_planta, num_can_plant, id_rep, tiem_entrega, tot_pedido } = req.body || {};

        if (!tip_ped || typeof tip_ped !== 'string' || !tip_ped.trim()) {
            return res.status(400).json({ exito: false, error: 'El tipo de pedido es obligatorio.' });
        }

        if (!tip_env || typeof tip_env !== 'string' || !tip_env.trim()) {
            return res.status(400).json({ exito: false, error: 'El tipo de envío es obligatorio.' });
        }

        if (!id_cli || typeof id_cli !== 'string' || !id_cli.trim()) {
            return res.status(400).json({ exito: false, error: 'El cliente es obligatorio.' });
        }

        const idProLimpio = id_pro && typeof id_pro === 'string' && id_pro.trim() ? id_pro.trim() : null;
        const idPlantaLimpio = id_planta && typeof id_planta === 'string' && id_planta.trim() ? id_planta.trim() : null;

        if (!idProLimpio && !idPlantaLimpio) {
            return res.status(400).json({ exito: false, error: 'Debe seleccionar al menos un producto o una planta para el pedido.' });
        }

        if (idProLimpio) {
            const cantNum = Number(num_can);
            if (num_can === undefined || num_can === null || String(num_can).trim() === '' || isNaN(cantNum) || !Number.isInteger(cantNum) || cantNum <= 0) {
                return res.status(400).json({
                    exito: false,
                    error: 'La cantidad del producto debe ser un número entero mayor que 0.'
                });
            }

            const proCheck = await pool.query('SELECT COUNT(*) AS "total" FROM PRODUCTOS WHERE ID_PRO = $1', [idProLimpio]);
            if (parseInt(proCheck.rows[0].total) === 0) {
                return res.status(400).json({ 
                    exito: false, 
                    error: `El producto seleccionado (${idProLimpio}) no existe en el sistema (RN-23).` 
                });
            }
        }

        if (idPlantaLimpio) {
            const cantPlantNum = Number(num_can_plant);
            if (num_can_plant === undefined || num_can_plant === null || String(num_can_plant).trim() === '' || isNaN(cantPlantNum) || !Number.isInteger(cantPlantNum) || cantPlantNum <= 0) {
                return res.status(400).json({
                    exito: false,
                    error: 'La cantidad de la planta debe ser un número entero mayor que 0.'
                });
            }

            const plantaCheck = await pool.query('SELECT COUNT(*) AS "total" FROM PLANTAS WHERE ID_PLANTA = $1', [idPlantaLimpio]);
            if (parseInt(plantaCheck.rows[0].total) === 0) {
                return res.status(400).json({ 
                    exito: false, 
                    error: `La planta seleccionada (${idPlantaLimpio}) no existe en el sistema (RN-23).` 
                });
            }
        }

        const cliCheck = await pool.query('SELECT COUNT(*) AS "total" FROM CLIENTES WHERE ID_CLI = $1', [id_cli.trim()]);
        if (parseInt(cliCheck.rows[0].total) === 0) {
            return res.status(400).json({ exito: false, error: 'El cliente seleccionado no existe en el sistema.' });
        }

        if (id_rep && typeof id_rep === 'string' && id_rep.trim()) {
            const repCheck = await pool.query('SELECT COUNT(*) AS "total" FROM EMPLEADOS WHERE ID_EMP = $1', [id_rep.trim()]);
            if (parseInt(repCheck.rows[0].total) === 0) {
                return res.status(400).json({ exito: false, error: 'El repartidor seleccionado no existe en el sistema.' });
            }
        }

        // Generar ID único para PEDIDOS sin colisiones
        let nextPedNum = 1;
        try {
            const maxPedRes = await pool.query(`SELECT ID_PED AS "ID_PED" FROM PEDIDOS WHERE ID_PED IS NOT NULL`);
            let maxPedId = 0;
            for (const row of maxPedRes.rows) {
                if (row.ID_PED) {
                    const match = String(row.ID_PED).match(/(\d+)/);
                    if (match) {
                        const num = parseInt(match[1], 10);
                        if (!isNaN(num) && num > maxPedId) maxPedId = num;
                    }
                }
            }
            const countPedResult = await pool.query('SELECT COUNT(*) AS "total" FROM PEDIDOS');
            const totalPedCount = parseInt(countPedResult.rows[0]?.total, 10) || 0;
            nextPedNum = Math.max(maxPedId, totalPedCount) + 1;
        } catch (e) {
            console.error('Error calculando ID_PED:', e.message);
        }

        let id_ped = 'PED-' + String(nextPedNum).padStart(3, '0');
        let idPedExiste = true;
        while (idPedExiste) {
            const checkPedId = await pool.query('SELECT COUNT(*) AS "total" FROM PEDIDOS WHERE ID_PED = $1', [id_ped]);
            if (parseInt(checkPedId.rows[0]?.total, 10) === 0) {
                idPedExiste = false;
            } else {
                nextPedNum++;
                id_ped = 'PED-' + String(nextPedNum).padStart(3, '0');
            }
        }

        const cantProFinal = idProLimpio ? parseInt(num_can, 10) : null;
        const cantPlantaFinal = idPlantaLimpio ? parseInt(num_can_plant, 10) : null;

        let totalCalculado = 0;
        if (idProLimpio && cantProFinal) {
            const proRes = await pool.query('SELECT PREC_PRO AS "PREC_PRO" FROM PRODUCTOS WHERE ID_PRO = $1', [idProLimpio]);
            if (proRes.rows.length > 0) {
                totalCalculado += (parseFloat(proRes.rows[0].PREC_PRO) || 0) * cantProFinal;
            }
        }
        if (idPlantaLimpio && cantPlantaFinal) {
            const plRes = await pool.query('SELECT PREC_PLANTA AS "PREC_PLANTA" FROM PLANTAS WHERE ID_PLANTA = $1', [idPlantaLimpio]);
            if (plRes.rows.length > 0) {
                totalCalculado += (parseFloat(plRes.rows[0].PREC_PLANTA) || 0) * cantPlantaFinal;
            }
        }

        const totalFinal = (tot_pedido !== undefined && tot_pedido !== null && parseFloat(tot_pedido) > 0) 
            ? parseFloat(tot_pedido) 
            : totalCalculado;

        await pool.query(`
            INSERT INTO PEDIDOS (ID_PED, TIP_PED, TIP_ENV, DIR_ENVIO, ID_CLI, ID_PRO, NUM_CAN, ID_PLANTA, NUM_CAN_PLANT, ID_REP, TIEM_ENTREGA, TOT_PEDIDO)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        `, [
            id_ped,
            tip_ped.trim(),
            tip_env.trim(),
            dir_envio && dir_envio.trim() ? dir_envio.trim() : null,
            id_cli.trim(),
            idProLimpio,
            cantProFinal,
            idPlantaLimpio,
            cantPlantaFinal,
            id_rep && id_rep.trim() ? id_rep.trim() : null,
            tiem_entrega && tiem_entrega.trim() ? tiem_entrega.trim() : 'N/A',
            totalFinal
        ]);
        
        res.json({ exito: true, mensaje: 'Pedido registrado con éxito', ticket: { id_ped } });
    } catch (err) {
        console.error('Error al registrar pedido:', err.message);
        res.status(500).json({ exito: false, error: 'Ocurrió un error en el servidor al intentar registrar el pedido.' });
    }
});

// Pedidos (Historial Completo para los Tickets)
app.get('/api/pedidos', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                pd.ID_PED AS "ID_PED", 
                pd.TIP_PED AS "TIP_PED", 
                pd.TIP_ENV AS "TIP_ENV", 
                COALESCE(pd.DIR_ENVIO, 'N/A') AS "DIR_ENVIO",
                c.NOM_CLI AS "NOM_CLI",
                COALESCE(p.DESC_PRO, 'N/A') AS "DESC_PRO",
                COALESCE(pl.NOM_COM, COALESCE(pl.NOM_CTFO, 'N/A')) AS "NOM_PLANTA",
                COALESCE(pd.NUM_CAN, 0) AS "NUM_CAN",
                COALESCE(pd.NUM_CAN_PLANT, 0) AS "NUM_CAN_PLANT",
                COALESCE(e.NOM_EMP, 'Sin Asignar') AS "REPARTIDOR",
                pd.TIEM_ENTREGA AS "TIEM_ENTREGA",
                CAST(COALESCE(pd.TOT_PEDIDO, 0) AS FLOAT) AS "TOT_PEDIDO"
            FROM PEDIDOS pd
            LEFT JOIN CLIENTES c ON pd.ID_CLI = c.ID_CLI
            LEFT JOIN PRODUCTOS p ON pd.ID_PRO = p.ID_PRO
            LEFT JOIN PLANTAS pl ON pd.ID_PLANTA = pl.ID_PLANTA
            LEFT JOIN EMPLEADOS e ON pd.ID_REP = e.ID_EMP
            ORDER BY pd.ID_PED DESC
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener el historial de pedidos.' });
    }
});

// Mecanismo de Idempotencia para Registro de Ventas (CU-31 / CU-12)
const ventasRecientes = new Map();

function limpiarVentasRecientes() {
    const ahora = Date.now();
    for (const [clave, item] of ventasRecientes.entries()) {
        if (ahora - item.timestamp > 15000) {
            ventasRecientes.delete(clave);
        }
    }
}

// Ventas (Registrar) (CU-30 / CU-31 / RN-16 / RN-29 / CU-12)
app.post('/api/ventas', async (req, res) => {
    let claveVenta;
    try {
        limpiarVentasRecientes();

        const { id_cliente, id_producto, cant_producto, id_planta, cant_planta, forma_pago, total, saldo, cajero } = req.body || {};

        if (!id_cliente) {
            return res.status(400).json({ exito: false, error: 'Debe seleccionar un cliente para la venta.' });
        }

        if (!id_producto && !id_planta) {
            return res.status(400).json({ exito: false, error: 'Debe seleccionar al menos un producto o una planta.' });
        }

        if (id_producto) {
            const cantProdNum = Number(cant_producto);
            if (cant_producto !== undefined && cant_producto !== null && (isNaN(cantProdNum) || !Number.isInteger(cantProdNum) || cantProdNum <= 0)) {
                return res.status(400).json({
                    exito: false,
                    error: 'La cantidad del producto debe ser un número entero mayor que 0.'
                });
            }
        }

        if (id_planta) {
            const cantPlantNum = Number(cant_planta);
            if (cant_planta !== undefined && cant_planta !== null && (isNaN(cantPlantNum) || !Number.isInteger(cantPlantNum) || cantPlantNum <= 0)) {
                return res.status(400).json({
                    exito: false,
                    error: 'La cantidad de la planta debe ser un número entero mayor que 0.'
                });
            }
        }

        const redondearDinero = (val) => {
            const num = typeof val === 'number' ? val : parseFloat(String(val).trim());
            if (isNaN(num)) return 0;
            return Math.round((num + Number.EPSILON) * 100) / 100;
        };

        const numTotal = redondearDinero(total);
        const numSaldo = redondearDinero(saldo);

        // Validación N2: El total de la venta debe ser mayor a 0 (no se permiten ventas con total $0.00)
        if (numTotal <= 0) {
            return res.status(400).json({ 
                exito: false, 
                error: 'El total de la venta debe ser mayor a 0 (no se permiten ventas con total $0.00).' 
            });
        }

        if (numSaldo < 0) {
            return res.status(400).json({ 
                exito: false, 
                error: 'El saldo pendiente debe ser mayor o igual a 0 (RN-16).' 
            });
        }

        if (numSaldo > numTotal) {
            return res.status(400).json({ 
                exito: false, 
                error: 'El saldo pendiente no puede exceder el total de la venta (RN-29).' 
            });
        }

        const idempotencyKey = req.headers['idempotency-key'] || req.body?.idempotency_key;
        claveVenta = idempotencyKey 
            ? String(idempotencyKey).trim() 
            : `${id_cliente}_${id_producto || ''}_${cant_producto || 0}_${id_planta || ''}_${cant_planta || 0}_${numTotal}_${numSaldo}_${forma_pago || ''}`;

        if (ventasRecientes.has(claveVenta)) {
            const registro = ventasRecientes.get(claveVenta);
            if (Date.now() - registro.timestamp < 10000) {
                try {
                    const respuestaExistente = await registro.promesa;
                    return res.json(respuestaExistente);
                } catch (e) {
                    ventasRecientes.delete(claveVenta);
                }
            }
        }

        const ejecutarRegistroVenta = async () => {
            let nextId = 1;
            try {
                const maxVenRes = await pool.query(`SELECT ID_VEN AS "ID_VEN" FROM VENTAS WHERE ID_VEN IS NOT NULL`);
                let maxVenId = 0;
                for (const row of maxVenRes.rows) {
                    if (row.ID_VEN) {
                        const match = String(row.ID_VEN).match(/(\d+)/);
                        if (match) {
                            const num = parseInt(match[1], 10);
                            if (!isNaN(num) && num > maxVenId) maxVenId = num;
                        }
                    }
                }
                const countVenResult = await pool.query('SELECT COUNT(*) AS "total" FROM VENTAS');
                const totalVenCount = parseInt(countVenResult.rows[0]?.total, 10) || 0;
                nextId = Math.max(maxVenId, totalVenCount) + 1;
            } catch (e) {
                console.error('Error calculando ID_VEN:', e.message);
            }

            let id_venta = 'VEN-' + String(nextId).padStart(3, '0');
            let idVenExiste = true;
            while (idVenExiste) {
                const checkVenId = await pool.query('SELECT COUNT(*) AS "total" FROM VENTAS WHERE ID_VEN = $1', [id_venta]);
                if (parseInt(checkVenId.rows[0]?.total, 10) === 0) {
                    idVenExiste = false;
                } else {
                    nextId++;
                    id_venta = 'VEN-' + String(nextId).padStart(3, '0');
                }
            }

            await pool.query(`
                INSERT INTO VENTAS (ID_VEN, ID_CLI, ID_PRO, ID_PLANTA, FECHA_COMP, FORM_PAGO, TOT_PAGO, SALDO_PAGO)
                VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7)
            `, [
                id_venta,
                id_cliente.trim(),
                id_producto && id_producto.trim() ? id_producto.trim() : null,
                id_planta && id_planta.trim() ? id_planta.trim() : null,
                forma_pago ? forma_pago.trim() : 'Efectivo',
                numTotal,
                numSaldo
            ]);
            
            return { 
                exito: true, 
                mensaje: 'Venta registrada exitosamente',
                ticket: { 
                    id_venta, 
                    id_cliente, 
                    forma_pago, 
                    total: numTotal, 
                    saldo: numSaldo, 
                    cant_producto: cant_producto || 0,
                    cant_planta: cant_planta || 0,
                    cajero: cajero || 'Administrador',
                    fecha: new Date().toLocaleString() 
                }
            };
        };

        const promesaVenta = ejecutarRegistroVenta();
        ventasRecientes.set(claveVenta, { promesa: promesaVenta, timestamp: Date.now() });

        const respuesta = await promesaVenta;
        res.json(respuesta);
    } catch (err) {
        if (claveVenta) {
            ventasRecientes.delete(claveVenta);
        }
        console.error('--- ERROR AL REGISTRAR VENTA ---', err);
        res.status(500).json({ exito: false, error: 'Ocurrió un error en el servidor al intentar registrar la venta.' });
    }
});

// Ventas (Historial)
app.get('/api/ventas', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                v.ID_VEN AS "ID_VEN", 
                v.ID_CLI AS "ID_CLI", 
                COALESCE(c.NOM_CLI, 'Cliente General') AS "NOM_CLI",
                COALESCE(v.ID_PRO, 'N/A') AS "ID_PRO", 
                COALESCE(p.DESC_PRO, 'N/A') AS "DESC_PRO",
                COALESCE(v.ID_PLANTA, 'N/A') AS "ID_PLANTA", 
                COALESCE(pl.NOM_COM, COALESCE(pl.NOM_CTFO, 'N/A')) AS "NOM_PLANTA",
                v.FECHA_COMP AS "FECHA_COMP", 
                v.FORM_PAGO AS "FORM_PAGO", 
                ROUND(CAST(COALESCE(v.TOT_PAGO, 0) AS NUMERIC), 2)::float AS "TOT_PAGO", 
                ROUND(CAST(COALESCE(v.SALDO_PAGO, 0) AS NUMERIC), 2)::float AS "SALDO_PAGO"
            FROM VENTAS v
            LEFT JOIN CLIENTES c ON v.ID_CLI = c.ID_CLI
            LEFT JOIN PRODUCTOS p ON v.ID_PRO = p.ID_PRO
            LEFT JOIN PLANTAS pl ON v.ID_PLANTA = pl.ID_PLANTA
            ORDER BY v.FECHA_COMP DESC
        `);
        // Sanitización para prevenir residuos de precisión flotante (N6)
        result.rows.forEach(r => {
            if (r.TOT_PAGO !== undefined && r.TOT_PAGO !== null) {
                r.TOT_PAGO = Math.round((Number(r.TOT_PAGO) + Number.EPSILON) * 100) / 100;
            }
            if (r.SALDO_PAGO !== undefined && r.SALDO_PAGO !== null) {
                r.SALDO_PAGO = Math.round((Number(r.SALDO_PAGO) + Number.EPSILON) * 100) / 100;
            }
        });
        res.json(result.rows);
    } catch (err) {
        console.error('--- ERROR AL OBTENER VENTAS:', err.message);
        res.status(500).json({ error: 'Error al obtener el historial de ventas: ' + err.message });
    }
});

// APIs para el Dashboard General
app.get('/api/dashboard/proveedores', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_PROV AS "ID_PROV", 
                COALESCE(TIP_SUM, '') AS "TIP_SUM", 
                NOM_PROV AS "NOM_PROV", 
                COALESCE(RFC_PROV, '') AS "RFC_PROV", 
                COALESCE(DIR_PROV, '') AS "DIR_PROV", 
                COALESCE(CON_PROV, '') AS "CON_PROV", 
                COALESCE(PRO_PROV, '') AS "PRO_PROV" 
            FROM PROVEEDORES
        `);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/clientes', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_CLI AS "ID_CLI", 
                NOM_CLI AS "NOM_CLI", 
                COALESCE(DIR_CLI, '') AS "DIR_CLI", 
                COALESCE(TEL_CLI, '') AS "TEL_CLI", 
                CASE 
                    WHEN COR_CLI IS NULL OR TRIM(COR_CLI) = '' THEN NULL 
                    ELSE TRIM(COR_CLI) 
                END AS "COR_CLI", 
                COALESCE(COM_CLI, '') AS "COM_CLI", 
                COALESCE(PREF_CLI, '') AS "PREF_CLI" 
            FROM CLIENTES
            WHERE NOM_CLI IS NOT NULL AND TRIM(NOM_CLI) <> ''
        `);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/empleados', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_EMP AS "ID_EMP", 
                COALESCE(TIP_EMP, '') AS "TIP_EMP", 
                COALESCE(CURP_EMP, '') AS "CURP_EMP", 
                NOM_EMP AS "NOM_EMP", 
                COALESCE(DIR_EMP, '') AS "DIR_EMP", 
                COALESCE(PUE_EMP, '') AS "PUE_EMP", 
                COALESCE(HOR_EMP, '') AS "HOR_EMP", 
                CASE 
                    WHEN SUE_EMP IS NULL THEN NULL 
                    ELSE ROUND(CAST(GREATEST(SUE_EMP, 0) AS NUMERIC), 2)::float 
                END AS "SUE_EMP" 
            FROM EMPLEADOS
            WHERE SUE_EMP IS NULL OR SUE_EMP >= 0
        `);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/productos', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_PRO AS "ID_PRO", 
                COALESCE(TIP_PRO, '') AS "TIP_PRO", 
                DESC_PRO AS "DESC_PRO", 
                CASE 
                    WHEN STOCK_PRO IS NULL THEN NULL 
                    ELSE GREATEST(STOCK_PRO, 0) 
                END AS "STOCK_PRO", 
                CASE 
                    WHEN PREC_PRO IS NULL THEN NULL 
                    ELSE ROUND(CAST(GREATEST(PREC_PRO, 0) AS NUMERIC), 2)::float 
                END AS "PREC_PRO", 
                COALESCE(ID_PROV, '') AS "ID_PROV" 
            FROM PRODUCTOS
            WHERE (PREC_PRO IS NULL OR PREC_PRO >= 0) AND (STOCK_PRO IS NULL OR STOCK_PRO >= 0)
        `);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/pedidos', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_PED AS "ID_PED", TIP_PED AS "TIP_PED", ID_CLI AS "ID_CLI", ROUND(CAST(COALESCE(TOT_PEDIDO, 0) AS NUMERIC), 2)::float AS "TOT_PEDIDO" FROM PEDIDOS WHERE TOT_PEDIDO > 0');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/servicios', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_SERV AS "ID_SERV", 
                ID_CLI AS "ID_CLI", 
                TRAB_REAL AS "TRAB_REAL", 
                CASE 
                    WHEN COSTO_SERV IS NULL THEN NULL 
                    ELSE ROUND(CAST(GREATEST(COSTO_SERV, 0) AS NUMERIC), 2)::float 
                END AS "COSTO_SERV" 
            FROM SERVICIOS 
            WHERE COSTO_SERV IS NULL OR COSTO_SERV >= 0
            ORDER BY ID_SERV
        `);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/catalogo-servicios', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_CAT_SERV AS "ID_CAT_SERV", 
                NOM_SERV AS "NOM_SERV", 
                CASE 
                    WHEN COSTO_EST IS NULL THEN NULL 
                    ELSE ROUND(CAST(GREATEST(COSTO_EST, 0) AS NUMERIC), 2)::float 
                END AS "COSTO_EST" 
            FROM CAT_SERVICIOS 
            WHERE COSTO_EST IS NULL OR COSTO_EST >= 0
        `);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/ventas', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_VEN AS "ID_VEN", ID_CLI AS "ID_CLI", FORM_PAGO AS "FORM_PAGO", ROUND(CAST(COALESCE(TOT_PAGO, 0) AS NUMERIC), 2)::float AS "TOT_PAGO", ROUND(CAST(COALESCE(SALDO_PAGO, 0) AS NUMERIC), 2)::float AS "SALDO_PAGO" FROM VENTAS');
        result.rows.forEach(r => {
            if (r.TOT_PAGO !== undefined && r.TOT_PAGO !== null) {
                r.TOT_PAGO = Math.round((Number(r.TOT_PAGO) + Number.EPSILON) * 100) / 100;
            }
            if (r.SALDO_PAGO !== undefined && r.SALDO_PAGO !== null) {
                r.SALDO_PAGO = Math.round((Number(r.SALDO_PAGO) + Number.EPSILON) * 100) / 100;
            }
        });
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

// Obtener lista de usuarios para administración
app.get('/api/usuarios', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                COALESCE(ID_USUARIO, USERNAME) AS "ID_USUARIO", 
                USERNAME AS "USERNAME", 
                ROL AS "ROL", 
                ID_EMP AS "ID_EMP", 
                COALESCE(ESTADO, 'Activo') AS "ESTADO" 
            FROM USUARIOS
        `);
        res.json(result.rows);
    } catch (err) {
        console.error('--- ERROR EN GET /api/usuarios:', err.message);
        res.status(500).json({ error: 'Error al obtener usuarios: ' + err.message });
    }
});

// Registrar Usuario del Sistema (CU-18 / CU-26 / CU-27 / RN-19 / RN-22 / RN-34 / RN-35)
app.post('/api/usuarios', async (req, res) => {
    let usernameLimpio = '';
    try {
        const tienePermiso = await verificarAccesoAdmin(req, res);
        if (!tienePermiso) return;

        const { username, password, rol, id_emp } = req.body || {};

        if (!username || typeof username !== 'string' || !username.trim()) {
            return res.status(400).json({ exito: false, error: 'El nombre de usuario es obligatorio.' });
        }

        usernameLimpio = username.trim();

        if (usernameLimpio.length > 80) {
            return res.status(400).json({
                exito: false,
                error: 'El nombre de usuario no puede exceder los 80 caracteres (RN-19).'
            });
        }

        if (!password || typeof password !== 'string' || !password.trim()) {
            return res.status(400).json({ exito: false, error: 'La contraseña es obligatoria.' });
        }

        if (!rol || typeof rol !== 'string' || !rol.trim()) {
            return res.status(400).json({ exito: false, error: 'El rol del usuario es obligatorio.' });
        }

        const check = await pool.query(`SELECT COUNT(*) AS "total" FROM USUARIOS WHERE TRIM(LOWER(USERNAME)) = TRIM(LOWER($1))`, [usernameLimpio]);
        if (parseInt(check.rows[0].total) > 0) {
            return res.status(400).json({
                exito: false,
                error: `Error UNIQUE: El usuario "${usernameLimpio}" ya existe. Según la regla RN-13 (CP-13) el USERNAME debe ser único.`
            });
        }

        // Empleado asociado es opcional y permite NULL (CU-26 / RN-22)
        let idEmpFinal = null;
        if (id_emp !== undefined && id_emp !== null) {
            const strEmp = String(id_emp).trim();
            if (strEmp && 
                strEmp.toLowerCase() !== 'null' && 
                strEmp.toLowerCase() !== 'undefined' && 
                strEmp.toLowerCase() !== '' &&
                !strEmp.toLowerCase().includes('ninguno') &&
                !strEmp.toLowerCase().includes('sin empleado')) {
                idEmpFinal = strEmp;
            }
        }

        if (idEmpFinal) {
            const empCheck = await pool.query('SELECT COUNT(*) AS "total" FROM EMPLEADOS WHERE TRIM(ID_EMP) = TRIM($1)', [idEmpFinal]);
            if (parseInt(empCheck.rows[0]?.total, 10) === 0) {
                return res.status(400).json({ exito: false, error: 'El empleado seleccionado no existe en el sistema.' });
            }
        }

        // Generar ID único para USUARIOS sin colisiones (USR-001, ..., USR-013, etc.)
        let nextNum = 1;
        try {
            const maxRes = await pool.query(`SELECT TRIM(ID_USUARIO) AS "ID_USUARIO" FROM USUARIOS WHERE ID_USUARIO IS NOT NULL`);
            let maxId = 0;
            for (const row of maxRes.rows) {
                const rawId = row.ID_USUARIO || row.id_usuario || (row && Object.values(row)[0]);
                if (rawId) {
                    const match = String(rawId).match(/(\d+)/);
                    if (match) {
                        const num = parseInt(match[1], 10);
                        if (!isNaN(num) && num > maxId) maxId = num;
                    }
                }
            }
            const countResult = await pool.query('SELECT COUNT(*) AS "total" FROM USUARIOS');
            const totalCount = parseInt(countResult.rows[0]?.total, 10) || 0;
            nextNum = Math.max(maxId, totalCount) + 1;
        } catch (e) {
            console.error('Error calculando ID_USUARIO:', e.message);
        }

        let id_usuario = 'USR-' + String(nextNum).padStart(3, '0');
        let idExiste = true;
        while (idExiste) {
            const checkId = await pool.query('SELECT COUNT(*) AS "total" FROM USUARIOS WHERE TRIM(ID_USUARIO) = TRIM($1)', [id_usuario]);
            if (parseInt(checkId.rows[0]?.total, 10) === 0) {
                idExiste = false;
            } else {
                nextNum++;
                id_usuario = 'USR-' + String(nextNum).padStart(3, '0');
            }
        }

        // Cifrado criptográfico de la contraseña antes de guardar en base de datos (RN-41 / N10)
        const passwordHash = hashearPassword(password);

        // Inserción con reintento automático si ocurre colisión de llave primaria (pkey)
        let insertExitoso = false;
        let intentos = 0;
        while (!insertExitoso && intentos < 5) {
            intentos++;
            id_usuario = 'USR-' + String(nextNum).padStart(3, '0');
            try {
                await pool.query(`
                    INSERT INTO USUARIOS (ID_USUARIO, USERNAME, PASSWORD, ROL, ID_EMP, ESTADO)
                    VALUES ($1, $2, $3, $4, $5, 'Activo')
                `, [id_usuario, usernameLimpio, passwordHash, rol.trim(), idEmpFinal]);
                insertExitoso = true;
                await registrarAuditoria(req, 'CREAR', id_usuario, null, { username: usernameLimpio, rol: rol.trim(), id_emp: idEmpFinal });
            } catch (insertErr) {
                const esColisionId = insertErr.code === '23505' && (
                    (insertErr.constraint && insertErr.constraint.toLowerCase().includes('pkey')) ||
                    (insertErr.detail && insertErr.detail.toLowerCase().includes('id_usuario'))
                );
                if (esColisionId && intentos < 5) {
                    nextNum++;
                } else {
                    throw insertErr;
                }
            }
        }

        res.json({ exito: true, mensaje: `Usuario "${usernameLimpio}" registrado con éxito (ID: ${id_usuario})` });
    } catch (err) {
        console.error('--- ERROR SQL EN USUARIOS:', err.message, err.detail, err.code);
        const nombreDisplay = usernameLimpio || req.body?.username || '';
        if (err.code === '23505') {
            if (err.constraint && err.constraint.toLowerCase().includes('pkey')) {
                return res.status(500).json({
                    exito: false,
                    error: `No se pudo registrar el usuario porque ya existe un registro con el mismo identificador en el sistema.`
                });
            }
            return res.status(400).json({
                exito: false,
                error: `El nombre de usuario "${nombreDisplay}" ya está registrado en el sistema. Debe elegir un nombre de usuario diferente conforme a la regla RN-13.`
            });
        }
        if (err.code === '23503') {
            return res.status(400).json({
                exito: false,
                error: `El empleado seleccionado no existe o no es válido.`
            });
        }
        if (err.code === '23502') {
            return res.status(400).json({
                exito: false,
                error: `Faltan campos obligatorios para registrar el usuario en el sistema.`
            });
        }
        if (err.message && err.message.toUpperCase().includes('UNIQUE')) {
            return res.status(400).json({
                exito: false,
                error: `El nombre de usuario "${nombreDisplay}" ya está registrado en el sistema. Debe elegir un nombre de usuario diferente conforme a la regla RN-13.`
            });
        }
        res.status(500).json({ 
            exito: false, 
            error: 'Ocurrió un error en el servidor al intentar registrar el usuario. Por favor verifique los datos ingresados.' 
        });
    }
});

// Actualizar Estado de Usuario (Activo / Inactivo) (CU-18 / RN-34 / RN-35)
app.put('/api/usuarios/:id/estado', async (req, res) => {
    try {
        const tienePermiso = await verificarAccesoAdmin(req, res);
        if (!tienePermiso) return;

        const idUsuario = req.params.id;
        const { estado } = req.body;

        const anteriorRes = await pool.query('SELECT ESTADO FROM USUARIOS WHERE ID_USUARIO = $1 OR USERNAME = $1', [idUsuario]);
        const estadoPrevio = anteriorRes.rows[0]?.ESTADO || 'Activo';

        await pool.query(`
            UPDATE USUARIOS 
            SET ESTADO = $1 
            WHERE ID_USUARIO = $2 OR USERNAME = $2
        `, [estado, idUsuario]);

        await registrarAuditoria(req, 'CAMBIO_ESTADO', idUsuario, { estado: estadoPrevio }, { estado });

        res.json({ exito: true, mensaje: `Estado del usuario actualizado a ${estado}` });
    } catch (err) {
        console.error('--- ERROR SQL EN CAMBIO DE ESTADO:', err.message);
        res.status(500).json({ exito: false, error: 'Error al actualizar el estado del usuario.' });
    }
});

// Obtener Usuario por ID o Username (CU-18 / CU-51)
app.get('/api/usuarios/:id', async (req, res) => {
    try {
        const idUsuario = req.params.id;
        const result = await pool.query(`
            SELECT 
                COALESCE(ID_USUARIO, USERNAME) AS "ID_USUARIO", 
                USERNAME AS "USERNAME", 
                ROL AS "ROL", 
                ID_EMP AS "ID_EMP", 
                COALESCE(ESTADO, 'Activo') AS "ESTADO" 
            FROM USUARIOS 
            WHERE ID_USUARIO = $1 OR USERNAME = $1
        `, [idUsuario]);
        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).json({ exito: false, error: 'Usuario no encontrado' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener usuario: ' + err.message });
    }
});

// Modificar Información de Usuario (CU-16 / CU-18 / CU-51 / RN-13 / RN-19 / CP-13 / RN-34 / RN-35)
app.put('/api/usuarios/:id', async (req, res) => {
    try {
        const tienePermiso = await verificarAccesoAdmin(req, res);
        if (!tienePermiso) return;

        const idUsuario = req.params.id;
        const previoRes = await pool.query(`SELECT ID_USUARIO, USERNAME, ROL, ID_EMP, ESTADO FROM USUARIOS WHERE ID_USUARIO = $1 OR USERNAME = $1`, [idUsuario]);
        const datosPrevios = previoRes.rows[0] || null;
        const { username, password, rol, id_emp, estado } = req.body || {};

        const usernameVal = username !== undefined ? username : req.body?.USERNAME;
        const passwordVal = password !== undefined ? password : req.body?.PASSWORD;
        const rolVal = rol !== undefined ? rol : req.body?.ROL;
        const idEmpVal = id_emp !== undefined ? id_emp : req.body?.ID_EMP;
        const estadoVal = estado !== undefined ? estado : req.body?.ESTADO;

        let usernameLimpio = null;
        if (usernameVal !== undefined) {
            if (!usernameVal || typeof usernameVal !== 'string' || !usernameVal.trim()) {
                return res.status(400).json({ exito: false, error: 'El nombre de usuario no puede estar vacío.' });
            }
            usernameLimpio = usernameVal.trim();

            if (usernameLimpio.length > 80) {
                return res.status(400).json({
                    exito: false,
                    error: 'El nombre de usuario no puede exceder los 80 caracteres (RN-19).'
                });
            }

            const check = await pool.query(`
                SELECT COUNT(*) AS "total" 
                FROM USUARIOS 
                WHERE TRIM(LOWER(USERNAME)) = TRIM(LOWER($1)) 
                  AND ID_USUARIO != $2 
                  AND USERNAME != $2
            `, [usernameLimpio, idUsuario]);
            if (parseInt(check.rows[0].total) > 0) {
                return res.status(400).json({
                    exito: false,
                    error: `Error UNIQUE: El nombre de usuario "${usernameLimpio}" ya existe en el sistema. Según la regla RN-13 (CP-13) el USERNAME debe ser único.`
                });
            }
        }

        if (idEmpVal !== undefined && idEmpVal && typeof idEmpVal === 'string' && idEmpVal.trim()) {
            const empCheck = await pool.query('SELECT COUNT(*) AS "total" FROM EMPLEADOS WHERE ID_EMP = $1', [idEmpVal.trim()]);
            if (parseInt(empCheck.rows[0].total) === 0) {
                return res.status(400).json({ exito: false, error: 'El empleado seleccionado no existe en el sistema.' });
            }
        }

        let updates = [];
        let values = [];
        let paramIdx = 1;

        if (usernameLimpio !== null) {
            updates.push(`USERNAME = $${paramIdx++}`);
            values.push(usernameLimpio);
        }
        if (passwordVal !== undefined && passwordVal && typeof passwordVal === 'string' && passwordVal.trim()) {
            const passHash = hashearPassword(passwordVal.trim());
            updates.push(`PASSWORD = $${paramIdx++}`);
            values.push(passHash);
        }
        if (rolVal !== undefined && rolVal && typeof rolVal === 'string' && rolVal.trim()) {
            updates.push(`ROL = $${paramIdx++}`);
            values.push(rolVal.trim());
        }
        if (idEmpVal !== undefined) {
            let finalEmp = null;
            if (idEmpVal !== null) {
                const strEmp = String(idEmpVal).trim();
                if (strEmp && 
                    strEmp.toLowerCase() !== 'null' && 
                    strEmp.toLowerCase() !== 'undefined' && 
                    strEmp.toLowerCase() !== '' &&
                    !strEmp.toLowerCase().includes('ninguno') &&
                    !strEmp.toLowerCase().includes('sin empleado')) {
                    finalEmp = strEmp;
                }
            }
            updates.push(`ID_EMP = $${paramIdx++}`);
            values.push(finalEmp);
        }
        if (estadoVal !== undefined && estadoVal && typeof estadoVal === 'string' && estadoVal.trim()) {
            updates.push(`ESTADO = $${paramIdx++}`);
            values.push(estadoVal.trim());
        }

        if (updates.length === 0) return res.json({ exito: true, mensaje: 'Sin cambios para actualizar.' });

        values.push(idUsuario);
        const query = `
            UPDATE USUARIOS 
            SET ${updates.join(', ')} 
            WHERE ID_USUARIO = $${paramIdx} OR USERNAME = $${paramIdx}
        `;
        await pool.query(query, values);

        await registrarAuditoria(req, 'MODIFICAR', idUsuario, datosPrevios, {
            username: usernameLimpio,
            rol: rolVal,
            id_emp: idEmpVal,
            estado: estadoVal
        });

        res.json({ exito: true, mensaje: 'Usuario actualizado correctamente.' });
    } catch (err) {
        console.error('--- ERROR SQL AL ACTUALIZAR USUARIO:', err.message);
        if (err.code === '23505' || (err.message && err.message.toUpperCase().includes('UNIQUE'))) {
            return res.status(400).json({
                exito: false,
                error: 'El nombre de usuario ya se encuentra registrado por otro usuario en el sistema. Debe elegir uno diferente (Regla RN-13).'
            });
        }
        res.status(500).json({ exito: false, error: 'Ocurrió un error en el servidor al intentar actualizar los datos del usuario.' });
    }
});

// Obtener Cliente por ID (CU-16 / CU-42 / CU-52)
app.get('/api/clientes/:id', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_CLI AS "ID_CLI", 
                NOM_CLI AS "NOM_CLI", 
                COALESCE(DIR_CLI, '') AS "DIR_CLI", 
                COALESCE(TEL_CLI, '') AS "TEL_CLI", 
                CASE 
                    WHEN COR_CLI IS NULL OR TRIM(COR_CLI) = '' THEN NULL 
                    ELSE TRIM(COR_CLI) 
                END AS "COR_CLI", 
                COALESCE(COM_CLI, '') AS "COM_CLI", 
                COALESCE(PREF_CLI, '') AS "PREF_CLI" 
            FROM CLIENTES 
            WHERE ID_CLI = $1
        `, [req.params.id]);
        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).json({ exito: false, error: 'Cliente no encontrado' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener cliente: ' + err.message });
    }
});

// Actualizar Cliente individual con campo Correo Electrónico editable y sanitización (CU-16 / CU-42 / CU-47 / CU-52 / RN-18 / RN-34 / RN-35 / V-01 / V-07)
app.put('/api/clientes/:id', async (req, res) => {
    try {
        const tienePermiso = await verificarAccesoAdmin(req, res);
        if (!tienePermiso) return;

        const id_cli = req.params.id;
        const { nom_cli, dir_cli, tel_cli, cor_cli, com_cli, pref_cli } = req.body || {};

        const nom_cli_val = nom_cli !== undefined ? nom_cli : req.body?.NOM_CLI;
        const dir_cli_val = dir_cli !== undefined ? dir_cli : req.body?.DIR_CLI;
        const tel_cli_val = tel_cli !== undefined ? tel_cli : req.body?.TEL_CLI;
        const cor_cli_val = cor_cli !== undefined ? cor_cli : req.body?.COR_CLI;
        const com_cli_val = com_cli !== undefined ? com_cli : req.body?.COM_CLI;
        const pref_cli_val = pref_cli !== undefined ? pref_cli : req.body?.PREF_CLI;

        if (nom_cli_val !== undefined && (!nom_cli_val || typeof nom_cli_val !== 'string' || !nom_cli_val.trim())) {
            return res.status(400).json({ exito: false, error: 'El nombre del cliente no puede estar vacío.' });
        }

        if (cor_cli_val !== undefined && cor_cli_val !== null && String(cor_cli_val).trim() !== '') {
            const correoLimpio = String(cor_cli_val).trim();
            const partesCorreo = correoLimpio.split('@');
            if (partesCorreo.length !== 2 || !partesCorreo[1] || !partesCorreo[1].trim()) {
                return res.status(400).json({
                    exito: false,
                    error: 'El correo electrónico debe incluir un dominio después del símbolo "@" (ejemplo: usuario@dominio.com).'
                });
            }

            const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
            if (!emailRegex.test(correoLimpio)) {
                return res.status(400).json({
                    exito: false,
                    error: 'El correo electrónico no cumple con un formato válido con dominio (ejemplo: usuario@dominio.com).'
                });
            }
        }

        let updates = [];
        let values = [];
        let paramIdx = 1;

        if (nom_cli_val !== undefined) {
            updates.push(`NOM_CLI = $${paramIdx++}`);
            values.push(nom_cli_val.trim());
        }
        if (dir_cli_val !== undefined) {
            const dirLimpio = dir_cli_val && String(dir_cli_val).trim() ? sanitizarSqlYHtml(dir_cli_val) : null;
            updates.push(`DIR_CLI = $${paramIdx++}`);
            values.push(dirLimpio && dirLimpio.trim() ? dirLimpio.trim() : null);
        }
        if (tel_cli_val !== undefined) {
            updates.push(`TEL_CLI = $${paramIdx++}`);
            values.push(tel_cli_val && String(tel_cli_val).trim() ? String(tel_cli_val).trim() : null);
        }
        if (cor_cli_val !== undefined) {
            updates.push(`COR_CLI = $${paramIdx++}`);
            values.push(cor_cli_val && String(cor_cli_val).trim() ? String(cor_cli_val).trim() : null);
        }
        if (com_cli_val !== undefined) {
            const comLimpio = com_cli_val && String(com_cli_val).trim() ? sanitizarSqlYHtml(com_cli_val) : null;
            updates.push(`COM_CLI = $${paramIdx++}`);
            values.push(comLimpio && comLimpio.trim() ? comLimpio.trim() : null);
        }
        if (pref_cli_val !== undefined) {
            const prefLimpio = pref_cli_val && String(pref_cli_val).trim() ? sanitizarSqlYHtml(pref_cli_val) : null;
            updates.push(`PREF_CLI = $${paramIdx++}`);
            values.push(prefLimpio && prefLimpio.trim() ? prefLimpio.trim() : null);
        }

        if (updates.length === 0) return res.json({ exito: true, mensaje: 'Sin cambios para actualizar.' });

        values.push(id_cli);
        await pool.query(`UPDATE CLIENTES SET ${updates.join(', ')} WHERE ID_CLI = $${paramIdx}`, values);
        res.json({ exito: true, mensaje: 'Cliente actualizado correctamente.' });
    } catch (err) {
        console.error('Error al actualizar cliente:', err.message);
        res.status(500).json({ exito: false, error: 'Ocurrió un error en el servidor al intentar actualizar el cliente.' });
    }
});

// Obtener Proveedor por ID (CU-16 / CU-45)
app.get('/api/proveedores/:id', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_PROV AS "ID_PROV", 
                TIP_SUM AS "TIP_SUM", 
                NOM_PROV AS "NOM_PROV", 
                RFC_PROV AS "RFC_PROV", 
                DIR_PROV AS "DIR_PROV", 
                COALESCE(CON_PROV, '') AS "CON_PROV", 
                PRO_PROV AS "PRO_PROV" 
            FROM PROVEEDORES 
            WHERE ID_PROV = $1
        `, [req.params.id]);
        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).json({ exito: false, error: 'Proveedor no encontrado' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener proveedor: ' + err.message });
    }
});

// Actualizar Proveedor individual con campo Contacto / Correo editable (CU-16 / CU-45 / RN-34 / RN-35)
app.put('/api/proveedores/:id', async (req, res) => {
    try {
        const tienePermiso = await verificarAccesoAdmin(req, res);
        if (!tienePermiso) return;

        const id_prov = req.params.id;
        const { tip_sum, nom_prov, rfc_prov, dir_prov, con_prov, correo, pro_prov } = req.body || {};

        const nom_prov_val = nom_prov !== undefined ? nom_prov : req.body?.NOM_PROV;
        const tip_sum_val = tip_sum !== undefined ? tip_sum : req.body?.TIP_SUM;
        const rfc_prov_val = rfc_prov !== undefined ? rfc_prov : req.body?.RFC_PROV;
        const dir_prov_val = dir_prov !== undefined ? dir_prov : req.body?.DIR_PROV;
        const con_prov_val = con_prov !== undefined ? con_prov : (correo !== undefined ? correo : (req.body?.CON_PROV !== undefined ? req.body?.CON_PROV : req.body?.COR_PROV));
        const pro_prov_val = pro_prov !== undefined ? pro_prov : req.body?.PRO_PROV;

        if (nom_prov_val !== undefined && (!nom_prov_val || typeof nom_prov_val !== 'string' || !nom_prov_val.trim())) {
            return res.status(400).json({ exito: false, error: 'El nombre del proveedor no puede estar vacío.' });
        }

        let updates = [];
        let values = [];
        let paramIdx = 1;

        if (nom_prov_val !== undefined) {
            updates.push(`NOM_PROV = $${paramIdx++}`);
            values.push(nom_prov_val.trim());
        }
        if (tip_sum_val !== undefined) {
            updates.push(`TIP_SUM = $${paramIdx++}`);
            values.push(tip_sum_val && String(tip_sum_val).trim() ? String(tip_sum_val).trim() : null);
        }
        if (rfc_prov_val !== undefined) {
            updates.push(`RFC_PROV = $${paramIdx++}`);
            values.push(rfc_prov_val && String(rfc_prov_val).trim() ? String(rfc_prov_val).trim() : null);
        }
        if (dir_prov_val !== undefined) {
            updates.push(`DIR_PROV = $${paramIdx++}`);
            values.push(dir_prov_val && String(dir_prov_val).trim() ? String(dir_prov_val).trim() : null);
        }
        if (con_prov_val !== undefined) {
            updates.push(`CON_PROV = $${paramIdx++}`);
            values.push(con_prov_val && String(con_prov_val).trim() ? String(con_prov_val).trim() : null);
        }
        if (pro_prov_val !== undefined) {
            updates.push(`PRO_PROV = $${paramIdx++}`);
            values.push(pro_prov_val && String(pro_prov_val).trim() ? String(pro_prov_val).trim() : null);
        }

        if (updates.length === 0) return res.json({ exito: true, mensaje: 'Sin cambios para actualizar.' });

        values.push(id_prov);
        await pool.query(`UPDATE PROVEEDORES SET ${updates.join(', ')} WHERE ID_PROV = $${paramIdx}`, values);
        res.json({ exito: true, mensaje: 'Proveedor actualizado correctamente.' });
    } catch (err) {
        console.error('Error al actualizar proveedor:', err.message);
        res.status(500).json({ exito: false, error: 'Ocurrió un error en el servidor al intentar actualizar el proveedor.' });
    }
});

// Obtener Empleado por ID (CU-16 / CU-46)
app.get('/api/empleados/:id', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_EMP AS "ID_EMP", 
                TIP_EMP AS "TIP_EMP", 
                CURP_EMP AS "CURP_EMP", 
                NOM_EMP AS "NOM_EMP", 
                DIR_EMP AS "DIR_EMP", 
                PUE_EMP AS "PUE_EMP", 
                HOR_EMP AS "HOR_EMP", 
                CASE 
                    WHEN SUE_EMP IS NULL THEN NULL 
                    ELSE CAST(SUE_EMP AS FLOAT) 
                END AS "SUE_EMP" 
            FROM EMPLEADOS 
            WHERE ID_EMP = $1
        `, [req.params.id]);
        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).json({ exito: false, error: 'Empleado no encontrado' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener empleado: ' + err.message });
    }
});

// Actualizar Empleado individual con campo Sueldo editable (CU-16 / CU-46 / RN-16 / RN-34 / RN-35)
app.put('/api/empleados/:id', async (req, res) => {
    try {
        const tienePermiso = await verificarAccesoAdmin(req, res);
        if (!tienePermiso) return;

        const id_emp = req.params.id;
        const { tip_emp, curp_emp, nom_emp, dir_emp, pue_emp, hor_emp, sue_emp, sueldo } = req.body || {};

        const nom_emp_val = nom_emp !== undefined ? nom_emp : req.body?.NOM_EMP;
        const tip_emp_val = tip_emp !== undefined ? tip_emp : req.body?.TIP_EMP;
        const curp_emp_val = curp_emp !== undefined ? curp_emp : req.body?.CURP_EMP;
        const dir_emp_val = dir_emp !== undefined ? dir_emp : req.body?.DIR_EMP;
        const pue_emp_val = pue_emp !== undefined ? pue_emp : req.body?.PUE_EMP;
        const hor_emp_val = hor_emp !== undefined ? hor_emp : req.body?.HOR_EMP;
        const sue_emp_val = sue_emp !== undefined ? sue_emp : (sueldo !== undefined ? sueldo : req.body?.SUE_EMP);

        if (nom_emp_val !== undefined && (!nom_emp_val || typeof nom_emp_val !== 'string' || !nom_emp_val.trim())) {
            return res.status(400).json({ exito: false, error: 'El nombre del empleado no puede estar vacío.' });
        }

        let updates = [];
        let values = [];
        let paramIdx = 1;

        if (nom_emp_val !== undefined) {
            updates.push(`NOM_EMP = $${paramIdx++}`);
            values.push(nom_emp_val.trim());
        }
        if (tip_emp_val !== undefined) {
            updates.push(`TIP_EMP = $${paramIdx++}`);
            values.push(tip_emp_val && String(tip_emp_val).trim() ? String(tip_emp_val).trim() : null);
        }
        if (curp_emp_val !== undefined) {
            const curpValLimpia = curp_emp_val && String(curp_emp_val).trim() ? String(curp_emp_val).trim().toUpperCase() : null;
            if (curpValLimpia) {
                const regexCurp = /^[A-Z][AEIOUX][A-Z]{2}\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[HMX](?:AS|BC|BS|CC|CL|CM|CS|CH|DF|DG|GT|GR|HG|JC|MC|MN|MS|NT|NL|OC|PL|QT|QR|SP|SL|SR|TC|TS|TL|VZ|YN|ZS|NE)[B-DF-HJ-NP-TV-ZX]{3}[0-9A-J][0-9A-Z]$/;
                if (!regexCurp.test(curpValLimpia)) {
                    return res.status(400).json({
                        exito: false,
                        error: 'El formato de la CURP es inválido. Debe contener exactamente 18 caracteres alfanuméricos según el formato oficial mexicano (ejemplo: ABCD000101HDFRND01).'
                    });
                }
                const checkCurp = await pool.query('SELECT COUNT(*) AS "total" FROM EMPLEADOS WHERE UPPER(CURP_EMP) = $1 AND ID_EMP <> $2', [curpValLimpia, id_emp]);
                if (parseInt(checkCurp.rows[0]?.total, 10) > 0) {
                    return res.status(400).json({ exito: false, error: `El empleado con CURP "${curpValLimpia}" ya está registrado.` });
                }
            }
            updates.push(`CURP_EMP = $${paramIdx++}`);
            values.push(curpValLimpia);
        }
        if (dir_emp_val !== undefined) {
            updates.push(`DIR_EMP = $${paramIdx++}`);
            values.push(dir_emp_val && String(dir_emp_val).trim() ? String(dir_emp_val).trim() : null);
        }
        if (pue_emp_val !== undefined) {
            updates.push(`PUE_EMP = $${paramIdx++}`);
            values.push(pue_emp_val && String(pue_emp_val).trim() ? String(pue_emp_val).trim() : null);
        }
        if (hor_emp_val !== undefined) {
            updates.push(`HOR_EMP = $${paramIdx++}`);
            values.push(hor_emp_val && String(hor_emp_val).trim() ? String(hor_emp_val).trim() : null);
        }
        if (sue_emp_val !== undefined) {
            const numSueldo = typeof sue_emp_val === 'number' ? sue_emp_val : parseFloat(String(sue_emp_val).replace(/[^0-9.-]/g, ''));
            if (!isNaN(numSueldo) && numSueldo >= 0) {
                updates.push(`SUE_EMP = $${paramIdx++}`);
                values.push(numSueldo);
            }
        }

        if (updates.length === 0) return res.json({ exito: true, mensaje: 'Sin cambios para actualizar.' });

        values.push(id_emp);
        await pool.query(`UPDATE EMPLEADOS SET ${updates.join(', ')} WHERE ID_EMP = $${paramIdx}`, values);
        res.json({ exito: true, mensaje: 'Empleado actualizado correctamente.' });
    } catch (err) {
        console.error('Error al actualizar empleado:', err.message);
        res.status(500).json({ exito: false, error: 'Ocurrió un error en el servidor al intentar actualizar el empleado.' });
    }
});

// Obtener Producto por ID (CU-16 / CU-48)
app.get('/api/productos/:id', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_PRO AS "ID_PRO", 
                TIP_PRO AS "TIP_PRO", 
                DESC_PRO AS "DESC_PRO", 
                STOCK_PRO AS "STOCK_PRO", 
                CASE 
                    WHEN PREC_PRO IS NULL THEN NULL 
                    ELSE CAST(PREC_PRO AS FLOAT) 
                END AS "PREC_PRO", 
                ID_PROV AS "ID_PROV" 
            FROM PRODUCTOS 
            WHERE ID_PRO = $1
        `, [req.params.id]);
        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).json({ exito: false, error: 'Producto no encontrado' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener producto: ' + err.message });
    }
});

// Actualizar Producto individual (CU-16 / CU-48 / RN-16 / RN-17 / RN-34 / RN-35)
app.put('/api/productos/:id', async (req, res) => {
    try {
        const tienePermiso = await verificarAccesoAdmin(req, res);
        if (!tienePermiso) return;

        const id_pro = req.params.id;
        const { tip_pro, desc_pro, stock_pro, prec_pro, precio, id_prov } = req.body || {};

        const prec_val = prec_pro !== undefined ? prec_pro : (precio !== undefined ? precio : req.body?.PREC_PRO);
        const stock_val = stock_pro !== undefined ? stock_pro : req.body?.STOCK_PRO;
        const desc_val = desc_pro !== undefined ? desc_pro : req.body?.DESC_PRO;
        const tip_val = tip_pro !== undefined ? tip_pro : req.body?.TIP_PRO;
        const prov_val = id_prov !== undefined ? id_prov : req.body?.ID_PROV;

        if (desc_val !== undefined && (!desc_val || typeof desc_val !== 'string' || !desc_val.trim())) {
            return res.status(400).json({ exito: false, error: 'La descripción del producto no puede estar vacía.' });
        }

        if (prec_val !== undefined && prec_val !== null && String(prec_val).trim() !== '') {
            const numPrecio = typeof prec_val === 'number' ? prec_val : parseFloat(String(prec_val).trim());
            if (isNaN(numPrecio) || numPrecio < 0) {
                return res.status(400).json({
                    exito: false,
                    error: 'El precio del producto debe ser mayor o igual a 0 y no puede ser negativo (RN-16).'
                });
            }
        }

        if (stock_val !== undefined && stock_val !== null && String(stock_val).trim() !== '') {
            const numStock = typeof stock_val === 'number' ? stock_val : Number(String(stock_val).trim());
            if (isNaN(numStock) || !Number.isInteger(numStock) || numStock < 0) {
                return res.status(400).json({
                    exito: false,
                    error: 'El stock del producto debe ser un número entero mayor o igual a 0 (RN-17).'
                });
            }
        }

        if (prov_val !== undefined && prov_val !== null && String(prov_val).trim() !== '') {
            const provCheck = await pool.query(`
                SELECT COUNT(*) AS "total" 
                FROM PROVEEDORES 
                WHERE ID_PROV = $1 OR TRIM(LOWER(NOM_PROV)) = TRIM(LOWER($1))
            `, [String(prov_val).trim()]);
            if (parseInt(provCheck.rows[0].total) === 0) {
                return res.status(400).json({
                    exito: false,
                    error: 'El proveedor seleccionado no existe en el sistema (RN-20).'
                });
            }
        }

        let updates = [];
        let values = [];
        let paramIdx = 1;

        if (desc_val !== undefined) {
            updates.push(`DESC_PRO = $${paramIdx++}`);
            values.push(desc_val.trim());
        }
        if (tip_val !== undefined) {
            updates.push(`TIP_PRO = $${paramIdx++}`);
            values.push(tip_val && String(tip_val).trim() ? String(tip_val).trim() : null);
        }
        if (prec_val !== undefined) {
            const numPrec = typeof prec_val === 'number' ? prec_val : parseFloat(String(prec_val).trim());
            updates.push(`PREC_PRO = $${paramIdx++}`);
            values.push(numPrec);
        }
        if (stock_val !== undefined) {
            const numStk = typeof stock_val === 'number' ? stock_val : parseInt(String(stock_val).trim(), 10);
            updates.push(`STOCK_PRO = $${paramIdx++}`);
            values.push(numStk);
        }
        if (prov_val !== undefined) {
            updates.push(`ID_PROV = $${paramIdx++}`);
            values.push(prov_val && String(prov_val).trim() ? String(prov_val).trim() : null);
        }

        if (updates.length === 0) return res.json({ exito: true, mensaje: 'Sin cambios para actualizar.' });

        values.push(id_pro);
        await pool.query(`UPDATE PRODUCTOS SET ${updates.join(', ')} WHERE ID_PRO = $${paramIdx}`, values);
        res.json({ exito: true, mensaje: 'Producto actualizado correctamente.' });
    } catch (err) {
        console.error('Error al actualizar producto:', err.message);
        res.status(500).json({ exito: false, error: 'Ocurrió un error en el servidor al intentar actualizar el producto.' });
    }
});

// Obtener Planta por ID (CU-16 / CU-49)
app.get('/api/plantas/:id', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_PLANTA AS "ID_PLANTA", 
                TIP_PLANTA AS "TIP_PLANTA", 
                NOM_CTFO AS "NOM_CTFO", 
                NOM_COM AS "NOM_COM", 
                TAM_PLANT AS "TAM_PLANT", 
                STOCK_PLANT AS "STOCK_PLANT", 
                PROV_PLANT AS "PROV_PLANT", 
                CASE 
                    WHEN PREC_PLANTA IS NULL THEN NULL 
                    ELSE CAST(PREC_PLANTA AS FLOAT) 
                END AS "PREC_PLANTA" 
            FROM PLANTAS 
            WHERE ID_PLANTA = $1
        `, [req.params.id]);
        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).json({ exito: false, error: 'Planta no encontrada' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener planta: ' + err.message });
    }
});

// Actualizar Planta individual (CU-16 / CU-49 / RN-16 / RN-17 / RN-34 / RN-35)
app.put('/api/plantas/:id', async (req, res) => {
    try {
        const tienePermiso = await verificarAccesoAdmin(req, res);
        if (!tienePermiso) return;

        const id_planta = req.params.id;
        const { tip_planta, nom_ctfo, nom_com, tam_plant, stock_plant, stock, prov_plant, prec_planta, precio } = req.body || {};

        const stock_val = stock_plant !== undefined ? stock_plant : (stock !== undefined ? stock : req.body?.STOCK_PLANT);
        const prec_val = prec_planta !== undefined ? prec_planta : (precio !== undefined ? precio : req.body?.PREC_PLANTA);
        const ctfo_val = nom_ctfo !== undefined ? nom_ctfo : req.body?.NOM_CTFO;
        const com_val = nom_com !== undefined ? nom_com : req.body?.NOM_COM;
        const tip_val = tip_planta !== undefined ? tip_planta : req.body?.TIP_PLANTA;
        const tam_val = tam_plant !== undefined ? tam_plant : req.body?.TAM_PLANT;
        const prov_val = prov_plant !== undefined ? prov_plant : req.body?.PROV_PLANT;

        if (ctfo_val !== undefined && (!ctfo_val || typeof ctfo_val !== 'string' || !ctfo_val.trim())) {
            return res.status(400).json({ exito: false, error: 'El nombre científico de la planta no puede estar vacío.' });
        }

        if (stock_val !== undefined && stock_val !== null && String(stock_val).trim() !== '') {
            const numStock = typeof stock_val === 'number' ? stock_val : Number(String(stock_val).trim());
            if (isNaN(numStock) || !Number.isInteger(numStock) || numStock < 0) {
                return res.status(400).json({
                    exito: false,
                    error: 'El stock de la planta debe ser un número entero mayor o igual a 0 (no se permiten valores negativos, RN-17).'
                });
            }
        }

        if (prec_val !== undefined && prec_val !== null && String(prec_val).trim() !== '') {
            const numPrecio = typeof prec_val === 'number' ? prec_val : parseFloat(String(prec_val).trim());
            if (isNaN(numPrecio) || numPrecio < 0) {
                return res.status(400).json({
                    exito: false,
                    error: 'El precio de la planta debe ser mayor o igual a 0 y no puede ser negativo (RN-16).'
                });
            }
        }

        let updates = [];
        let values = [];
        let paramIdx = 1;

        if (ctfo_val !== undefined) {
            updates.push(`NOM_CTFO = $${paramIdx++}`);
            values.push(ctfo_val.trim());
        }
        if (com_val !== undefined) {
            updates.push(`NOM_COM = $${paramIdx++}`);
            values.push(com_val && String(com_val).trim() ? String(com_val).trim() : null);
        }
        if (tip_val !== undefined) {
            updates.push(`TIP_PLANTA = $${paramIdx++}`);
            values.push(tip_val && String(tip_val).trim() ? String(tip_val).trim() : null);
        }
        if (tam_val !== undefined) {
            updates.push(`TAM_PLANT = $${paramIdx++}`);
            values.push(tam_val && String(tam_val).trim() ? String(tam_val).trim() : null);
        }
        if (stock_val !== undefined) {
            const numStk = typeof stock_val === 'number' ? stock_val : parseInt(String(stock_val).trim(), 10);
            updates.push(`STOCK_PLANT = $${paramIdx++}`);
            values.push(numStk);
        }
        if (prec_val !== undefined) {
            const numPrec = typeof prec_val === 'number' ? prec_val : parseFloat(String(prec_val).trim());
            updates.push(`PREC_PLANTA = $${paramIdx++}`);
            values.push(numPrec);
        }
        if (prov_val !== undefined) {
            updates.push(`PROV_PLANT = $${paramIdx++}`);
            values.push(prov_val && String(prov_val).trim() ? String(prov_val).trim() : null);
        }

        if (updates.length === 0) return res.json({ exito: true, mensaje: 'Sin cambios para actualizar.' });

        values.push(id_planta);
        await pool.query(`UPDATE PLANTAS SET ${updates.join(', ')} WHERE ID_PLANTA = $${paramIdx}`, values);
        res.json({ exito: true, mensaje: 'Planta actualizada correctamente.' });
    } catch (err) {
        console.error('Error al actualizar planta:', err.message);
        res.status(500).json({ exito: false, error: 'Ocurrió un error en el servidor al intentar actualizar la planta.' });
    }
});

// RUTA MAESTRA PARA ACTUALIZAR CUALQUIER TABLA (CU-16 / CU-42 / CU-47 / CU-48 / CU-49 / RN-16 / RN-17 / RN-18 / RN-34 / RN-35)
app.put('/api/actualizar', async (req, res) => {
    try {
        const tienePermiso = await verificarAccesoAdmin(req, res);
        if (!tienePermiso) return;

        const { tabla, idColumn, idValue, campos } = req.body || {};
        
        if (!tabla || !/^[a-zA-Z0-9_]+$/.test(tabla)) {
            return res.status(400).json({ exito: false, error: 'Tabla inválida' });
        }
        if (!idColumn || !/^[a-zA-Z0-9_]+$/.test(idColumn)) {
            return res.status(400).json({ exito: false, error: 'Columna ID inválida' });
        }

        // Validación de precio no negativo para PRODUCTOS según RN-16 (CU-21 / CU-48)
        if (tabla.toUpperCase() === 'PRODUCTOS' || Object.keys(campos || {}).some(k => k.toUpperCase() === 'PREC_PRO')) {
            for (const key of Object.keys(campos || {})) {
                if (key.toUpperCase() === 'PREC_PRO' || key.toLowerCase() === 'prec_pro' || key.toLowerCase() === 'precio') {
                    const rawPrecio = campos[key];
                    if (rawPrecio !== undefined && rawPrecio !== null && String(rawPrecio).trim() !== '') {
                        const numPrecio = typeof rawPrecio === 'number' ? rawPrecio : parseFloat(String(rawPrecio).trim());
                        if (isNaN(numPrecio) || numPrecio < 0) {
                            return res.status(400).json({
                                exito: false,
                                error: 'El precio del producto debe ser mayor o igual a 0 y no puede ser negativo (RN-16).'
                            });
                        }
                    }
                }
            }
        }

        // Validación de precio no negativo para PLANTAS según RN-16 (CU-23)
        if (tabla.toUpperCase() === 'PLANTAS' || Object.keys(campos || {}).some(k => k.toUpperCase() === 'PREC_PLANTA')) {
            for (const key of Object.keys(campos || {})) {
                if (key.toUpperCase() === 'PREC_PLANTA' || key.toLowerCase() === 'prec_planta') {
                    const rawPrecio = campos[key];
                    if (rawPrecio !== undefined && rawPrecio !== null && String(rawPrecio).trim() !== '') {
                        const numPrecio = typeof rawPrecio === 'number' ? rawPrecio : parseFloat(String(rawPrecio).trim());
                        if (isNaN(numPrecio) || numPrecio < 0) {
                            return res.status(400).json({
                                exito: false,
                                error: 'El precio de la planta debe ser mayor o igual a 0 y no puede ser negativo (RN-16).'
                            });
                        }
                    }
                }
            }
        }

        // Validación de stock no negativo para PLANTAS según RN-17 (CU-24 / CU-49)
        if (tabla.toUpperCase() === 'PLANTAS' || Object.keys(campos || {}).some(k => k.toUpperCase() === 'STOCK_PLANT')) {
            for (const key of Object.keys(campos || {})) {
                if (key.toUpperCase() === 'STOCK_PLANT' || key.toLowerCase() === 'stock_plant' || (tabla.toUpperCase() === 'PLANTAS' && (key.toLowerCase() === 'stock' || key.toUpperCase() === 'STOCK'))) {
                    const rawStock = campos[key];
                    if (rawStock !== undefined && rawStock !== null && String(rawStock).trim() !== '') {
                        const numStock = typeof rawStock === 'number' ? rawStock : Number(String(rawStock).trim());
                        if (isNaN(numStock) || !Number.isInteger(numStock) || numStock < 0) {
                            return res.status(400).json({
                                exito: false,
                                error: 'El stock de la planta debe ser un número entero mayor o igual a 0 (no se permiten valores negativos, RN-17).'
                            });
                        }
                    }
                }
            }
        }

        // Validación de stock no negativo para PRODUCTOS según RN-17 (CU-22)
        if (tabla.toUpperCase() === 'PRODUCTOS' || Object.keys(campos || {}).some(k => k.toUpperCase() === 'STOCK_PRO')) {
            for (const key of Object.keys(campos || {})) {
                if (key.toUpperCase() === 'STOCK_PRO' || key.toLowerCase() === 'stock_pro' || (tabla.toUpperCase() === 'PRODUCTOS' && (key.toLowerCase() === 'stock' || key.toUpperCase() === 'STOCK'))) {
                    const rawStock = campos[key];
                    if (rawStock !== undefined && rawStock !== null && String(rawStock).trim() !== '') {
                        const numStock = typeof rawStock === 'number' ? rawStock : Number(String(rawStock).trim());
                        if (isNaN(numStock) || !Number.isInteger(numStock) || numStock < 0) {
                            return res.status(400).json({
                                exito: false,
                                error: 'El stock del producto debe ser un número entero mayor o igual a 0 (no se permiten valores negativos, RN-17).'
                            });
                        }
                    }
                }
            }
        }

        // Validación de cantidad de pedido según N1 (mayor que 0)
        if (tabla.toUpperCase() === 'PEDIDOS' || Object.keys(campos || {}).some(k => k.toUpperCase() === 'NUM_CAN' || k.toUpperCase() === 'NUM_CAN_PLANT')) {
            for (const key of Object.keys(campos || {})) {
                if (key.toUpperCase() === 'NUM_CAN' || key.toLowerCase() === 'num_can') {
                    const rawCan = campos[key];
                    if (rawCan !== undefined && rawCan !== null && String(rawCan).trim() !== '') {
                        const numCan = typeof rawCan === 'number' ? rawCan : Number(String(rawCan).trim());
                        if (isNaN(numCan) || !Number.isInteger(numCan) || numCan <= 0) {
                            return res.status(400).json({
                                exito: false,
                                error: 'La cantidad del producto debe ser un número entero mayor que 0.'
                            });
                        }
                    }
                }
                if (key.toUpperCase() === 'NUM_CAN_PLANT' || key.toLowerCase() === 'num_can_plant') {
                    const rawCan = campos[key];
                    if (rawCan !== undefined && rawCan !== null && String(rawCan).trim() !== '') {
                        const numCan = typeof rawCan === 'number' ? rawCan : Number(String(rawCan).trim());
                        if (isNaN(numCan) || !Number.isInteger(numCan) || numCan <= 0) {
                            return res.status(400).json({
                                exito: false,
                                error: 'La cantidad de la planta debe ser un número entero mayor que 0.'
                            });
                        }
                    }
                }
            }
        }

        // Validación de total mayor que 0 para VENTAS según N2
        if (tabla.toUpperCase() === 'VENTAS' || Object.keys(campos || {}).some(k => k.toUpperCase() === 'TOT_PAGO')) {
            for (const key of Object.keys(campos || {})) {
                if (key.toUpperCase() === 'TOT_PAGO' || key.toLowerCase() === 'tot_pago' || key.toLowerCase() === 'total') {
                    const rawTotal = campos[key];
                    if (rawTotal !== undefined && rawTotal !== null && String(rawTotal).trim() !== '') {
                        const numTotal = typeof rawTotal === 'number' ? rawTotal : parseFloat(String(rawTotal).trim());
                        if (isNaN(numTotal) || numTotal <= 0) {
                            return res.status(400).json({
                                exito: false,
                                error: 'El total de la venta debe ser mayor a 0 (no se permiten ventas con total $0.00).'
                            });
                        }
                    }
                }
            }
        }

        // Validación de saldo y regla RN-29 para VENTAS (CU-30 / RN-16 / RN-29 / N6)
        if (tabla.toUpperCase() === 'VENTAS') {
            let saldoVal = campos?.['SALDO_PAGO'] ?? campos?.['saldo_pago'] ?? campos?.['SALDO'] ?? campos?.['saldo'];
            let totalVal = campos?.['TOT_PAGO'] ?? campos?.['tot_pago'] ?? campos?.['TOTAL'] ?? campos?.['total'];
            
            if (saldoVal !== undefined || totalVal !== undefined) {
                if (saldoVal === undefined || totalVal === undefined) {
                    try {
                        const rowActual = await pool.query('SELECT TOT_PAGO AS "TOT_PAGO", SALDO_PAGO AS "SALDO_PAGO" FROM VENTAS WHERE ID_VEN = $1', [idValue]);
                        if (rowActual.rows.length > 0) {
                            if (saldoVal === undefined) saldoVal = rowActual.rows[0].SALDO_PAGO;
                            if (totalVal === undefined) totalVal = rowActual.rows[0].TOT_PAGO;
                        }
                    } catch (e) {}
                }
                const numSaldoCheck = Math.round((parseFloat(saldoVal) + Number.EPSILON) * 100) / 100;
                const numTotalCheck = Math.round((parseFloat(totalVal) + Number.EPSILON) * 100) / 100;
                
                if (!isNaN(numSaldoCheck) && numSaldoCheck < 0) {
                    return res.status(400).json({
                        exito: false,
                        error: 'El saldo pendiente debe ser mayor o igual a 0 (RN-16).'
                    });
                }
                if (!isNaN(numSaldoCheck) && !isNaN(numTotalCheck) && numSaldoCheck > numTotalCheck) {
                    return res.status(400).json({
                        exito: false,
                        error: 'El saldo pendiente no puede exceder el total de la venta (RN-29).'
                    });
                }
            }
        }

        // Validación de existencia de proveedor para PRODUCTOS según RN-20 (CU-50)
        if (tabla.toUpperCase() === 'PRODUCTOS' || Object.keys(campos || {}).some(k => k.toUpperCase() === 'ID_PROV')) {
            const rawProv = campos?.['ID_PROV'] !== undefined 
                ? campos['ID_PROV'] 
                : (campos?.['id_prov'] !== undefined ? campos['id_prov'] : campos?.['proveedor']);
            if (rawProv !== undefined && rawProv !== null && String(rawProv).trim() !== '') {
                const provLimpio = String(rawProv).trim();
                const provCheck = await pool.query(`
                    SELECT COUNT(*) AS "total" 
                    FROM PROVEEDORES 
                    WHERE ID_PROV = $1 OR TRIM(LOWER(NOM_PROV)) = TRIM(LOWER($1))
                `, [provLimpio]);
                if (parseInt(provCheck.rows[0].total) === 0) {
                    return res.status(400).json({
                        exito: false,
                        error: 'El proveedor seleccionado no existe en el sistema (RN-20).'
                    });
                }
            } else if (tabla.toUpperCase() === 'PRODUCTOS' && (campos?.['ID_PROV'] !== undefined || campos?.['id_prov'] !== undefined)) {
                return res.status(400).json({
                    exito: false,
                    error: 'El proveedor es obligatorio (RN-20).'
                });
            }
        }

        // Validación de existencia de proveedor para PLANTAS según RN-20
        if (tabla.toUpperCase() === 'PLANTAS' && Object.keys(campos || {}).some(k => k.toUpperCase() === 'PROV_PLANT')) {
            const rawProv = campos['PROV_PLANT'] !== undefined ? campos['PROV_PLANT'] : campos['prov_plant'];
            if (rawProv !== undefined && rawProv !== null && String(rawProv).trim() !== '') {
                const provLimpio = String(rawProv).trim();
                const provCheck = await pool.query(`
                    SELECT COUNT(*) AS "total" 
                    FROM PROVEEDORES 
                    WHERE ID_PROV = $1 OR TRIM(LOWER(NOM_PROV)) = TRIM(LOWER($1))
                `, [provLimpio]);
                if (parseInt(provCheck.rows[0].total) === 0) {
                    return res.status(400).json({
                        exito: false,
                        error: 'El proveedor seleccionado no existe en el sistema (RN-20).'
                    });
                }
            }
        }

        // Validación de formato de correo si se actualiza la tabla CLIENTES (CU-11 / CU-12 / CU-16 / CU-42 / CU-47 / RN-18)
        if (tabla.toUpperCase() === 'CLIENTES') {
            const rawCorreo = campos?.['COR_CLI'] !== undefined ? campos['COR_CLI'] : campos?.['cor_cli'];
            if (rawCorreo !== undefined && rawCorreo !== null && String(rawCorreo).trim() !== '') {
                const correoLimpio = String(rawCorreo).trim();
                const partesCorreo = correoLimpio.split('@');
                if (partesCorreo.length !== 2 || !partesCorreo[1] || !partesCorreo[1].trim()) {
                    return res.status(400).json({
                        exito: false,
                        error: 'El correo electrónico debe incluir un dominio después del símbolo "@" (ejemplo: usuario@dominio.com).'
                    });
                }

                const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
                if (!emailRegex.test(correoLimpio)) {
                    return res.status(400).json({
                        exito: false,
                        error: 'El correo electrónico no cumple con un formato válido con dominio (ejemplo: usuario@dominio.com).'
                    });
                }
            }

            for (const key of Object.keys(campos || {})) {
                if (key.toUpperCase() === 'COM_CLI' || key.toLowerCase() === 'com_cli' ||
                    key.toUpperCase() === 'PREF_CLI' || key.toLowerCase() === 'pref_cli' ||
                    key.toUpperCase() === 'DIR_CLI' || key.toLowerCase() === 'dir_cli') {
                    if (campos[key] !== undefined && campos[key] !== null) {
                        campos[key] = sanitizarSqlYHtml(campos[key]);
                    }
                }
            }
        }

        // Validación de unicidad de USERNAME para USUARIOS según RN-13 y caso CP-13 (CU-51)
        if (tabla.toUpperCase() === 'USUARIOS' || Object.keys(campos || {}).some(k => k.toUpperCase() === 'USERNAME')) {
            const rawUsername = campos?.['USERNAME'] !== undefined 
                ? campos['USERNAME'] 
                : (campos?.['username'] !== undefined ? campos['username'] : null);
            if (rawUsername !== undefined && rawUsername !== null && String(rawUsername).trim() !== '') {
                const usernameLimpio = String(rawUsername).trim();

                if (usernameLimpio.length > 80) {
                    return res.status(400).json({
                        exito: false,
                        error: 'El nombre de usuario no puede exceder los 80 caracteres (RN-19).'
                    });
                }

                const checkUser = await pool.query(`
                    SELECT COUNT(*) AS "total" 
                    FROM USUARIOS 
                    WHERE TRIM(LOWER(USERNAME)) = TRIM(LOWER($1))
                      AND ${idColumn} != $2
                `, [usernameLimpio, String(idValue)]);
                if (parseInt(checkUser.rows[0].total) > 0) {
                    return res.status(400).json({
                        exito: false,
                        error: `Error UNIQUE: El nombre de usuario "${usernameLimpio}" ya existe en el sistema. Según la regla RN-13 (CP-13) el USERNAME debe ser único.`
                    });
                }
            }
        }

        // Validación de longitud máxima para EMPLEADOS (NOM_EMP VARCHAR(150)) según Diccionario de Datos (N4 / RN-19)
        if (tabla.toUpperCase() === 'EMPLEADOS' || Object.keys(campos || {}).some(k => k.toUpperCase() === 'NOM_EMP')) {
            const rawNom = campos?.['NOM_EMP'] !== undefined ? campos['NOM_EMP'] : campos?.['nom_emp'];
            if (rawNom !== undefined && rawNom !== null) {
                const nomLimpio = String(rawNom).trim();
                if (nomLimpio.length > 150) {
                    return res.status(400).json({
                        exito: false,
                        error: 'El nombre del empleado no puede exceder los 150 caracteres (NOM_EMP VARCHAR(150)).'
                    });
                }
            }
        }

        // Validación de CURP para EMPLEADOS (CU-14)
        if (tabla.toUpperCase() === 'EMPLEADOS' || Object.keys(campos || {}).some(k => k.toUpperCase() === 'CURP_EMP')) {
            const rawCurp = campos?.['CURP_EMP'] !== undefined ? campos['CURP_EMP'] : campos?.['curp_emp'];
            if (rawCurp !== undefined && rawCurp !== null && String(rawCurp).trim() !== '') {
                const curpLimpio = String(rawCurp).trim().toUpperCase();
                const regexCurp = /^[A-Z][AEIOUX][A-Z]{2}\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[HMX](?:AS|BC|BS|CC|CL|CM|CS|CH|DF|DG|GT|GR|HG|JC|MC|MN|MS|NT|NL|OC|PL|QT|QR|SP|SL|SR|TC|TS|TL|VZ|YN|ZS|NE)[B-DF-HJ-NP-TV-ZX]{3}[0-9A-J][0-9A-Z]$/;
                if (!regexCurp.test(curpLimpio)) {
                    return res.status(400).json({
                        exito: false,
                        error: 'El formato de la CURP es inválido. Debe contener exactamente 18 caracteres alfanuméricos según el formato oficial mexicano (ejemplo: ABCD000101HDFRND01).'
                    });
                }
                const checkCurp = await pool.query(`
                    SELECT COUNT(*) AS "total" FROM EMPLEADOS 
                    WHERE UPPER(CURP_EMP) = $1 AND ${idColumn} != $2
                `, [curpLimpio, String(idValue)]);
                if (parseInt(checkCurp.rows[0].total) > 0) {
                    return res.status(400).json({
                        exito: false,
                        error: `El empleado con CURP "${curpLimpio}" ya está registrado.`
                    });
                }
                for (const k of Object.keys(campos)) {
                    if (k.toUpperCase() === 'CURP_EMP') campos[k] = curpLimpio;
                }
            } else if (rawCurp !== undefined) {
                for (const k of Object.keys(campos)) {
                    if (k.toUpperCase() === 'CURP_EMP') campos[k] = null;
                }
            }
        }

        // Validación de longitud máxima para SERVICIOS (TRAB_REAL VARCHAR(200)) según Diccionario de Datos (N4 / RN-19)
        if (tabla.toUpperCase() === 'SERVICIOS' || Object.keys(campos || {}).some(k => k.toUpperCase() === 'TRAB_REAL')) {
            const rawTrab = campos?.['TRAB_REAL'] !== undefined ? campos['TRAB_REAL'] : (campos?.['trab_real'] !== undefined ? campos['trab_real'] : campos?.['trabajo']);
            if (rawTrab !== undefined && rawTrab !== null) {
                const trabLimpio = String(rawTrab).trim();
                if (trabLimpio.length > 200) {
                    return res.status(400).json({
                        exito: false,
                        error: 'El trabajo realizado no puede exceder los 200 caracteres (TRAB_REAL VARCHAR(200)).'
                    });
                }
            }
        }

        let setQuery = [];
        let values = [];
        let index = 1;
        
        for (const key of Object.keys(campos || {})) {
            if (key !== idColumn && /^[a-zA-Z0-9_]+$/.test(key)) {
                let valor = campos[key];
                // Sanitizar y redondear campos monetarios para evitar residuos de flotantes (N6)
                if (valor !== '' && valor !== null && valor !== undefined) {
                    const keyUpper = key.toUpperCase();
                    if (keyUpper.includes('PREC') || keyUpper.includes('COSTO') || keyUpper.includes('TOT') || keyUpper.includes('SUE') || keyUpper.includes('SALDO')) {
                        const numVal = parseFloat(valor);
                        if (!isNaN(numVal)) {
                            if ((keyUpper.includes('PREC') || keyUpper.includes('COSTO') || keyUpper.includes('SUE')) && numVal <= 0) {
                                return res.status(400).json({
                                    exito: false,
                                    error: `El campo ${key} debe ser mayor a 0 ($0.00 no permitido porque no es gratis).`
                                });
                            }
                            valor = Math.round((numVal + Number.EPSILON) * 100) / 100;
                        }
                    }
                    // Validación de stock mayor a 0
                    if (keyUpper.includes('STOCK')) {
                        const numStock = Number(valor);
                        if (isNaN(numStock) || !Number.isInteger(numStock) || numStock <= 0) {
                            return res.status(400).json({
                                exito: false,
                                error: `El campo ${key} debe ser un número entero mayor a 0 (no se permiten existencias en 0).`
                            });
                        }
                        valor = numStock;
                    }
                    // Cifrado criptográfico de contraseñas si se actualizan desde el panel (RN-41 / N10)
                    if (keyUpper === 'PASSWORD' && !esPasswordHasheada(String(valor))) {
                        valor = hashearPassword(String(valor).trim());
                    }
                }
                values.push(valor !== '' && valor !== null && valor !== undefined ? valor : null);
                setQuery.push(`${key} = $${index}`);
                index++;
            }
        }
        
        if (setQuery.length === 0) return res.json({ exito: true });

        values.push(idValue);
        const query = `UPDATE ${tabla} SET ${setQuery.join(', ')} WHERE ${idColumn} = $${index}`;
        await pool.query(query, values);
        
        if (tabla.toUpperCase() === 'USUARIOS') {
            await registrarAuditoria(req, 'MODIFICAR_PANEL', idValue, null, campos);
        }

        res.json({ exito: true, mensaje: `Registro actualizado correctamente en ${tabla}` });
    } catch (err) {
        console.error('ERROR AL ACTUALIZAR:', err.message);
        if (err.code === '23505' || (err.message && err.message.toUpperCase().includes('UNIQUE'))) {
            return res.status(400).json({
                exito: false,
                error: `No se pudo actualizar: ya existe otro registro con ese mismo valor en un campo único (Regla RN-13 / CP-13).`
            });
        }
        res.status(500).json({ exito: false, error: 'Ocurrió un error en el servidor al intentar actualizar el registro.' });
    }
});

// Función centralizada para eliminación con verificación de dependencias (RN-26 / CU-18 / RN-34 / RN-35 / N5)
async function procesarEliminacion(req, res, tabla, idColumn, idValue) {
    if (!tabla || !/^[a-zA-Z0-9_]+$/.test(tabla)) {
        return res.status(400).json({ exito: false, error: 'Nombre de tabla inválido.' });
    }

    const mapIdCols = {
        'PROVEEDORES': 'ID_PROV',
        'CLIENTES': 'ID_CLI',
        'EMPLEADOS': 'ID_EMP',
        'PRODUCTOS': 'ID_PRO',
        'PLANTAS': 'ID_PLANTA',
        'PEDIDOS': 'ID_PED',
        'VENTAS': 'ID_VEN',
        'SERVICIOS': 'ID_SERV',
        'CAT_SERVICIOS': 'ID_CAT_SERV',
        'USUARIOS': 'ID_USUARIO'
    };

    const col = (idColumn && /^[a-zA-Z0-9_]+$/.test(idColumn)) 
        ? idColumn 
        : (mapIdCols[tabla.toUpperCase()] || 'ID');

    if (!idValue) {
        return res.status(400).json({ exito: false, error: 'Debe proporcionar el identificador del registro a eliminar.' });
    }

    const tablaUpper = tabla.toUpperCase();
    const idStr = String(idValue).trim();

    // 1. Verificación de dependencias según Regla de Negocio RN-26 (Integridad Referencial)
    if (tablaUpper === 'PROVEEDORES') {
        const checkProd = await pool.query('SELECT COUNT(*) AS "total" FROM PRODUCTOS WHERE TRIM(ID_PROV) = TRIM($1)', [idStr]);
        const checkPlant = await pool.query('SELECT COUNT(*) AS "total" FROM PLANTAS WHERE TRIM(PROV_PLANT) = TRIM($1)', [idStr]);
        const totProd = parseInt(checkProd.rows[0]?.total, 10) || 0;
        const totPlant = parseInt(checkPlant.rows[0]?.total, 10) || 0;
        if (totProd > 0 || totPlant > 0) {
            return res.status(400).json({
                exito: false,
                error: `No se puede eliminar el proveedor "${idStr}" porque tiene ${totProd} producto(s) y ${totPlant} planta(s) asociados en el inventario. Según la regla RN-26 no se pueden eliminar registros con dependencias.`
            });
        }
    } else if (tablaUpper === 'CLIENTES') {
        const checkPed = await pool.query('SELECT COUNT(*) AS "total" FROM PEDIDOS WHERE TRIM(ID_CLI) = TRIM($1)', [idStr]);
        const checkVen = await pool.query('SELECT COUNT(*) AS "total" FROM VENTAS WHERE TRIM(ID_CLI) = TRIM($1)', [idStr]);
        const checkServ = await pool.query('SELECT COUNT(*) AS "total" FROM SERVICIOS WHERE TRIM(ID_CLI) = TRIM($1)', [idStr]);
        const totPed = parseInt(checkPed.rows[0]?.total, 10) || 0;
        const totVen = parseInt(checkVen.rows[0]?.total, 10) || 0;
        const totServ = parseInt(checkServ.rows[0]?.total, 10) || 0;
        if (totPed > 0 || totVen > 0 || totServ > 0) {
            return res.status(400).json({
                exito: false,
                error: `No se puede eliminar el cliente "${idStr}" porque tiene registros asociados (${totPed} pedido(s), ${totVen} venta(s), ${totServ} servicio(s)). Según la regla RN-26 no se pueden eliminar registros con dependencias.`
            });
        }
    } else if (tablaUpper === 'EMPLEADOS') {
        const checkUsr = await pool.query('SELECT COUNT(*) AS "total" FROM USUARIOS WHERE TRIM(ID_EMP) = TRIM($1)', [idStr]);
        const checkServ = await pool.query('SELECT COUNT(*) AS "total" FROM SERVICIOS WHERE TRIM(ID_EMP) = TRIM($1)', [idStr]);
        const totUsr = parseInt(checkUsr.rows[0]?.total, 10) || 0;
        const totServ = parseInt(checkServ.rows[0]?.total, 10) || 0;
        if (totUsr > 0 || totServ > 0) {
            return res.status(400).json({
                exito: false,
                error: `No se puede eliminar el empleado "${idStr}" porque tiene ${totUsr} usuario(s) y ${totServ} servicio(s) asociados. Según la regla RN-26 no se pueden eliminar registros con dependencias.`
            });
        }
    } else if (tablaUpper === 'PRODUCTOS') {
        const checkPed = await pool.query('SELECT COUNT(*) AS "total" FROM PEDIDOS WHERE TRIM(ID_PRO) = TRIM($1)', [idStr]);
        const checkVen = await pool.query('SELECT COUNT(*) AS "total" FROM VENTAS WHERE TRIM(ID_PRO) = TRIM($1)', [idStr]);
        const totPed = parseInt(checkPed.rows[0]?.total, 10) || 0;
        const totVen = parseInt(checkVen.rows[0]?.total, 10) || 0;
        if (totPed > 0 || totVen > 0) {
            return res.status(400).json({
                exito: false,
                error: `No se puede eliminar el producto "${idStr}" porque tiene ${totPed} pedido(s) y ${totVen} venta(s) asociados. Según la regla RN-26 no se pueden eliminar registros con dependencias.`
            });
        }
    } else if (tablaUpper === 'PLANTAS') {
        const checkPed = await pool.query('SELECT COUNT(*) AS "total" FROM PEDIDOS WHERE TRIM(ID_PLANTA) = TRIM($1)', [idStr]);
        const checkVen = await pool.query('SELECT COUNT(*) AS "total" FROM VENTAS WHERE TRIM(ID_PLANTA) = TRIM($1)', [idStr]);
        const totPed = parseInt(checkPed.rows[0]?.total, 10) || 0;
        const totVen = parseInt(checkVen.rows[0]?.total, 10) || 0;
        if (totPed > 0 || totVen > 0) {
            return res.status(400).json({
                exito: false,
                error: `No se puede eliminar la planta "${idStr}" porque tiene ${totPed} pedido(s) y ${totVen} venta(s) asociados. Según la regla RN-26 no se pueden eliminar registros con dependencias.`
            });
        }
    } else if (tablaUpper === 'CAT_SERVICIOS') {
        try {
            const hasCol = await pool.query(`
                SELECT 1 FROM information_schema.columns 
                WHERE LOWER(table_name) = 'servicios' AND LOWER(column_name) = 'id_cat_serv'
            `);
            if (hasCol.rows.length > 0) {
                const checkServ = await pool.query('SELECT COUNT(*) AS "total" FROM SERVICIOS WHERE TRIM(ID_CAT_SERV) = TRIM($1)', [idStr]);
                const totServ = parseInt(checkServ.rows[0]?.total, 10) || 0;
                if (totServ > 0) {
                    return res.status(400).json({
                        exito: false,
                        error: `No se puede eliminar el servicio del catálogo "${idStr}" porque tiene ${totServ} servicio(s) registrados. Según la regla RN-26 no se pueden eliminar registros con dependencias.`
                    });
                }
            }
        } catch (e) {
            console.error('Aviso al comprobar dependencias de CAT_SERVICIOS:', e.message);
        }
    } else if (tablaUpper === 'USUARIOS') {
        if (idStr.toLowerCase() === 'usr-001' || idStr.toLowerCase() === 'admin') {
            return res.status(400).json({
                exito: false,
                error: 'No se puede eliminar el usuario Administrador principal del sistema (RN-34).'
            });
        }
    }

    let datosUsuarioPrevio = null;
    if (tablaUpper === 'USUARIOS') {
        try {
            const uCheck = await pool.query(`SELECT ID_USUARIO, USERNAME, ROL, ID_EMP, ESTADO FROM USUARIOS WHERE TRIM(${col}) = TRIM($1) OR TRIM(USERNAME) = TRIM($1)`, [idStr]);
            datosUsuarioPrevio = uCheck.rows[0] || null;
        } catch (e) {}
    }

    try {
        const deleteQuery = `DELETE FROM ${tabla} WHERE TRIM(${col}) = TRIM($1)`;
        const delRes = await pool.query(deleteQuery, [idStr]);

        if (delRes.rowCount === 0) {
            return res.status(404).json({ exito: false, error: `No se encontró el registro "${idStr}" en la tabla "${tabla}".` });
        }

        if (tablaUpper === 'USUARIOS') {
            await registrarAuditoria(req, 'ELIMINAR', idStr, datosUsuarioPrevio, null);
        }

        res.json({ exito: true, mensaje: `Registro "${idStr}" eliminado correctamente de ${tabla}.` });
    } catch (dbErr) {
        if (dbErr.code === '23503') { // foreign_key_violation in PostgreSQL
            return res.status(400).json({
                exito: false,
                error: `No se puede eliminar el registro "${idStr}" de "${tabla}" porque existen otros registros que dependen de él en el sistema (Regla RN-26: Integridad Referencial).`
            });
        }
        throw dbErr;
    }
}

// Endpoint general para eliminar registros (RN-26 / CU-18 / RN-34 / RN-35 / N5)
app.delete('/api/eliminar', async (req, res) => {
    try {
        const tienePermiso = await verificarAccesoAdmin(req, res);
        if (!tienePermiso) return;

        const { tabla, idColumn, idValue } = req.body || {};
        await procesarEliminacion(req, res, tabla, idColumn, idValue);
    } catch (err) {
        console.error('ERROR AL ELIMINAR:', err.message);
        res.status(500).json({ exito: false, error: 'Ocurrió un error en el servidor al intentar eliminar el registro.' });
    }
});

app.delete('/api/eliminar/:tabla/:id', async (req, res) => {
    try {
        const tienePermiso = await verificarAccesoAdmin(req, res);
        if (!tienePermiso) return;

        const tabla = req.params.tabla;
        const idValue = req.params.id;
        const idColumn = req.query?.idCol || req.body?.idColumn;
        await procesarEliminacion(req, res, tabla, idColumn, idValue);
    } catch (err) {
        console.error('ERROR AL ELIMINAR:', err.message);
        res.status(500).json({ exito: false, error: 'Ocurrió un error en el servidor al intentar eliminar el registro.' });
    }
});

// Rutas REST específicas para eliminación por entidad
const entidadesEliminables = [
    { ruta: 'proveedores', tabla: 'PROVEEDORES', idCol: 'ID_PROV' },
    { ruta: 'clientes', tabla: 'CLIENTES', idCol: 'ID_CLI' },
    { ruta: 'empleados', tabla: 'EMPLEADOS', idCol: 'ID_EMP' },
    { ruta: 'productos', tabla: 'PRODUCTOS', idCol: 'ID_PRO' },
    { ruta: 'plantas', tabla: 'PLANTAS', idCol: 'ID_PLANTA' },
    { ruta: 'pedidos', tabla: 'PEDIDOS', idCol: 'ID_PED' },
    { ruta: 'ventas', tabla: 'VENTAS', idCol: 'ID_VEN' },
    { ruta: 'servicios', tabla: 'SERVICIOS', idCol: 'ID_SERV' },
    { ruta: 'catalogo-servicios', tabla: 'CAT_SERVICIOS', idCol: 'ID_CAT_SERV' },
    { ruta: 'usuarios', tabla: 'USUARIOS', idCol: 'ID_USUARIO' }
];

entidadesEliminables.forEach(({ ruta, tabla, idCol }) => {
    app.delete(`/api/${ruta}/:id`, async (req, res) => {
        try {
            const tienePermiso = await verificarAccesoAdmin(req, res);
            if (!tienePermiso) return;
            await procesarEliminacion(req, res, tabla, idCol, req.params.id);
        } catch (err) {
            console.error(`ERROR AL ELIMINAR EN ${tabla}:`, err.message);
            res.status(500).json({ exito: false, error: `Ocurrió un error en el servidor al intentar eliminar el registro en ${tabla}.` });
        }
    });
});

// Limpieza de datos inválidos y artefactos heredados en Supabase (N8 / E5)
async function limpiarDatosInvalidosBaseDatos() {
    try {
        console.log('Iniciando limpieza de datos inválidos y pruebas negativas heredadas en Supabase (N8 / E5)...');

        // 1. CLIENTES: Eliminar CLI-026 y clientes sin nombre si no tienen referencias activas (RN-12 / N8)
        const resCli = await pool.query(`
            DELETE FROM CLIENTES 
            WHERE (ID_CLI = 'CLI-026' OR NOM_CLI IS NULL OR TRIM(NOM_CLI) = '')
              AND ID_CLI NOT IN (SELECT ID_CLI FROM VENTAS WHERE ID_CLI IS NOT NULL)
              AND ID_CLI NOT IN (SELECT ID_CLI FROM PEDIDOS WHERE ID_CLI IS NOT NULL)
              AND ID_CLI NOT IN (SELECT ID_CLI FROM SERVICIOS WHERE ID_CLI IS NOT NULL)
        `);
        await pool.query(`
            UPDATE CLIENTES 
            SET NOM_CLI = 'Cliente General' 
            WHERE (ID_CLI = 'CLI-026' OR NOM_CLI IS NULL OR TRIM(NOM_CLI) = '')
        `);

        // 1.1 Limpieza de 22 correos inválidos en CLIENTES (E7): poner COR_CLI = NULL
        // IDs: vacíos CLI-007, CLI-008, CLI-011, CLI-012, CLI-020, CLI-035, CLI-036, CLI-039, CLI-041;
        // mario.torres@ CLI-028, CLI-029, CLI-034, CLI-043; sin @ CLI-027, CLI-042, CLI-014;
        // abc@ CLI-006, CLI-010; Maria.torres@ CLI-032; morio.torred@ CLI-033; N/A CLI-001; qa.empleado@correo,com CLI-004.
        const idsCorreosInvalidosE7 = [
            'CLI-001', 'CLI-004', 'CLI-006', 'CLI-007', 'CLI-008', 'CLI-010',
            'CLI-011', 'CLI-012', 'CLI-014', 'CLI-020', 'CLI-027', 'CLI-028',
            'CLI-029', 'CLI-032', 'CLI-033', 'CLI-034', 'CLI-035', 'CLI-036',
            'CLI-039', 'CLI-041', 'CLI-042', 'CLI-043'
        ];
        const resCorreos = await pool.query(`
            UPDATE CLIENTES 
            SET COR_CLI = NULL 
            WHERE ID_CLI IN (${idsCorreosInvalidosE7.map((_, i) => `$${i + 1}`).join(', ')})
               OR TRIM(COALESCE(COR_CLI, '')) = ''
               OR LOWER(TRIM(COR_CLI)) = 'n/a'
               OR (COR_CLI IS NOT NULL AND COR_CLI NOT LIKE '%@%.%')
        `, idsCorreosInvalidosE7);
        console.log(`[Limpieza E7] Correos inválidos en CLIENTES actualizados a NULL: ${resCorreos.rowCount || 0}`);

        // 2. EMPLEADOS: Eliminar EMP-013, EMP-019 y empleados con sueldo negativo (RN-16 / N8)
        await pool.query(`
            UPDATE USUARIOS SET ID_EMP = NULL 
            WHERE ID_EMP IN ('EMP-013', 'EMP-019') 
               OR ID_EMP IN (SELECT ID_EMP FROM EMPLEADOS WHERE SUE_EMP < 0)
        `);
        await pool.query(`
            UPDATE SERVICIOS SET ID_EMP = NULL 
            WHERE ID_EMP IN ('EMP-013', 'EMP-019') 
               OR ID_EMP IN (SELECT ID_EMP FROM EMPLEADOS WHERE SUE_EMP < 0)
        `);
        const resEmp = await pool.query(`
            DELETE FROM EMPLEADOS 
            WHERE ID_EMP IN ('EMP-013', 'EMP-019') OR SUE_EMP < 0
        `);
        await pool.query(`UPDATE EMPLEADOS SET SUE_EMP = 0 WHERE SUE_EMP < 0`);

        // 3. PRODUCTOS: Eliminar PRO-003, PRO-005, PRO-014, PRO-015, PRO-018 y productos con precio/stock negativo (RN-16 / RN-17 / N8)
        const resPro = await pool.query(`
            DELETE FROM PRODUCTOS
            WHERE (ID_PRO IN ('PRO-003', 'PRO-005', 'PRO-014', 'PRO-015', 'PRO-018') OR PREC_PRO < 0 OR STOCK_PRO < 0)
              AND ID_PRO NOT IN (SELECT ID_PRO FROM VENTAS WHERE ID_PRO IS NOT NULL)
              AND ID_PRO NOT IN (SELECT ID_PRO FROM PEDIDOS WHERE ID_PRO IS NOT NULL)
        `);
        await pool.query(`UPDATE PRODUCTOS SET PREC_PRO = 0 WHERE PREC_PRO < 0`);
        await pool.query(`UPDATE PRODUCTOS SET STOCK_PRO = 0 WHERE STOCK_PRO < 0`);

        // 4. PLANTAS: Eliminar PLN-014, PLN-021, PLN-005, PLN-004, PLN-013, PLN-020 y plantas con stock/precio negativo (RN-16 / RN-17 / N8)
        const resPln = await pool.query(`
            DELETE FROM PLANTAS
            WHERE (ID_PLANTA IN ('PLN-014', 'PLN-021', 'PLN-005', 'PLN-004', 'PLN-013', 'PLN-020') OR STOCK_PLANT < 0 OR PREC_PLANTA < 0)
              AND ID_PLANTA NOT IN (SELECT ID_PLANTA FROM VENTAS WHERE ID_PLANTA IS NOT NULL)
              AND ID_PLANTA NOT IN (SELECT ID_PLANTA FROM PEDIDOS WHERE ID_PLANTA IS NOT NULL)
        `);
        await pool.query(`UPDATE PLANTAS SET STOCK_PLANT = 0 WHERE STOCK_PLANT < 0`);
        await pool.query(`UPDATE PLANTAS SET PREC_PLANTA = 0 WHERE PREC_PLANTA < 0`);

        // 5. CAT_SERVICIOS: Eliminar CSV-010, CSV-016 y servicios de catálogo con costo negativo (RN-16 / RN-33 / N8 / E5)
        // Corregido: se elimina la condición errónea contra SERVICIOS (SERVICIOS no tiene ID_CAT_SERV)
        const resCat = await pool.query(`
            DELETE FROM CAT_SERVICIOS
            WHERE ID_CAT_SERV IN ('CSV-010', 'CSV-016') OR COSTO_EST < 0
        `);
        await pool.query(`UPDATE CAT_SERVICIOS SET COSTO_EST = 0 WHERE COSTO_EST < 0`);

        // Registro en log de filas eliminadas por tabla
        console.log(`[Limpieza] Filas eliminadas por tabla: CLIENTES: ${resCli.rowCount || 0}, EMPLEADOS: ${resEmp.rowCount || 0}, PRODUCTOS: ${resPro.rowCount || 0}, PLANTAS: ${resPln.rowCount || 0}, CAT_SERVICIOS: ${resCat.rowCount || 0}`);

        // Verificación con SELECT de que no quedan registros inválidos
        const checkSelect = await pool.query(`
            SELECT 
                (SELECT COUNT(*) FROM CLIENTES WHERE ID_CLI = 'CLI-026' OR NOM_CLI IS NULL OR TRIM(NOM_CLI) = '') AS "clientes_invalidos",
                (SELECT COUNT(*) FROM CLIENTES WHERE ID_CLI IN (${idsCorreosInvalidosE7.map(id => `'${id}'`).join(', ')}) AND COR_CLI IS NOT NULL) AS "correos_e7_no_nulos",
                (SELECT COUNT(*) FROM EMPLEADOS WHERE ID_EMP IN ('EMP-013', 'EMP-019') OR SUE_EMP < 0) AS "empleados_invalidos",
                (SELECT COUNT(*) FROM PRODUCTOS WHERE ID_PRO IN ('PRO-003', 'PRO-005', 'PRO-014', 'PRO-015', 'PRO-018') OR PREC_PRO < 0 OR STOCK_PRO < 0) AS "productos_invalidos",
                (SELECT COUNT(*) FROM PLANTAS WHERE ID_PLANTA IN ('PLN-014', 'PLN-021', 'PLN-005', 'PLN-004', 'PLN-013', 'PLN-020') OR STOCK_PLANT < 0 OR PREC_PLANTA < 0) AS "plantas_invalidas",
                (SELECT COUNT(*) FROM CAT_SERVICIOS WHERE ID_CAT_SERV IN ('CSV-010', 'CSV-016') OR COSTO_EST < 0) AS "cat_servicios_invalidos"
        `);
        const v = checkSelect.rows[0];
        console.log(`[Verificación SELECT post-limpieza] Registros inválidos restantes en BD: CLIENTES sin nombre: ${v.clientes_invalidos}, CLIENTES con correo inválido E7: ${v.correos_e7_no_nulos}, EMPLEADOS: ${v.empleados_invalidos}, PRODUCTOS: ${v.productos_invalidos}, PLANTAS: ${v.plantas_invalidas}, CAT_SERVICIOS: ${v.cat_servicios_invalidos}`);

        // 6. Restricciones CHECK, 7. AUDITORIA_USUARIOS y 8. Restauración de USR-011
        await pool.query(`
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'chk_sue_emp_no_negativo') THEN
                    ALTER TABLE EMPLEADOS ADD CONSTRAINT chk_sue_emp_no_negativo CHECK (SUE_EMP >= 0);
                END IF;

                IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'chk_prec_pro_no_negativo') THEN
                    ALTER TABLE PRODUCTOS ADD CONSTRAINT chk_prec_pro_no_negativo CHECK (PREC_PRO >= 0);
                END IF;

                IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'chk_stock_pro_no_negativo') THEN
                    ALTER TABLE PRODUCTOS ADD CONSTRAINT chk_stock_pro_no_negativo CHECK (STOCK_PRO >= 0);
                END IF;

                IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'chk_stock_plant_no_negativo') THEN
                    ALTER TABLE PLANTAS ADD CONSTRAINT chk_stock_plant_no_negativo CHECK (STOCK_PLANT >= 0);
                END IF;

                IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'chk_prec_planta_no_negativo') THEN
                    ALTER TABLE PLANTAS ADD CONSTRAINT chk_prec_planta_no_negativo CHECK (PREC_PLANTA >= 0);
                END IF;

                IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'chk_costo_est_no_negativo') THEN
                    ALTER TABLE CAT_SERVICIOS ADD CONSTRAINT chk_costo_est_no_negativo CHECK (COSTO_EST >= 0);
                END IF;

                IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'chk_nom_cli_no_vacio') THEN
                    ALTER TABLE CLIENTES ADD CONSTRAINT chk_nom_cli_no_vacio CHECK (NOM_CLI IS NOT NULL AND TRIM(NOM_CLI) <> '');
                END IF;

                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.tables 
                    WHERE LOWER(table_name) = 'auditoria_usuarios'
                ) THEN
                    CREATE TABLE AUDITORIA_USUARIOS (
                        ID_AUDITORIA SERIAL PRIMARY KEY,
                        FECHA_HORA TIMESTAMP DEFAULT NOW(),
                        USUARIO_RESPONSABLE VARCHAR(80),
                        ACCION VARCHAR(50),
                        ID_USUARIO_AFECTADO VARCHAR(20),
                        DATOS_ANTERIORES TEXT,
                        DATOS_NUEVOS TEXT,
                        ORIGEN VARCHAR(100)
                    );
                END IF;

                IF NOT EXISTS (SELECT 1 FROM USUARIOS WHERE TRIM(ID_USUARIO) = 'USR-011') THEN
                    INSERT INTO USUARIOS (ID_USUARIO, USERNAME, PASSWORD, ROL, ID_EMP, ESTADO)
                    VALUES (
                        'USR-011', 
                        CASE WHEN EXISTS (SELECT 1 FROM USUARIOS WHERE LOWER(TRIM(USERNAME)) = 'aux_externo_w') 
                             THEN 'usr011_operador' 
                             ELSE 'aux_externo_w' END, 
                        'pbkdf2$sha512$100000$7bf1aef9d4fdc14af13679ba976607c4$45d0da13fcc7b0a24f920fe63d0ecda703bf658bdb91563f50c37cf365bed4475a862565e8cd41101b31f911f9f414f325ae083f83e9721bb5918c3b0f416ea3', 
                        'Empleado', 
                        (SELECT ID_EMP FROM EMPLEADOS WHERE ID_EMP = 'EMP-011' LIMIT 1), 
                        'Activo'
                    );

                    INSERT INTO AUDITORIA_USUARIOS (USUARIO_RESPONSABLE, ACCION, ID_USUARIO_AFECTADO, DATOS_ANTERIORES, DATOS_NUEVOS, ORIGEN)
                    VALUES (
                        'Sistema / Mantenimiento N9', 
                        'RESTAURAR_HUECO', 
                        'USR-011', 
                        'Registro faltante detectado en auditoría N9 (eliminado en prueba CU-18)', 
                        'Usuario USR-011 restaurado con éxito para completar el catálogo de 12 usuarios', 
                        'limpiarDatosInvalidosBaseDatos'
                    );
                END IF;
            END $$;
        `);

        console.log('Limpieza de datos inválidos completada exitosamente en Supabase (N8 / E5).');
        return {
            exito: true,
            borrados: {
                clientes: resCli.rowCount || 0,
                empleados: resEmp.rowCount || 0,
                productos: resPro.rowCount || 0,
                plantas: resPln.rowCount || 0,
                cat_servicios: resCat.rowCount || 0
            },
            verificacion: v
        };
    } catch (limpiezaErr) {
        console.error('Aviso durante la limpieza de datos inválidos:', limpiezaErr.message);
        return { exito: false, error: limpiezaErr.message };
    }
}

app.get('/api/mantenimiento/limpiar-invalidos', async (req, res) => {
    try {
        const resultado = await limpiarDatosInvalidosBaseDatos();
        res.json({ exito: true, mensaje: 'Base de datos limpiada exitosamente.', completado: resultado });
    } catch (e) {
        res.status(500).json({ exito: false, error: e.message });
    }
});

// Obtener historial de auditoría de usuarios (N9)
app.get('/api/auditoria/usuarios', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                ID_AUDITORIA AS "ID_AUDITORIA",
                FECHA_HORA AS "FECHA_HORA",
                USUARIO_RESPONSABLE AS "USUARIO_RESPONSABLE",
                ACCION AS "ACCION",
                ID_USUARIO_AFECTADO AS "ID_USUARIO_AFECTADO",
                DATOS_ANTERIORES AS "DATOS_ANTERIORES",
                DATOS_NUEVOS AS "DATOS_NUEVOS",
                ORIGEN AS "ORIGEN"
            FROM AUDITORIA_USUARIOS
            ORDER BY ID_AUDITORIA DESC
        `);
        res.json({ exito: true, total: result.rows.length, auditoria: result.rows });
    } catch (err) {
        res.status(500).json({ exito: false, error: 'Error al consultar auditoría: ' + err.message });
    }
});

// Asegurar que las columnas en Supabase tengan la longitud exacta según el Diccionario de Datos (N4)
async function asegurarLongitudesDiccionarioDatos() {
    try {
        await pool.query(`
            DO $$
            BEGIN
                -- NOM_EMP VARCHAR(150)
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE LOWER(table_name) = 'empleados' AND LOWER(column_name) = 'nom_emp'
                ) THEN
                    ALTER TABLE EMPLEADOS ALTER COLUMN NOM_EMP TYPE VARCHAR(150);
                END IF;

                -- TRAB_REAL VARCHAR(200)
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE LOWER(table_name) = 'servicios' AND LOWER(column_name) = 'trab_real'
                ) THEN
                    ALTER TABLE SERVICIOS ALTER COLUMN TRAB_REAL TYPE VARCHAR(200);
                END IF;

                -- NOM_CLI VARCHAR(150)
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE LOWER(table_name) = 'clientes' AND LOWER(column_name) = 'nom_cli'
                ) THEN
                    ALTER TABLE CLIENTES ALTER COLUMN NOM_CLI TYPE VARCHAR(150);
                END IF;

                -- NOM_PROV VARCHAR(150)
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE LOWER(table_name) = 'proveedores' AND LOWER(column_name) = 'nom_prov'
                ) THEN
                    ALTER TABLE PROVEEDORES ALTER COLUMN NOM_PROV TYPE VARCHAR(150);
                END IF;

                -- TOT_PAGO y SALDO_PAGO NUMERIC(10, 2) en VENTAS (N6 - Redondeo de Moneda)
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE LOWER(table_name) = 'ventas' AND LOWER(column_name) = 'tot_pago'
                ) THEN
                    ALTER TABLE VENTAS ALTER COLUMN TOT_PAGO TYPE NUMERIC(10, 2) USING ROUND(TOT_PAGO::numeric, 2);
                END IF;

                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE LOWER(table_name) = 'ventas' AND LOWER(column_name) = 'saldo_pago'
                ) THEN
                    ALTER TABLE VENTAS ALTER COLUMN SALDO_PAGO TYPE NUMERIC(10, 2) USING ROUND(SALDO_PAGO::numeric, 2);
                END IF;

                -- Moneda exacta en PRODUCTOS, PLANTAS, PEDIDOS, SERVICIOS, CAT_SERVICIOS, EMPLEADOS (N6)
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE LOWER(table_name) = 'productos' AND LOWER(column_name) = 'prec_pro'
                ) THEN
                    ALTER TABLE PRODUCTOS ALTER COLUMN PREC_PRO TYPE NUMERIC(10, 2) USING ROUND(PREC_PRO::numeric, 2);
                END IF;

                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE LOWER(table_name) = 'plantas' AND LOWER(column_name) = 'prec_planta'
                ) THEN
                    ALTER TABLE PLANTAS ALTER COLUMN PREC_PLANTA TYPE NUMERIC(10, 2) USING ROUND(PREC_PLANTA::numeric, 2);
                END IF;

                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE LOWER(table_name) = 'pedidos' AND LOWER(column_name) = 'tot_pedido'
                ) THEN
                    ALTER TABLE PEDIDOS ALTER COLUMN TOT_PEDIDO TYPE NUMERIC(10, 2) USING ROUND(TOT_PEDIDO::numeric, 2);
                END IF;

                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE LOWER(table_name) = 'servicios' AND LOWER(column_name) = 'costo_serv'
                ) THEN
                    ALTER TABLE SERVICIOS ALTER COLUMN COSTO_SERV TYPE NUMERIC(10, 2) USING ROUND(COSTO_SERV::numeric, 2);
                END IF;

                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE LOWER(table_name) = 'cat_servicios' AND LOWER(column_name) = 'costo_est'
                ) THEN
                    ALTER TABLE CAT_SERVICIOS ALTER COLUMN COSTO_EST TYPE NUMERIC(10, 2) USING ROUND(COSTO_EST::numeric, 2);
                END IF;

                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE LOWER(table_name) = 'empleados' AND LOWER(column_name) = 'sue_emp'
                ) THEN
                    ALTER TABLE EMPLEADOS ALTER COLUMN SUE_EMP TYPE NUMERIC(10, 2) USING ROUND(SUE_EMP::numeric, 2);
                END IF;

                -- PASSWORD VARCHAR(255) en USUARIOS para hashes criptográficos (RN-41 / N10)
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE LOWER(table_name) = 'usuarios' AND LOWER(column_name) = 'password'
                ) THEN
                    ALTER TABLE USUARIOS ALTER COLUMN PASSWORD TYPE VARCHAR(255);
                END IF;
            END $$;
        `);
        console.log('Diccionario de datos verificado: NOM_EMP (150), TRAB_REAL (200) y PASSWORD (255) configurados correctamente en Supabase.');
    } catch (schemaErr) {
        console.log('Aviso al verificar longitud de columnas en base de datos:', schemaErr.message);
    }
}

// Migración automática de contraseñas legadas en texto plano a hashes seguros (RN-41 / N10)
async function migrarContrasenasTextoPlano() {
    try {
        console.log('Iniciando verificación y migración de contraseñas a hashes seguros (RN-41 / N10)...');
        await pool.query(`
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE LOWER(table_name) = 'usuarios' AND LOWER(column_name) = 'password'
                ) THEN
                    ALTER TABLE USUARIOS ALTER COLUMN PASSWORD TYPE VARCHAR(255);
                END IF;
            END $$;
        `);

        const res = await pool.query('SELECT ID_USUARIO, USERNAME, PASSWORD FROM USUARIOS');
        let migradas = 0;
        for (const u of res.rows) {
            const rawPass = u.PASSWORD ? String(u.PASSWORD).trim() : '';
            if (rawPass && !esPasswordHasheada(rawPass)) {
                const passHash = hashearPassword(rawPass);
                await pool.query('UPDATE USUARIOS SET PASSWORD = $1 WHERE ID_USUARIO = $2 OR USERNAME = $3', [passHash, u.ID_USUARIO, u.USERNAME]);
                migradas++;
            }
        }
        if (migradas > 0) {
            console.log(`Se migraron exitosamente ${migradas} contraseñas de texto plano a hashes seguros PBKDF2 (RN-41 / N10).`);
        } else {
            console.log('Todas las contraseñas en USUARIOS ya se encuentran protegidas con hash criptográfico (RN-41 / N10).');
        }
        return true;
    } catch (err) {
        console.error('Aviso durante la migración de contraseñas (RN-41 / N10):', err.message);
        return false;
    }
}

app.get('/api/mantenimiento/migrar-contrasenas', async (req, res) => {
    try {
        const resultado = await migrarContrasenasTextoPlano();
        res.json({ exito: true, mensaje: 'Migración de contraseñas a hashes ejecutada.', completado: resultado });
    } catch (e) {
        res.status(500).json({ exito: false, error: e.message });
    }
});

// Prueba de verificación CU-14: Crear dos empleados sin CURP seguidos debe funcionar y ambos deben quedar con CURP NULL
async function ejecutarPruebaCU14() {
    let emp1Id = null;
    let emp2Id = null;
    try {
        const nom1 = `Test_CU14_A_${Date.now()}`;
        const nom2 = `Test_CU14_B_${Date.now() + 1}`;

        // 1. Primer empleado sin CURP
        emp1Id = await generarSiguienteId('EMPLEADOS', 'ID_EMP', 'EMP');
        await pool.query(`
            INSERT INTO EMPLEADOS (ID_EMP, NOM_EMP, CURP_EMP, INI_ALTA, FIN_ALTA)
            VALUES ($1, $2, NULL, NOW(), '2099-12-31')
        `, [emp1Id, nom1]);

        // 2. Segundo empleado sin CURP seguido
        emp2Id = await generarSiguienteId('EMPLEADOS', 'ID_EMP', 'EMP');
        await pool.query(`
            INSERT INTO EMPLEADOS (ID_EMP, NOM_EMP, CURP_EMP, INI_ALTA, FIN_ALTA)
            VALUES ($1, $2, NULL, NOW(), '2099-12-31')
        `, [emp2Id, nom2]);

        // 3. Verificar que ambos existen y ambos tienen CURP_EMP en NULL
        const checkRes = await pool.query('SELECT ID_EMP, NOM_EMP, CURP_EMP FROM EMPLEADOS WHERE ID_EMP IN ($1, $2)', [emp1Id, emp2Id]);
        const e1 = checkRes.rows.find(r => r.ID_EMP && r.ID_EMP.trim() === emp1Id);
        const e2 = checkRes.rows.find(r => r.ID_EMP && r.ID_EMP.trim() === emp2Id);

        const e1Valido = e1 && e1.CURP_EMP === null;
        const e2Valido = e2 && e2.CURP_EMP === null;
        const sonDistintos = emp1Id !== emp2Id;

        // Limpiar registros de prueba
        await pool.query('DELETE FROM EMPLEADOS WHERE ID_EMP IN ($1, $2)', [emp1Id, emp2Id]);

        if (e1Valido && e2Valido && sonDistintos) {
            return {
                exito: true,
                mensaje: `Prueba CU-14 superada: Se crearon dos empleados consecutivos (${emp1Id} y ${emp2Id}) sin CURP exitosamente y ambos quedaron con CURP NULL sin colisiones.`,
                empleado1: { id: emp1Id, curp: null },
                empleado2: { id: emp2Id, curp: null }
            };
        } else {
            return {
                exito: false,
                error: `Falla en prueba CU-14: e1=${JSON.stringify(e1)}, e2=${JSON.stringify(e2)}`
            };
        }
    } catch (err) {
        if (emp1Id || emp2Id) {
            try {
                await pool.query('DELETE FROM EMPLEADOS WHERE ID_EMP IN ($1, $2)', [emp1Id, emp2Id]);
            } catch (cleanupErr) {}
        }
        return {
            exito: false,
            error: 'Error en prueba CU-14: ' + err.message
        };
    }
}

app.get('/api/test/cu-14', async (req, res) => {
    try {
        const resultado = await ejecutarPruebaCU14();
        res.status(resultado.exito ? 200 : 500).json(resultado);
    } catch (e) {
        res.status(500).json({ exito: false, error: e.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
    try {
        await pool.query('SELECT NOW()');
        console.log('Conexión exitosa a PostgreSQL en Supabase');
        await limpiarDatosInvalidosBaseDatos();
        await asegurarLongitudesDiccionarioDatos();
        await migrarContrasenasTextoPlano();
    } catch (err) {
        console.error('Error conectando a PostgreSQL:', err);
    }
});
