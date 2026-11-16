require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');

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

// --- API BACKEND ---

// Login con validación de estado Activo / Inactivo (Consulta parametrizada contra Inyección SQL - CU-5 / V-01)
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body || {};

        if (!username || !password) {
            return res.json({ exito: false, error: 'Usuario o contraseña incorrectos.' });
        }

        const result = await pool.query(`
            SELECT TRIM(USERNAME) AS "USERNAME", TRIM(ROL) AS "ROL", 
                   COALESCE(ESTADO, 'Activo') AS "ESTADO" 
            FROM USUARIOS 
            WHERE TRIM(USERNAME) = $1 AND TRIM(PASSWORD) = $2
        `, [String(username).trim(), String(password).trim()]);

        if (result.rows.length > 0) {
            const usuario = result.rows[0];
            if (usuario.ESTADO && usuario.ESTADO.toLowerCase() === 'inactivo') {
                return res.json({ 
                    exito: false, 
                    error: 'Su cuenta se encuentra inactiva. Comuníquese con el administrador del sistema.' 
                });
            }
            res.json({ exito: true, usuario: { USERNAME: usuario.USERNAME, ROL: usuario.ROL } });
        } else {
            res.json({ exito: false, error: 'Usuario o contraseña incorrectos.' });
        }
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
                STOCK_PLANT AS "STOCK_PLANT", 
                COALESCE(PROV_PLANT, '') AS "PROV_PLANT", 
                CAST(COALESCE(PREC_PLANTA, 0) AS FLOAT) AS "PREC_PLANTA" 
            FROM PLANTAS
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
                COALESCE(COR_CLI, '') AS "COR_CLI", 
                COALESCE(COM_CLI, '') AS "COM_CLI", 
                COALESCE(PREF_CLI, '') AS "PREF_CLI" 
            FROM CLIENTES
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
                CAST(COALESCE(SUE_EMP, 0) AS FLOAT) AS "SUE_EMP"
            FROM EMPLEADOS
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
                CAST(COALESCE(COSTO_EST, 0) AS FLOAT) AS "COSTO_EST" 
            FROM CAT_SERVICIOS
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
                STOCK_PRO AS "STOCK_PRO", 
                CAST(COALESCE(PREC_PRO, 0) AS FLOAT) AS "PREC_PRO", 
                COALESCE(ID_PROV, '') AS "ID_PROV" 
            FROM PRODUCTOS
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener productos' });
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

        const countResult = await pool.query('SELECT COUNT(*) AS "total" FROM PROVEEDORES');
        const id_prov = 'PRV-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

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

        const countResult = await pool.query('SELECT COUNT(*) AS "total" FROM CLIENTES');
        const id_cli = 'CLI-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

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
           req.body?.rol || 
           req.body?.role || 
           req.query?.rol;
}

function obtenerUsuarioSolicitante(req) {
    return req.headers['x-usuario'] || 
           req.headers['x-user'] || 
           req.headers['x-username'] ||
           req.body?.usuarioLogueado || 
           req.body?.usuario_solicitante || 
           req.body?.solicitante || 
           req.body?.username ||
           req.body?.usuario ||
           req.body?.cajero ||
           req.query?.usuario ||
           req.query?.username;
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

// Empleados (CU-13 / CU-14 / CU-15 / CU-16 / CU-17 / CU-18 / RN-12 / RN-15 / RN-16 / RN-19 / RN-34 / RN-35)
app.post('/api/empleados', async (req, res) => {
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
            if (isNaN(numSueldo) || numSueldo < 0) {
                return res.status(400).json({
                    exito: false,
                    error: 'El sueldo no puede ser un valor negativo (debe ser mayor o igual a 0).'
                });
            }
            sueldoFinal = numSueldo;
        }

        const curpLimpio = curp_emp && typeof curp_emp === 'string' && curp_emp.trim() ? curp_emp.trim().toUpperCase() : null;

        if (curpLimpio) {
            const check = await pool.query(`SELECT COUNT(*) AS "total" FROM EMPLEADOS WHERE UPPER(CURP_EMP) = $1`, [curpLimpio]);
            if (parseInt(check.rows[0].total) > 0) {
                return res.status(400).json({ exito: false, error: `El empleado con CURP "${curpLimpio}" ya está registrado.` });
            }
        }

        const countResult = await pool.query('SELECT COUNT(*) AS "total" FROM EMPLEADOS');
        const id_emp = 'EMP-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

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
        let costoFinal = 0;
        if (costoEntrada !== undefined && costoEntrada !== null && costoEntrada !== '') {
            const numCosto = typeof costoEntrada === 'number'
                ? costoEntrada
                : parseFloat(costoEntrada);
            if (isNaN(numCosto) || numCosto < 0) {
                return res.status(400).json({ 
                    exito: false, 
                    error: 'El costo estándar no acepta valores negativos, debe ser mayor o igual a 0 (RN-16).' 
                });
            }
            costoFinal = numCosto;
        }

        const descLimpia = desc_serv && typeof desc_serv === 'string' && desc_serv.trim() ? desc_serv.trim() : null;

        const check = await pool.query(`SELECT COUNT(*) AS "total" FROM CAT_SERVICIOS WHERE TRIM(LOWER(NOM_SERV)) = TRIM(LOWER($1))`, [nombreLimpio]);
        if (parseInt(check.rows[0].total) > 0) {
            return res.status(400).json({ exito: false, error: `El servicio "${nombreLimpio}" ya existe en el catálogo.` });
        }

        const countResult = await pool.query('SELECT COUNT(*) AS "total" FROM CAT_SERVICIOS');
        const id_cat = 'CSV-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

        await pool.query(`
            INSERT INTO CAT_SERVICIOS (ID_CAT_SERV, NOM_SERV, DESC_SERV, COSTO_EST)
            VALUES ($1, $2, $3, $4)
        `, [id_cat, nombreLimpio, descLimpia, costoFinal]);

        res.json({ exito: true, mensaje: `Servicio agregado al catálogo con éxito (ID: ${id_cat})` });
    } catch (err) {
        console.error('Error al guardar en catálogo:', err.message);
        res.status(500).json({ exito: false, error: 'Error al guardar el servicio en el catálogo: ' + err.message });
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

        let precioFinal = 0;
        if (prec_pro !== undefined && prec_pro !== null && prec_pro !== '') {
            const numPrecio = parseFloat(prec_pro);
            if (isNaN(numPrecio) || numPrecio < 0) {
                return res.status(400).json({
                    exito: false,
                    error: 'El precio del producto debe ser mayor o igual a 0 y no puede ser negativo.'
                });
            }
            precioFinal = numPrecio;
        }

        let stockFinal = 0;
        if (stock_pro !== undefined && stock_pro !== null && stock_pro !== '') {
            const numStock = Number(stock_pro);
            if (isNaN(numStock) || !Number.isInteger(numStock) || numStock < 0) {
                return res.status(400).json({
                    exito: false,
                    error: 'El stock del producto debe ser un número entero mayor o igual a 0.'
                });
            }
            stockFinal = numStock;
        }

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

        const countResult = await pool.query('SELECT COUNT(*) AS "total" FROM PRODUCTOS');
        const id_pro = 'PRO-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

        await pool.query(`
            INSERT INTO PRODUCTOS (ID_PRO, TIP_PRO, DESC_PRO, STOCK_PRO, PREC_PRO, ID_PROV)
            VALUES ($1, $2, $3, $4, $5, $6)
        `, [id_pro, tipoFinal, descripcionLimpia, isNaN(stockFinal) ? 0 : stockFinal, isNaN(precioFinal) ? 0 : precioFinal, id_prov.trim()]);

        res.json({ exito: true, mensaje: `Producto registrado con éxito (ID: ${id_pro})` });
    } catch (err) {
        console.error('Error al registrar producto:', err.message);
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
        .optional()
        .custom((valor) => {
            if (valor !== undefined && valor !== null && valor !== '') {
                if (contieneSqlOHtml(String(valor))) {
                    throw new Error('El stock de la planta contiene caracteres no permitidos.');
                }
                const n = Number(valor);
                if (isNaN(n) || !Number.isInteger(n) || n < 0) {
                    throw new Error('El stock de la planta debe ser un número entero mayor o igual a 0 (no se permiten valores negativos).');
                }
            }
            return true;
        }),
    body('precio')
        .optional()
        .custom((valor) => {
            if (valor !== undefined && valor !== null && valor !== '') {
                if (contieneSqlOHtml(String(valor))) {
                    throw new Error('El precio de la planta contiene caracteres no permitidos.');
                }
                const n = parseFloat(valor);
                if (isNaN(n) || n < 0) {
                    throw new Error('El precio de la planta debe ser mayor o igual a 0 y no puede ser negativo.');
                }
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

        let stockFinal = 0;
        if (stock !== undefined && stock !== null && stock !== '') {
            const numStock = Number(stock);
            if (isNaN(numStock) || !Number.isInteger(numStock) || numStock < 0) {
                return res.status(400).json({
                    exito: false,
                    error: 'El stock de la planta debe ser un número entero mayor o igual a 0 (no se permiten valores negativos).'
                });
            }
            stockFinal = numStock;
        }

        let precioFinal = 0;
        if (precio !== undefined && precio !== null && precio !== '') {
            const numPrecio = parseFloat(precio);
            if (isNaN(numPrecio) || numPrecio < 0) {
                return res.status(400).json({
                    exito: false,
                    error: 'El precio de la planta debe ser mayor o igual a 0 y no puede ser negativo.'
                });
            }
            precioFinal = numPrecio;
        }

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

        const countResult = await pool.query('SELECT COUNT(*) AS "total" FROM PLANTAS');
        const id_planta = 'PLN-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

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
        let costoFinal = 0;
        if (costoEntrada !== undefined && costoEntrada !== null && costoEntrada !== '') {
            const numCosto = typeof costoEntrada === 'number'
                ? costoEntrada
                : parseFloat(String(costoEntrada).replace(/[^0-9.-]/g, ''));
            if (isNaN(numCosto) || numCosto < 0) {
                return res.status(400).json({ 
                    exito: false, 
                    error: 'El costo del servicio debe ser un número mayor o igual a 0 (el cero es un valor válido, RN-16 / RN-33).' 
                });
            }
            costoFinal = numCosto;
        }

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
        res.status(500).json({ exito: false, error: 'Error al registrar el servicio: ' + err.message });
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
            const proCheck = await pool.query('SELECT COUNT(*) AS "total" FROM PRODUCTOS WHERE ID_PRO = $1', [idProLimpio]);
            if (parseInt(proCheck.rows[0].total) === 0) {
                return res.status(400).json({ 
                    exito: false, 
                    error: `El producto seleccionado (${idProLimpio}) no existe en el sistema (RN-23).` 
                });
            }
        }

        if (idPlantaLimpio) {
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

        const countResult = await pool.query('SELECT COUNT(*) AS "total" FROM PEDIDOS');
        const id_ped = 'PED-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

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
            idProLimpio ? (parseInt(num_can) || 0) : null,
            idPlantaLimpio,
            idPlantaLimpio ? (parseInt(num_can_plant) || 0) : null,
            id_rep && id_rep.trim() ? id_rep.trim() : null,
            tiem_entrega && tiem_entrega.trim() ? tiem_entrega.trim() : 'N/A',
            parseFloat(tot_pedido) || 0
        ]);
        
        res.json({ exito: true, mensaje: 'Pedido registrado con éxito', ticket: { id_ped } });
    } catch (err) {
        console.error('Error al registrar pedido:', err.message);
        res.status(500).json({ exito: false, error: 'Error al registrar el pedido: ' + err.message });
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

        const numTotal = parseFloat(total) || 0;
        const numSaldo = parseFloat(saldo) || 0;

        if (numTotal < 0 || numSaldo < 0) {
            return res.status(400).json({ 
                exito: false, 
                error: 'El total y el saldo deben ser mayores o iguales a 0 (RN-16).' 
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
            const lastVen = await pool.query(`SELECT ID_VEN AS "ID_VEN" FROM VENTAS ORDER BY LENGTH(ID_VEN) DESC, ID_VEN DESC LIMIT 1`);
            let nextId = 1;
            if (lastVen.rows.length > 0 && lastVen.rows[0].ID_VEN) {
                const lastIdStr = lastVen.rows[0].ID_VEN.replace('VEN-', '');
                nextId = parseInt(lastIdStr) + 1;
            }
            const id_venta = 'VEN-' + String(nextId).padStart(3, '0');

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
        res.status(500).json({ exito: false, error: 'Error al registrar la venta: ' + err.message });
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
                CAST(COALESCE(v.TOT_PAGO, 0) AS FLOAT) AS "TOT_PAGO", 
                CAST(COALESCE(v.SALDO_PAGO, 0) AS FLOAT) AS "SALDO_PAGO"
            FROM VENTAS v
            LEFT JOIN CLIENTES c ON v.ID_CLI = c.ID_CLI
            LEFT JOIN PRODUCTOS p ON v.ID_PRO = p.ID_PRO
            LEFT JOIN PLANTAS pl ON v.ID_PLANTA = pl.ID_PLANTA
            ORDER BY v.FECHA_COMP DESC
        `);
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
                COALESCE(COR_CLI, '') AS "COR_CLI", 
                COALESCE(COM_CLI, '') AS "COM_CLI", 
                COALESCE(PREF_CLI, '') AS "PREF_CLI" 
            FROM CLIENTES
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
                CAST(COALESCE(SUE_EMP, 0) AS FLOAT) AS "SUE_EMP" 
            FROM EMPLEADOS
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
                STOCK_PRO AS "STOCK_PRO", 
                CAST(COALESCE(PREC_PRO, 0) AS FLOAT) AS "PREC_PRO", 
                COALESCE(ID_PROV, '') AS "ID_PROV" 
            FROM PRODUCTOS
        `);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/pedidos', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_PED AS "ID_PED", TIP_PED AS "TIP_PED", ID_CLI AS "ID_CLI", CAST(COALESCE(TOT_PEDIDO, 0) AS FLOAT) AS "TOT_PEDIDO" FROM PEDIDOS');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/servicios', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_SERV AS "ID_SERV", ID_CLI AS "ID_CLI", TRAB_REAL AS "TRAB_REAL", CAST(COALESCE(COSTO_SERV, 0) AS FLOAT) AS "COSTO_SERV" FROM SERVICIOS');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/catalogo-servicios', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_CAT_SERV AS "ID_CAT_SERV", NOM_SERV AS "NOM_SERV", CAST(COALESCE(COSTO_EST, 0) AS FLOAT) AS "COSTO_EST" FROM CAT_SERVICIOS');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/ventas', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_VEN AS "ID_VEN", ID_CLI AS "ID_CLI", FORM_PAGO AS "FORM_PAGO", CAST(COALESCE(TOT_PAGO, 0) AS FLOAT) AS "TOT_PAGO" FROM VENTAS');
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
    try {
        const tienePermiso = await verificarAccesoAdmin(req, res);
        if (!tienePermiso) return;

        const { username, password, rol, id_emp } = req.body || {};

        if (!username || typeof username !== 'string' || !username.trim()) {
            return res.status(400).json({ exito: false, error: 'El nombre de usuario es obligatorio.' });
        }

        const usernameLimpio = username.trim();

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

        const idEmpFinal = id_emp && typeof id_emp === 'string' && id_emp.trim() ? id_emp.trim() : null;

        if (idEmpFinal) {
            const empCheck = await pool.query('SELECT COUNT(*) AS "total" FROM EMPLEADOS WHERE ID_EMP = $1', [idEmpFinal]);
            if (parseInt(empCheck.rows[0].total) === 0) {
                return res.status(400).json({ exito: false, error: 'El empleado seleccionado no existe en el sistema.' });
            }
        }

        const countResult = await pool.query('SELECT COUNT(*) AS "total" FROM USUARIOS');
        const id_usuario = 'USR-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

        await pool.query(`
            INSERT INTO USUARIOS (ID_USUARIO, USERNAME, PASSWORD, ROL, ID_EMP, ESTADO)
            VALUES ($1, $2, $3, $4, $5, 'Activo')
        `, [id_usuario, usernameLimpio, password, rol.trim(), idEmpFinal]);

        res.json({ exito: true, mensaje: `Usuario "${usernameLimpio}" registrado con éxito (ID: ${id_usuario})` });
    } catch (err) {
        console.error('--- ERROR SQL EN USUARIOS:', err.message);
        if (err.code === '23505' || (err.message && err.message.toUpperCase().includes('UNIQUE'))) {
            return res.status(400).json({
                exito: false,
                error: `Error UNIQUE: Violación de restricción UNIQUE. El nombre de usuario "${usernameLimpio}" ya existe en el sistema (RN-13 / CP-13).`
            });
        }
        res.status(500).json({ exito: false, error: 'Error al registrar el usuario: ' + err.message });
    }
});

// Actualizar Estado de Usuario (Activo / Inactivo) (CU-18 / RN-34 / RN-35)
app.put('/api/usuarios/:id/estado', async (req, res) => {
    try {
        const tienePermiso = await verificarAccesoAdmin(req, res);
        if (!tienePermiso) return;

        const idUsuario = req.params.id;
        const { estado } = req.body;

        await pool.query(`
            UPDATE USUARIOS 
            SET ESTADO = $1 
            WHERE ID_USUARIO = $2 OR USERNAME = $2
        `, [estado, idUsuario]);

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
            updates.push(`PASSWORD = $${paramIdx++}`);
            values.push(passwordVal.trim());
        }
        if (rolVal !== undefined && rolVal && typeof rolVal === 'string' && rolVal.trim()) {
            updates.push(`ROL = $${paramIdx++}`);
            values.push(rolVal.trim());
        }
        if (idEmpVal !== undefined) {
            const finalEmp = idEmpVal && typeof idEmpVal === 'string' && idEmpVal.trim() ? idEmpVal.trim() : null;
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

        res.json({ exito: true, mensaje: 'Usuario actualizado correctamente.' });
    } catch (err) {
        console.error('--- ERROR SQL AL ACTUALIZAR USUARIO:', err.message);
        if (err.code === '23505' || (err.message && err.message.toUpperCase().includes('UNIQUE'))) {
            return res.status(400).json({
                exito: false,
                error: 'Error UNIQUE: Violación de restricción UNIQUE. El nombre de usuario ya se encuentra registrado (RN-13 / CP-13).'
            });
        }
        res.status(500).json({ exito: false, error: 'Error al actualizar usuario: ' + err.message });
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
                COALESCE(COR_CLI, '') AS "COR_CLI", 
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
        res.status(500).json({ exito: false, error: 'Error al actualizar cliente: ' + err.message });
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
        res.status(500).json({ exito: false, error: 'Error al actualizar proveedor: ' + err.message });
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
                CAST(COALESCE(SUE_EMP, 0) AS FLOAT) AS "SUE_EMP" 
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
            updates.push(`CURP_EMP = $${paramIdx++}`);
            values.push(curp_emp_val && String(curp_emp_val).trim() ? String(curp_emp_val).trim() : null);
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
        res.status(500).json({ exito: false, error: 'Error al actualizar empleado: ' + err.message });
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
                CAST(COALESCE(PREC_PRO, 0) AS FLOAT) AS "PREC_PRO", 
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
        res.status(500).json({ exito: false, error: 'Error al actualizar producto: ' + err.message });
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
                CAST(COALESCE(PREC_PLANTA, 0) AS FLOAT) AS "PREC_PLANTA" 
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
        res.status(500).json({ exito: false, error: 'Error al actualizar planta: ' + err.message });
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

        let setQuery = [];
        let values = [];
        let index = 1;
        
        for (const key of Object.keys(campos || {})) {
            if (key !== idColumn && /^[a-zA-Z0-9_]+$/.test(key)) {
                const valor = campos[key];
                values.push(valor !== '' && valor !== null && valor !== undefined ? valor : null);
                setQuery.push(`${key} = $${index}`);
                index++;
            }
        }
        
        if (setQuery.length === 0) return res.json({ exito: true });

        values.push(idValue);
        const query = `UPDATE ${tabla} SET ${setQuery.join(', ')} WHERE ${idColumn} = $${index}`;
        await pool.query(query, values);
        
        res.json({ exito: true, mensaje: `Registro actualizado correctamente en ${tabla}` });
    } catch (err) {
        console.error('ERROR AL ACTUALIZAR:', err.message);
        if (err.code === '23505' || (err.message && err.message.toUpperCase().includes('UNIQUE'))) {
            return res.status(400).json({
                exito: false,
                error: `Error UNIQUE: Violación de restricción UNIQUE. Ya existe un registro con ese valor en un campo único (RN-13 / CP-13). ${err.message}`
            });
        }
        res.status(500).json({ exito: false, error: 'Error al actualizar: ' + err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
    try {
        await pool.query('SELECT NOW()');
        console.log('Conexión exitosa a PostgreSQL en Supabase');
    } catch (err) {
        console.error('Error conectando a PostgreSQL:', err);
    }
});
