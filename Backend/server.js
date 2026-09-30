require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

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

// Login con validación de estado Activo / Inactivo
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const result = await pool.query(`
            SELECT TRIM(USERNAME) AS "USERNAME", TRIM(ROL) AS "ROL", 
                   COALESCE(ESTADO, 'Activo') AS "ESTADO" 
            FROM USUARIOS 
            WHERE TRIM(USERNAME) = '${username}' AND TRIM(PASSWORD) = '${password}'
        `);
        
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
        console.error('--- ERROR DETALLADO EN LOGIN ---', err);
        res.status(500).json({ error: 'Error del servidor: ' + err.message });
    }
});

// Obtener Plantas
app.get('/api/plantas', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT ID_PLANTA AS "ID_PLANTA", TIP_PLANTA AS "TIP_PLANTA", 
                   NOM_CTFO AS "NOM_CTFO", NOM_COM AS "NOM_COM", 
                   STOCK_PLANT AS "STOCK_PLANT", 
                   COALESCE(PREC_PLANTA, 0)::float AS "PREC_PLANTA" 
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
        const result = await pool.query('SELECT ID_PROV AS "ID_PROV", NOM_PROV AS "NOM_PROV" FROM PROVEEDORES');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener proveedores' });
    }
});

// Obtener Clientes
app.get('/api/clientes', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_CLI AS "ID_CLI", NOM_CLI AS "NOM_CLI" FROM CLIENTES');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener clientes' });
    }
});

// Obtener Empleados
app.get('/api/empleados', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_EMP AS "ID_EMP", NOM_EMP AS "NOM_EMP", PUE_EMP AS "PUE_EMP" FROM EMPLEADOS');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener empleados' });
    }
});

// Obtener Catálogo de Servicios
app.get('/api/catalogo-servicios', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_CAT_SERV AS "ID_CAT_SERV", NOM_SERV AS "NOM_SERV", DESC_SERV AS "DESC_SERV", COALESCE(COSTO_EST, 0)::float AS "COSTO_EST" FROM CAT_SERVICIOS');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener catálogo de servicios' });
    }
});

// Obtener Productos
app.get('/api/productos', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT ID_PRO AS "ID_PRO", TIP_PRO AS "TIP_PRO", DESC_PRO AS "DESC_PRO", 
                   STOCK_PRO AS "STOCK_PRO", 
                   COALESCE(PREC_PRO, 0)::float AS "PREC_PRO", 
                   ID_PROV AS "ID_PROV" 
            FROM PRODUCTOS
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener productos' });
    }
});

// Proveedores (Registrar)
app.post('/api/proveedores', async (req, res) => {
    try {
        const { tip_sum, nom_prov, rfc_prov, dir_prov, con_prov, pro_prov } = req.body;
        
        const check = await pool.query(`SELECT COUNT(*) as total FROM PROVEEDORES WHERE RFC_PROV = '${rfc_prov}'`);
        if (parseInt(check.rows[0].total) > 0) {
            return res.status(400).json({ exito: false, error: 'Este proveedor con el mismo RFC ya está registrado.' });
        }

        const countResult = await pool.query('SELECT COUNT(*) as total FROM PROVEEDORES');
        const id_prov = 'PRV-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

        await pool.query(`
            INSERT INTO PROVEEDORES (ID_PROV, TIP_SUM, NOM_PROV, RFC_PROV, DIR_PROV, CON_PROV, PRO_PROV)
            VALUES ('${id_prov}', '${tip_sum}', '${nom_prov}', '${rfc_prov}', '${dir_prov}', '${con_prov}', '${pro_prov}')
        `);
        res.json({ exito: true, mensaje: `Proveedor registrado con éxito (ID: ${id_prov})` });
    } catch (err) {
        res.status(500).json({ exito: false, error: 'Error al guardar el proveedor.' });
    }
});

// Clientes (Registrar)
app.post('/api/clientes', async (req, res) => {
    try {
        const { nom_cli, dir_cli, tel_cli, cor_cli, com_cli, pref_cli } = req.body;

        const check = await pool.query(`
            SELECT COUNT(*) as total 
            FROM CLIENTES 
            WHERE TRIM(LOWER(NOM_CLI)) = TRIM(LOWER('${nom_cli}'))
        `);

        if (parseInt(check.rows[0].total) > 0) {
            return res.status(400).json({ exito: false, error: `El cliente "${nom_cli}" ya se encuentra registrado.` });
        }

        const countResult = await pool.query('SELECT COUNT(*) as total FROM CLIENTES');
        const id_cli = 'CLI-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

        await pool.query(`
            INSERT INTO CLIENTES (ID_CLI, NOM_CLI, DIR_CLI, TEL_CLI, COR_CLI, COM_CLI, PREF_CLI)
            VALUES ('${id_cli}', '${nom_cli}', '${dir_cli}', '${tel_cli}', '${cor_cli}', '${com_cli}', '${pref_cli}')
        `);
        res.json({ exito: true, mensaje: `Cliente registrado con éxito (ID: ${id_cli})` });
    } catch (err) {
        res.status(500).json({ exito: false, error: 'Error al guardar el cliente.' });
    }
});

// Empleados (Registrar)
app.post('/api/empleados', async (req, res) => {
    try {
        const { tip_emp, curp_emp, nom_emp, dir_emp, pue_emp, hor_emp, sue_emp } = req.body;

        const check = await pool.query(`SELECT COUNT(*) as total FROM EMPLEADOS WHERE CURP_EMP = '${curp_emp}'`);
        if (parseInt(check.rows[0].total) > 0) {
            return res.status(400).json({ exito: false, error: `El empleado con CURP "${curp_emp}" ya está registrado.` });
        }

        const countResult = await pool.query('SELECT COUNT(*) as total FROM EMPLEADOS');
        const id_emp = 'EMP-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

        await pool.query(`
            INSERT INTO EMPLEADOS (ID_EMP, TIP_EMP, CURP_EMP, NOM_EMP, DIR_EMP, PUE_EMP, HOR_EMP, SUE_EMP, INI_ALTA, FIN_ALTA)
            VALUES ('${id_emp}', '${tip_emp}', '${curp_emp}', '${nom_emp}', '${dir_emp}', '${pue_emp}', '${hor_emp}', ${sue_emp}, NOW(), '2099-12-31')
        `);
        res.json({ exito: true, mensaje: `Empleado registrado con éxito (ID: ${id_emp})` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ exito: false, error: 'Error al guardar el empleado.' });
    }
});

// Catálogo de Servicios (Registrar)
app.post('/api/catalogo-servicios', async (req, res) => {
    try {
        const { nom_serv, desc_serv, costo_est } = req.body;

        const check = await pool.query(`SELECT COUNT(*) as total FROM CAT_SERVICIOS WHERE TRIM(LOWER(NOM_SERV)) = TRIM(LOWER('${nom_serv}'))`);
        if (parseInt(check.rows[0].total) > 0) {
            return res.status(400).json({ exito: false, error: `El servicio "${nom_serv}" ya existe en el catálogo.` });
        }

        const countResult = await pool.query('SELECT COUNT(*) as total FROM CAT_SERVICIOS');
        const id_cat = 'CSV-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

        await pool.query(`
            INSERT INTO CAT_SERVICIOS (ID_CAT_SERV, NOM_SERV, DESC_SERV, COSTO_EST)
            VALUES ('${id_cat}', '${nom_serv}', '${desc_serv}', ${costo_est})
        `);
        res.json({ exito: true, mensaje: `Servicio agregado al catálogo con éxito (ID: ${id_cat})` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ exito: false, error: 'Error al guardar el servicio en el catálogo.' });
    }
});

// Productos (Registrar)
app.post('/api/productos', async (req, res) => {
    try {
        const { tip_pro, desc_pro, stock_pro, prec_pro, id_prov } = req.body;

        const check = await pool.query(`
            SELECT COUNT(*) as total 
            FROM PRODUCTOS 
            WHERE TRIM(LOWER(DESC_PRO)) = TRIM(LOWER('${desc_pro}'))
        `);

        if (parseInt(check.rows[0].total) > 0) {
            return res.status(400).json({ exito: false, error: `El producto "${desc_pro}" ya existe en el inventario.` });
        }

        const countResult = await pool.query('SELECT COUNT(*) as total FROM PRODUCTOS');
        const id_pro = 'PRO-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

        await pool.query(`
            INSERT INTO PRODUCTOS (ID_PRO, TIP_PRO, DESC_PRO, STOCK_PRO, PREC_PRO, ID_PROV)
            VALUES ('${id_pro}', '${tip_pro}', '${desc_pro}', ${stock_pro}, ${prec_pro}, '${id_prov}')
        `);
        res.json({ exito: true, mensaje: `Producto registrado con éxito (ID: ${id_pro})` });
    } catch (err) {
        res.status(500).json({ exito: false, error: 'Error al guardar el producto.' });
    }
});

// Plantas (Registrar)
app.post('/api/plantas', async (req, res) => {
    try {
        const { tipo, cientifico, comun, tamano, stock, precio, proveedor } = req.body;

        const check = await pool.query(`
            SELECT COUNT(*) as total 
            FROM PLANTAS 
            WHERE TRIM(LOWER(NOM_CTFO)) = TRIM(LOWER('${cientifico}'))
        `);

        if (parseInt(check.rows[0].total) > 0) {
            return res.status(400).json({ exito: false, error: `La planta "${cientifico}" ya se encuentra registrada.` });
        }

        const countResult = await pool.query('SELECT COUNT(*) as total FROM PLANTAS');
        const id_planta = 'PLN-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

        await pool.query(`
            INSERT INTO PLANTAS (ID_PLANTA, TIP_PLANTA, NOM_CTFO, NOM_COM, TAM_PLANT, STOCK_PLANT, PROV_PLANT, PREC_PLANTA)
            VALUES ('${id_planta}', '${tipo}', '${cientifico}', '${comun}', '${tamano}', ${stock}, '${proveedor}', ${precio})
        `);
        res.json({ exito: true, mensaje: `Planta registrada con éxito (ID: ${id_planta})` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ exito: false, error: 'Error al guardar la planta.' });
    }
});

// Servicios (Registrar)
app.post('/api/servicios', async (req, res) => {
    try {
        const { id_serv, id_cli, trabalho, fecha_ejec, costo, id_emp } = req.body;

        const countResult = await pool.query('SELECT COUNT(*) as total FROM SERVICIOS');
        const id_servicio = id_serv || ('SRV-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0'));

        const fechaQuery = fecha_ejec ? `'${fecha_ejec}'` : 'NOW()';

        await pool.query(`
            INSERT INTO SERVICIOS (ID_SERV, ID_CLI, TRAB_REAL, FECHA_EJEC, COSTO_SERV, ID_EMP)
            VALUES ('${id_servicio}', '${id_cli}', '${trabajo}', ${fechaQuery}, ${costo}, '${id_emp}')
        `);
        res.json({ exito: true, mensaje: `Servicio registrado con éxito (ID: ${id_servicio})` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ exito: false, error: 'Error al registrar el servicio.' });
    }
});

// Pedidos (Registrar)
app.post('/api/pedidos', async (req, res) => {
    try {
        const { tip_ped, tip_env, dir_envio, id_cli, id_pro, num_can, id_planta, num_can_plant, id_rep, tiem_entrega, tot_pedido } = req.body;

        const countResult = await pool.query('SELECT COUNT(*) as total FROM PEDIDOS');
        const id_ped = 'PED-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

        const dirEnvioVal = dir_envio ? `'${dir_envio}'` : 'NULL';
        const idProVal = id_pro ? `'${id_pro}'` : 'NULL';
        const numCanVal = id_pro ? (num_can || 0) : 'NULL';
        const idPlantaVal = id_planta ? `'${id_planta}'` : 'NULL';
        const numCanPlantVal = id_planta ? (num_can_plant || 0) : 'NULL';
        const totPedidoVal = tot_pedido || 0;

        await pool.query(`
            INSERT INTO PEDIDOS (ID_PED, TIP_PED, TIP_ENV, DIR_ENVIO, ID_CLI, ID_PRO, NUM_CAN, ID_PLANTA, NUM_CAN_PLANT, ID_REP, TIEM_ENTREGA, TOT_PEDIDO)
            VALUES ('${id_ped}', '${tip_ped}', '${tip_env}', ${dirEnvioVal}, '${id_cli}', ${idProVal}, ${numCanVal}, ${idPlantaVal}, ${numCanPlantVal}, '${id_rep}', '${tiem_entrega}', ${totPedidoVal})
        `);
        
        res.json({ exito: true, mensaje: 'Pedido registrado con éxito', ticket: { id_ped } });
    } catch (err) {
        res.status(500).json({ exito: false, error: 'Error al registrar el pedido: ' + err.message });
    }
});

// Pedidos (Historial)
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
                COALESCE(pd.TOT_PEDIDO, 0)::float AS "TOT_PEDIDO"
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

// Ventas (Registrar)
app.post('/api/ventas', async (req, res) => {
    try {
        const { id_cliente, id_producto, cant_producto, id_planta, cant_planta, forma_pago, total, saldo, cajero } = req.body;
        
        const lastVen = await pool.query(`SELECT ID_VEN AS "ID_VEN" FROM VENTAS ORDER BY ID_VEN DESC LIMIT 1`);
        let nextId = 1;
        if (lastVen.rows.length > 0 && lastVen.rows[0].ID_VEN) {
            const lastIdStr = lastVen.rows[0].ID_VEN.replace('VEN-', '');
            nextId = parseInt(lastIdStr) + 1;
        }
        const id_venta = 'VEN-' + String(nextId).padStart(3, '0');

        await pool.query(`
            INSERT INTO VENTAS (ID_VEN, ID_CLI, ID_PRO, ID_PLANTA, FECHA_COMP, FORM_PAGO, TOT_PAGO, SALDO_PAGO)
            VALUES (
                '${id_venta}', 
                '${id_cliente}', 
                ${id_producto ? `'${id_producto}'` : 'NULL'}, 
                ${id_planta ? `'${id_planta}'` : 'NULL'}, 
                NOW(), 
                '${forma_pago}', 
                ${total}, 
                ${saldo}
            )
        `);
        
        res.json({ 
            exito: true, 
            mensaje: 'Venta registrada exitosamente',
            ticket: { 
                id_venta, 
                id_cliente, 
                forma_pago, 
                total, 
                saldo, 
                cant_producto: cant_producto || 0,
                cant_planta: cant_planta || 0,
                cajero: cajero || 'Administrador',
                fecha: new Date().toLocaleString() 
            }
        });
    } catch (err) {
        console.error('--- ERROR AL REGISTRAR VENTA ---', err);
        res.status(500).json({ exito: false, error: 'Error de SQL: ' + err.message });
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
                COALESCE(v.TOT_PAGO, 0)::float AS "TOT_PAGO", 
                COALESCE(v.SALDO_PAGO, 0)::float AS "SALDO_PAGO"
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
        const result = await pool.query('SELECT ID_PROV AS "ID_PROV", NOM_PROV AS "NOM_PROV", RFC_PROV AS "RFC_PROV" FROM PROVEEDORES');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/clientes', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_CLI AS "ID_CLI", NOM_CLI AS "NOM_CLI", TEL_CLI AS "TEL_CLI" FROM CLIENTES');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/empleados', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_EMP AS "ID_EMP", NOM_EMP AS "NOM_EMP", PUE_EMP AS "PUE_EMP" FROM EMPLEADOS');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/productos', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_PRO AS "ID_PRO", DESC_PRO AS "DESC_PRO", STOCK_PRO AS "STOCK_PRO", COALESCE(PREC_PRO, 0)::float AS "PREC_PRO" FROM PRODUCTOS');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/pedidos', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_PED AS "ID_PED", TIP_PED AS "TIP_PED", ID_CLI AS "ID_CLI", COALESCE(TOT_PEDIDO, 0)::float AS "TOT_PEDIDO" FROM PEDIDOS');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/servicios', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_SERV AS "ID_SERV", ID_CLI AS "ID_CLI", TRAB_REAL AS "TRAB_REAL", COALESCE(COSTO_SERV, 0)::float AS "COSTO_SERV" FROM SERVICIOS');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/catalogo-servicios', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_CAT_SERV AS "ID_CAT_SERV", NOM_SERV AS "NOM_SERV", COALESCE(COSTO_EST, 0)::float AS "COSTO_EST" FROM CAT_SERVICIOS');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/dashboard/ventas', async (req, res) => {
    try {
        const result = await pool.query('SELECT ID_VEN AS "ID_VEN", ID_CLI AS "ID_CLI", FORM_PAGO AS "FORM_PAGO", COALESCE(TOT_PAGO, 0)::float AS "TOT_PAGO" FROM VENTAS');
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

// Registrar Usuario del Sistema
app.post('/api/usuarios', async (req, res) => {
    try {
        const { username, password, rol, id_emp } = req.body;

        const check = await pool.query(`SELECT COUNT(*) as total FROM USUARIOS WHERE USERNAME = '${username}'`);
        if (parseInt(check.rows[0].total) > 0) {
            return res.status(400).json({ exito: false, error: `El usuario "${username}" ya existe.` });
        }

        if (!id_emp) {
            return res.status(400).json({ exito: false, error: 'Debe seleccionar un empleado válido para asociarlo al usuario.' });
        }

        const countResult = await pool.query('SELECT COUNT(*) as total FROM USUARIOS');
        const id_usuario = 'USR-' + String(parseInt(countResult.rows[0].total) + 1).padStart(3, '0');

        await pool.query(`
            INSERT INTO USUARIOS (ID_USUARIO, USERNAME, PASSWORD, ROL, ID_EMP, ESTADO)
            VALUES ('${id_usuario}', '${username}', '${password}', '${rol}', '${id_emp}', 'Activo')
        `);
        res.json({ exito: true, mensaje: `Usuario "${username}" registrado con éxito (ID: ${id_usuario})` });
    } catch (err) {
        console.error('--- ERROR SQL EN USUARIOS:', err.message);
        res.status(500).json({ exito: false, error: 'Error al registrar el usuario: ' + err.message });
    }
});

// Actualizar Estado de Usuario (Activo / Inactivo)
app.put('/api/usuarios/:id/estado', async (req, res) => {
    try {
        const idUsuario = req.params.id;
        const { estado } = req.body;

        await pool.query(`
            UPDATE USUARIOS 
            SET ESTADO = '${estado}' 
            WHERE ID_USUARIO = '${idUsuario}' OR USERNAME = '${idUsuario}'
        `);

        res.json({ exito: true, mensaje: `Estado del usuario actualizado a ${estado}` });
    } catch (err) {
        console.error('--- ERROR SQL EN CAMBIO DE ESTADO:', err.message);
        res.status(500).json({ exito: false, error: 'Error al actualizar el estado del usuario.' });
    }
});

// RUTA MAESTRA PARA ACTUALIZAR CUALQUIER TABLA
app.put('/api/actualizar', async (req, res) => {
    try {
        const { tabla, idColumn, idValue, campos } = req.body;
        let setQuery = [];
        let values = [];
        let paramIndex = 1;
        
        Object.keys(campos).forEach((key) => {
            if(key !== idColumn) {
                setQuery.push(`${key} = $${paramIndex}`);
                values.push(campos[key]);
                paramIndex++;
            }
        });
        
        if(setQuery.length === 0) return res.json({ exito: true });

        values.push(idValue);
        const query = `UPDATE ${tabla} SET ${setQuery.join(', ')} WHERE ${idColumn} = $${paramIndex}`;
        await pool.query(query, values);
        
        res.json({ exito: true, mensaje: `Registro actualizado correctamente en ${tabla}` });
    } catch (err) {
        console.error('ERROR AL ACTUALIZAR:', err.message);
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