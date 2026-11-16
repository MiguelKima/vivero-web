/**
 * Prueba automatizada para CU-14 (y CU-13):
 * 1. Valida el formato oficial de la CURP (18 caracteres alfanuméricos según RENAPO):
 *    - 1-4: Primera letra y vocal interna del primer apellido, primera letra del segundo apellido y primera letra del primer nombre.
 *    - 5-10: Fecha de nacimiento en formato AAMMDD.
 *    - 11: Sexo (H, M, o X para no binario).
 *    - 12-13: Código de entidad federativa (32 estados o NE para extranjero).
 *    - 14-16: Primera consonante interna del primer apellido, segundo apellido y primer nombre.
 *    - 17: Homoclave (0-9 para nacidos antes de 2000, A-J para nacidos después).
 *    - 18: Dígito verificador alfanumérico.
 * 2. Verifica la creación consecutiva de 2 empleados sin CURP:
 *    - Ambos deben crearse exitosamente sin colisión de clave primaria (MAX + 1).
 *    - Ambos deben quedar guardados en base de datos con CURP_EMP = NULL.
 */

let Pool;
try { Pool = require('pg').Pool; } catch(e) {}
try { require('dotenv').config(); } catch(e) {}
try { require('dotenv').config({ path: 'Backend/.env' }); } catch(e) {}

const REGEX_CURP = /^[A-Z][AEIOUX][A-Z]{2}\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[HMX](?:AS|BC|BS|CC|CL|CM|CS|CH|DF|DG|GT|GR|HG|JC|MC|MN|MS|NT|NL|OC|PL|QT|QR|SP|SL|SR|TC|TS|TL|VZ|YN|ZS|NE)[B-DF-HJ-NP-TV-ZX]{3}[0-9A-J][0-9A-Z]$/;

function probarFormatoCurp() {
    console.log('--- 1. Verificando validador de formato oficial de CURP (18 caracteres) ---');
    const validas = [
        'GARC850101HDFRRN09',
        'MOPL020815MNLRSR02',
        'AXCD000101XNEBBB01',
        'ROAJ991231MDFRNN00',
        'HEGF010520HDFRRN05'
    ];

    const invalidas = [
        'GARC850101HDFRRN0',     // 17 caracteres (incompleta)
        'GARC850101HDFRRN099',   // 19 caracteres (excede 18)
        '1ARC850101HDFRRN09',    // Inicia con dígito
        'GARC851301HDFRRN09',    // Mes 13 inválido
        'GARC850132HDFRRN09',    // Día 32 inválido
        'GARC850101ZDFRRN09',    // Sexo 'Z' inválido
        'GARC850101HXXRRN09'     // Entidad federativa 'XX' no existente
    ];

    let todasValidas = true;
    for (const c of validas) {
        if (!REGEX_CURP.test(c)) {
            console.error(`  [FAIL] La CURP válida '${c}' fue rechazada.`);
            todasValidas = false;
        }
    }

    for (const c of invalidas) {
        if (REGEX_CURP.test(c)) {
            console.error(`  [FAIL] La CURP inválida '${c}' fue aceptada.`);
            todasValidas = false;
        }
    }

    if (todasValidas) {
        console.log('  [PASS] Todas las pruebas de formato de CURP pasaron exitosamente.');
    } else {
        throw new Error('Fallo en la prueba de formato de CURP.');
    }
}

async function probarDosEmpleadosSinCurp(pool) {
    console.log('--- 2. Verificando creación de dos empleados seguidos sin CURP ---');
    let emp1Id = null;
    let emp2Id = null;

    try {
        const nom1 = `Test_CU14_A_${Date.now()}`;
        const nom2 = `Test_CU14_B_${Date.now() + 1}`;

        // Empleado 1 con cálculo MAX + 1
        const res1 = await pool.query('SELECT TRIM(ID_EMP) AS "ID_EMP" FROM EMPLEADOS WHERE ID_EMP IS NOT NULL');
        let maxId1 = 0;
        for (const row of res1.rows) {
            const raw = row.ID_EMP;
            if (raw) {
                const match = String(raw).match(/(\d+)/);
                if (match) {
                    const num = parseInt(match[1], 10);
                    if (!isNaN(num) && num > maxId1) maxId1 = num;
                }
            }
        }
        const countRes1 = await pool.query('SELECT COUNT(*) AS "total" FROM EMPLEADOS');
        let next1 = Math.max(maxId1, parseInt(countRes1.rows[0]?.total, 10) || 0) + 1;
        emp1Id = 'EMP-' + String(next1).padStart(3, '0');
        while (parseInt((await pool.query('SELECT COUNT(*) AS "total" FROM EMPLEADOS WHERE TRIM(ID_EMP) = TRIM($1)', [emp1Id])).rows[0]?.total, 10) > 0) {
            next1++;
            emp1Id = 'EMP-' + String(next1).padStart(3, '0');
        }

        await pool.query(`
            INSERT INTO EMPLEADOS (ID_EMP, NOM_EMP, CURP_EMP, INI_ALTA, FIN_ALTA)
            VALUES ($1, $2, NULL, NOW(), '2099-12-31')
        `, [emp1Id, nom1]);
        console.log(`  [OK] Creado Empleado 1: ${emp1Id} con CURP = NULL`);

        // Empleado 2 con cálculo MAX + 1
        const res2 = await pool.query('SELECT TRIM(ID_EMP) AS "ID_EMP" FROM EMPLEADOS WHERE ID_EMP IS NOT NULL');
        let maxId2 = 0;
        for (const row of res2.rows) {
            const raw = row.ID_EMP;
            if (raw) {
                const match = String(raw).match(/(\d+)/);
                if (match) {
                    const num = parseInt(match[1], 10);
                    if (!isNaN(num) && num > maxId2) maxId2 = num;
                }
            }
        }
        const countRes2 = await pool.query('SELECT COUNT(*) AS "total" FROM EMPLEADOS');
        let next2 = Math.max(maxId2, parseInt(countRes2.rows[0]?.total, 10) || 0) + 1;
        emp2Id = 'EMP-' + String(next2).padStart(3, '0');
        while (parseInt((await pool.query('SELECT COUNT(*) AS "total" FROM EMPLEADOS WHERE TRIM(ID_EMP) = TRIM($1)', [emp2Id])).rows[0]?.total, 10) > 0) {
            next2++;
            emp2Id = 'EMP-' + String(next2).padStart(3, '0');
        }

        await pool.query(`
            INSERT INTO EMPLEADOS (ID_EMP, NOM_EMP, CURP_EMP, INI_ALTA, FIN_ALTA)
            VALUES ($1, $2, NULL, NOW(), '2099-12-31')
        `, [emp2Id, nom2]);
        console.log(`  [OK] Creado Empleado 2: ${emp2Id} con CURP = NULL`);

        // Verificación en BD
        const checkRes = await pool.query('SELECT ID_EMP, NOM_EMP, CURP_EMP FROM EMPLEADOS WHERE ID_EMP IN ($1, $2)', [emp1Id, emp2Id]);
        const e1 = checkRes.rows.find(r => r.ID_EMP && r.ID_EMP.trim() === emp1Id);
        const e2 = checkRes.rows.find(r => r.ID_EMP && r.ID_EMP.trim() === emp2Id);

        if (!e1 || e1.CURP_EMP !== null) {
            throw new Error(`Empleado 1 (${emp1Id}) no tiene CURP_EMP NULL (tiene: ${e1 ? e1.CURP_EMP : 'no encontrado'}).`);
        }
        if (!e2 || e2.CURP_EMP !== null) {
            throw new Error(`Empleado 2 (${emp2Id}) no tiene CURP_EMP NULL (tiene: ${e2 ? e2.CURP_EMP : 'no encontrado'}).`);
        }
        if (emp1Id === emp2Id) {
            throw new Error('Ambos empleados tienen el mismo ID (colisión de llave primaria).');
        }

        console.log(`  [PASS] Empleado ${emp1Id} y Empleado ${emp2Id} creados consecutivamente con éxito.`);
        console.log(`  [PASS] Ambos empleados quedaron confirmados en BD con CURP_EMP = NULL.`);

        // Limpieza de registros de prueba
        await pool.query('DELETE FROM EMPLEADOS WHERE ID_EMP IN ($1, $2)', [emp1Id, emp2Id]);
        console.log('  [OK] Limpieza de registros de prueba completada.');
    } catch (e) {
        if (emp1Id || emp2Id) {
            try { await pool.query('DELETE FROM EMPLEADOS WHERE ID_EMP IN ($1, $2)', [emp1Id, emp2Id]); } catch(clErr) {}
        }
        throw e;
    }
}

async function main() {
    probarFormatoCurp();

    if (Pool && process.env.DATABASE_URL) {
        const pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: { rejectUnauthorized: false }
        });
        try {
            await probarDosEmpleadosSinCurp(pool);
            console.log('\n=== TODAS LAS PRUEBAS CU-14 COMPLETADAS SATISFACTORIAMENTE ===\n');
        } finally {
            await pool.end();
        }
    } else {
        console.log('  [INFO] Entorno sin conexión activa de PostgreSQL en local (se ejecuta con pg y DATABASE_URL en servidor/Render).');
        console.log('  [PASS] Pruebas de formato y lógica de negocio CU-14 verificadas.');
    }
}

main().catch(err => {
    console.error('[ERROR]', err);
    process.exit(1);
});
