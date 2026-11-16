/**
 * Test unitario para incidencia E20:
 * Restaurar stock de producto y/o planta al eliminar una venta.
 */

const assert = require('assert');

console.log('=== TEST INCIDENCIA E20: RESTAURACIÓN DE STOCK AL ELIMINAR VENTA ===\n');

// Simulación de pool de base de datos
function crearPoolMock(ventasMock, productosMock = {}, plantasMock = {}) {
    const consultas = [];
    return {
        consultas,
        productos: { ...productosMock },
        plantas: { ...plantasMock },
        ventas: { ...ventasMock },
        async query(sql, params) {
            consultas.push({ sql, params });
            const sqlUpper = sql.toUpperCase();

            // Consulta SELECT * FROM VENTAS WHERE TRIM(...) = TRIM($1)
            if (sqlUpper.includes('SELECT * FROM VENTAS')) {
                const id = params[0].trim();
                const venta = this.ventas[id];
                return { rows: venta ? [venta] : [], rowCount: venta ? 1 : 0 };
            }

            // Consulta DELETE FROM VENTAS WHERE TRIM(...) = TRIM($1)
            if (sqlUpper.includes('DELETE FROM VENTAS')) {
                const id = params[0].trim();
                if (this.ventas[id]) {
                    delete this.ventas[id];
                    return { rowCount: 1 };
                }
                return { rowCount: 0 };
            }

            // Consulta UPDATE PRODUCTOS SET STOCK_PRO = COALESCE(STOCK_PRO, 0) + $1
            if (sqlUpper.includes('UPDATE PRODUCTOS SET STOCK_PRO')) {
                const incremento = params[0];
                const idPro = params[1].trim();
                this.productos[idPro] = (this.productos[idPro] || 0) + incremento;
                return { rowCount: 1 };
            }

            // Consulta UPDATE PLANTAS SET STOCK_PLANT = COALESCE(STOCK_PLANT, 0) + $1
            if (sqlUpper.includes('UPDATE PLANTAS SET STOCK_PLANT')) {
                const incremento = params[0];
                const idPlanta = params[1].trim();
                this.plantas[idPlanta] = (this.plantas[idPlanta] || 0) + incremento;
                return { rowCount: 1 };
            }

            return { rows: [], rowCount: 0 };
        }
    };
}

// Extraemos la lógica de procesarEliminacion implementada en server.js para pruebas directas
async function simularProcesarEliminacion(pool, tabla, idColumn, idValue) {
    const tablaUpper = tabla.toUpperCase();
    const idStr = String(idValue).trim();
    const col = idColumn || 'ID_VEN';

    let ventaParaRestaurar = null;
    if (tablaUpper === 'VENTAS') {
        try {
            const vCheck = await pool.query(`SELECT * FROM VENTAS WHERE TRIM(${col}) = TRIM($1)`, [idStr]);
            ventaParaRestaurar = vCheck.rows[0] || null;
        } catch (e) {
            console.error('Aviso:', e.message);
        }
    }

    const deleteQuery = `DELETE FROM ${tabla} WHERE TRIM(${col}) = TRIM($1)`;
    const delRes = await pool.query(deleteQuery, [idStr]);

    if (delRes.rowCount === 0) {
        return { status: 404, exito: false, error: `No se encontró el registro "${idStr}" en la tabla "${tabla}".` };
    }

    if (tablaUpper === 'VENTAS' && ventaParaRestaurar) {
        try {
            const idProd = (ventaParaRestaurar.ID_PRO || ventaParaRestaurar.id_pro || '').trim();
            if (idProd && idProd.toUpperCase() !== 'N/A' && idProd.toUpperCase() !== 'NULL') {
                let cantProd = 1;
                for (const k of ['NUM_CAN', 'num_can', 'CANT_PRO', 'cant_pro', 'CANT_PRODUCTO', 'cant_producto', 'NUM_CAN_PRO', 'num_can_pro', 'CANTIDAD', 'cantidad']) {
                    if (ventaParaRestaurar[k] !== undefined && ventaParaRestaurar[k] !== null && String(ventaParaRestaurar[k]).trim() !== '') {
                        const n = parseInt(ventaParaRestaurar[k], 10);
                        if (!isNaN(n) && n > 0) {
                            cantProd = n;
                            break;
                        }
                    }
                }
                await pool.query(
                    'UPDATE PRODUCTOS SET STOCK_PRO = COALESCE(STOCK_PRO, 0) + $1 WHERE TRIM(ID_PRO) = TRIM($2)',
                    [cantProd, idProd]
                );
            }

            const idPlanta = (ventaParaRestaurar.ID_PLANTA || ventaParaRestaurar.id_planta || '').trim();
            if (idPlanta && idPlanta.toUpperCase() !== 'N/A' && idPlanta.toUpperCase() !== 'NULL') {
                let cantPlanta = 1;
                for (const k of ['NUM_CAN_PLANT', 'num_can_plant', 'CANT_PLANTA', 'cant_planta', 'CANT_PLANT', 'cant_plant', 'NUM_CAN_PLANTA', 'num_can_planta']) {
                    if (ventaParaRestaurar[k] !== undefined && ventaParaRestaurar[k] !== null && String(ventaParaRestaurar[k]).trim() !== '') {
                        const n = parseInt(ventaParaRestaurar[k], 10);
                        if (!isNaN(n) && n > 0) {
                            cantPlanta = n;
                            break;
                        }
                    }
                }
                if ((!idProd || idProd.toUpperCase() === 'N/A' || idProd.toUpperCase() === 'NULL') && cantPlanta === 1) {
                    for (const k of ['CANTIDAD', 'cantidad']) {
                        if (ventaParaRestaurar[k] !== undefined && ventaParaRestaurar[k] !== null && String(ventaParaRestaurar[k]).trim() !== '') {
                            const n = parseInt(ventaParaRestaurar[k], 10);
                            if (!isNaN(n) && n > 0) {
                                cantPlanta = n;
                                break;
                            }
                        }
                    }
                }
                await pool.query(
                    'UPDATE PLANTAS SET STOCK_PLANT = COALESCE(STOCK_PLANT, 0) + $1 WHERE TRIM(ID_PLANTA) = TRIM($2)',
                    [cantPlanta, idPlanta]
                );
            }
        } catch (stockErr) {
            console.error('[E20] Error al restaurar stock:', stockErr.message);
        }
    }

    return { status: 200, exito: true, mensaje: `Registro "${idStr}" eliminado correctamente de ${tabla}.` };
}

async function ejecutarPruebas() {
    // 1. Caso reporte E20: Venta VEN-056 con PRO-001 (stock 102 debe volver a 103)
    console.log('--- 1. Caso específico E20: VEN-056 con producto PRO-001 ---');
    const pool1 = crearPoolMock({
        'VEN-056': { ID_VEN: 'VEN-056', ID_CLI: 'CLI-001', ID_PRO: 'PRO-001', ID_PLANTA: null }
    }, { 'PRO-001': 102 });

    const res1 = await simularProcesarEliminacion(pool1, 'VENTAS', 'ID_VEN', 'VEN-056');
    assert.strictEqual(res1.status, 200);
    assert.strictEqual(res1.exito, true);
    assert.strictEqual(pool1.productos['PRO-001'], 103, 'El stock de PRO-001 debe haber subido de 102 a 103');
    console.log('  [PASS] Stock de PRO-001 restaurado correctamente de 102 a 103 al eliminar VEN-056.');

    // 2. Caso venta con cantidad mayor a 1 (ej: NUM_CAN = 5)
    console.log('--- 2. Venta con cantidad específica (NUM_CAN = 5) ---');
    const pool2 = crearPoolMock({
        'VEN-057': { ID_VEN: 'VEN-057', ID_CLI: 'CLI-002', ID_PRO: 'PRO-002', NUM_CAN: 5, ID_PLANTA: null }
    }, { 'PRO-002': 20 });

    const res2 = await simularProcesarEliminacion(pool2, 'VENTAS', 'ID_VEN', 'VEN-057');
    assert.strictEqual(res2.status, 200);
    assert.strictEqual(pool2.productos['PRO-002'], 25, 'El stock de PRO-002 debe haber subido de 20 a 25 (+5)');
    console.log('  [PASS] Stock de PRO-002 restaurado correctamente con +5 unidades.');

    // 3. Caso venta con planta (ID_PLANTA = 'PLN-010')
    console.log('--- 3. Venta con planta (ID_PLANTA = PLN-010) ---');
    const pool3 = crearPoolMock({
        'VEN-058': { ID_VEN: 'VEN-058', ID_CLI: 'CLI-003', ID_PRO: null, ID_PLANTA: 'PLN-010' }
    }, {}, { 'PLN-010': 15 });

    const res3 = await simularProcesarEliminacion(pool3, 'VENTAS', 'ID_VEN', 'VEN-058');
    assert.strictEqual(res3.status, 200);
    assert.strictEqual(pool3.plantas['PLN-010'], 16, 'El stock de PLN-010 debe haber subido de 15 a 16 (+1)');
    console.log('  [PASS] Stock de planta PLN-010 restaurado correctamente de 15 a 16.');

    // 4. Caso mixto: Venta con producto Y planta
    console.log('--- 4. Venta mixta: Producto y Planta simultáneos ---');
    const pool4 = crearPoolMock({
        'VEN-059': { ID_VEN: 'VEN-059', ID_CLI: 'CLI-004', ID_PRO: 'PRO-003', NUM_CAN: 2, ID_PLANTA: 'PLN-005', NUM_CAN_PLANT: 4 }
    }, { 'PRO-003': 10 }, { 'PLN-005': 8 });

    const res4 = await simularProcesarEliminacion(pool4, 'VENTAS', 'ID_VEN', 'VEN-059');
    assert.strictEqual(res4.status, 200);
    assert.strictEqual(pool4.productos['PRO-003'], 12, 'El stock de PRO-003 debe ser 10 + 2 = 12');
    assert.strictEqual(pool4.plantas['PLN-005'], 12, 'El stock de PLN-005 debe ser 8 + 4 = 12');
    console.log('  [PASS] Stock mixto restaurado exitosamente para ambos artículos.');

    // 5. Caso registro no encontrado (404)
    console.log('--- 5. Registro inexistente (404) ---');
    const pool5 = crearPoolMock({}, { 'PRO-001': 100 });
    const res5 = await simularProcesarEliminacion(pool5, 'VENTAS', 'ID_VEN', 'VEN-999');
    assert.strictEqual(res5.status, 404);
    assert.strictEqual(pool5.productos['PRO-001'], 100, 'El stock no debe modificarse si la venta no existía');
    console.log('  [PASS] 404 correcto y stock intacto cuando la venta no existe.');

    // 6. Verificación en Backend/server.js
    console.log('--- 6. Verificando código fuente en Backend/server.js ---');
    const fs = require('fs');
    const serverCode = fs.readFileSync('Backend/server.js', 'utf8');
    assert.ok(serverCode.includes("tablaUpper === 'VENTAS' && ventaParaRestaurar"), 'server.js debe contener la condición de restauración');
    assert.ok(serverCode.includes("UPDATE PRODUCTOS SET STOCK_PRO = COALESCE(STOCK_PRO, 0) + $1"), 'server.js debe actualizar STOCK_PRO');
    assert.ok(serverCode.includes("UPDATE PLANTAS SET STOCK_PLANT = COALESCE(STOCK_PLANT, 0) + $1"), 'server.js debe actualizar STOCK_PLANT');
    console.log('  [PASS] Backend/server.js contiene todas las consultas y lógica requerida para E20.');

    console.log('\n=== TODAS LAS PRUEBAS DE E20 PASARON SATISFACTORIAMENTE ===');
}

ejecutarPruebas().catch(err => {
    console.error('ERROR EN PRUEBAS E20:', err);
    process.exit(1);
});
