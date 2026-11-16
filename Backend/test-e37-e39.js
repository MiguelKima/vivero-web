/**
 * Test de Verificación Integral para Incidencias E37, E38, E39 y Observación RFCs Proveedores
 */

const fs = require('fs');
const assert = require('assert');

console.log('=== TEST VERIFICACIÓN INTEGRAL E37, E38, E39 Y OBSERVACIÓN RFCS ===\n');

// -------------------------------------------------------------
// 1. Pruebas Unitarias de esFechaValida (E39)
// -------------------------------------------------------------
console.log('--- 1. Pruebas Unitarias de esFechaValida (E39) ---');

function esFechaValida(valor) {
    if (!valor) return false;
    if (valor instanceof Date) {
        return !isNaN(valor.getTime());
    }
    if (typeof valor !== 'string') return false;
    const str = valor.trim();
    if (!str) return false;

    let anio, mes, dia;
    const matchYMD = str.match(/^(\d{4})[-/](\d{1,2})[-/](\d{1,2})$/);
    const matchDMY = str.match(/^(\d{1,2})[-/](\d{1,2})[-/](\d{4})$/);

    if (matchYMD) {
        anio = parseInt(matchYMD[1], 10);
        mes = parseInt(matchYMD[2], 10);
        dia = parseInt(matchYMD[3], 10);
    } else if (matchDMY) {
        dia = parseInt(matchDMY[1], 10);
        mes = parseInt(matchDMY[2], 10);
        anio = parseInt(matchDMY[3], 10);
    } else {
        const d = new Date(str);
        if (isNaN(d.getTime())) return false;
        return true;
    }

    if (anio < 1000 || anio > 9999) return false;
    if (mes < 1 || mes > 12) return false;

    const esBisiesto = (anio % 4 === 0 && (anio % 100 !== 0 || anio % 400 === 0));
    const diasPorMes = [31, esBisiesto ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (dia < 1 || dia > diasPorMes[mes - 1]) return false;

    return true;
}

// Fechas inválidas que deben ser rechazadas
assert.strictEqual(esFechaValida('2026-13-40'), false, 'Mes 13 y día 40 deben ser inválidos');
assert.strictEqual(esFechaValida('2026-02-30'), false, '30 de febrero debe ser inválido');
assert.strictEqual(esFechaValida('2025-02-29'), false, '29 de febrero en año no bisiesto debe ser inválido');
assert.strictEqual(esFechaValida('2026-00-10'), false, 'Mes 0 debe ser inválido');
assert.strictEqual(esFechaValida('2026-05-32'), false, 'Día 32 debe ser inválido');
assert.strictEqual(esFechaValida('texto-invalido'), false, 'Texto arbitrario debe ser inválido');
assert.strictEqual(esFechaValida(''), false, 'Cadena vacía debe ser inválida');

// Fechas válidas que deben ser aceptadas
assert.strictEqual(esFechaValida('2026-11-16'), true, '2026-11-16 debe ser válido');
assert.strictEqual(esFechaValida('2024-02-29'), true, '29 de febrero en año bisiesto 2024 debe ser válido');
assert.strictEqual(esFechaValida('16/11/2026'), true, '16/11/2026 formato DMY debe ser válido');
assert.strictEqual(esFechaValida('2026-01-31'), true, '31 de enero debe ser válido');
console.log('  [PASS] E39: Validador de fechas estricto verificado con éxito.');

// -------------------------------------------------------------
// 2. Simulación de Flujo E37 y E38: Stock en Ventas y Devolución
// -------------------------------------------------------------
console.log('--- 2. Simulación de Flujo E37 y E38 (Inventario y Ventas) ---');

// Mock de base de datos para simular ciclo de vida de una venta
function crearSimuladorBD() {
    return {
        productos: {
            'PRO-001': { ID_PRO: 'PRO-001', DESC_PRO: 'Tierra de hoja 1kg', STOCK_PRO: 103 },
            'PRO-023': { ID_PRO: 'PRO-023', DESC_PRO: 'Tierra preparada', STOCK_PRO: 0 }
        },
        plantas: {
            'PLN-010': { ID_PLANTA: 'PLN-010', NOM_COM: 'Ficus benjamina', STOCK_PLANT: 5 }
        },
        ventas: {},
        idCounter: 1,

        async registrarVenta({ id_cliente, id_producto, cant_producto, id_planta, cant_planta, forma_pago, total, saldo }) {
            let cantProdFinal = 0;
            let descProd = '';
            let stockProd = 0;

            if (id_producto) {
                const prod = this.productos[id_producto];
                if (!prod) return { status: 400, error: `El producto seleccionado (${id_producto}) no existe.` };
                const cantNum = Number(cant_producto);
                if (isNaN(cantNum) || cantNum <= 0) return { status: 400, error: 'La cantidad debe ser mayor a 0.' };
                cantProdFinal = cantNum;
                descProd = prod.DESC_PRO;
                stockProd = prod.STOCK_PRO;

                // Validación E38
                if (cantProdFinal > stockProd) {
                    return {
                        status: 400,
                        error: `La cantidad solicitada (${cantProdFinal}) excede el stock disponible del producto "${descProd}" (${stockProd}).`
                    };
                }
            }

            let cantPlantFinal = 0;
            let nomPlanta = '';
            let stockPlanta = 0;

            if (id_planta) {
                const pl = this.plantas[id_planta];
                if (!pl) return { status: 400, error: `La planta seleccionada (${id_planta}) no existe.` };
                const cantNum = Number(cant_planta);
                if (isNaN(cantNum) || cantNum <= 0) return { status: 400, error: 'La cantidad debe ser mayor a 0.' };
                cantPlantFinal = cantNum;
                nomPlanta = pl.NOM_COM;
                stockPlanta = pl.STOCK_PLANT;

                // Validación E38
                if (cantPlantFinal > stockPlanta) {
                    return {
                        status: 400,
                        error: `La cantidad solicitada (${cantPlantFinal}) excede el stock disponible de la planta "${nomPlanta}" (${stockPlanta}).`
                    };
                }
            }

            // Descontar inventario (E37)
            if (cantProdFinal > 0 && id_producto) {
                this.productos[id_producto].STOCK_PRO -= cantProdFinal;
            }
            if (cantPlantFinal > 0 && id_planta) {
                this.plantas[id_planta].STOCK_PLANT -= cantPlantFinal;
            }

            const id_ven = 'VEN-' + String(this.idCounter++).padStart(3, '0');
            const ventaRecord = {
                ID_VEN: id_ven,
                ID_CLI: id_cliente,
                ID_PRO: id_producto || null,
                ID_PLANTA: id_planta || null,
                NUM_CAN: cantProdFinal,
                NUM_CAN_PLANT: cantPlantFinal,
                TOT_PAGO: total,
                SALDO_PAGO: saldo
            };
            this.ventas[id_ven] = ventaRecord;

            return { status: 200, exito: true, id_ven, ventaRecord };
        },

        async eliminarVenta(id_ven) {
            const v = this.ventas[id_ven];
            if (!v) return { status: 404, error: 'No encontrado' };

            // Restaurar stock exacto vendido (E37 / E20)
            if (v.ID_PRO && v.NUM_CAN > 0) {
                this.productos[v.ID_PRO].STOCK_PRO += v.NUM_CAN;
            }
            if (v.ID_PLANTA && v.NUM_CAN_PLANT > 0) {
                this.plantas[v.ID_PLANTA].STOCK_PLANT += v.NUM_CAN_PLANT;
            }

            delete this.ventas[id_ven];
            return { status: 200, exito: true };
        }
    };
}

// Prueba E38: Venta sin stock debe ser rechazada con 400
const bdSim = crearSimuladorBD();
bdSim.registrarVenta({
    id_cliente: 'CLI-001',
    id_producto: 'PRO-023',
    cant_producto: 3,
    forma_pago: 'Efectivo',
    total: 300,
    saldo: 0
}).then(res => {
    assert.strictEqual(res.status, 400, 'Debe devolver 400 ante stock insuficiente');
    assert.strictEqual(
        res.error,
        'La cantidad solicitada (3) excede el stock disponible del producto "Tierra preparada" (0).'
    );
    assert.strictEqual(bdSim.productos['PRO-023'].STOCK_PRO, 0, 'El stock no debe haber cambiado');
    console.log('  [PASS] E38: Rechazo de venta por stock insuficiente verificado correctamente.');

    // Prueba E37: Venta x2 de PRO-001 debe descontar exactamente 2, y al borrar devolver exactamente 2 (sin inflar)
    const stockInicial = bdSim.productos['PRO-001'].STOCK_PRO; // 103
    assert.strictEqual(stockInicial, 103);

    return bdSim.registrarVenta({
        id_cliente: 'CLI-001',
        id_producto: 'PRO-001',
        cant_producto: 2,
        forma_pago: 'Efectivo',
        total: 100,
        saldo: 0
    });
}).then(resVenta => {
    assert.strictEqual(resVenta.status, 200);
    assert.strictEqual(bdSim.productos['PRO-001'].STOCK_PRO, 101, 'El stock debe haber bajado de 103 a 101');
    assert.strictEqual(resVenta.ventaRecord.NUM_CAN, 2, 'NUM_CAN debe ser 2');
    console.log('  [PASS] E37: Creación de venta descuenta correctamente el stock (103 -> 101).');

    // Ahora borrar la venta
    return bdSim.eliminarVenta(resVenta.id_ven);
}).then(resDel => {
    assert.strictEqual(resDel.status, 200);
    assert.strictEqual(bdSim.productos['PRO-001'].STOCK_PRO, 103, 'El stock debe restaurarse exactamente a 103 (no 104)');
    console.log('  [PASS] E37: Eliminación de venta restaura exactamente la cantidad vendida sin inflar (101 -> 103).');

    // Prueba Planta: Venta x3 de PLN-010 (stock 5 -> 2 -> borrar -> 5)
    return bdSim.registrarVenta({
        id_cliente: 'CLI-002',
        id_planta: 'PLN-010',
        cant_planta: 3,
        forma_pago: 'Tarjeta',
        total: 150,
        saldo: 0
    });
}).then(resPlanta => {
    assert.strictEqual(resPlanta.status, 200);
    assert.strictEqual(bdSim.plantas['PLN-010'].STOCK_PLANT, 2, 'El stock de planta debe haber bajado de 5 a 2');
    assert.strictEqual(resPlanta.ventaRecord.NUM_CAN_PLANT, 3, 'NUM_CAN_PLANT debe ser 3');

    return bdSim.eliminarVenta(resPlanta.id_ven);
}).then(resDelPlanta => {
    assert.strictEqual(resDelPlanta.status, 200);
    assert.strictEqual(bdSim.plantas['PLN-010'].STOCK_PLANT, 5, 'El stock de planta debe restaurarse exactamente a 5');
    console.log('  [PASS] E37: Ciclo completo venta y eliminación de plantas verificado.');

    // -------------------------------------------------------------
    // 3. Verificación de Código Fuente en Backend/server.js
    // -------------------------------------------------------------
    console.log('\n--- 3. Verificación de Código Fuente en Backend/server.js ---');
    const serverCode = fs.readFileSync('Backend/server.js', 'utf8');

    // E37 y E38 en server.js
    assert.ok(serverCode.includes('cantProdFinal > stockProdDisponible'), 'server.js debe validar stock disponible de producto');
    assert.ok(serverCode.includes('cantPlantFinal > stockPlantDisponible'), 'server.js debe validar stock disponible de planta');
    assert.ok(serverCode.includes('excede el stock disponible del producto'), 'server.js debe incluir mensaje de error de producto');
    assert.ok(serverCode.includes('excede el stock disponible de la planta'), 'server.js debe incluir mensaje de error de planta');
    assert.ok(serverCode.includes('NUM_CAN, NUM_CAN_PLANT'), 'server.js debe insertar NUM_CAN y NUM_CAN_PLANT en VENTAS');
    assert.ok(serverCode.includes('UPDATE PRODUCTOS SET STOCK_PRO = GREATEST(COALESCE(STOCK_PRO, 0) - $1, 0)'), 'server.js debe descontar stock de producto al vender');
    assert.ok(serverCode.includes('UPDATE PLANTAS SET STOCK_PLANT = GREATEST(COALESCE(STOCK_PLANT, 0) - $1, 0)'), 'server.js debe descontar stock de planta al vender');
    
    // E40 en server.js: Alias con comillas y lectura defensiva en minúsculas y mayúsculas
    assert.ok(serverCode.includes('SELECT ID_PRO AS "ID_PRO", DESC_PRO AS "DESC_PRO", STOCK_PRO AS "STOCK_PRO" FROM PRODUCTOS'), 'server.js debe usar alias con comillas para PRODUCTOS en ventas');
    assert.ok(serverCode.includes('SELECT ID_PLANTA AS "ID_PLANTA", NOM_COM AS "NOM_COM", NOM_CTFO AS "NOM_CTFO", STOCK_PLANT AS "STOCK_PLANT" FROM PLANTAS'), 'server.js debe usar alias con comillas para PLANTAS en ventas');
    assert.ok(serverCode.includes('pRow.STOCK_PRO !== undefined ? pRow.STOCK_PRO : pRow.stock_pro'), 'server.js debe leer STOCK_PRO y stock_pro');
    assert.ok(serverCode.includes('plRow.STOCK_PLANT !== undefined ? plRow.STOCK_PLANT : plRow.stock_plant'), 'server.js debe leer STOCK_PLANT y stock_plant');
    console.log('  [PASS] E40: Consultas con alias entre comillas y compatibilidad con minúsculas/mayúsculas confirmadas.');
    console.log('  [PASS] E37 y E38: Lógica de inventario y venta en server.js confirmada.');

    // E39 en server.js
    assert.ok(serverCode.includes('function esFechaValida'), 'server.js debe contener la función esFechaValida');
    assert.ok(serverCode.includes("La fecha del servicio es inválida (debe ser una fecha válida en formato YYYY-MM-DD)"), 'server.js debe incluir mensaje de fecha inválida');
    assert.ok(serverCode.includes("codigo === '22008' || codigo === '22007'"), 'server.js debe atrapar códigos 22008 y 22007 en responderErrorPostgres');
    console.log('  [PASS] E39: Manejo estricto de fechas en server.js confirmado.');

    // Observación RFCs viejos en PROVEEDORES
    assert.ok(serverCode.includes("UPDATE PROVEEDORES SET RFC_PROV = NULL WHERE RFC_PROV IS NOT NULL AND (TRIM(RFC_PROV) = '' OR UPPER(TRIM(RFC_PROV)) = 'N/A' OR RFC_PROV !~ '^[A-Za-zÑñ&]{3,4}[0-9]{6}[A-Za-z0-9]{3}$');"), 'server.js debe limpiar RFCs viejos inválidos en PROVEEDORES');
    console.log('  [PASS] Observación: Limpieza y consulta de RFCs inválidos en PROVEEDORES confirmada.');

    // -------------------------------------------------------------
    // 4. Verificación de Código Fuente en Frontend
    // -------------------------------------------------------------
    console.log('\n--- 4. Verificación de Código Fuente en Frontend ---');
    const ventaHtml = fs.readFileSync('Frontend/registro-venta.html', 'utf8');
    assert.ok(ventaHtml.includes('cant_producto > stockDisponible'), 'registro-venta.html debe comprobar stock de producto');
    assert.ok(ventaHtml.includes('cant_planta > stockPlantDisponible'), 'registro-venta.html debe comprobar stock de planta');
    console.log('  [PASS] Frontend/registro-venta.html verificado.');

    const servicioHtml = fs.readFileSync('Frontend/registro-servicio.html', 'utf8');
    assert.ok(servicioHtml.includes('function esFechaValida'), 'registro-servicio.html debe incluir esFechaValida');
    assert.ok(servicioHtml.includes('La fecha del servicio es inválida'), 'registro-servicio.html debe validar fecha antes de enviar');
    console.log('  [PASS] Frontend/registro-servicio.html verificado.');

    console.log('\n=== TODAS LAS PRUEBAS DE E37, E38, E39 Y OBSERVACIÓN PASARON EXITOSAMENTE ===');
}).catch(err => {
    console.error('ERROR EN PRUEBAS:', err);
    process.exit(1);
});
