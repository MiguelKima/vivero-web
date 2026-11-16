const fs = require('fs');
const assert = require('assert');

console.log('=== TEST REGRESIÓN DE LOS $0 (CU-19, CU-23, CU-34, CU-37, EDICIONES) ===\n');

// 1. Verificar Frontend/registro-producto.html
console.log('--- 1. Verificando Frontend/registro-producto.html ---');
const htmlProd = fs.readFileSync('Frontend/registro-producto.html', 'utf8');
assert(htmlProd.includes('<form novalidate'), 'registro-producto.html debe tener novalidate en <form>');
assert(!htmlProd.includes('min="1"'), 'registro-producto.html no debe tener min="1" en inputs');
assert(!htmlProd.includes('min="0.01"'), 'registro-producto.html no debe tener min="0.01" en inputs');
assert(!/id="stock_pro"[^>]*required/.test(htmlProd), 'stock_pro no debe tener required para CU-19');
assert(!/id="prec_pro"[^>]*required/.test(htmlProd), 'prec_pro no debe tener required para CU-19');
assert(htmlProd.includes('precioNum < 0'), 'JS debe rechazar únicamente precioNum < 0');
assert(htmlProd.includes('stockNum < 0'), 'JS debe rechazar únicamente stockNum < 0');
assert(!htmlProd.includes('precioNum <= 0'), 'JS no debe rechazar precioNum <= 0');
assert(!htmlProd.includes('stockNum <= 0'), 'JS no debe rechazar stockNum <= 0');
console.log('  [PASS] Frontend/registro-producto.html verificado correctamente.');

// 2. Verificar Frontend/registro-planta.html
console.log('\n--- 2. Verificando Frontend/registro-planta.html ---');
const htmlPlanta = fs.readFileSync('Frontend/registro-planta.html', 'utf8');
assert(htmlPlanta.includes('<form novalidate'), 'registro-planta.html debe tener novalidate en <form>');
assert(!htmlPlanta.includes('min="1"'), 'registro-planta.html no debe tener min="1" en inputs');
assert(!htmlPlanta.includes('min="0.01"'), 'registro-planta.html no debe tener min="0.01" en inputs');
assert(!/id="stock"[^>]*required/.test(htmlPlanta), 'stock no debe tener required para CU-23');
assert(!/id="precio"[^>]*required/.test(htmlPlanta), 'precio no debe tener required para CU-23');
assert(htmlPlanta.includes('stockNum < 0'), 'JS debe rechazar únicamente stockNum < 0');
assert(htmlPlanta.includes('precioNum < 0'), 'JS debe rechazar únicamente precioNum < 0');
assert(!htmlPlanta.includes('stockNum <= 0'), 'JS no debe rechazar stockNum <= 0');
assert(!htmlPlanta.includes('precioNum <= 0'), 'JS no debe rechazar precioNum <= 0');
console.log('  [PASS] Frontend/registro-planta.html verificado correctamente.');

// 3. Verificar Frontend/registro-servicio.html
console.log('\n--- 3. Verificando Frontend/registro-servicio.html ---');
const htmlServ = fs.readFileSync('Frontend/registro-servicio.html', 'utf8');
assert(htmlServ.includes('<form novalidate'), 'registro-servicio.html debe tener novalidate en <form>');
assert(!htmlServ.includes('min="0.01"'), 'registro-servicio.html no debe tener min="0.01" en inputs');
assert(htmlServ.includes('parsedCosto < 0'), 'JS debe rechazar únicamente parsedCosto < 0');
assert(!htmlServ.includes('parsedCosto <= 0'), 'JS no debe rechazar parsedCosto <= 0');
console.log('  [PASS] Frontend/registro-servicio.html verificado correctamente.');

// 4. Verificar Frontend/registro-catalogo-servicio.html
console.log('\n--- 4. Verificando Frontend/registro-catalogo-servicio.html ---');
const htmlCat = fs.readFileSync('Frontend/registro-catalogo-servicio.html', 'utf8');
assert(htmlCat.includes('<form novalidate'), 'registro-catalogo-servicio.html debe tener novalidate en <form>');
assert(!htmlCat.includes('min="0.01"'), 'registro-catalogo-servicio.html no debe tener min="0.01" en inputs');
assert(!/id="costo_est"[^>]*required/.test(htmlCat), 'costo_est no debe tener required para CU-37');
assert(htmlCat.includes('parsedCosto < 0'), 'JS debe rechazar únicamente parsedCosto < 0');
assert(!htmlCat.includes('parsedCosto <= 0'), 'JS no debe rechazar parsedCosto <= 0');
console.log('  [PASS] Frontend/registro-catalogo-servicio.html verificado correctamente.');

// 5. Verificar Frontend/registro-empleado.html
console.log('\n--- 5. Verificando Frontend/registro-empleado.html ---');
const htmlEmp = fs.readFileSync('Frontend/registro-empleado.html', 'utf8');
assert(htmlEmp.includes('<form novalidate'), 'registro-empleado.html debe tener novalidate en <form>');
assert(htmlEmp.includes('sueldoNum < 0'), 'JS debe rechazar únicamente sueldoNum < 0');
assert(!htmlEmp.includes('sueldoNum <= 0'), 'JS no debe rechazar sueldoNum <= 0');
console.log('  [PASS] Frontend/registro-empleado.html verificado correctamente.');

// 6. Verificar Frontend/dashboard.html
console.log('\n--- 6. Verificando Frontend/dashboard.html (edición en panel) ---');
const htmlDash = fs.readFileSync('Frontend/dashboard.html', 'utf8');
assert(htmlDash.includes('numPrecio < 0'), 'dashboard.html debe rechazar numPrecio < 0');
assert(htmlDash.includes('numStock < 0'), 'dashboard.html debe rechazar numStock < 0');
assert(htmlDash.includes('numPrecioPlant < 0'), 'dashboard.html debe rechazar numPrecioPlant < 0');
assert(htmlDash.includes('numCosto < 0'), 'dashboard.html debe rechazar numCosto < 0');
assert(htmlDash.includes('numCostoServ < 0'), 'dashboard.html debe rechazar numCostoServ < 0');
assert(htmlDash.includes('numSueldo < 0'), 'dashboard.html debe rechazar numSueldo < 0');
assert(!htmlDash.includes('numPrecio <= 0'), 'dashboard.html no debe contener numPrecio <= 0');
assert(!htmlDash.includes('numPrecioPlant <= 0'), 'dashboard.html no debe contener numPrecioPlant <= 0');
assert(!htmlDash.includes('numCosto <= 0'), 'dashboard.html no debe contener numCosto <= 0');
assert(!htmlDash.includes('numCostoServ <= 0'), 'dashboard.html no debe contener numCostoServ <= 0');
assert(!htmlDash.includes('numSueldo <= 0'), 'dashboard.html no debe contener numSueldo <= 0');
console.log('  [PASS] Frontend/dashboard.html verificado correctamente.');

// 7. Verificar Backend/server.js
console.log('\n--- 7. Verificando Backend/server.js lógica de validación y actualización ---');
const serverSource = fs.readFileSync('Backend/server.js', 'utf8');

// POST /api/empleados
assert(serverSource.includes('numSueldo < 0'), 'server.js /api/empleados debe validar numSueldo < 0');
assert(!serverSource.includes('numSueldo <= 0'), 'server.js /api/empleados no debe validar numSueldo <= 0');

// POST /api/catalogo-servicios
assert(serverSource.includes('numCosto < 0'), 'server.js /api/catalogo-servicios debe validar numCosto < 0');

// POST /api/productos
assert(serverSource.includes('numPrecio < 0'), 'server.js /api/productos debe validar numPrecio < 0');

// POST /api/plantas (validacionesPlanta y endpoint)
const matchPlantaVal = serverSource.match(/const validacionesPlanta = \[([\s\S]*?)\];/);
assert(matchPlantaVal, 'Debe existir validacionesPlanta');
assert(matchPlantaVal[0].includes('n < 0'), 'validacionesPlanta debe validar n < 0');
assert(!matchPlantaVal[0].includes('n <= 0'), 'validacionesPlanta no debe contener n <= 0');

// PUT /api/actualizar
const matchActualizar = serverSource.match(/app\.put\('\/api\/actualizar'[\s\S]*?\n\}\);/);
assert(matchActualizar, 'Debe existir PUT /api/actualizar');
const actCode = matchActualizar[0];
assert(actCode.includes('numVal < 0'), 'PUT /api/actualizar debe validar numVal < 0');
assert(actCode.includes('numStock < 0'), 'PUT /api/actualizar debe validar numStock < 0');
assert(!actCode.includes('numVal <= 0'), 'PUT /api/actualizar no debe validar numVal <= 0');
assert(!actCode.includes('numStock <= 0'), 'PUT /api/actualizar no debe validar numStock <= 0');

console.log('  [PASS] Backend/server.js verificado correctamente.');

// 8. Pruebas de unidad de la lógica de evaluación de PUT /api/actualizar
console.log('\n--- 8. Pruebas unitarias de actualización (CU-48, CU-49, y ceros) ---');

function validarCampoActualizar(key, valor) {
    const keyUpper = key.toUpperCase();
    if (valor !== '' && valor !== null && valor !== undefined) {
        if (keyUpper.includes('PREC') || keyUpper.includes('COSTO') || keyUpper.includes('TOT') || keyUpper.includes('SUE') || keyUpper.includes('SALDO')) {
            const numVal = parseFloat(valor);
            if (!isNaN(numVal)) {
                if ((keyUpper.includes('PREC') || keyUpper.includes('COSTO') || keyUpper.includes('SUE')) && numVal < 0) {
                    return { valido: false, error: `El campo ${key} no puede ser un valor negativo (debe ser mayor o igual a 0).` };
                }
            }
        }
        if (keyUpper.includes('STOCK')) {
            const numStock = Number(valor);
            if (isNaN(numStock) || !Number.isInteger(numStock) || numStock < 0) {
                return { valido: false, error: `El campo ${key} debe ser un número entero mayor o igual a 0.` };
            }
        }
    }
    return { valido: true };
}

// CU-48: editar precio a -10 rechazado
const testCu48 = validarCampoActualizar('PREC_PRO', -10);
assert(!testCu48.valido, 'CU-48: Precio -10 debe ser rechazado');
console.log('  [PASS] CU-48: Editar precio a -10 rechazado correctamente.');

// Editar precio a 0 permitido
const testPrecioCero = validarCampoActualizar('PREC_PRO', 0);
assert(testPrecioCero.valido, 'Precio $0 debe ser permitido');
console.log('  [PASS] Editar precio a $0.00 permitido exitosamente.');

// CU-49: editar stock de planta a -5 rechazado
const testCu49 = validarCampoActualizar('STOCK_PLANT', -5);
assert(!testCu49.valido, 'CU-49: Stock -5 debe ser rechazado');
console.log('  [PASS] CU-49: Editar stock a -5 rechazado correctamente.');

// Editar stock a 0 permitido
const testStockCero = validarCampoActualizar('STOCK_PLANT', 0);
assert(testStockCero.valido, 'Stock 0 debe ser permitido');
console.log('  [PASS] Editar stock a 0 permitido exitosamente.');

// Editar costo a 0 permitido
const testCostoCero = validarCampoActualizar('COSTO_EST', 0);
assert(testCostoCero.valido, 'Costo $0 debe ser permitido');
console.log('  [PASS] Editar costo a $0 permitido exitosamente.');

// Editar costo a -10 rechazado
const testCostoNeg = validarCampoActualizar('COSTO_EST', -10);
assert(!testCostoNeg.valido, 'Costo -10 debe ser rechazado');
console.log('  [PASS] Editar costo a -10 rechazado correctamente.');

// Editar sueldo a 0 permitido
const testSueldoCero = validarCampoActualizar('SUE_EMP', 0);
assert(testSueldoCero.valido, 'Sueldo $0 debe ser permitido');
console.log('  [PASS] Editar sueldo a $0 permitido exitosamente.');

// Editar sueldo a -500 rechazado
const testSueldoNeg = validarCampoActualizar('SUE_EMP', -500);
assert(!testSueldoNeg.valido, 'Sueldo -500 debe ser rechazado');
console.log('  [PASS] Editar sueldo a -500 rechazado correctamente.');

console.log('\n=== TODAS LAS PRUEBAS DE REGRESIÓN DE $0 PASARON SATISFACTORIAMENTE ===\n');
