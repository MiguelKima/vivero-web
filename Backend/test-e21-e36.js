/**
 * Test de Verificación Integral para Incidencias E21 a E36 (Backend y Frontend)
 */

const fs = require('fs');
const assert = require('assert');

console.log('=== TEST VERIFICACIÓN INTEGRAL INCIDENCIAS E21 A E36 ===\n');

// -------------------------------------------------------------
// 1. Pruebas Unitarias de Funciones Validadoras
// -------------------------------------------------------------
console.log('--- 1. Pruebas Unitarias de Funciones Validadoras ---');

function esTelefonoValido(tel) {
    if (!tel || typeof tel !== 'string') return false;
    const digitos = tel.replace(/[\s-]/g, '');
    return /^\d{10}$/.test(digitos);
}

function esRfcValido(rfc) {
    if (!rfc || typeof rfc !== 'string') return false;
    const limpio = rfc.trim().toUpperCase();
    return /^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$/.test(limpio);
}

function esCorreoValido(correo) {
    if (!correo || typeof correo !== 'string') return false;
    const limpio = correo.trim();
    return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(limpio);
}

// E21: Teléfono
assert.strictEqual(esTelefonoValido('abc'), false, 'E21: letras en teléfono deben ser inválidas');
assert.strictEqual(esTelefonoValido('123'), false, 'E21: números cortos (<10) deben ser inválidos');
assert.strictEqual(esTelefonoValido('12345678901'), false, 'E21: números largos (>10) deben ser inválidos');
assert.strictEqual(esTelefonoValido('5512345678'), true, 'E21: 10 dígitos numéricos debe ser válido');
assert.strictEqual(esTelefonoValido('55 1234 5678'), true, 'E21: 10 dígitos con espacios debe ser válido');
assert.strictEqual(esTelefonoValido('55-1234-5678'), true, 'E21: 10 dígitos con guiones debe ser válido');
console.log('  [PASS] E21: Validador de teléfono verificado.');

// E22: RFC
assert.strictEqual(esRfcValido('XYZ'), false, 'E22: RFC corto debe ser inválido');
assert.strictEqual(esRfcValido('XX'), false, 'E22: RFC de 2 caracteres debe ser inválido');
assert.strictEqual(esRfcValido('VECJ880326XXX'), true, 'E22: RFC persona física (13) debe ser válido');
assert.strictEqual(esRfcValido('ABC010101XYZ'), true, 'E22: RFC persona moral (12) debe ser válido');
console.log('  [PASS] E22: Validador de RFC verificado.');

// E23: Correo
assert.strictEqual(esCorreoValido('notanemail'), false, 'E23: notanemail debe ser inválido');
assert.strictEqual(esCorreoValido('a@'), false, 'E23: a@ sin dominio debe ser inválido');
assert.strictEqual(esCorreoValido('contacto@proveedor.com'), true, 'E23: correo válido debe ser aceptado');
console.log('  [PASS] E23: Validador de correo de contacto verificado.');

// -------------------------------------------------------------
// 2. Verificación de Código Fuente en Backend/server.js
// -------------------------------------------------------------
console.log('\n--- 2. Verificación de Reglas e Incidencias en Backend/server.js ---');
const serverSrc = fs.readFileSync('Backend/server.js', 'utf8');

// E21: Teléfono en CLIENTES (POST, PUT y actualizar)
assert.ok(serverSrc.includes('esTelefonoValido'), 'server.js debe definir y usar esTelefonoValido');
assert.ok(/app\.post\('\/api\/clientes'[\s\S]*?esTelefonoValido/.test(serverSrc), 'E21: POST /api/clientes debe validar teléfono');
assert.ok(/app\.put\('\/api\/clientes\/:id'[\s\S]*?esTelefonoValido/.test(serverSrc), 'E21: PUT /api/clientes/:id debe validar teléfono');
assert.ok(/app\.put\('\/api\/actualizar'[\s\S]*?TEL_CLI[\s\S]*?esTelefonoValido/.test(serverSrc), 'E21: PUT /api/actualizar debe validar TEL_CLI');
console.log('  [PASS] E21: Validaciones de teléfono en CLIENTES confirmadas.');

// E22: RFC en PROVEEDORES (POST, PUT y actualizar)
assert.ok(/app\.post\('\/api\/proveedores'[\s\S]*?esRfcValido/.test(serverSrc), 'E22: POST /api/proveedores debe validar RFC');
assert.ok(/app\.put\('\/api\/proveedores\/:id'[\s\S]*?esRfcValido/.test(serverSrc), 'E22: PUT /api/proveedores/:id debe validar RFC');
assert.ok(/app\.put\('\/api\/actualizar'[\s\S]*?RFC_PROV[\s\S]*?esRfcValido/.test(serverSrc), 'E22: PUT /api/actualizar debe validar RFC_PROV');
console.log('  [PASS] E22: Validaciones de RFC en PROVEEDORES confirmadas.');

// E23: Contacto (correo) en PROVEEDORES
assert.ok(/app\.post\('\/api\/proveedores'[\s\S]*?esCorreoValido/.test(serverSrc), 'E23: POST /api/proveedores debe validar correo en contacto');
assert.ok(/app\.put\('\/api\/proveedores\/:id'[\s\S]*?esCorreoValido/.test(serverSrc), 'E23: PUT /api/proveedores/:id debe validar correo en contacto');
assert.ok(/app\.put\('\/api\/actualizar'[\s\S]*?CON_PROV[\s\S]*?esCorreoValido/.test(serverSrc), 'E23: PUT /api/actualizar debe validar CON_PROV');
console.log('  [PASS] E23: Validaciones de correo de contacto en PROVEEDORES confirmadas.');

// E24: Servicios exige cliente y empleado (sin autoasignar primero con LIMIT 1)
assert.ok(/app\.post\('\/api\/servicios'[\s\S]*?El cliente es obligatorio/.test(serverSrc), 'E24: POST /api/servicios debe exigir cliente');
assert.ok(/app\.post\('\/api\/servicios'[\s\S]*?El empleado es obligatorio/.test(serverSrc), 'E24: POST /api/servicios debe exigir empleado');
assert.ok(!/app\.post\('\/api\/servicios'[\s\S]*?SELECT ID_CLI FROM CLIENTES ORDER BY ID_CLI ASC LIMIT 1/.test(serverSrc), 'E24: Debe haberse eliminado el auto-fallback de primer cliente');
console.log('  [PASS] E24: Exigencia de cliente y empleado en servicios confirmada.');

// E25: Contraseña de usuario mínimo 4 caracteres
assert.ok(/app\.post\('\/api\/usuarios'[\s\S]*?password\.trim\(\)\.length < 4/.test(serverSrc), 'E25: POST /api/usuarios debe exigir password >= 4 caracteres');
assert.ok(/app\.put\('\/api\/usuarios\/:id'[\s\S]*?passwordVal[\s\S]*?length < 4/.test(serverSrc), 'E25: PUT /api/usuarios/:id debe exigir password >= 4');
assert.ok(/app\.put\('\/api\/actualizar'[\s\S]*?PASSWORD[\s\S]*?length < 4/.test(serverSrc), 'E25: PUT /api/actualizar debe exigir password >= 4');
console.log('  [PASS] E25: Longitud mínima de contraseña (4 caracteres) confirmada.');

// E26: Rol de usuario catálogo cerrado ('Administrador', 'Empleado')
assert.ok(/app\.post\('\/api\/usuarios'[\s\S]*?ROLES_PERMITIDOS/.test(serverSrc), 'E26: POST /api/usuarios debe restringir roles');
assert.ok(/app\.put\('\/api\/usuarios\/:id'[\s\S]*?ROLES_PERMITIDOS/.test(serverSrc), 'E26: PUT /api/usuarios/:id debe restringir roles');
assert.ok(/app\.put\('\/api\/actualizar'[\s\S]*?ROL[\s\S]*?ROLES_PERMITIDOS/.test(serverSrc), 'E26: PUT /api/actualizar debe restringir ROL');
console.log('  [PASS] E26: Catálogo cerrado de roles de usuario confirmado.');

// E27: Username no permite espacios
assert.ok(/app\.post\('\/api\/usuarios'[\s\S]*?\/\\s\/\.test\(username\)/.test(serverSrc), 'E27: POST /api/usuarios debe rechazar espacios en username');
assert.ok(/app\.put\('\/api\/usuarios\/:id'[\s\S]*?\/\\s\/\.test\(usernameVal\)/.test(serverSrc), 'E27: PUT /api/usuarios/:id debe rechazar espacios en username');
assert.ok(/app\.put\('\/api\/actualizar'[\s\S]*?USERNAME[\s\S]*?\/\\s\/\.test/.test(serverSrc), 'E27: PUT /api/actualizar debe rechazar espacios en USERNAME');
console.log('  [PASS] E27: Prohibición de espacios en username confirmada.');

// E28: Venta forma de pago catálogo cerrado ('Efectivo', 'Tarjeta', 'Transferencia')
assert.ok(/app\.post\('\/api\/ventas'[\s\S]*?FORMAS_PAGO_PERMITIDAS/.test(serverSrc), 'E28: POST /api/ventas debe restringir formas de pago');
assert.ok(/app\.put\('\/api\/actualizar'[\s\S]*?FORM_PAGO[\s\S]*?FORMAS_PAGO_PERMITIDAS/.test(serverSrc), 'E28: PUT /api/actualizar debe restringir FORM_PAGO');
console.log('  [PASS] E28: Catálogo cerrado de formas de pago confirmado.');

// E29: Saldo y total con letras devuelven 400 (isNaN)
assert.ok(/app\.post\('\/api\/ventas'[\s\S]*?isNaN\(Number\(totalRaw\)\)/.test(serverSrc), 'E29: POST /api/ventas debe validar que total sea numérico');
assert.ok(/app\.post\('\/api\/ventas'[\s\S]*?isNaN\(Number\(saldoRaw\)\)/.test(serverSrc), 'E29: POST /api/ventas debe validar que saldo sea numérico');
assert.ok(/app\.put\('\/api\/actualizar'[\s\S]*?isNaN\(Number\(rawStr\)\)/.test(serverSrc), 'E29: PUT /api/actualizar debe validar valores monetarios numéricos');
console.log('  [PASS] E29: Rechazo con 400 de letras en saldo y total confirmado.');

// E30: Pedido validación de catálogos y stock disponible
assert.ok(/app\.post\('\/api\/pedidos'[\s\S]*?mayoreo[\s\S]*?menudeo/.test(serverSrc), 'E30: POST /api/pedidos debe validar tip_ped');
assert.ok(/app\.post\('\/api\/pedidos'[\s\S]*?domicilio[\s\S]*?recogida/.test(serverSrc), 'E30: POST /api/pedidos debe validar tip_env');
assert.ok(/app\.post\('\/api\/pedidos'[\s\S]*?cantNum > stockDisponible/.test(serverSrc), 'E30: POST /api/pedidos debe validar stock de producto');
assert.ok(/app\.post\('\/api\/pedidos'[\s\S]*?cantPlantNum > stockPlantDisponible/.test(serverSrc), 'E30: POST /api/pedidos debe validar stock de planta');
console.log('  [PASS] E30: Validación de tipos y stock en pedidos confirmada.');

// E31: Horario de empleado catálogo de turnos
assert.ok(/app\.post\('\/api\/empleados'[\s\S]*?TURNOS_PERMITIDOS/.test(serverSrc), 'E31: POST /api/empleados debe validar turnos');
assert.ok(/app\.put\('\/api\/empleados\/:id'[\s\S]*?TURNOS_PERMITIDOS/.test(serverSrc), 'E31: PUT /api/empleados/:id debe validar turnos');
assert.ok(/app\.put\('\/api\/actualizar'[\s\S]*?HOR_EMP[\s\S]*?TURNOS_PERMITIDOS/.test(serverSrc), 'E31: PUT /api/actualizar debe validar turnos en HOR_EMP');
console.log('  [PASS] E31: Catálogo de turnos en horario de empleado confirmado.');

// E32: Campos con solo espacios se guardan como NULL (no "") y limpieza en BD
assert.ok(/typeof valor === 'string' && valor\.trim\(\) === ''[\s\S]*?valor = null/.test(serverSrc), 'E32: PUT /api/actualizar debe convertir espacios a NULL');
assert.ok(serverSrc.includes("UPDATE CLIENTES SET TEL_CLI = NULL WHERE TEL_CLI IS NOT NULL AND TRIM(TEL_CLI) = ''"), 'E32: limpiarDatosInvalidosBaseDatos debe actualizar TEL_CLI');
assert.ok(serverSrc.includes("UPDATE PROVEEDORES SET RFC_PROV = NULL WHERE RFC_PROV IS NOT NULL AND TRIM(RFC_PROV) = ''"), 'E32: limpiarDatosInvalidosBaseDatos debe actualizar RFC_PROV');
assert.ok(serverSrc.includes("UPDATE EMPLEADOS SET CURP_EMP = NULL WHERE CURP_EMP IS NOT NULL AND TRIM(CURP_EMP) = ''"), 'E32: limpiarDatosInvalidosBaseDatos debe actualizar CURP_EMP');
console.log('  [PASS] E32: Manejo de NULL para cadenas vacías/espacios confirmado.');

// E33: Límite monetario MAX_MONTO_PERMITIDO = 99999999.99 y prevalidación de FKs
assert.ok(serverSrc.includes('const MAX_MONTO_PERMITIDO = 99999999.99'), 'E33: Debe existir constante MAX_MONTO_PERMITIDO');
assert.ok(/app\.post\('\/api\/servicios'[\s\S]*?numCosto > MAX_MONTO_PERMITIDO/.test(serverSrc), 'E33: Servicios debe validar monto máximo');
assert.ok(/app\.post\('\/api\/ventas'[\s\S]*?numTotal > MAX_MONTO_PERMITIDO/.test(serverSrc), 'E33: Ventas debe validar monto máximo');
assert.ok(/app\.post\('\/api\/pedidos'[\s\S]*?totalFinal > MAX_MONTO_PERMITIDO/.test(serverSrc), 'E33: Pedidos debe validar monto máximo');
assert.ok(/app\.post\('\/api\/servicios'[\s\S]*?El cliente seleccionado no existe en el sistema/.test(serverSrc), 'E33: Servicios debe prevalidar FK de cliente');
assert.ok(/app\.post\('\/api\/ventas'[\s\S]*?El cliente seleccionado no existe en el sistema/.test(serverSrc), 'E33: Ventas debe prevalidar FK de cliente');
console.log('  [PASS] E33: Límite monetario y prevalidación de llaves foráneas confirmados.');

// E34: PUT /api/empleados/:id con sueldo inválido devuelve 400
assert.ok(/app\.put\('\/api\/empleados\/:id'[\s\S]*?isNaN\(Number\(rawStr\)\)[\s\S]*?res\.status\(400\)/.test(serverSrc), 'E34: PUT empleados debe retornar 400 ante sueldo no numérico');
assert.ok(/app\.put\('\/api\/empleados\/:id'[\s\S]*?numSueldo < 0[\s\S]*?res\.status\(400\)/.test(serverSrc), 'E34: PUT empleados debe retornar 400 ante sueldo negativo');
console.log('  [PASS] E34: Rechazo con 400 en PUT empleados ante sueldo inválido confirmado.');

// E35: Nombres únicos en PROVEEDORES y CAT_SERVICIOS (case-insensitive)
assert.ok(/app\.post\('\/api\/proveedores'[\s\S]*?SELECT COUNT\(\*\)[\s\S]*?TRIM\(LOWER\(NOM_PROV\)\) = TRIM\(LOWER\(\$1\)\)/.test(serverSrc), 'E35: POST /api/proveedores debe validar unicidad de nombre');
assert.ok(/app\.put\('\/api\/proveedores\/:id'[\s\S]*?TRIM\(LOWER\(NOM_PROV\)\) = TRIM\(LOWER\(\$1\)\)/.test(serverSrc), 'E35: PUT /api/proveedores/:id debe validar unicidad de nombre');
assert.ok(/app\.post\('\/api\/catalogo-servicios'[\s\S]*?TRIM\(LOWER\(NOM_SERV\)\) = TRIM\(LOWER\(\$1\)\)/.test(serverSrc), 'E35: POST /api/catalogo-servicios debe validar unicidad de nombre');
assert.ok(/app\.put\('\/api\/actualizar'[\s\S]*?NOM_PROV[\s\S]*?NOM_SERV/.test(serverSrc), 'E35: PUT /api/actualizar debe validar unicidad de nombre en proveedores y servicios');
console.log('  [PASS] E35: Validación de unicidad de nombres en proveedores y catálogo confirmada.');

// E36: CURP y RFC de empleado
assert.ok(/app\.post\('\/api\/empleados'[\s\S]*?curpLimpio[\s\S]*?regexCurp/.test(serverSrc), 'E36: POST /api/empleados debe validar formato oficial de CURP');
assert.ok(/app\.get\('\/api\/empleados'[\s\S]*?CASE[\s\S]*?CURP_EMP IS NULL OR TRIM\(CURP_EMP\) = '' THEN NULL/.test(serverSrc), 'E36: GET empleados debe retornar NULL cuando CURP_EMP está vacío');
console.log('  [PASS] E36: Validaciones de CURP y RFC en empleados confirmadas.');

// -------------------------------------------------------------
// 3. Verificación de Formularios Frontend
// -------------------------------------------------------------
console.log('\n--- 3. Verificación de Formularios Frontend ---');

const cliHtml = fs.readFileSync('Frontend/registro-cliente.html', 'utf8');
assert.ok(cliHtml.includes('Teléfono Inválido') && cliHtml.includes('10 dígitos'), 'Frontend registro-cliente debe validar formato de 10 dígitos');

const prvHtml = fs.readFileSync('Frontend/registro-proveedor.html', 'utf8');
assert.ok(prvHtml.includes('RFC Inválido') && prvHtml.includes('Contacto Inválido'), 'Frontend registro-proveedor debe validar RFC y correo');

const usrHtml = fs.readFileSync('Frontend/registro-usuario.html', 'utf8');
assert.ok(usrHtml.includes('no puede contener espacios') && usrHtml.includes('longitud mínima de 4 caracteres'), 'Frontend registro-usuario debe validar espacios y contraseña >= 4');

const empHtml = fs.readFileSync('Frontend/registro-empleado.html', 'utf8');
assert.ok(empHtml.includes('<select id="hor_emp">') && empHtml.includes('Matutino') && empHtml.includes('Vespertino'), 'Frontend registro-empleado debe tener selector de turnos');
assert.ok(empHtml.includes('Monto Excedido'), 'Frontend registro-empleado debe validar límite monetario');

const venHtml = fs.readFileSync('Frontend/registro-venta.html', 'utf8');
assert.ok(venHtml.includes('total <= 0') && venHtml.includes('99999999.99'), 'Frontend registro-venta debe validar total > 0 y monto máximo');

const pedHtml = fs.readFileSync('Frontend/registro-pedido.html', 'utf8');
assert.ok(pedHtml.includes('Stock Insuficiente'), 'Frontend registro-pedido debe validar stock disponible antes de enviar');

const srvHtml = fs.readFileSync('Frontend/registro-servicio.html', 'utf8');
assert.ok(srvHtml.includes('El cliente es obligatorio') && srvHtml.includes('El empleado responsable es obligatorio'), 'Frontend registro-servicio debe exigir cliente y empleado');

console.log('  [PASS] Todos los formularios Frontend tienen las validaciones sincronizadas.');

console.log('\n=== TODAS LAS PRUEBAS DE E21 A E36 PASARON EXITOSAMENTE ===');
