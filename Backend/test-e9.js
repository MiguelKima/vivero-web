const fs = require('fs');
const assert = require('assert');

// 1. Verificar presencia de responderErrorPostgres en server.js
const serverSource = fs.readFileSync('Backend/server.js', 'utf8');

assert(serverSource.includes('function responderErrorPostgres'), 'Debe existir la función responderErrorPostgres');
assert(serverSource.includes('El identificador'), 'Debe incluir "El identificador"');
assert(serverSource.includes('ya existe en el sistema'), 'Debe incluir "ya existe en el sistema"');
assert(serverSource.includes('La referencia no existe'), 'Debe incluir "La referencia no existe"');
assert(serverSource.includes('Falta un campo obligatorio'), 'Debe incluir "Falta un campo obligatorio"');

// 2. Extraer y evaluar responderErrorPostgres directamente
const matchHelper = serverSource.match(/function responderErrorPostgres\([\s\S]*?\n\}/);
assert(matchHelper, 'No se pudo extraer responderErrorPostgres');

const fnCode = matchHelper[0];
const fn = new Function('res', 'err', 'idPropuesto', 'mensajePorDefecto', 'logPrefix', `
    ${fnCode};
    return responderErrorPostgres(res, err, idPropuesto, mensajePorDefecto, logPrefix);
`);

console.log('--- Probando función responderErrorPostgres ---');

function mockRes() {
    return {
        _status: null,
        _json: null,
        status(s) {
            this._status = s;
            return this;
        },
        json(j) {
            this._json = j;
            return this;
        }
    };
}

// Capturar logs de console.error
let logs = [];
const originalConsoleError = console.error;
console.error = (...args) => {
    logs.push(args.join(' '));
};

try {
    // Caso 1: Error 23505 con idPropuesto
    logs = [];
    let res = mockRes();
    fn(res, { code: '23505', message: 'duplicate key value violates unique constraint "empleados_pkey"', detail: 'Key (id_emp)=(EMP-025) already exists.' }, 'EMP-025', 'Error al guardar el empleado.', 'Error al registrar empleado');
    assert.strictEqual(res._status, 500);
    assert.deepStrictEqual(res._json, { exito: false, error: 'El identificador EMP-025 ya existe en el sistema' });
    assert(logs.some(l => l.includes('violates unique constraint') && l.includes('Key (id_emp)=(EMP-025) already exists.')), 'Debe registrar err.message y err.detail en el log');
    console.log('  [PASS] 23505 con idPropuesto devuelve "El identificador EMP-025 ya existe en el sistema" y loguea err.message y err.detail.');

    // Caso 2: Error 23505 sin idPropuesto pero con err.detail
    logs = [];
    res = mockRes();
    fn(res, { code: '23505', message: 'duplicate key', detail: 'Key (id_cli)=(CLI-045) already exists.' }, null, 'Error al guardar el cliente.', 'Error al registrar cliente');
    assert.strictEqual(res._status, 500);
    assert.deepStrictEqual(res._json, { exito: false, error: 'El identificador CLI-045 ya existe en el sistema' });
    console.log('  [PASS] 23505 extrayendo ID de err.detail devuelve "El identificador CLI-045 ya existe en el sistema".');

    // Caso 3: Error 23503 (Foreign key)
    logs = [];
    res = mockRes();
    fn(res, { code: '23503', message: 'insert or update on table "productos" violates foreign key constraint', detail: 'Key (id_prov)=(PRV-999) is not present in table "proveedores".' }, 'PRO-025', 'Error al guardar el producto.', 'Error al registrar producto');
    assert.strictEqual(res._status, 500);
    assert.deepStrictEqual(res._json, { exito: false, error: 'La referencia no existe' });
    assert(logs.some(l => l.includes('violates foreign key constraint') && l.includes('is not present in table')), 'Debe registrar err.message y err.detail en el log');
    console.log('  [PASS] 23503 devuelve "La referencia no existe" y loguea err.message y err.detail.');

    // Caso 4: Error 23502 (Not null)
    logs = [];
    res = mockRes();
    fn(res, { code: '23502', message: 'null value in column "nom_emp" violates not-null constraint', detail: 'Failing row contains (EMP-025, null).' }, 'EMP-025', 'Error al guardar el empleado.', 'Error al registrar empleado');
    assert.strictEqual(res._status, 500);
    assert.deepStrictEqual(res._json, { exito: false, error: 'Falta un campo obligatorio' });
    assert(logs.some(l => l.includes('violates not-null constraint') && l.includes('Failing row contains')), 'Debe registrar err.message y err.detail en el log');
    console.log('  [PASS] 23502 devuelve "Falta un campo obligatorio" y loguea err.message y err.detail.');

    // Caso 5: Error genérico
    logs = [];
    res = mockRes();
    fn(res, { code: '42P01', message: 'relation "inventario" does not exist', detail: undefined }, 'PRO-025', 'Error al guardar el producto.', 'Error al registrar producto');
    assert.strictEqual(res._status, 500);
    assert.deepStrictEqual(res._json, { exito: false, error: 'Error al guardar el producto.' });
    console.log('  [PASS] Error no clasificado mantiene el mensaje por defecto del endpoint.');

} finally {
    console.error = originalConsoleError;
}

// 3. Verificar que los 10 endpoints de registro tienen responderErrorPostgres en su catch
const endpoints = [
    { nombre: 'POST /api/proveedores', regex: /app\.post\('\/api\/proveedores'[\s\S]*?responderErrorPostgres/ },
    { nombre: 'POST /api/clientes', regex: /app\.post\('\/api\/clientes'[\s\S]*?responderErrorPostgres/ },
    { nombre: 'POST /api/empleados', regex: /app\.post\('\/api\/empleados'[\s\S]*?responderErrorPostgres/ },
    { nombre: 'POST /api/catalogo-servicios', regex: /app\.post\('\/api\/catalogo-servicios'[\s\S]*?responderErrorPostgres/ },
    { nombre: 'POST /api/productos', regex: /app\.post\('\/api\/productos'[\s\S]*?responderErrorPostgres/ },
    { nombre: 'POST /api/plantas', regex: /app\.post\('\/api\/plantas'[\s\S]*?responderErrorPostgres/ },
    { nombre: 'POST /api/servicios', regex: /app\.post\('\/api\/servicios'[\s\S]*?responderErrorPostgres/ },
    { nombre: 'POST /api/pedidos', regex: /app\.post\('\/api\/pedidos'[\s\S]*?responderErrorPostgres/ },
    { nombre: 'POST /api/ventas', regex: /app\.post\('\/api\/ventas'[\s\S]*?responderErrorPostgres/ },
    { nombre: 'POST /api/usuarios', regex: /app\.post\('\/api\/usuarios'[\s\S]*?responderErrorPostgres/ }
];

console.log('\n--- Verificando conexión en los 10 endpoints POST ---');
for (const ep of endpoints) {
    assert(ep.regex.test(serverSource), `El endpoint ${ep.nombre} debe usar responderErrorPostgres en su catch`);
    console.log(`  [PASS] ${ep.nombre} conectado correctamente.`);
}

console.log('\n=== TODAS LAS VERIFICACIONES DE E9 COMPLETADAS EXITOSAMENTE ===\n');
